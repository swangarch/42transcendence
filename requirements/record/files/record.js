const fastify = require('fastify')();
const Database = require('better-sqlite3');


var database;
try{
  database = new Database('./data/record.db');
}
catch(e)
{
  console.log("info [user]: Failed to create / load database.");
}

//--------------------------------------------record----------------------------------------------------

try {
      database.exec(`
      CREATE TABLE IF NOT EXISTS record(
        id  INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        alias1    TEXT,
        alias2   TEXT,
        type     TEXT,
        winner   TEXT,
        score    TEXT
      ) STRICT
  `);
}
catch (e)
{
  console.log("info [record]:", e);
}

const insert = database.prepare('INSERT INTO record (timestamp, alias1, alias2, winner, score, type) VALUES (?, ?, ?, ?, ?, ?)');
const query_record = database.prepare('SELECT timestamp, alias1, alias2, type, winner, score FROM record WHERE alias1=? or alias2=?');
const update_alias1 = database.prepare('UPDATE record SET alias1=@new_alias WHERE alias1=@old_alias');
const update_alias2 = database.prepare('UPDATE record SET alias2=@new_alias WHERE alias2=@old_alias');

//--------------------------------------------record----------------------------------------------------


//--------------------------------------------score----------------------------------------------------

try {
  database.exec(`
      CREATE TABLE IF NOT EXISTS score_table(
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      alias   TEXT UNIQUE,
      score   INTEGER DEFAULT 0,
      wins    INTEGER DEFAULT 0,
      losses  INTEGER DEFAULT 0

      ) STRICT
`);
}
catch (e)
{
  console.log("info [record]:", e);
}

const update_alias_score_table = database.prepare('UPDATE score_table SET alias=@new_alias WHERE alias=@old_alias');
const save_user_result = database.prepare(`INSERT INTO score_table(alias, score, wins, losses) VALUES (?, ?, ?, ?) 
    ON CONFLICT (alias) DO UPDATE SET 
    score= score + excluded.score, 
    wins= wins + excluded.wins, 
    losses= losses + excluded.losses`
);

const get_user_score = database.prepare(`SELECT * FROM score_table ORDER BY score DESC LIMIT 10`);

const get_user_record = database.prepare(`SELECT * FROM score_table WHERE alias=?`);
const get_user_rank = database.prepare(`SELECT COUNT(*) + 1 AS rank 
    FROM score_table
    WHERE score > (SELECT score FROM score_table WHERE alias=?)`);

//--------------------------------------------score----------------------------------------------------


function show_record_db(database)
{
  const query = database.prepare('SELECT * FROM record ORDER BY id');
  console.table(query.all());
}

//---------------------------------------recieve update of alias from user---------------------------------------------//


fastify.patch('/internal/api/update', (req, res) => { //update alias when it is changed
  try{
    const alias1_updated = update_alias1.run(req.body);
    const alias2_updated = update_alias2.run(req.body);
    const alias_scoretable_updated = update_alias_score_table.run(req.body);
    if(alias1_updated.changes != 0 || alias2_updated.changes != 0 || alias_scoretable_updated.changes != 0)
    {
      console.log("info [friend]: User alias has been updated from", req.body.old_alias, "to", req.body.new_alias);
      res.code(200).send({info: "[record] User alias updated"});
    }
    else
    {
      res.code(200).send({info: "[record] User alias not need to be updated"});
    }
  } 
  catch(e)
  {
    res.code(400).send({info: "[record] Error: User alias not updated"});
    console.log("info [friend]:", e);
  }
});

//---------------------------------------recieve update of alias from user---------------------------------------------//

fastify.post('/internal/api/record/', (req, res) => {
  var info = '';
  try
  {
    insert.run(req.body.timestamp, req.body.alias1, req.body.alias2, req.body.winner, req.body.score, req.body.type);

    //------------------------------score----------------------
    
    let  score_gained = 100;
    if (req.body.type === "tournament_semifinal")
      score_gained = 200;
    else if (req.body.type === "tournament_final")
      score_gained = 400;

    const winner = req.body.winner;
    const loser = req.body.alias2 === req.body.winner ? req.body.alias1 : req.body.alias2;
    if (winner !== "AI_Bot")
      save_user_result.run(winner, score_gained, 1, 0); //winner
    if (loser !== "AI_Bot")
      save_user_result.run(loser, 10, 0, 1); //loser


    ////////////////////////////////////////////////////visualize database in the background/////////////////////////////////
    // show_record_db(database);
    ////////////////////////////////////////////////////visualize database in the background/////////////////////////////////
    console.log("info [record]: record", req.body.alias1, "is created.");

    res.code(200).send({info: 'Record created.'});
  }
  catch(e)
  {
    res.code(400).send({info: 'Error: Fail to create record.'});
    console.log("info [record]:", e);
  }
});

fastify.get('/api/record/:id', (req, res) =>{  //request info [user], like alias
  try
  {
    const userId = req.params.id;
    const record = query_record.all(userId, userId);
    const dataBack = JSON.stringify(record);
    res.code(200).send(dataBack);
  }
  catch(e)
  {
    const dataStr = {"info": "Error: request error.", success: false};
    const dataBack = JSON.stringify(dataStr);
    res.code(400).send(dataBack);
    console.log("info [record]: Error:", error);
    return;
  }
});

fastify.get('/api/record/statistic/:id', (req,res) => 
{
  try{
    const user_record = get_user_record.get(req.params.id);
    const user_rank = get_user_rank.get(req.params.id);

    if (!user_record || !user_rank)
    {
      const dataReturn = {
      info: "Successfully get user record list.",
      data: {
          alias: req.params.id,
          score: 0,
          wins: 0,
          losses: 0,
          rate: 0,
          total_matches: 0,
          rank: -1,
          online: true
        }
      };
      const dataBack = JSON.stringify(dataReturn);
      res.code(200).send(dataBack);
      return;
    }

    const dataReturn = {
      info: "Successfully get user record list.",
      data: {
        alias: user_record.alias,
        score: user_record.score,
        wins: user_record.wins,
        losses: user_record.losses,
        rate: user_record.wins / (user_record.wins + user_record.losses),
        total_matches: user_record.wins + user_record.losses,
        rank: user_rank.rank,
        online: true
      }
    };

    res.code(200).send(JSON.stringify(dataReturn));
  }
  catch (error)
  {
    res.code(400).send( {"info": "Error: request error.", success: false});
    console.log("info [record]: Error:", error);
  }
});

fastify.get('/internal/api/rank/', (req,res) => {
  try{
    const top10 = get_user_score.all();
    res.code(200).send({info: "Successfully get rank list", data: top10});
  }
  catch (error)
  {
    res.code(400).send({"info": "Error: request error.", success: false});
    console.log("info [record]: Error:", error);
  }
});

fastify.listen({port : 9431, host: '0.0.0.0'}, (err)=>{
  if (err){
    fastify.log.error(err);
    process.exit(1);
  }
  console.log("info [record]: Record server listening to port 9431");
});
