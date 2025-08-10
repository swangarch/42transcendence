if (!process.env.JWT_SECRET || process.env.JWT_SECRET === "")
{
    console.log("info [game]: Error, no token is provide.");
    process.exit(1);
}
const jwt_secret = process.env.JWT_SECRET;

const fastify = require('fastify')();
const Database = require('better-sqlite3');

const fastifyJwt = require('@fastify/jwt');
const fastifyCookie = require('@fastify/cookie');
const fastifyCors = require('@fastify/cors');

const database = new Database('./data/friendsDB.db');


try {
  database.exec(`
      CREATE TABLE IF NOT EXISTS friends(
        id  INTEGER PRIMARY KEY AUTOINCREMENT,
        alias1    TEXT,
        alias2   TEXT,
        state   TEXT
      )
  `);
}
catch(e)
{
  console.log("info [friend]:", e);
}


const insert = database.prepare('INSERT INTO friends (alias1, alias2, state) VALUES (?, ?, ?)');
const query_friends = database.prepare('SELECT alias1, alias2, state FROM friends WHERE (alias1=? or alias2=?) and (state=\'accepted\' or state=\'pending\')');
const query_bidirectional_friend = database.prepare('SELECT alias1, alias2, state FROM friends WHERE (alias1=? and alias2=?) or (alias2=? and alias1=?)');
const query_pending_request = database.prepare('SELECT alias1, alias2, state FROM friends WHERE (alias1=? and alias2=?) and state=\'pending\'');
const update_friend = database.prepare('UPDATE friends SET state=@state WHERE alias1=@from and alias2=@to');
const delete_friend = database.prepare('DELETE FROM friends WHERE (alias1=? and alias2=?) or (alias2=? and alias1=?)');

fastify.register(fastifyCors, {
  origin: 'https://localhost:9000',
  credentials: true
});

fastify.register(fastifyJwt, {
  secret: jwt_secret,
  cookie: {
    cookieName: 'token',
    signed: false
  },
  token: (request) => {
    const auth = request.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) {
      return auth.slice(7);
    }
    if (request.cookies && request.cookies.token) {
      return request.cookies.token;
    }
    return null;
  }
});

fastify.register(fastifyCookie);

async function verifyToken(req, res) {
  try {
    await req.jwtVerify();
    return false;
  } catch (err) {
    console.log('JWT verify failed:', err);
    res.code(401).send({ info: 'Invalid token', username: '', alias: '', state2fa: false });
    return true;
  }
}

function show_record_db(database)
{
  const query = database.prepare('SELECT * FROM friends ORDER BY id');
  console.table(query.all());
}

async function check_alias_exist(userAlias) {
  try {
    const uri = "http://t_user:9223/internal/api/users/" + userAlias;
    const res = await fetch(uri, {
      method: "GET",
    });

    if (res.status === 404)
    {
      return false;
    }

    if (!res.ok) {
      throw new Error("Error: wrong response from the other services");
    }

    const data = await res.json();
    return true;
  }
  catch (e)
  {
    console.log("info [friend]:", e);
    return false;
  }
}

fastify.post('/api/friends/add/', async (req, res) => {
  var info = '';
  try
  {
    if (await verifyToken(req, res)) return;
    if (req.user.alias !== req.body.from) {
      res.code(403).send({ info: 'Forbidden' });
      return ;
    }
    const check_bidirectional_friend = query_bidirectional_friend.all(req.body.from, req.body.to, req.body.from, req.body.to);

    const friend_exist = await check_alias_exist(req.body.to);

    if (!friend_exist)
    {
      res.code(400);
      info = 'Error: Fail to add friend.';
      body = JSON.stringify({info});
      res.send(body);
      console.log("info [friend]: Friend request from", req.body.from, "send to non existing user.");
      return;
    }

    if (req.body.from === req.body.to)
    {
      res.code(400);
      info = 'Error: Fail to add friend.';
      body = JSON.stringify({info});
      res.send(body);
      console.log("info [friend]: Friend request from", req.body.from, "send to same user.");
      return;
    }
    if (check_bidirectional_friend.length != 0)
    {
      res.code(409);
      info = 'Error: Fail to add friend.';
      body = JSON.stringify({info});
      res.send(body);
      console.log("info [friend]: Friend request from", req.body.from, "to", req.body.to, "already exists.");
      return;
    }
    insert.run(req.body.from, req.body.to, 'pending');
    ////////////////////////////////////////////////////visualize database in the background/////////////////////////////////
    // show_record_db(database);
    ////////////////////////////////////////////////////visualize database in the background/////////////////////////////////
    console.log("info [friend]: Friend request from", req.body.from, "is added to", req.body.to, ".");

    res.code(200);
    res.header('Content-Type', 'application/json');
    info = 'Friend request sended.';
    body = JSON.stringify({info});
    res.send(body);
  }
  catch(e)
  {
    res.code(400);
    info = 'Error: Fail to add friend.';
    body = JSON.stringify({info});
    res.send(body);
    console.log("info [friend]:", e);
  }
});

function get_friend_list(id, friendsList)
{
  let outlist = [];
  try {
    for (let i = 0; i < friendsList.length; i++)
    {
      if (friendsList[i].alias1 === id)
      {
        outlist.push({alias: friendsList[i].alias2, state: friendsList[i].state, fromUser: true});
      } 
      else if (friendsList[i].alias2 === id)
      {
        outlist.push({alias: friendsList[i].alias1, state: friendsList[i].state, fromUser: false});
      }
      else {
        ;
      }
    }
    return outlist;
  }
  catch(e)
  {
    console.log("info [friend]:", e);
    return [];
  }
}

fastify.get('/internal/api/friends/:id', async (req, res) =>{
  try
  {
    const userId = req.params.id;
    const friend = query_friends.all(userId, userId);
    const dataBack = {"info" : "Friends list get." , "data" : get_friend_list(userId, friend)};
    res.code(200).send(dataBack);
  }
  catch(e)
  {
    const dataStr = {"info": "Error: request error.", success: false};
    const dataBack = JSON.stringify(dataStr);
    res.code(400).send(dataBack);
    console.log(e);
    return;
  }
});

fastify.post('/api/friends/accept', async (req, res) =>{
  try
  {
    if (await verifyToken(req, res)) return;
    if (req.user.alias !== req.body.to) {
      res.code(403).send({ info: 'Forbidden' });
      return ;
    }
    const check_existing_request = query_pending_request.all(req.body.from, req.body.to);

    if (check_existing_request.length == 0)
    {
      res.code(400);
      info = 'Error: Fail to accept friend request.';
      body = JSON.stringify({info});
      res.send(body);
      console.log("info [friend]: Try to accept request from", req.body.from, "to", req.body.to, "which doesn't exist.");
      return;
    }

    if (req.body.accepted === true)
    {
        update_friend.run({state: "accepted", from: req.body.from, to: req.body.to});
        res.code(200).send({info: "Friends request accepted."});
        console.log("info [friend]: Friend request to", req.body.to, "is accepted.");
        ////////////////////////////////////////////////////visualize database in the background/////////////////////////////////
        // show_record_db(database);
        ////////////////////////////////////////////////////visualize database in the background/////////////////////////////////
    }
    else
    {
        update_friend.run({state: "refused", from: req.body.from, to: req.body.to});
        res.code(200).send({info: "Friends request refused."});
        console.log("info [friend]: Friend request to", req.body.to, "is refused.");
    }
  }
  catch(e)
  {
    const dataStr = {"info": "Error: Fail to accept friend request.", success: false};
    const dataBack = JSON.stringify(dataStr);
    res.code(400).send(dataBack);
    console.log(e);
    return;
  }
});

fastify.post('/api/friends/delete', async (req, res) => {
    try{
        if (await verifyToken(req, res)) return;
        if (req.user.alias !== req.body.from && req.user.alias !== req.body.to) {
          res.code(403).send({ info: 'Forbidden' });
          return ;
        }
        const info = delete_friend.run(req.body.from, req.body.to, req.body.from, req.body.to);

        if (info.changes === 0)
        {
            res.code(200).send(JSON.stringify({info: "Not friend yet."}))
        }
        else
        {
            res.code(200).send(JSON.stringify({info: "Friend deleted."}))
        }
    }
    catch (e)
    {
      console.log("info [friends]:", e);
      res.code(400),send(JSON.stringify({info: "Failed to delete friend."}))
    }
});

//---------------------------------------recieve update of alias from user---------------------------------------------//
const update_alias1 = database.prepare('UPDATE friends SET alias1=@new_alias WHERE alias1=@old_alias');
const update_alias2 = database.prepare('UPDATE friends SET alias2=@new_alias WHERE alias2=@old_alias');

fastify.patch('/internal/api/update', (req, res) => {
  try{
    const alias1_updated = update_alias1.run(req.body);
    const alias2_updated = update_alias2.run(req.body);
    if(alias1_updated.changes != 0 || alias2_updated.changes != 0)
    {
      console.log("info [friend]: User alias has been updated from", req.body.old_alias, "to", req.body.new_alias);
      res.code(200).send({info: "[friend] User alias updated"});
    }
    else
    {
      res.code(200).send({info: "[friend] User alias not need to be updated"});
    }
  } 
  catch(e)
  {
    res.code(400).send({info: "[friend] Error: User alias not updated"});
    console.log("info [friend]:", e);
  }
});

fastify.listen({port : 9766, host: '0.0.0.0'}, (err)=>{
  if (err){
    fastify.log.error(err);
    process.exit(1);
  }
  console.log("info [friend]: Friend server listening to port 9766");
});
