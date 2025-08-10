if (!process.env.JWT_SECRET || process.env.JWT_SECRET === "")
{
    console.log("info [game]: Error, no token is provide.");
    process.exit(1);
}
const jwt_secret = process.env.JWT_SECRET;

const fastify = require('fastify')();
const WebSocket = require('ws');

const jwt = require('jsonwebtoken');
const cookie = require('cookie');

const socket = new WebSocket.Server({port: 9555, host: "0.0.0.0"});
console.log("info [broker]: Broker websocket listening to port 9555");

var sockMap = new Map();
var roomid = 1000;

var rank_list = undefined;
class connection{
    constructor(init_event, socket)
    {
        this.username = init_event.username;
        this.socket = socket;
        this.alias = init_event.alias;
        this.friend_list = undefined;
        this.game_record = undefined;
        this.user_card = undefined;
    }
}

socket.on('connection', async (socket, req) => {
  const cookies = cookie.parse(req.headers.cookie || '');
  const token = cookies.token;

  if (!token) {
    socket.close(4001, 'No token provided');
    console.log("info [broker]: Failed to verify token, connection refused at " + req.socket.remoteAddress.replace("::ffff:", "") + ":" + req.socket.remotePort);
    return;
  }

  try {
    const decoded = jwt.verify(token, jwt_secret);
    socket.user = decoded;
    console.log('info [broker]: WebSocket JWT verified, use added:', socket.user.username, socket.user.alias);

    socket.user.socket = socket;
    sockMap.set(socket, new connection(socket.user, socket));
    await send_friend_list(socket, true);
    await send_game_record(socket, true);
    await send_rank_list(true);
    await send_user_card(socket, true);
    
    } catch (err) {
        socket.close(4002, 'Invalid token');
        console.log('info [broker]: Error:', err);
    }


  socket.on('close', () => {
    console.log("info [broker]: Client disconnected from server for", socket.user.alias);
    sockMap.delete(socket);
    });

  socket.on('error', (error) => {
    console.log("info [broker]: Error Websocket: ", error);
    sockMap.delete(socket);
    socket.close();
    });

  socket.on('message', message => {
    try {
        event_handler(message, socket);
    }
    catch (e)
    {
      console.log("info [broker]: Error:", e);
    }
  });
});


function create_event_map()
{
    return {
        "create_game_remote": (data) => create_game(data.leftPlayer, data.rightPlayer),

        "invite_remote_init": (data) => {
            const socket_to = get_socket_by_alias(data.to);
            const socket_from = get_socket_by_alias(data.from);
            
            if (socket_from === undefined || socket_to === undefined || data.from === data.to)
            {
                const dataReturn = {
                    evt: "invite_remote_impossible",
                    from: data.from, 
                    to: data.to,
                }
                const dataJson = JSON.stringify(dataReturn);
                socket_from.send(dataJson);
            }
            else
            {
                const dataReturn = {
                    evt: "invite_remote_server",
                    from: data.from, 
                    to: data.to,
                }
                const dataJson = JSON.stringify(dataReturn);
                socket_to.send(dataJson);
            }
        },

        "invite_remote_accept": (data) => {
            console.log("info [broker]: Game invitation from", data.from, "to", data.to, "is accepted.");
            const socket_from = get_socket_by_alias(data.from);

            const dataReturn_host = {
                evt: "invite_remote_established_host",
                from: data.from, 
                to: data.to,
                roomid: roomid++
            }
            const dataJson_host = JSON.stringify(dataReturn_host);

            socket_from.send(dataJson_host);
        },

        "invite_remote_refuse": (data) => {
            console.log("info [broker]: Game invitation from", data.from, "to", data.to, "is refused.");
            const socket_from = get_socket_by_alias(data.from);

            const dataReturn_host = {
                evt: "invitation_refused",
                from: data.from, 
                to: data.to,
            }
            const dataJson_host = JSON.stringify(dataReturn_host);

            socket_from.send(dataJson_host);
        },

        "invite_remote_busy": (data) => {
            console.log("info [broker]: Game invitation from", data.from, "to", data.to, "is refused.");
            const socket_from = get_socket_by_alias(data.from);

            const dataReturn_host = {
                evt: "invitation_busy",
                from: data.from, 
                to: data.to,
            }
            const dataJson_host = JSON.stringify(dataReturn_host);

            socket_from.send(dataJson_host);
        },

        "invite_remote_game_created": (data) => {
            console.log("info [broker]: Game invitation from", data.from, "to", data.to, "is created.");
            const socket_to = get_socket_by_alias(data.to);

            const dataReturn_guest = {
                evt: "invite_remote_established_guest",
                from: data.from, 
                to: data.to,
                roomid: data.roomid
            }
            const dataJson_guest = JSON.stringify(dataReturn_guest);
            socket_to.send(dataJson_guest);
        },

        "ping": (data) => {},
    };
}


const handlers = create_event_map();

function event_handler(message, socket)
{
    try
    {
        const data = JSON.parse(message);

        const handler = handlers[data.evt];
        if (handler)
            handler(data);
        else
            console.log("info [broker]: Unhandled event", data.evt);
    }
    catch (e)
    {
        console.log("info [broker]: Parse error", message);
    }
    
}

//-----------------------------------------------------------------keep alive----------------------------------------------------

function keep_connection()
{
    pong_timer = setInterval(() => {
        try{
            for (const [sock, conn] of sockMap)
            {
                sock.send(JSON.stringify({username: conn.username, evt: "pong"}));
            } 
        }
        catch(e)
        {
            console.log("info [broker]:", e);
        }
        
    }, 5000);
}
//-----------------------------------------------------------------keep alive----------------------------------------------------

//-----------------------------------------------------------------rank list----------------------------------------------------
let curr_rank_list = "";

async function send_rank_list(isInit)
{
    try{
        const res = await fetch ('http://t_record:9431/internal/api/rank/', {
                method: 'GET',
            }
        );

        if (!res.ok) {
            const info = await res.json();
            throw new Error(JSON.stringify(info) || 'failed to get game rank');
        }

        const resp = await res.json();
        const respStr = JSON.stringify(resp);

        if (!isInit && curr_rank_list === respStr)  //only if rank list changed, brodcast it
            return;

        curr_rank_list = respStr;

        for (const [sock, conn] of sockMap)
        {
            const dataReturn = {evt: "get_rank_list", data: resp.data}
            sock.send(JSON.stringify(dataReturn));
        }
    }
    catch (error)
    {
        ;
    }
}

let broadcast_rank_list_timer = null;
function broadcast_rank_list()
{
    broadcast_rank_list_timer = setInterval(async () => {
        const promises = [];

        send_rank_list(false);
        await Promise.all(promises);
    }, 300);
}
//-----------------------------------------------------------------rank list----------------------------------------------------


//-----------------------------------------------------------------friend list----------------------------------------------------
function get_socket_by_alias(alias)
{
    for (const [sock, conn] of sockMap)
    {
        if (conn.alias === alias)
            return sock;
    }
    return undefined;
}

function add_online_state(friend_list)
{
    for (const friend of friend_list)
    {
        if (get_socket_by_alias(friend.alias) != undefined)
            friend.online = true;
        else
            friend.online = false;
    }
}

async function send_friend_list(socket, isInit)
{
    try{
        const conn = sockMap.get(socket);

        if (!conn)
            return;

        const prevFriendList = conn.friend_list;

        const uri = "http://t_friend:9766/internal/api/friends/" + conn.alias;

        const res = await fetch (uri, {
                method: 'GET',
            }
        );

        if (!res.ok) {;
            throw new Error(JSON.stringify(await res.json()) || 'failed to get friend list');
        }

        const resp = await res.json();

        add_online_state(resp.data);
        const respStr = JSON.stringify(resp);

        if (!isInit && respStr === prevFriendList)
        {
            return;
        }
        conn.friend_list = respStr;
        socket.send(JSON.stringify({evt: "update_friend_list", data: respStr}));
    }
    catch (error)
    {
        console.log('info [broker]: Error:', error);
        return;
    }
}

let broadcast_friend_list_timer = null;
function broadcast_friend_list()
{
    broadcast_friend_list_timer = setInterval(async () => {
        const promises = [];

        for (const [sock, conn] of sockMap)
        {
            promises.push(send_friend_list(sock, false));
        }

        await Promise.all(promises);
    }, 300);
}

//-----------------------------------------------------------------friend list----------------------------------------------------


async function send_user_card(socket, isInit)
{
    try{
        const conn = sockMap.get(socket);

        if (!conn)
            return;

        const prevUserCard = conn.user_card;

        const uri = "http://t_record:9431/api/record/statistic/" + conn.alias;

        const res = await fetch (uri, {
                method: 'GET',
            }
        );

        if (!res.ok) {;
            throw new Error(JSON.stringify(await res.json()) || 'failed to get user card');
        }

        const resp = await res.json();
        const respStr = JSON.stringify(resp.data);

        if (!isInit && respStr === prevUserCard) {
            return;
        }
        conn.user_card = respStr;
        socket.send(JSON.stringify({evt: "update_user_card", data: respStr}));
    }
    catch (error) {
        console.log('info [broker]: Error:', error);
        return;
    }
}

let broadcast_user_card_timer = null;
function broadcast_user_card()
{
    broadcast_user_card_timer = setInterval(async () => {
        const promises = [];

        for (const [sock, conn] of sockMap)
        {
            promises.push(send_user_card(sock, false));
        }

        await Promise.all(promises);
    }, 300);
}

//-----------------------------------------------------------------user card------------------------------------------------------

function flip_score(score)
{
    const scoreTab = score.split(":");
    return scoreTab[1] + ":" + scoreTab[0];
}

async function  send_game_record(socket, isInit)
{
    const conn = sockMap.get(socket);

    if (!conn)
        return;

    const prevGameRecord = conn.game_record;

    let matches = [];

    const uri = "http://t_record:9431/api/record/" + conn.alias;
    try{
        const res = await fetch(uri, {
            method: "GET",
        })

        if (!res.ok)
        {
            throw(new Error("Error from record server!"))
        }
        const resp = await res.json();

        matches.length = 0;

        for (let i = 0; i < resp.length; i++)
        {
            let record = {
              id: i,
              date: resp[i].timestamp,
              opponent: (conn.alias === resp[i].alias1) ? resp[i].alias2 : resp[i].alias1,
              score: (conn.alias === resp[i].alias1) ? resp[i].score : flip_score(resp[i].score),
              type: resp[i].type,
              result: (conn.alias === resp[i].winner) ? "win" : "loss"
            }
            matches.push(record);
        }
        const respStr = JSON.stringify(matches);
        if (!isInit && respStr === prevGameRecord)
        {
            return;
        }
        conn.game_record = respStr;
        socket.send(JSON.stringify({evt: "update_game_record", data: matches}));
    }
    catch(error)
    {
        console.log("info [broker]: Error:", error);
    }
}

let broadcast_game_record_timer = null;
function broadcast_game_record()
{
    broadcast_game_record_timer = setInterval(async () => {
        const promises = [];

        for (const [sock, conn] of sockMap)
        {
            promises.push(send_game_record(sock, false));
        }

        await Promise.all(promises);
    }, 300);
}



//-----------------------------------------------------------------broadcast list----------------------------------------------------
try{
    keep_connection();
    broadcast_friend_list();
    broadcast_game_record();
    broadcast_rank_list();
    broadcast_user_card();
}
catch (e)
{
    console.log("info [broker]:", e);
}

//-----------------------------------------------------------------broadcast list----------------------------------------------------

fastify.patch('/internal/api/update', (req, res) => {
  try {
    const sock = get_socket_by_alias(req.body.old_alias);
    if (sock != undefined)
    {
        sockMap.get(sock).alias = req.body.new_alias;
    }
  } 
  catch(e)
  {
    res.code(400).send({info: "[broker] Error: User alias not updated"});
    console.log("info [friend]:", e);
  }
});

fastify.listen({port : 9899, host: '0.0.0.0'}, (err)=>{
  if (err){
    fastify.log.error(err);
    process.exit(1);
  }
  console.log("info [broker]: Broker server listening to port 9899");
});
