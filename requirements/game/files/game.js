if (!process.env.JWT_SECRET || process.env.JWT_SECRET === "")
{
    console.log("info [game]: Error, no token is provide.");
    process.exit(1);
}
const jwt_secret = process.env.JWT_SECRET;

const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');

const { gameManager } = require('./gameManager'); 
const websocket_handler = require('./websocketHandler');

//___________________________websocket__________________________________________
const port_number = 9999;
const server = new WebSocket.Server({ port: port_number});
console.log("info [game]: Game server listen to port", port_number);

//___________________________websocket__________________________________________


var gm = new gameManager();

//--------------------------------------------websocket------------------

server.on('connection', (socket, req) => {
        console.log("info [game]: Client connected to game server at " + req.socket.remoteAddress.replace("::ffff:", "") + ":" + req.socket.remotePort);

        const cookies = cookie.parse(req.headers.cookie || '');
        const token = cookies.token;

        if (!token) {
            socket.close(4001, 'No token provided');
            return;
        }

        try {
            const decoded = jwt.verify(token, jwt_secret);
            socket.user = decoded;
            console.log('info [game]: WebSocket JWT verified:', socket.user.username);
            
            gm.store_socket(socket.user.alias, socket);
            console.log("info [game]: Websocket is initialized by " + socket.user.alias + " at " + req.socket.remoteAddress.replace("::ffff:", "") + ":" + req.socket.remotePort);
            
        } catch (err) {
            socket.close(4002, 'Invalid token');
        }

        socket.on('close', () => {
            console.log("info [game]: Client disconnected from game server at " + req.socket.remoteAddress.replace("::ffff:", "") + ":" + req.socket.remotePort);
        });

        socket.on('error', (error) => {
            console.log("info [game]: Error Websocket: ", error);
        });

        socket.on('message', message => {
            try
            {
                websocket_handler.event_handler(message, socket, req, gm);
            }
            catch(e)
            {
                console.log("info [game]: Error:", e);
            }
        });
    }
)

