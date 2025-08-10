const {config} = require('./gameClass'); 

function event_handler(message, socket, req, gm)
{
    if (message != "")
    {
        const data = JSON.parse(message);

        if (data.evt === "create_game")
        {
            gm.create_game(data.leftPlayer, data.rightPlayer, data.type);
        }
        else if (data.evt === "start_game")
        {
            gm.launch_game(data.leftPlayer, data.rightPlayer, socket);
        }
        else if (data.evt === "pause_game")
        {
            gm.pause_game(data.leftPlayer, data.rightPlayer);
        }
        else if (data.evt === "resume_game")
        {
            gm.resume_game(data.leftPlayer, data.rightPlayer, socket);
        }
        else if (data.evt == "stop_game")
        {
            gm.remove_game(data.leftPlayer, data.rightPlayer);
            const dataReturn = {
                evt: "game_state",
                ballPosX: config.INIT_BALL_X,
                ballPosY: config.INIT_BALL_Y,
                leftRacketPos: config.INIT_LEFT_RACKET_POS,
                rightRacketPos: config.INIT_RIGHT_RACKET_POS,
                leftScore: 0,
                rightScore: 0,
            }

            const dataJson = JSON.stringify(dataReturn);
            socket.send(dataJson);
        }
        else if (data.evt === "game_playing")
        {
            gm.control_game(data.leftPlayer, data.rightPlayer, data.leftKey, data.rightKey);
        }
        else if (data.evt === "game_playing_host")
        {
            gm.control_game_host(data.leftPlayer, data.rightPlayer, data.leftKey);
        }
        else if (data.evt === "game_playing_guest")
        {
            gm.control_game_guest(data.leftPlayer, data.rightPlayer, data.rightKey);
        }
        else if (data.evt === "create_game_remote")
        {
            gm.create_game(data.leftPlayer, data.rightPlayer, data.type);    
        }
        else if (data.evt === "join_game_remote")
        {
            var counter = null;
            var countNum = 5;

            const socket_from = gm.get_socket_by_alias(data.leftPlayer);
            const socket_to = gm.get_socket_by_alias(data.rightPlayer);

            if (socket_from)
            {
                socket_from.on("close", ()=> {
                    try {
                        const dataReturn = {
                            evt: "game_aborted",
                            player1: data.leftPlayer,
                            player2: data.rightPlayer,
                        }

                        const dataJson = JSON.stringify(dataReturn);
                        socket_to.send(dataJson);
                        
                    }
                    catch (e)
                    {
                        console.log("info [game]: Error:", e);
                    }
                    if (counter)
                    {
                        clearInterval(counter);
                        counter = null;
                    }
                    gm.remove_game(data.leftPlayer, data.rightPlayer);
                });
            }
            
            if (socket_to){
                socket_to.on("close", ()=> {
                    try {
                        const dataReturn = {
                            evt: "game_aborted",
                            player1: data.leftPlayer,
                            player2: data.rightPlayer,
                        }

                        const dataJson = JSON.stringify(dataReturn);
                        socket_from.send(dataJson);
                    }
                    catch (e)
                    {
                        console.log("info [game]: Error:", e);
                    }
                    if (counter)
                    {
                        clearInterval(counter);
                        counter = null;
                    }
                    gm.remove_game(data.leftPlayer, data.rightPlayer);
                });
            }
            

            counter = setInterval(() => {

                if (countNum < 0)
                {
                    clearInterval(counter);
                    counter = null;
                    gm.launch_game_remote(data.leftPlayer, data.rightPlayer, gm.get_socket_by_alias(data.leftPlayer), gm.get_socket_by_alias(data.rightPlayer));
                }

                const dataReturn = {
                    evt: "count_down",
                    num: countNum, 
                }
                const dataJson = JSON.stringify(dataReturn);

                const socket_from = gm.get_socket_by_alias(data.leftPlayer);
                const socket_to = gm.get_socket_by_alias(data.rightPlayer);

                if (socket_to)
                    socket_to.send(dataJson);
                if (socket_from)
                    socket_from.send(dataJson);

                countNum--;
            }, 1000);
        }
        else if (data.evt === "invite_remote_init")
        {
            const socket_to = gm.get_socket_by_alias(data.to);
            const socket_from = gm.get_socket_by_alias(data.from);
            
            if (socket_to === undefined || data.from === data.to)
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
        }
        else if (data.evt === "invite_remote_accept")
        {
            console.log("info [game]: Game invitation from " + data.from + " to " + data.to + " is accepted.");
            const socket_from = gm.get_socket_by_alias(data.from);

            const dataReturn_host = {
                evt: "invite_remote_established_host",
                from: data.from, 
                to: data.to,
            }
            const dataJson_host = JSON.stringify(dataReturn_host);

            socket_from.send(dataJson_host);
        }
        else if (data.evt === "invite_remote_game_created")
        {
            console.log("info [game]: Game invitation from" + data.from + "to" + data.to + "is accepted.");
            const socket_to = gm.get_socket_by_alias(data.to);

            const dataReturn_guest = {
                evt: "invite_remote_established_guest",
                from: data.from, 
                to: data.to,
            }
            const dataJson_guest = JSON.stringify(dataReturn_guest);

            socket_to.send(dataJson_guest);
        }
        else if (data.evt === "ping")
        {
            ;
        }
    }
}

exports.event_handler = event_handler;

