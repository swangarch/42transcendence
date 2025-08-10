declare var game : gameData;

//_____________________websocket__________________________________________________

var reconnect_time = 0;
var show_reconnect_progress = [".", "..", "..."];

let reconnect_timer: number | undefined;
let isReconnecting = false;

function init_msg_socket()
{
    if (game.msg_socket)
        return;

    try {
        game.msg_socket = new WebSocket(`wss://${location.hostname}:9000/api/msg_wss/`);
    } catch (error) {
        console.log("info [client]:", error);
    }

	if (!game.msg_socket)
		return;

	game.msg_socket.onopen = () => {
        try
        {
            console.log("info [client]: msg_socket is connected to server.");

            game.timer_msgsocket_ping = setInterval(() => {
                if (game.msg_socket)
                    game.msg_socket!.send(JSON.stringify({evt: "ping"}));
            }, 10000);
        }
		catch(e)
        {
            console.log("info [client]:", e);
        }
	}

	game.msg_socket.onmessage = (event) => {
        try{
		    const msg : any = JSON.parse(event.data);
            msg_socket_event_handler(msg);
        }
        catch(e)
        {
            console.log("info [client]:", e);
        }
	}

	game.msg_socket.onerror = (error) =>
	{
		console.log("info [client]: msg_socket has error: ", error);
        showCustomAlertStrict("Connection error, please wait and refresh page.");
	}

	game.msg_socket.onclose = (event) =>
	{ 
        try{
            console.log("info [client]: msg_socket is closed.", event.code);

            if (event.code === 4001 || event.code === 4002 || !game.logged_in)
            {
                game.msg_socket = null;
                return;
            }
            clearInterval(game.timer_msgsocket_ping);
            game.timer_msgsocket_ping = undefined;
            setInterval(() => {
                showCustomAlertStrict("Connection lost, please wait and refresh page.");
            },500);
        }
        catch(e)
        {
            console.log("info [client]:", e);
        }
	}
}

function msg_socket_event_handler(msg : any) : void
{
    if (msg.evt === "invite_remote_server")
    {
        game.invitation = msg;
        if (game.game_socket || game.in_game_page)
        {
            busy_invitation();
            return ;
        }
        const alertStr : string = "You have a invitation from " + msg.from;  
        
        let timeout = setTimeout(() => {
            showCustomAlertStrict("Invitation timeout, refused.");
            if (!game.invitation || !game.msg_socket)
                return ;
            const dataReturn = {
                    evt: "invite_remote_refuse",
                    from: game.invitation.from,
                    to: game.invitation.to,
                }
            const dataJson = JSON.stringify(dataReturn);
            game.msg_socket!.send(dataJson);
        }, 10000);

        showCustomAlertStrict(alertStr, [
            { text: "Accept",
                onClick: (event?: MouseEvent) => {
                    accept_invitation(event as MouseEvent);
                    clearTimeout(timeout);
                }
            },
            { text: "Refuse", 
                onClick: (event?) => { 
                    refuse_invitation(event as MouseEvent);
                    clearTimeout(timeout);
                } 
            }
        ]);
    }
    if (msg.evt === "invitation_refused")
    {
        const alertStr : string = "Your invitation is refused by " + msg.to;  

        showCustomAlert(alertStr, [
            { text: "Ok",
                onClick: (event?: MouseEvent) => {
                }
            },
        ]);
    }
    if (msg.evt === "invitation_busy")
    {
        const alertStr : string =  msg.to + " is busy.";  
        
        showCustomAlert(alertStr, [
            { text: "Ok",
                onClick: (event?: MouseEvent) => {
                }
            },
        ]);

    }
    else if (msg.evt === "invite_remote_established_host")
    {
        if (!game.msg_socket)
            return;
        console.log("info [client]: Remote game established host ready!");
        game.roomid = msg.roomid;
        host_create_game();
        const dataReturn = {
            evt: "invite_remote_game_created",
            from: msg.from,
            to: msg.to,
            roomid: msg.roomid
        }
        const dataJson : string = JSON.stringify(dataReturn);
        game.msg_socket.send(dataJson);

    }
    else if (msg.evt === "invite_remote_established_guest")
    {
        game.roomid = msg.roomid;
        console.log("info [client]: Remote game created!");
        
        guest_join_game();
    }
    else if (msg.evt === "update_friend_list")
    {
        try { 
            const parsed = JSON.parse(msg.data);
            game.friendList = parsed.data;
            userMenuManager.insertFriendsList(parsed.data);
            userMenuManager.loadMiniFriendsList(parsed.data);

            let friendReqCount = 0;
            for (const friend of game.friendList)
            {
                if (friend.state === "pending" && !friend.fromUser)
                    friendReqCount++;
            }

            let notif_dot = document.getElementById("notfi-dot");
            if (notif_dot)
            {
                notif_dot.innerHTML = friendReqCount < 4 ? friendReqCount.toString() : ".."
                if (friendReqCount === 0)
                {
                    document.getElementById("notfi-dot")!.style.display = "none";
                    game.has_friend_req = false;
                }
                else
                {
                    document.getElementById("notfi-dot")!.style.display = "flex";
                    game.has_friend_req = true;
                }
            }
            
        }
        catch (e)
        {
            console.log("info [client]:", e);
        }
    }
    else if (msg.evt === "update_game_record")
    {
        matches.length = 0;

        for (const record of msg.data)
        {
            matches.push(record);
        }        
        showReducedMatchTable();
        update_history_chat();
        updateMatchHistory();
    }
    else if (msg.evt === "update_user_card")
    {
        const data = JSON.parse(msg.data);
        update_chart(data.wins, data.losses);
        updateUserProfileCard(data);
    }
    else if (msg.evt === "get_rank_list")
    {
        topClassement = msg.data;

        showLeaderBoard();
        userProfileCardRank();
    }
    else if (msg.evt === "invite_remote_impossible")
    {

        if (msg.from === msg.to)
        {
            showCustomAlert("You can't invite yourself.");
        }
        else
        {
            showCustomAlert(msg.to + " can't be invited.");
        }
    }
}

(window as any).match_number = match_number;
