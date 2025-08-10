
// Declare global variable from gameControl.ts
declare var currentTournamentMatch: {
    player1: string;
    player2: string;
};

// Declare unified tournament functions
declare function updateMatchDisplay(currentMatchIndex: number, currentRoundId: string, updateType: 'ongoing' | 'played'): void;
declare function updatePlayersDisplay(playersData: PlayerTournament[] | string[], containerId?: string): void;
declare function updatePlayerResults(winner: string): void;
declare function manageWinnerEffect(action: 'show' | 'hide', winner?: string, count?: number): void;

function connect_game_socket(onConnected?: () => void)
{
    try
    {
        let uri = "";
        if (game.roomid != 0)
            uri = `wss://${location.hostname}:9000/api/wss/?roomid=` + game.roomid.toString();
        else
            uri = `wss://${location.hostname}:9000/api/wss/`;

        game.game_socket = new WebSocket(uri);
    }
    catch(e)
    {
        console.log("info [client]:", e);
        return;
    }
    

	game.game_socket.onopen = () => {
        try{
            if (!game.game_socket)
                return;
            console.log("info [client]: Game websocket is connected to server.");

            game.timer_websocket_ping = setInterval(() => {
                const dataReturn = {
                    evt: "ping",
                    alias: game.alias,
                };
                const dataJson : string = JSON.stringify(dataReturn);
                game.game_socket!.send(dataJson);
            }, 10000);

            if (onConnected)
                onConnected();
        }
        catch(e)
        {
            console.log("info [client]:", e);
        }
	}

	game.game_socket.onmessage = (event) => {
        try{
		    const msg : any = JSON.parse(event.data);
		    game_socket_event_handler(msg);
        }
        catch(e)
        {
            console.log("info [client]:", e);
        }
	}

	game.game_socket.onerror = (error) =>
	{
		console.log("info [client]: Game websocket has error: ", error);
	}

	game.game_socket.onclose = (event) =>
	{
       
       try{
            console.log("Game socket is closed");
            if (!game.game_socket)
                return;
            console.log("info [client]: Game websocket is closed.", event.code);
            game.game_socket = null;

            clearInterval(game.timer_websocket_ping);
            game.timer_websocket_ping = undefined;
            showCustomAlert("Server connection is lost, Aborting game.")
            setTimeout(() => {
                to_main_page();
            }, 2000);
       }
       catch(e)
       {
            console.log("info [client]:", e);
       }
	}
}

let isFinalEnded = false;


function game_socket_event_handler(msg : any) : void
{
    if (msg.evt == "game_state")
    {
        game.lastBallPosX = game.ballPosX;
        game.lastBallPosY = game.ballPosY;

        game.ballPosX = msg.ballPosX;
        game.ballPosY = msg.ballPosY;

        game.speedx = (game.ballPosX - game.lastBallPosX) / game.refresh_interval;
        game.speedy = (game.ballPosY - game.lastBallPosY) / game.refresh_interval;

        game.leftRacketPos = msg.leftRacketPos;
        game.rightRacketPos = msg.rightRacketPos;
        game.leftScore = msg.leftScore;
        game.rightScore = msg.rightScore;
        let scoreHTML = document.getElementById("score");
        if (scoreHTML)
            scoreHTML.innerHTML = game.leftScore + ":" + game.rightScore;
    }
    else if (msg.evt == "game_finish")
    { 

        let scoreHTML = document.getElementById("score");
        if (scoreHTML)
            scoreHTML.innerHTML = msg.leftScore + ":" + msg.rightScore;
        document.getElementById('result')!.innerHTML = 'Finish!';

        setTimeout(()=>{
            if (scoreHTML)
                scoreHTML.innerHTML = msg.winner + " wins!";
        
            const dataReturn = {
                evt: "stop_game",
            }
            const dataJson : string = JSON.stringify(dataReturn);
            if (game.game_socket)
                game.game_socket!.send(dataJson);

            game.ballPosX = 0;
            game.ballPosY = 0;

            game.game_on = false;
            game.game_created = false;
            // Add result to allPlayers and mark them as played

            updatePlayerResults(msg.winner);
            console.log("info [client]: Game finished. Winner: ", msg.winner);
            }, 200);
        
        let count: number = 5;
        var return_to_main_page_timer: number | undefined = setInterval(() => {
            if (!game.in_game_page) {
                clearInterval(return_to_main_page_timer);
                return_to_main_page_timer = undefined;
                document.getElementById('result')!.innerHTML = "Ready";
                manageWinnerEffect('hide');
                return;
            }
            if (count < 0) {
                clearInterval(return_to_main_page_timer);
                return_to_main_page_timer = undefined;

                if (isTournament == "false") {
                    console.log("Not tournement")
                    to_main_page();
                    match_number = 0;
                    game.AI = false;
                    AI_stop();
                }
                else if (isTournament == "ongoing") {
                    isFinalEnded = false;
                    const player1 =  allPlayers[match_number].name;
                    const player2 =  allPlayers[match_number + 1].name;
                    tournament_create_game(player1, player2);
                    tournament_start_game(player1, player2);

                    setPlayersDisplay(player1, player2);

                    match_number += 2;
                    if (match_number >= allPlayers.length) {
                        isTournament = "nextRound";
                    }
                }
                else if (isTournament == "nextRound") {
                    updateMatchDisplay(match_number / 2, (window as any).currentRoundId, 'played');
                    isTournament = "ongoing";
                    match_number = 0;
                    generateFullTournament(shufflePlayers(nextRoundBuffer));
                    nextRoundBuffer = [];
                    syncLiveToTournamentView();
                    navigate_to("tournamentView");
                }
                else if (isTournament == "end") {
                    isFinalEnded = true;
                    document.getElementById("button-tournament")?.classList.add("hidden");
                    document.getElementById("next-round-button")?.classList.add("hidden");
                    updatePlayersDisplay(allPlayers);
                    updateMatchDisplay(match_number, (window as any).currentRoundId, 'played');
                    syncLiveToTournamentView();
                    match_number = 0;
                    game.AI = false;
                    AI_stop();
                    isTournament = "false";
                    const bannerContent = document.getElementById("next-match-banner-content");
                    if (bannerContent) bannerContent.innerHTML = "";
                    navigate_to("tournamentView");
                }
                return;
            }
            document.getElementById('result')!.innerHTML = count.toString();
            //here can add congratulation effect
            manageWinnerEffect('show', msg.winner, count);
            count--;
        }, 1000);

        game.reset_after_game();
    }
    else if (msg.evt == "invite_remote_server")
    {
        const alertStr : string = "You have a invitation from " + msg.from;  
        showCustomAlert(alertStr, [
        { text: "Accept",
            onClick: (event?: MouseEvent) => {
                accept_invitation(event as MouseEvent);
            }
        },
        { text: "Refuse", 
            onClick: () => { console.log("Refuse invitation."); } 
        }
        ]);
        game.invitation = msg;
        console.log(msg);
    }
    else if (msg.evt == "count_down")
    {
        var show_num = msg.num;
        if (msg.num == 0 && isTournament == "false") {
            show_num = "Start!";
        }
        let scoreHTML = document.getElementById("score");
        if (scoreHTML)
            scoreHTML.innerHTML = show_num;
    }
    else if (msg.evt == "game_aborted")
    {
        const alertStr : string =  (game.alias === msg.player1 ? msg.player2 : msg.player1) + " has left the game.";  
        
        showCustomAlert(alertStr, [
            { text: "Ok",
                onClick: (event?: MouseEvent) => {
                }
            },

        ]);

        let count = 5;
        let return_to_main_page_timer: number | undefined = setInterval(() => {
            if (count <= 0)
            {
                clearInterval(return_to_main_page_timer);
                return_to_main_page_timer = undefined;
                
                game.reset_after_game();
                to_main_page();
            }
            document.getElementById('result')!.innerHTML = count.toString();
            count--;
        }, 1000);
    }
}