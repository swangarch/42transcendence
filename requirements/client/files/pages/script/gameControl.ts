declare function host_create_game(): void;
declare function guest_join_game(): void;
declare function updateMatchBanner(): void;
declare function updateCurrentMatchDisplay(player1Name: string, player2Name: string): void;
declare function updateMatchDisplay(currentMatchIndex: number, currentRoundId: string, updateType: 'ongoing' | 'played'): void;
declare function updatePlayersDisplay(playersData: PlayerTournament[] | string[], containerId?: string): void;

type invite = {
    from: string;
    to: string;
}

class gameData {

    ballPosX:number = 0;
    ballPosY:number = 0;
    leftRacketPos:number = 0;
    rightRacketPos:number = 0;
    speedx:number = 0;
    speedy:number = 0;
    lastBallPosX:number = 0;
    lastBallPosY:number = 0;

    leftScore:number = 0;
    rightScore:number = 0;

    isWPressed:boolean = false;
    isSPressed:boolean = false;
    isIPressed:boolean = false;
    isKPressed:boolean = false;

    lastLeftKey:string = "";
    lastRightKey:string = "";
    leftKeyPressed:string = "";
    rightKeyPressed:string = "";

    FPS:number = 48;
    refresh_interval:number = 1.0 / this.FPS * 1000;

    AI = false;
    alias: string = "";
    username: string = "";
    friendList : Friend[] = [];
    state2fa:boolean = false;

    left:string = "player1";
    right:string = "player2";

    game_created:boolean = false;
    game_on:boolean = false;
    controlId : number | undefined = undefined;
    invitation : null | invite = null; //json
    invitation_init : null | invite = null;

    msg_socket : WebSocket | null = null;
    game_socket : WebSocket | null = null;
    roomid :number = 0;
    timer_websocket_ping : number | undefined = undefined;
    timer_msgsocket_ping : number | undefined = undefined;

    in_game_page = false;
    has_friend_req = false;
    logged_in = false;

    constructor(){}

    reset_after_game()
    {
        this.ballPosX = 0;
        this.ballPosY = 0;
        this.leftRacketPos = 0;
        this.rightRacketPos = 0;
        this.speedx = 0;
        this.speedy = 0;
        this.lastBallPosX = 0;
        this.lastBallPosY = 0;

        this.leftScore = 0;
        this.rightScore = 0;

        this.isWPressed = false;
        this.isSPressed = false;
        this.isIPressed = false;
        this.isKPressed = false;

        this.lastLeftKey = "";
        this.lastRightKey = "";
        this.leftKeyPressed = "";
        this.rightKeyPressed = "";

        this.AI = false;
        this.left = "player1";
        this.right = "player2";
        
        if (this.controlId)
        {
            clearInterval(this.controlId);
            this.controlId = undefined;
        }

        this.roomid = 0;
        AI_stop();
        this.close_game_socket();
        this.invitation  = null; //json
        this.invitation_init = null;
        this.game_created = false;
        this.game_on = false;

        if (this.timer_websocket_ping)
        {
            clearInterval(this.timer_websocket_ping)
            this.timer_websocket_ping = undefined;
        }
        if (this.timer_msgsocket_ping)
        {
            clearInterval(this.timer_msgsocket_ping)
            this.timer_msgsocket_ping = undefined;
        }

        document.getElementById("score")!.innerHTML = "0:0";
        document.getElementById("result")!.innerHTML = "Ready";

        p.x = 0;
        p.y = 0;
    }

    reset_logout()
    {
        this.ballPosX = 0;
        this.ballPosY = 0;
        this.leftRacketPos = 0;
        this.rightRacketPos = 0;
        this.speedx = 0;
        this.speedy = 0;
        this.lastBallPosX = 0;
        this.lastBallPosY = 0;

        this.leftScore = 0;
        this.rightScore = 0;

        this.isWPressed = false;
        this.isSPressed = false;
        this.isIPressed = false;
        this.isKPressed = false;

        this.lastLeftKey = "";
        this.lastRightKey = "";
        this.leftKeyPressed = "";
        this.rightKeyPressed = "";

        this.AI = false;
        this.alias = "";
        this.username = "";
        this.friendList = [];
        this.state2fa = false;
        this.left = "player1";
        this.right = "player2";
        
        if (this.controlId)
        {
            clearInterval(this.controlId);
            this.controlId = undefined;
        }

        this.roomid = 0;
        AI_stop();
        this.close_game_socket();
        this.close_msg_socket();
        matches.length = 0;
        this.invitation  = null; //json
        this.invitation_init = null;
        this.game_created = false;
        this.game_on = false;
        
        this.has_friend_req = false;
        this.in_game_page = false;

        document.getElementById("score")!.innerHTML = "0:0";
        document.getElementById("result")!.innerHTML = "Ready";

        if (this.timer_websocket_ping)
        {
            clearInterval(this.timer_websocket_ping)
            this.timer_websocket_ping = undefined;
        }
        if (this.timer_msgsocket_ping)
        {
            clearInterval(this.timer_msgsocket_ping)
            this.timer_msgsocket_ping = undefined;
        }
        //reset all page element

        p.x = 0;
        p.y = 0;

        this.logged_in = false;
    }

    async close_game_socket()
    {
        if (!this.game_socket)
            return;
        var dataReturn = {
            evt: "stop_game",
            leftPlayer: this.left,
            rightPlayer: this.right,
        }
        const dataJson : string = JSON.stringify(dataReturn);
        this.game_socket!.send(dataJson);

        if (this.timer_websocket_ping)
        {
            clearInterval(this.timer_websocket_ping);
            this.timer_websocket_ping = undefined;
        }

        setTimeout(()=>{
            if (this.game_socket)
            {
                this.game_socket.close(1000, "Client closed connection");
                this.game_socket = null;
            }
        }, 250);
    }

    async close_msg_socket()
    {
        if (this.timer_msgsocket_ping)
        {
            clearInterval(this.timer_msgsocket_ping);
            this.timer_msgsocket_ping = undefined;
        }

        if (this.msg_socket)
        {
            this.msg_socket.close(1000, "Client closed connection");
            this.msg_socket = null;
        }
    }
}

var game : gameData = new gameData();
var isTournament = "false";

// Store current match players for color updates
var currentTournamentMatch = {
    player1: "",
    player2: ""
};

//_____________________key control__________________________________________________
document.addEventListener('keydown', function(event) {
    if (event.key === 'w') game.isWPressed = true;
    if (event.key === 's') game.isSPressed = true;
    if (game.AI)
        return;
    if (event.key === 'i') game.isIPressed = true;
    if (event.key === 'k') game.isKPressed = true;
});

document.addEventListener('keyup', function(event) {
    if (event.key === 'w') game.isWPressed = false;
    if (event.key === 's') game.isSPressed = false;
    if (game.AI)
        return;
    if (event.key === 'i') game.isIPressed = false;
    if (event.key === 'k') game.isKPressed = false;
});

function listen_key_control() : void
{
    game.leftKeyPressed = "";
    game.rightKeyPressed = "";

    if (game.isWPressed && game.isSPressed)
        game.leftKeyPressed = "";
    else if (game.isWPressed)
        game.leftKeyPressed = "w";
    else if (game.isSPressed)
        game.leftKeyPressed = "s";
    else
        game.leftKeyPressed = "";

    if (game.isIPressed && game.isKPressed)
        game.rightKeyPressed = "";
    else if (game.isIPressed)
        game.rightKeyPressed = "i";
    else if (game.isKPressed)
        game.rightKeyPressed = "k";
    else
        game.rightKeyPressed = "";

    if (game.lastLeftKey === game.leftKeyPressed && game.lastRightKey === game.rightKeyPressed)
    {
        return;
    }

    game.lastLeftKey = game.leftKeyPressed;
    game.lastRightKey = game.rightKeyPressed;
}
//_____________________key control__________________________________________________


declare function updateMatchDisplay(currentMatchIndex: number, currentRoundId: string, updateType: 'ongoing' | 'played'): void;
let match_number = 0;

//_____________________game management__________________________________________________
function tournament_launch(): void
{
    console.log("> Tournament launched.");
    const player1 =  allPlayers[match_number].name;
    const player2 =  allPlayers[match_number + 1].name;

    tournament_create_game(player1, player2);
    load_model("pixel.glb");
    start_2player_game();
    tournament_start_game(player1, player2);

    match_number += 2;
}

function tournament_create_game(player1 :string, player2:string) : void
{
    showRacketControlsBeforeStart('show');
    updateMatchBanner();
    updateMatchDisplay(match_number / 2, (window as any).currentRoundId, 'ongoing');

    game.left = player1;
    game.right = player2;

    // Store current match players for color updates
    currentTournamentMatch.player1 = player1;
    currentTournamentMatch.player2 = player2;
    console.log("Current match players:", currentTournamentMatch);

    create_game("tournament");

    if (allPlayers.length > 3)
        isTournament = "ongoing";
    else
        isTournament = "end";
}

function tournament_start_game(player1: string, player2: string): void {
    if (!game.game_created || !isTournament) return;

    // Store current match players for color updates
    currentTournamentMatch.player1 = player1;
    currentTournamentMatch.player2 = player2;

    let count = 5;

    game.in_game_page = true;

    const timer = setInterval(() => {
        if (count < 0) {
            document.getElementById('result')!.innerHTML = "Match in progress...";
            clearInterval(timer);

            game.controlId = setInterval(() => {
                if (!game.game_on)
                    return;

                game.left = player1;
                game.right = player2;

                showRacketControlsBeforeStart('hide');

                listen_key_control();

                var dataReturn = {
                    evt: "game_playing",
                    leftKey: game.leftKeyPressed,
                    rightKey: game.rightKeyPressed,
                    leftPlayer: player1,
                    rightPlayer: player2,
                }

                const dataJson = JSON.stringify(dataReturn);
                if (game.game_socket)
                    game.game_socket.send(dataJson);
            }, 1.0 / 48 * 1000);

            var dataReturn = {
                evt: "start_game",
                leftPlayer: game.left,
                rightPlayer: game.right,
            }
            const dataJson: string = JSON.stringify(dataReturn);
            if (game.game_socket) 
                game.game_socket.send(dataJson);
            game.game_on = true;

        } else {
            document.getElementById('result')!.innerHTML = count.toString();
            count--;
        }
    }, 1000);
}


function create_game(type: string = "1v1") : void
{
    if (game.AI) 
    {
        console.log("Creating game with AI opponent");
        type = "AI_Bot"
        game.left = game.alias;
        game.right = "AI_Bot";
        (document.getElementById('player2Avatar')! as HTMLImageElement).src = "/api/avatar/AI_Bot";
    }
    connect_game_socket(()=>
    {
        if (type !== "tournament" && type !== "AI_Bot") {
            game.left = game.alias;
        } 
    
        setPlayersDisplay(game.left, game.right);
        showRacketControlsBeforeStart('show');
        var dataReturn = {
            evt: "create_game",
            leftPlayer: game.left,
            rightPlayer: game.right,
            type: type
        }
        const dataJson : string = JSON.stringify(dataReturn);
        if (game.game_socket)
            game.game_socket!.send(dataJson);
        game.game_created = true;

        document.getElementById('score')!.innerHTML = "0:0";
    });
}

function start_game() : void
{
    if (!game.game_created || !game.game_socket)
        return ;
    
    document.getElementById('result')!.innerHTML = 'Start!';
    
    game.controlId = setInterval(() => {
        if (!game.game_on)
            return;
        
        // Don't reassign game.left in tournament mode to preserve correct player assignments
        if (isTournament === "false") {
            game.left = game.alias;
        }
        
        showRacketControlsBeforeStart('hide');
        listen_key_control();

        var dataReturn = {
            evt: "game_playing",
            leftKey: game.leftKeyPressed,
            rightKey: game.rightKeyPressed,
            leftPlayer: game.left,
            rightPlayer: game.right,
        }

        const dataJson = JSON.stringify(dataReturn);
        if (game.game_socket)
            game.game_socket.send(dataJson);
    }, 1.0 / 48 * 1000);

    var dataReturn = {
        evt: "start_game",
        leftPlayer: game.left,
        rightPlayer: game.right,
    }
    const dataJson : string = JSON.stringify(dataReturn);
    if (game.game_socket)
        game.game_socket.send(dataJson);
    game.game_on = true;
}

function host_game_remote() : void
{
    connect_game_socket(() =>{
        game.controlId = setInterval(() => {
            if (!game.game_on)
                return;
            
            setPlayersDisplay(game.left, game.right, true);
            listen_key_control();
            var dataReturn = {
                evt: "game_playing_host",
                leftKey: game.leftKeyPressed,
                rightKey: "",
                leftPlayer: game.left,
                rightPlayer: game.right,
            }
            
            const dataJson : string = JSON.stringify(dataReturn);
            if (game.game_socket)
                game.game_socket.send(dataJson);
        }, 1.0 / 48 * 1000);
        
        var dataReturn = {
            evt: "create_game_remote",
            leftPlayer: game.left,
            rightPlayer: game.right,
            type: "1v1"
        }
        const dataJson : string = JSON.stringify(dataReturn);
        if (game.game_socket)
            game.game_socket.send(dataJson);
        game.game_on = true;
    });
}

function join_game_remote() : void
{
    connect_game_socket(() =>{
        game.controlId = setInterval(() => {
            if (!game.game_on)
                return;

            setPlayersDisplay(game.left, game.right, true);
            listen_key_control();

            var dataReturn = {
                evt: "game_playing_guest",
                leftKey: "",
                rightKey: game.rightKeyPressed,
                leftPlayer: game.left,
                rightPlayer: game.right,
            }
            const dataJson : string = JSON.stringify(dataReturn);
            if (game.game_socket)
                game.game_socket.send(dataJson);
        }, 1.0 / 48 * 1000);

        var dataReturn = {
            evt: "join_game_remote",
            leftPlayer: game.left,
            rightPlayer: game.right,
        }
        const dataJson : string = JSON.stringify(dataReturn);
        if (game.game_socket)
            game.game_socket.send(dataJson);
        game.game_on = true;
    });
}

function stop_game() : void
{
    game.reset_after_game();

    document.getElementById("score")!.innerHTML = "0:0";
    document.getElementById("result")!.innerHTML = "Ready";
    
    stop_babylon();
}

//_____________________game management__________________________________________________

declare  var allPlayers: PlayerTournament[]; 
let nextRoundBuffer: PlayerTournament[] = [];

(window as any).match_number = match_number;

//_____________________handle event__________________________________________________

// Reset game and stop the game socket
function stop_game_reset() : void
{   
    console.log("Stopping game and resetting all data...");
    stop_game();
    
    match_number = 0;
    if (isTournament != "end") {

        isTournament = "false";
        
        // Clear tournament banner when stopping tournament
        const bannerContent = document.getElementById("next-match-banner-content");
        if (bannerContent) {
            bannerContent.innerHTML = "";
        }
    }
    if (typeof nextRoundBuffer !== 'undefined') {
        nextRoundBuffer = [];
    }
    console.log("info [client]: Game stopped and all data reset successfully");
}