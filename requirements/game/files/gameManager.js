const { gameInstance } = require('./gameClass'); 

class   gameManager {
    constructor()
    {
        this.games = new Map();
        this.gameid = 0;
        this.gameMatcher = new Map();
        this.socketMap = new Map();
    }

    store_socket(alias, socket)
    {
        this.socketMap.set(alias, socket);
    }

    get_socket_by_alias(alias)
    {
        return (this.socketMap.get(alias));
    }

    //-------------------------------------------------------local game------------------------------------------------------------------------
    getGameId(player1, player2)
    {
        return (this.gameMatcher.get(player1 + "|" + player2));
    }

    create_game(player1, player2, type)
    {
        console.log("info [game]: Game", this.gameid, "between", player1, "and", player2, "is created.")
        this.games.set(this.gameid, new gameInstance(player1, player2, type));
        this.gameMatcher.set(player1 + "|" + player2, this.gameid);
        return (this.gameid++);
    }

    launch_game(player1, player2, socket)
    {
        var gameid = this.getGameId(player1, player2);
        if (gameid === undefined)
            return;
        console.log("info [game]: Game", gameid, "is running.")

        if (!this.games.get(gameid))
            return ;

        if (this.games.get(gameid).get_game_state() === "started")
            return ;

        this.games.get(gameid).game_start(socket);
    }

    launch_game_remote(player1, player2, socket1, socket2)
    {
        var gameid = this.getGameId(player1, player2);
        if (gameid === undefined)
            return;
        console.log("info [game]: Game", gameid, "is running.")

        if (!this.games.get(gameid))
            return ;

        if (this.games.get(gameid).get_game_state() === "started")
            return ;

        this.games.get(gameid).game_start_remote(socket1, socket2);
    }

    control_game(player1, player2, leftkey, rightkey)
    {
        var gameid = this.getGameId(player1, player2);
        if (gameid === undefined)
            return;
        var game_instance = this.games.get(gameid);
        if (game_instance)
            game_instance.set_key(leftkey, rightkey);
    }

    control_game_host(player1, player2, leftkey)
    {
        var gameid = this.getGameId(player1, player2);
        if (gameid === undefined)
            return;
        var game_instance = this.games.get(gameid);
        if (game_instance)
            game_instance.set_left_key(leftkey);
    }

    control_game_guest(player1, player2, rightkey)
    {
        var gameid = this.getGameId(player1, player2);
        if (gameid === undefined)
            return;

        var game_instance = this.games.get(gameid);
        if (game_instance)
            game_instance.set_right_key(rightkey);

    }

    get_game_instance(player1, player2)
    {
        var gameid = this.getGameId(player1, player2);
        return (this.games.get(gameid));
    }

    remove_game(player1, player2)
    {
        var gameid = this.getGameId(player1, player2);
        if (gameid === undefined)
            return;
        console.log("info [game]: Game", gameid, "is closed.")
        const gameInstance = this.games.get(gameid);
        if (gameInstance)
        {
            //------------------------------clean game matcher--------------------

            this.socketMap.delete(gameInstance.player1);
            this.socketMap.delete(gameInstance.player2);

            this.gameMatcher.delete(gameInstance.player1 + gameInstance.player2);

            //------------------------------clean game matcher--------------------
            this.games.get(gameid).game_end();
            this.games.delete(gameid);
        }
    }

    //-------------------------------------------------------remote game------------------------------------------------------------------------
}

exports.gameManager = gameManager;