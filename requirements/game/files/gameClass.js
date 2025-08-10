const { save_game_record } = require('./recordGame'); 


class   config {
    static LENGTH = 15;
    static WIDTH = 10;
    static FPS = 48;
    static TIMEVAL = 1.0 / config.FPS * 1000; //ms
    static INIT_BALL_SPEED = 0.005;
    static MAX_BALL_SPEED = 0.2;
    static RACKET_SPEED = 0.2;

    static RACKET_SIZE = 2.5;
    static BALL_SIZE = 0.5;

    static INIT_BALL_X = 0;
    static INIT_BALL_Y = 0;

    static INIT_BALL_SPEED_X = config.INIT_BALL_SPEED;
    static INIT_BALL_SPEED_Y = config.INIT_BALL_SPEED;

    static INIT_RIGHT_RACKET_POS = 0;
    static INIT_LEFT_RACKET_POS = 0;

    static ACCELERATION = 1.1;

    static PRECISION = 0.1;

    static FORCE = 0.003;
}

class   gameInstance{
    constructor(playerName1, playerName2, type) {
        this.rightRacketPos = config.INIT_RIGHT_RACKET_POS;
        this.leftRacketPos = config.INIT_LEFT_RACKET_POS;

        this.leftScore = 0;
        this.rightScore = 0;

        this.player1 = playerName1;
        this.player2 = playerName2;

        this.ballPosX = config.INIT_BALL_X;
        this.ballPosY = config.INIT_BALL_Y / 2;

        this.startTime = new Date();  //seems not used
        this.gameTime = 0; //seems not used

        this.ballSpeedX = config.INIT_BALL_SPEED_X;
        this.ballSpeedY = config.INIT_BALL_SPEED_Y;

        this.leftkey = "";
        this.rightkey = "";

        this.leftDelay = "";
        this.rightDelay = "";

        this.state = "created";

        this.type = type;

    }

    hit_boundary_vertical()
    {
        var next_ball_x = this.ballPosX + config.TIMEVAL * this.ballSpeedX;
        var next_ball_y = this.ballPosY + config.TIMEVAL * this.ballSpeedY;

        if (next_ball_x >= config.LENGTH / 2.0) //hit right boundary
        {
            if (next_ball_y <= this.rightRacketPos + config.RACKET_SIZE / 2.0 + config.BALL_SIZE / 4.0 + config.PRECISION && next_ball_y >= this.rightRacketPos - config.RACKET_SIZE / 2.0 - config.BALL_SIZE / 4.0 - config.PRECISION) {  //hit the right racket
                this.ballSpeedX *= -config.ACCELERATION; //accelerate by multiplying smaller number
                this.ballPosX += config.TIMEVAL * this.ballSpeedX;

                if (this.rightDelay === "i")
                {
                    this.ballSpeedY += config.FORCE * config.ACCELERATION;
                }
                else if (this.rightDelay === "k")
                {
                    this.ballSpeedY -= config.FORCE * config.ACCELERATION;
                }
            }
            else {
                this.leftScore += 1;

                this.ballPosX = 0;
                this.ballPosY = 0;
                this.ballSpeedX = config.INIT_BALL_SPEED_X;
                this.ballSpeedY = config.INIT_BALL_SPEED_Y;
            }
        }
        else if (next_ball_x <= -config.LENGTH / 2.0) //hit left boundary
        {
            if (next_ball_y <= this.leftRacketPos + config.RACKET_SIZE / 2.0 + config.BALL_SIZE / 4.0 + config.PRECISION && next_ball_y >= this.leftRacketPos - config.RACKET_SIZE / 2.0 - config.BALL_SIZE / 4.0 - config.PRECISION) {
                this.ballSpeedX *= -config.ACCELERATION; //accelerate by multiplying smaller number
                this.ballPosX += config.TIMEVAL * this.ballSpeedX;

                if (this.leftDelay === "w")
                {
                    this.ballSpeedY += config.FORCE * config.ACCELERATION;
                }
                else if (this.leftDelay === "s")
                {
                    this.ballSpeedY -= config.FORCE * config.ACCELERATION;
                }
            }
            else {
                this.rightScore += 1;

                this.ballPosX = 0;
                this.ballPosY = 0;
                this.ballSpeedX = -config.INIT_BALL_SPEED_X;
                this.ballSpeedY = -config.INIT_BALL_SPEED_Y;
            }
        }
        else
        {
            return (false);
        }
        return (true);
    }

    hit_boundary_horizontal()
    {
        var next_ball_y = this.ballPosY + config.TIMEVAL * this.ballSpeedY;

        if (next_ball_y >= config.WIDTH / 2.0 || next_ball_y <= -config.WIDTH / 2.0) {
            this.ballSpeedY *= -1;
            this.ballPosY = this.ballPosY + config.TIMEVAL * this.ballSpeedY;
            return (true);
        }
        return (false);
    }

    ball_move()  //didn't count ball size yet
    {
        var hit_h = this.hit_boundary_horizontal();
        var hit_v = this.hit_boundary_vertical();

        if (hit_h && hit_v)
        {
            ;
        }
        else if (hit_h)
        {
            this.ballPosX += config.TIMEVAL * this.ballSpeedX;
        }
        else if (hit_v)
        {
            this.ballPosY += config.TIMEVAL * this.ballSpeedY;
        }
        else {
            this.ballPosX += config.TIMEVAL * this.ballSpeedX;
            this.ballPosY += config.TIMEVAL * this.ballSpeedY;
        }

        if (this.ballSpeedX > config.MAX_BALL_SPEED)
            this.ballSpeedX = config.MAX_BALL_SPEED;

        if (this.ballSpeedY > config.MAX_BALL_SPEED)
            this.ballSpeedY = config.MAX_BALL_SPEED;

    }

    racket_move(left, right)
    {
        if (left == "" && right == "")
            return;

        if (left == "w")
        {
            if (this.leftRacketPos + config.RACKET_SIZE / 2.0 + config.RACKET_SPEED <= config.WIDTH / 2.0)
                this.leftRacketPos += config.RACKET_SPEED;
        }
        else if (left == "s")
        {
            if (this.leftRacketPos - config.RACKET_SIZE / 2.0 - config.RACKET_SPEED >= -config.WIDTH / 2.0)
                this.leftRacketPos -= config.RACKET_SPEED;
        }

        if (right == "i")
        {
            if (this.rightRacketPos + config.RACKET_SIZE / 2.0 + config.RACKET_SPEED <= config.WIDTH / 2.0)
                this.rightRacketPos += config.RACKET_SPEED;
        }
        else if (right == "k")
        {
            if (this.rightRacketPos - config.RACKET_SIZE / 2.0 - config.RACKET_SPEED >= -config.WIDTH / 2.0)
                this.rightRacketPos -= config.RACKET_SPEED;
        }
    }

    racket_move_left(left)
    {
        if (left == "")
            return;

        if (left == "w")
        {
            if (this.leftRacketPos + config.RACKET_SIZE / 2.0 + config.RACKET_SPEED <= config.WIDTH / 2.0)
                this.leftRacketPos += config.RACKET_SPEED;
        }
        else if (left == "s")
        {
            if (this.leftRacketPos - config.RACKET_SIZE / 2.0 - config.RACKET_SPEED >= -config.WIDTH / 2.0)
                this.leftRacketPos -= config.RACKET_SPEED;
        }
    }

    racket_move_right(right)
    {
        if (right == "")
            return;

        if (right == "i")
        {
            if (this.rightRacketPos + config.RACKET_SIZE / 2.0 + config.RACKET_SPEED <= config.WIDTH / 2.0)
                this.rightRacketPos += config.RACKET_SPEED;
        }
        else if (right == "k")
        {
            if (this.rightRacketPos - config.RACKET_SIZE / 2.0 - config.RACKET_SPEED >= -config.WIDTH / 2.0)
                this.rightRacketPos -= config.RACKET_SPEED;
        }
    }

    game_start(socket) {
        
        socket.on("close", ()=> {
            this.game_end();
        });

        this.state = "started";

        this.timer_update_frame = setInterval(() => {
            this.gameTime += config.TIMEVAL - this.startTime; //not used

            this.racket_move(this.leftkey, this.rightkey);
            this.ball_move();

            if (this.leftScore >= 7 || this.rightScore >= 7) {

                this.state = "finished";

                let winner = this.leftScore > this.rightScore ? this.player1 : this.player2;

                const dataReturn = {
                    evt: "game_finish",
                    winner: winner,
                    leftScore: this.leftScore,
                    rightScore: this.rightScore,
                }
                const score = this.leftScore.toString() + ":" + this.rightScore.toString();

                const dataJson = JSON.stringify(dataReturn);
                socket.send(dataJson);

                console.log("info [game]: Game is finished, winner: %s", winner);

                
                //--------------------------save to record server-------------//
                const record = {
                    timestamp: new Date().toISOString(),
                    alias1: this.player1,
                    alias2: this.player2,
                    winner: winner,
                    type: this.type,
                    score: score
                }

                save_game_record(record);
                //--------------------------save to record server-------------//

                this.game_end();
                return ;
            }

            const dataReturn = {
                evt: "game_state",
                ballPosX: this.ballPosX,
                ballPosY: this.ballPosY,
                leftRacketPos: this.leftRacketPos,
                rightRacketPos: this.rightRacketPos,
                leftScore: this.leftScore,
                rightScore: this.rightScore,
            }

            const dataJson = JSON.stringify(dataReturn);
            socket.send(dataJson);
        }, 1.0 / config.FPS * 1000);
    }

    game_start_remote(socket1, socket2) {   //this for remote mode, to update the game state to both side
        
        this.state = "started";

        socket1.on("close", ()=> {
            try {
                const dataReturn = {
                    evt: "game_aborted",
                    player1: this.player1,
                    player2: this.player2,
                }

                const dataJson = JSON.stringify(dataReturn);
                socket2.send(dataJson);
            }
            catch (e)
            {
                console.log("info [game]: Error:", e);
            }
            this.game_end();
        });

        socket2.on("close", ()=> {
            try {
                const dataReturn = {
                    evt: "game_aborted",
                    player1: this.player1,
                    player2: this.player2,
                }

                const dataJson = JSON.stringify(dataReturn);
                socket1.send(dataJson);
            }
            catch (e)
            {
                console.log("info [game]: Error:", e);
            }
            this.game_end();
        });

        this.timer_update_frame = setInterval(() => {
            this.gameTime += config.TIMEVAL - this.startTime; //not used

            this.racket_move(this.leftkey, this.rightkey);
            this.ball_move();

            if (this.leftScore >= 7 || this.rightScore >= 7) {

                this.state = "finished";

                let winner = this.leftScore > this.rightScore ? this.player1 : this.player2;

                const dataReturn = {
                    evt: "game_finish",
                    winner: winner,
                    leftScore: this.leftScore,
                    rightScore: this.rightScore,
                }

                const dataJson = JSON.stringify(dataReturn);


                try{
                    socket1.send(dataJson);
                    socket2.send(dataJson);
                }
                catch(e)
                {
                    this.game_end();
                    return;
                }

                console.log("info [game]: Game is finished, winner: ", winner);

                //--------------------------save to record server-------------//

                const score = this.leftScore.toString() + ":" + this.rightScore.toString();
                const record = {
                    timestamp: new Date().toISOString(),
                    alias1: this.player1,
                    alias2: this.player2,
                    winner: winner,
                    type: this.type,
                    score: score,
                }

                save_game_record(record);
                //--------------------------save to record server-------------//

                this.game_end();
                return ;
            }

            const dataReturn = {
                evt: "game_state",
                ballPosX: this.ballPosX,
                ballPosY: this.ballPosY,
                leftRacketPos: this.leftRacketPos,
                rightRacketPos: this.rightRacketPos,
                leftScore: this.leftScore,
                rightScore: this.rightScore,
            }

            const dataJson = JSON.stringify(dataReturn);

            try{
                socket1.send(dataJson);
                socket2.send(dataJson);
            }
            catch(e)
            {
                this.game_end();
                return;
            }
            
        }, 1.0 / config.FPS * 1000);
    }

    get_game_state()
    {
        return (this.state);
    }

    set_key(left, right)
    {
        this.leftkey = left;
        this.rightkey = right;

        this.rightDelay = right;
        this.leftDelay = left;

        setTimeout(() => {
            this.rightDelay  = "";
            this.leftDelay = "";
        }, 200);
    }

    set_left_key(left)
    {
        this.leftkey = left;

        this.leftDelay = left;

        setTimeout(() => {
            this.leftDelay = "";
        }, 200);
    }

    set_right_key(right)
    {
        this.rightkey = right;

        this.rightDelay = right;

        setTimeout(() => {
            this.rightDelay = "";
        }, 200);
    }

    /////////////////////////////////////////////////////////////////////TEMP/////////

    game_end() {
        this.state = "stopped";

        this.ballPosX = config.INIT_BALL_X;
        this.ballPosY = config.INIT_BALL_Y;

        clearInterval(this.timer_update_frame);
        this.timer_update_frame = null;
    }
}

exports.config = config;
exports.gameInstance = gameInstance;