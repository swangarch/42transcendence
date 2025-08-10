declare var siteLength : number;
declare var siteWidth : number;
declare var game : gameData;

class game_AI
{
	timer_AI_get_game_state : number | null = null;
	timer_AI_move : number| null = null;
	AI_ball_posx : number = 0;
	AI_ball_posy : number = 0;
	AI_leftRacketPos : number = 0;
	AI_rightRacketPos : number = 0;
	AI_speedx : number = 0;
	AI_speedy : number = 0;
	racketSpeed : number = 0.1;
	minerr : number = 0.1;
	v : pt = new vec(0, 0);
	lastpt: pt = new pt(0, 0);

	constructor(){}

	private on_edge(pt1 : pt):boolean
	{
		const halfLength = siteLength / 2.0;
		const halfWidth = siteWidth / 2.0;

		if (Math.abs(pt1.x - halfLength) <= this.minerr || 
			Math.abs(pt1.x + halfLength) <= this.minerr ||
				Math.abs(pt1.y - halfWidth) <= this.minerr || 
					Math.abs(pt1.y + halfWidth) <= this.minerr) {
			return true;
		}
		return false;
	}

	private out_of_bound(pt1 : pt, v1: vec) : boolean
	{
		const halfLength = siteLength / 2.0;
		const halfWidth = siteWidth / 2.0;
		let bounced = false;

		if (pt1.x > halfLength) {
			v1.x = -Math.abs(v1.x);
			bounced = true;
		} else if (pt1.x < -halfLength) {
			v1.x = Math.abs(v1.x); 
			bounced = true;
		}

		if (pt1.y > halfWidth) {
			v1.y = -Math.abs(v1.y); 
			bounced = true;
		} else if (pt1.y < -halfWidth) {
			v1.y = Math.abs(v1.y); 
			bounced = true;
		}

		return bounced;
	}

	private next_hit_pos(pt1 : pt, v1: vec) : [pt, vec]
	{
		const x = pt1.x;
		const y = pt1.y;
		const vx = v1.x;
		const vy = v1.y;

		if (Math.abs(vx) < 0.001) { 
			return [pt1, v1];
		}

		const halfLength = siteLength / 2.0;
		const halfWidth = siteWidth / 2.0;

		if (this.out_of_bound(pt1, v1)) {
			return [pt1, v1];
		}

		if (this.on_edge(pt1)) {
			return [new pt(pt1.x + v1.x * 0.1, pt1.y + v1.y * 0.1), new vec(v1.x, v1.y)];
		}

		let minTime = Infinity;
		let hitPoint: pt = pt1;
		let newVelocity: vec = v1;

		if (vx > 0) {
			const timeToRight = (halfLength - x) / vx;
			const yAtRight = y + vy * timeToRight;
			if (timeToRight > 0 && Math.abs(yAtRight) <= halfWidth) {
				if (timeToRight < minTime) {
					minTime = timeToRight;
					hitPoint = new pt(halfLength, yAtRight);
					newVelocity = new vec(-vx, vy);
				}
			}
		}

		if (vx < 0) {
			const timeToLeft = (-halfLength - x) / vx;
			const yAtLeft = y + vy * timeToLeft;
			if (timeToLeft > 0 && Math.abs(yAtLeft) <= halfWidth) {
				if (timeToLeft < minTime) {
					minTime = timeToLeft;
					hitPoint = new pt(-halfLength, yAtLeft);
					newVelocity = new vec(-vx, vy);
				}
			}
		}

		if (vy > 0) {
			const timeToTop = (halfWidth - y) / vy;
			const xAtTop = x + vx * timeToTop;
			if (timeToTop > 0 && Math.abs(xAtTop) <= halfLength) {
				if (timeToTop < minTime) {
					minTime = timeToTop;
					hitPoint = new pt(xAtTop, halfWidth);
					newVelocity = new vec(vx, -vy);
				}
			}
		}

		if (vy < 0) {
			const timeToBottom = (-halfWidth - y) / vy;
			const xAtBottom = x + vx * timeToBottom;
			if (timeToBottom > 0 && Math.abs(xAtBottom) <= halfLength) {
				if (timeToBottom < minTime) {
					minTime = timeToBottom;
					hitPoint = new pt(xAtBottom, -halfWidth);
					newVelocity = new vec(vx, -vy);
				}
			}
		}

		return [hitPoint, newVelocity];
	}

	public start() : void
	{
		this.timer_AI_get_game_state = setInterval(() => {
			this.AI_ball_posx = game.ballPosX;
			this.AI_ball_posy = game.ballPosY;
			this.AI_leftRacketPos = game.leftRacketPos;
			this.AI_rightRacketPos = game.rightRacketPos;
			this.AI_speedx = game.speedx;
			this.AI_speedy = game.speedy;

			if (this.AI_speedx > 0) {
				p.x = this.AI_ball_posx;
				p.y = this.AI_ball_posy;
				this.v.x = this.AI_speedx;
				this.v.y = this.AI_speedy;

				let count = 0;
				const maxIterations = 10;

				while (count < maxIterations) {
					let res = this.next_hit_pos(p, this.v);
					p = res[0];
					this.v = res[1];

					if (Math.abs(p.x - siteLength / 2.0) <= this.minerr) {
						break;
					}
					count++;
				}
				this.lastpt = new pt(p.x, p.y);
			}
		}, 100);

		this.timer_AI_move = setInterval(() => {
			if (this.AI_speedx > 0) {
				const targetY = this.lastpt.y;
				const currentY = this.AI_rightRacketPos;
				const tolerance = 0.05; 

				if (targetY > currentY + tolerance) {
					game.isIPressed = true;
					game.isKPressed = false;
				} else if (targetY < currentY - tolerance) {
					game.isKPressed = true;
					game.isIPressed = false;
				} else {
					game.isIPressed = false;
					game.isKPressed = false;
				}
			} else {
				game.isIPressed = false;
				game.isKPressed = false;
			}
		}, 1000 / 60.0);
	}

	public stop() : void
	{
		if (this.timer_AI_get_game_state != null)
			{
				clearInterval(this.timer_AI_get_game_state);
				this.timer_AI_get_game_state = null;
			}

			if (this.timer_AI_move)
				{
					clearInterval(this.timer_AI_move);
					this.timer_AI_move = null;
				}   
	}
}

class pt
{
	x: number;
	y: number;

	constructor(x : number, y: number)
	{
		this.x = x;
		this.y = y;
	}
}

class vec
{
	x: number;
	y: number;

	constructor(x:number, y:number)
	{
		this.x = x;
		this.y = y;
	}
}

var AI_instance: game_AI = new game_AI();
var p = new pt(0,0);

function AI_start() : void
{
	AI_instance.start();
}

function AI_stop() : void
{
	AI_instance.stop();
}
