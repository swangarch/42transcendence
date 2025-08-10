FROM debian:bullseye

RUN apt update && apt install -y curl

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    
RUN apt-get install -y nodejs

RUN mkdir -p /app/transcendence/game

EXPOSE 9999

COPY ./files/ /app/transcendence/game

WORKDIR /app/transcendence/game

RUN npm install ws && npm install typescript && npm install --save-dev @types/node @types/ws

RUN npm install jsonwebtoken cookie

CMD ["node", "/app/transcendence/game/game.js"]

