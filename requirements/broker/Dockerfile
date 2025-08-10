FROM debian:bullseye

RUN apt update && apt install -y curl

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    
RUN apt-get install -y nodejs

RUN mkdir -p /app/transcendence/broker_manage

EXPOSE 9899

EXPOSE 9555

COPY ./files/broker.js /app/transcendence/broker_manage

WORKDIR /app/transcendence/broker_manage

RUN npm install fastify better-sqlite3 ws

RUN npm install jsonwebtoken cookie

CMD ["node", "/app/transcendence/broker_manage/broker.js"]

