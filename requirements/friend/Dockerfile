FROM debian:bullseye

RUN apt update && apt install -y curl

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    
RUN apt-get install -y nodejs

RUN mkdir -p /app/transcendence/friend_manage /app/transcendence/friend_manage/data

EXPOSE 9766

COPY ./files/friend.js /app/transcendence/friend_manage

COPY ./tools/data/. /app/transcendence/friend_manage/data/

WORKDIR /app/transcendence/friend_manage

RUN npm install fastify better-sqlite3 

RUN npm install @fastify/jwt @fastify/cookie @fastify/cors

CMD ["node", "/app/transcendence/friend_manage/friend.js"]

