FROM debian:bullseye

RUN apt update && apt install -y curl

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    
RUN apt-get install -y nodejs

RUN mkdir -p /app/transcendence/user_manage /app/transcendence/user_manage/avatar /app/transcendence/user_manage/data

EXPOSE 9223

COPY ./files/user.js /app/transcendence/user_manage

COPY ./tools/avatar/. /app/transcendence/user_manage/avatar/

COPY ./tools/data/. /app/transcendence/user_manage/data/

WORKDIR /app/transcendence/user_manage

RUN npm install fastify better-sqlite3 @fastify/multipart google-auth-library axios

RUN npm install @fastify/jwt @fastify/cookie @fastify/cors

RUN npm install otplib qrcode

CMD ["node", "/app/transcendence/user_manage/user.js"]

