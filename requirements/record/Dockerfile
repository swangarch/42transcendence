FROM debian:bullseye
# FROM ubuntu:22.04

RUN apt update && apt install -y curl

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    
RUN apt-get install -y nodejs

RUN mkdir -p /app/transcendence/record_manage /app/transcendence/record_manage/data

EXPOSE 9431

COPY ./files/record.js /app/transcendence/record_manage

COPY ./tools/data/. /app/transcendence/record_manage/data/

WORKDIR /app/transcendence/record_manage

RUN npm install fastify better-sqlite3 

CMD ["node", "/app/transcendence/record_manage/record.js"]

