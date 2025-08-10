# Etape 1 : builder Node for Tailwind
FROM node:18-alpine AS builder

ARG GOOGLE_USER_ID
ENV GOOGLE_USER_ID=${GOOGLE_USER_ID}

WORKDIR /app

# Install tailwind and his dependances
COPY /files/pages/script/package.json /files/pages/script/postcss.config.js /files/pages/script/tailwind.config.js ./

RUN npm install

# Install TypeScript globally 
RUN npm install -g typescript

# Copy HTML/CSS/JS files
COPY ./files/pages ./files/pages
# COPY ./files/pages/fonts.css /var/www/html/css/

# Compile Tailwind
RUN npx tailwindcss -i ./files/pages/main.css -o ./files/pages/main.final.css --minify

RUN echo "const google_client_id: string = \"${GOOGLE_USER_ID}\";" > ./files/pages/script/env.ts

# Compile TypeScript 
RUN tsc --project ./files/pages/script/tsconfig.json

# Etape 2 : final image of Nginx
FROM debian:bullseye
# FROM ubuntu:22.04

RUN apt update -y && apt upgrade -y && apt install -y \
        openssl \
        curl \
        nginx 

RUN mkdir -p /etc/nginx/ssl

RUN openssl req -x509 -nodes -out /etc/nginx/ssl/transcendence.crt -keyout /etc/nginx/ssl/transcendence.key -subj "/C=FR/ST=IDF/L=Paris/O=42/OU=42/CN=localhost/UID=shuwang"

RUN mkdir -p /var/www/html

EXPOSE 9000

COPY ./conf/nginx.conf /etc/nginx/nginx.conf

COPY --from=builder /app/files/pages/main.final.css ./main.final.css

COPY --from=builder /app/files/pages/script/*.js /var/www/html/script/

COPY --from=builder /app/files/pages /var/www/html

RUN chmod -R 755 /var/www/html

RUN chown -R www-data:www-data /var/www/html

CMD ["nginx", "-g", "daemon off;"]