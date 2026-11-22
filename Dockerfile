FROM node:22-alpine
RUN apk upgrade --no-cache
WORKDIR /app
COPY package.json ./
COPY server.js ./
EXPOSE 3000
CMD ["node", "server.js"]
