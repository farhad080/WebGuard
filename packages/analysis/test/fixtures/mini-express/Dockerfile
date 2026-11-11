FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci
CMD ["node", "src/server.js"]
