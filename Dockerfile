FROM node:25-alpine
WORKDIR /app
RUN apk add --no-cache python3 make g++ \
 && ln -sf python3 /usr/bin/python
COPY package.json yarn.lock* ./
RUN corepack enable && yarn install --frozen-lockfile || yarn install
COPY src ./src
ENV NODE_ENV=production
ENV UPLOAD_DIR=/data/uploads
ENV DATA_DIR=/data/db
EXPOSE 3000
CMD ["node", "src/server.js"]
