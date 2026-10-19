FROM node:22-bookworm-slim
WORKDIR /app
COPY server/package.json server/package-lock.json* ./server/
RUN cd server && npm install --omit=dev
COPY server ./server
COPY client ./client
RUN mkdir -p /data && chown -R node:node /app
USER node
ENV NODE_ENV=production PORT=8080 DATA_DIR=/data
EXPOSE 8080
CMD ["node", "server/src/server.mjs"]
