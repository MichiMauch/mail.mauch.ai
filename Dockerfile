FROM node:20-alpine

# Redis installieren
RUN apk add --no-cache redis

# App-User erstellen
RUN addgroup -S mailapp && adduser -S mailapp -G mailapp

WORKDIR /app

# Dependencies
COPY package.json package-lock.json ./
RUN npm ci --production && npm cache clean --force

# App-Code
COPY config/ ./config/
COPY src/ ./src/

# Verzeichnisse
RUN mkdir -p logs /data && chown -R mailapp:mailapp logs

# Start-Script: Redis + Node.js
RUN printf '#!/bin/sh\nredis-server --daemonize yes --maxmemory 128mb --maxmemory-policy allkeys-lru --save ""\nexec node src/server/index.js\n' > /app/start.sh && chmod +x /app/start.sh

EXPOSE 3000

ENV REDIS_URL=redis://127.0.0.1:6379

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/config || exit 1

CMD ["/app/start.sh"]
