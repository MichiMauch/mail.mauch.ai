FROM node:20-alpine

# Redis installieren
RUN apk add --no-cache redis su-exec

# App-User erstellen
RUN addgroup -S mailapp && adduser -S mailapp -G mailapp

WORKDIR /app

# Dependencies
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# App-Code
COPY config/ ./config/
COPY src/ ./src/

# Verzeichnisse
RUN mkdir -p logs && chown -R mailapp:mailapp logs /app

# Start-Script: Redis als root, dann Node als mailapp
COPY <<'EOF' /app/start.sh
#!/bin/sh
redis-server --daemonize yes --maxmemory 128mb --maxmemory-policy allkeys-lru --save "" --loglevel warning
echo "[Redis] gestartet"
exec su-exec mailapp node src/server/index.js
EOF
RUN chmod +x /app/start.sh

EXPOSE 3000

ENV REDIS_URL=redis://127.0.0.1:6379

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/config || exit 1

CMD ["/app/start.sh"]
