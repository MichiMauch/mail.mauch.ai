#!/bin/sh
echo "[Start] Redis starten..."
redis-server --daemonize yes --maxmemory 128mb --maxmemory-policy allkeys-lru --save "" --loglevel warning
sleep 1
echo "[Start] Redis PID: $(cat /var/run/redis/redis-server.pid 2>/dev/null || echo 'unknown')"
redis-cli ping || echo "[Start] Redis PING fehlgeschlagen"
echo "[Start] Node.js starten..."
exec su-exec mailapp node src/server/index.js
