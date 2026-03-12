#!/bin/sh
redis-server --daemonize yes --maxmemory 128mb --maxmemory-policy allkeys-lru --save "" --loglevel warning
echo "[Redis] gestartet"
exec su-exec mailapp node src/server/index.js
