FROM node:20-alpine

RUN apk add --no-cache redis su-exec

RUN addgroup -S mailapp && adduser -S mailapp -G mailapp

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY config/ ./config/
COPY src/ ./src/
COPY start.sh ./start.sh
RUN chmod +x /app/start.sh

RUN mkdir -p logs && chown -R mailapp:mailapp logs /app

EXPOSE 3000

ENV REDIS_URL=redis://127.0.0.1:6379

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/config || exit 1

CMD ["/app/start.sh"]
