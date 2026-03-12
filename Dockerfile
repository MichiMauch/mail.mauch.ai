FROM node:20-alpine

# Sicherheit: Nicht als root laufen
RUN addgroup -S mailapp && adduser -S mailapp -G mailapp

WORKDIR /app

# Dependencies zuerst (Cache-Layer)
COPY package.json package-lock.json ./
RUN npm ci --production && npm cache clean --force

# App-Code
COPY config/ ./config/
COPY src/ ./src/

# Logs-Verzeichnis
RUN mkdir -p logs && chown mailapp:mailapp logs

# Kein root
USER mailapp

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:3000/api/config || exit 1

CMD ["node", "src/server/index.js"]
