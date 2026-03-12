# Deployment-Handbuch – IMAP Mail Client auf Hetzner

> **Zielumgebung:** Hetzner Cloud VPS (Ubuntu 24.04), Nginx, Let's Encrypt, PM2
> **Bedrohungsmodell:** Öffentlich erreichbar via HTTPS, Multi-User

---

## Inhaltsverzeichnis

1. [Checkliste (TL;DR)](#1-checkliste-tldr)
2. [Was sich gegenüber localhost ändert](#2-was-sich-gegenüber-localhost-ändert)
3. [Server-Vorbereitung](#3-server-vorbereitung)
4. [Nginx als Reverse Proxy](#4-nginx-als-reverse-proxy)
5. [Let's Encrypt (HTTPS)](#5-lets-encrypt-https)
6. [Applikation deployen](#6-applikation-deployen)
7. [Environment-Variablen](#7-environment-variablen)
8. [PM2 Prozess-Manager](#8-pm2-prozess-manager)
9. [Session-Store (Redis)](#9-session-store-redis)
10. [Multi-User-Architektur](#10-multi-user-architektur)
11. [Vorgeschalteter Auth-Layer](#11-vorgeschalteter-auth-layer)
12. [Firewall & Netzwerk](#12-firewall--netzwerk)
13. [DoS-Härtung](#13-dos-härtung)
14. [Logging & Monitoring](#14-logging--monitoring)
15. [Automatische Updates](#15-automatische-updates)
16. [Backup & Recovery](#16-backup--recovery)
17. [Security-Audit-Zyklus](#17-security-audit-zyklus)

---

## 1. Checkliste (TL;DR)

```
Vor dem Deployment:
  □  NODE_ENV=production
  □  SESSION_SECRET gesetzt (mind. 32 Bytes, zufällig)
  □  APP_DOMAIN gesetzt (z.B. mail.example.com)
  □  TLS_REJECT_UNAUTHORIZED=true (Standard, nicht überschreiben!)
  □  BIND_ADDRESS=127.0.0.1 (nur über Nginx erreichbar)
  □  TRUST_PROXY=1
  □  Redis installiert + Session-Store konfiguriert
  □  Nginx + Let's Encrypt konfiguriert
  □  Firewall: nur 22/443 offen
  □  Node.js NICHT als root (eigener User 'mailapp')
  □  PM2 mit --max-memory-restart
  □  npm audit clean
  □  .env.local NICHT im Repository

Nach dem Deployment:
  □  curl -I https://mail.example.com → HSTS, CSP, Permissions-Policy
  □  curl -H "Host: evil.com" https://IP → 403
  □  Logs unter /var/log/mailapp/ oder in Loki/ELK
  □  Fail2ban-Regel aktiv
```

---

## 2. Was sich gegenüber localhost ändert

| Aspekt | localhost | Hetzner |
|---|---|---|
| HTTPS | Optional | **Pflicht** – sonst Passwörter im Klartext |
| Session-Cookie `secure` | `false` | **`true`** – Cookie nur über HTTPS |
| Nutzeranzahl | 1 | Mehrere gleichzeitig |
| IMAP-Verbindungen | 1 global | **Pro Session isoliert** |
| Attachment-Tokens | Global | **Session-gebunden** |
| Session-Store | RAM | **Redis** (überlebt Restarts) |
| Auth-Layer | Keiner nötig | **HTTP Basic / Authelia / OAuth** |
| Rate Limiting | Per `req.ip` | Per `X-Forwarded-For` (trust proxy) |
| CSP `style-src` | `'unsafe-inline'` | **Nonce-basiert** |
| Logging | Lokale Datei | **Zentrales Logging + Alerting** |
| DoS-Schutz | Irrelevant | **Nginx + Fail2ban + Connection Limits** |
| Host-Header-Check | `localhost` only | **`APP_DOMAIN` erlaubt** |
| CORS-Origins | `http://localhost:3000` | **`https://mail.example.com`** |

> **Der Code erkennt `NODE_ENV=production` automatisch** und passt Cookies, Rate Limits, CSP und Host-Header-Check an.

---

## 3. Server-Vorbereitung

```bash
# 1. Hetzner Cloud – Ubuntu 24.04, mindestens CX21 (2 vCPU, 4GB RAM)
# 2. SSH-Key statt Passwort

# System aktualisieren
sudo apt update && sudo apt upgrade -y

# Eigener User für die App (NICHT root)
sudo useradd -m -s /bin/bash mailapp
sudo mkdir -p /opt/mailapp
sudo chown mailapp:mailapp /opt/mailapp

# Node.js 20 LTS installieren
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# PM2 global installieren
sudo npm install -g pm2

# Redis installieren (für Session-Store)
sudo apt install -y redis-server
sudo systemctl enable redis-server

# Nginx installieren
sudo apt install -y nginx
sudo systemctl enable nginx

# Fail2ban installieren
sudo apt install -y fail2ban
sudo systemctl enable fail2ban
```

---

## 4. Nginx als Reverse Proxy

```nginx
# /etc/nginx/sites-available/mailapp
server {
    listen 80;
    server_name mail.example.com;
    # Redirect zu HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name mail.example.com;

    # ── TLS (Let's Encrypt) ────────────────────────
    ssl_certificate     /etc/letsencrypt/live/mail.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5:!RC4;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    # ── HSTS (2 Jahre, inkl. Subdomains) ───────────
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # ── Request-Limits (vor Express!) ──────────────
    client_max_body_size       2m;      # Max Upload-Grösse
    client_body_timeout        10s;     # Slowloris-Schutz
    client_header_timeout      10s;
    keepalive_timeout          65s;
    send_timeout               10s;
    proxy_read_timeout         60s;     # IMAP-Operationen brauchen Zeit
    proxy_connect_timeout      10s;

    # ── Rate Limiting (Nginx-Level) ────────────────
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;

    # ── Nur GET/POST/DELETE erlauben ───────────────
    if ($request_method !~ ^(GET|POST|DELETE|HEAD|OPTIONS)$ ) {
        return 405;
    }

    # ── X-Forwarded-For überschreiben (nicht anhängen!) ──
    proxy_set_header X-Forwarded-For    $remote_addr;
    proxy_set_header X-Forwarded-Proto  $scheme;
    proxy_set_header X-Real-IP          $remote_addr;
    proxy_set_header Host               $host;

    # ── Login-Endpunkt: Extra Rate Limit ───────────
    location = /api/connect {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://127.0.0.1:3000;
    }

    # ── API-Endpunkte ─────────────────────────────
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:3000;
    }

    # ── Statische Dateien ──────────────────────────
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
    }
}
```

**Kritischer Punkt: `X-Forwarded-For` überschreiben!**

```nginx
# RICHTIG: Setzt den Header auf die echte Client-IP
proxy_set_header X-Forwarded-For $remote_addr;

# FALSCH: Hängt an → Angreifer kann eigene IP voranstellen
# proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

Ohne Überschreiben kann ein Angreifer `curl -H "X-Forwarded-For: 8.8.8.8"` senden und das Rate Limiting umgehen.

```bash
# Aktivieren
sudo ln -s /etc/nginx/sites-available/mailapp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## 5. Let's Encrypt (HTTPS)

```bash
# Certbot installieren
sudo apt install -y certbot python3-certbot-nginx

# Zertifikat holen (DNS muss bereits auf den Server zeigen)
sudo certbot --nginx -d mail.example.com

# Auto-Renewal testen
sudo certbot renew --dry-run

# Renewal ist automatisch via systemd timer
```

---

## 6. Applikation deployen

```bash
# Als mailapp-User
sudo -u mailapp -i

# Code klonen
cd /opt/mailapp
git clone https://github.com/your-repo/imap-mail-client.git app
cd app

# Dependencies installieren (respektiert package-lock.json exakt)
npm ci --production

# Security-Tests ausführen
npm run security:test
npm audit

# .env.local erstellen
cat > .env.local << 'EOF'
NODE_ENV=production
APP_DOMAIN=mail.example.com
BIND_ADDRESS=127.0.0.1
TRUST_PROXY=1
SESSION_SECRET=$(openssl rand -hex 32)
IMAP_HOST=mail.cyon.ch
IMAP_PORT=993
SMTP_HOST=mail.cyon.ch
SMTP_PORT=465
TLS_REJECT_UNAUTHORIZED=true
MAX_SESSIONS=50
SESSION_TIMEOUT=1800000
EOF

# WICHTIG: .env.local darf nur vom App-User lesbar sein
chmod 600 .env.local
```

---

## 7. Environment-Variablen

| Variable | Pflicht | Default | Beschreibung |
|---|---|---|---|
| `NODE_ENV` | **Ja** | `development` | `production` aktiviert HTTPS-Cookies, Nonce-CSP, strengere Limits |
| `APP_DOMAIN` | **Ja** | – | Erlaubter Host-Header (z.B. `mail.example.com`) |
| `SESSION_SECRET` | **Ja** | Random | Mind. 32 Bytes Hex. **Muss** persistent sein (sonst Logout bei Restart) |
| `BIND_ADDRESS` | Empfohlen | `0.0.0.0` / `127.0.0.1` | In Prod: `127.0.0.1` (nur über Nginx) |
| `TRUST_PROXY` | **Ja** (Prod) | – | `1` für einen Proxy (Nginx). `2` für zwei. |
| `PORT` | Nein | `3000` | Interner Port (Nginx leitet dahin) |
| `IMAP_HOST` | Nein | `config/default.json` | Fester IMAP-Server |
| `IMAP_PORT` | Nein | `993` | IMAP-Port |
| `SMTP_HOST` | Nein | abgeleitet | Fester SMTP-Server |
| `SMTP_PORT` | Nein | `465` | SMTP-Port |
| `TLS_REJECT_UNAUTHORIZED` | Nein | `true` | **Nie `false` in Production!** |
| `MAX_SESSIONS` | Nein | `50` | Max gleichzeitige User-Verbindungen |
| `SESSION_TIMEOUT` | Nein | `1800000` | Session-Timeout in ms (Default: 30 Min) |
| `REDIS_URL` | Empfohlen | – | z.B. `redis://127.0.0.1:6379` (für Session-Store) |

---

## 8. PM2 Prozess-Manager

```bash
# ecosystem.config.cjs
module.exports = {
  apps: [{
    name: 'mailapp',
    script: 'src/server/index.js',
    cwd: '/opt/mailapp/app',
    instances: 1,           // Single Instance (wegen IMAP-Verbindungen)
    exec_mode: 'fork',
    max_memory_restart: '512M',
    env: {
      NODE_ENV: 'production',
    },
    // Logs
    error_file: '/var/log/mailapp/error.log',
    out_file: '/var/log/mailapp/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    // Auto-Restart
    watch: false,
    autorestart: true,
    max_restarts: 10,
    restart_delay: 5000,
  }],
};
```

```bash
# Log-Verzeichnis erstellen
sudo mkdir -p /var/log/mailapp
sudo chown mailapp:mailapp /var/log/mailapp

# Starten
pm2 start ecosystem.config.cjs

# Auto-Start bei Boot
pm2 save
pm2 startup systemd -u mailapp --hp /home/mailapp

# Status
pm2 status
pm2 logs mailapp
```

### Warum `instances: 1`?

IMAP-Verbindungen sind stateful – sie können nicht zwischen Prozessen geteilt werden. Mit `instances: 2` würde ein Request an Prozess A gehen und der nächste an Prozess B (das die IMAP-Verbindung nicht hat).

**Für Skalierung:** Redis-Session-Store + Sticky Sessions in Nginx (`ip_hash`).

---

## 9. Session-Store (Redis)

Im RAM-Store gehen Sessions bei jedem Restart verloren. Mit Redis bleiben sie persistent.

```bash
npm install connect-redis
```

```javascript
// In src/server/index.js – Session-Konfiguration erweitern:
import { createClient } from 'redis';
import RedisStore from 'connect-redis';

let sessionStore;
if (process.env.REDIS_URL) {
  const redisClient = createClient({ url: process.env.REDIS_URL });
  await redisClient.connect();
  sessionStore = new RedisStore({ client: redisClient });
  console.log('[Redis] Session-Store verbunden');
}

app.use(session({
  store: sessionStore,   // undefined = MemoryStore (Fallback für Dev)
  // ... rest wie gehabt
}));
```

**Redis-Härtung:**

```bash
# /etc/redis/redis.conf
bind 127.0.0.1      # Nur lokal erreichbar
requirepass DEIN_REDIS_PASSWORT
maxmemory 256mb
maxmemory-policy allkeys-lru
```

---

## 10. Multi-User-Architektur

Die App ist jetzt Multi-User-fähig. Jeder angemeldete Nutzer bekommt eine eigene IMAP/SMTP-Verbindung:

```
Browser A ──┐
             ├──► Express ──► Session Store (Redis)
Browser B ──┘         │
                      ├──► Session A → IMAP(user-a@cyon.ch), SMTP(user-a)
                      └──► Session B → IMAP(user-b@cyon.ch), SMTP(user-b)
```

### Isolation

| Aspekt | Massnahme |
|---|---|
| IMAP-Verbindung | Pro Session-ID, in `userConnections` Map |
| SMTP-Verbindung | Pro Session-ID, zusammen mit IMAP |
| Attachment-Tokens | Session-ID gebunden, Cross-Session-Zugriff blockiert |
| Session-Cookie | `httpOnly`, `sameSite: strict`, `secure` |
| Credentials | Pro Verbindung im RAM, bei Disconnect gelöscht |

### Limits

| Parameter | Wert | Env-Variable |
|---|---|---|
| Max gleichzeitige Sessions | 50 | `MAX_SESSIONS` |
| Session-Timeout | 30 Minuten | `SESSION_TIMEOUT` |
| Eviction bei Überlauf | Älteste Session wird getrennt | – |

### Was ein Angreifer NICHT kann

- ❌ Tokens von User A als User B einlösen (Session-Check)
- ❌ IMAP-Verbindung von User A über User B's Session nutzen
- ❌ Session-Cookie klauen (HttpOnly + SameSite)
- ❌ Session-Fixation (Session-Rotation bei Login)

---

## 11. Vorgeschalteter Auth-Layer

Ohne Auth-Layer kann **jeder, der die URL kennt**, den Login-Screen sehen und beliebige IMAP-Server ansprechen. Optionen:

### Option A: Nginx HTTP Basic Auth (einfachste Lösung)

```bash
# Passwort-Datei erstellen
sudo apt install -y apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd michael
```

```nginx
# In Nginx server block:
location / {
    auth_basic "Mail Client";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://127.0.0.1:3000;
}
```

**Vorteil:** Kein Code-Change.
**Nachteil:** Kein Logout, kein MFA, Passwort im Browser-Dialog.

### Option B: Authelia (empfohlen für Multi-User)

```bash
# Docker-basiert
docker run -d \
  --name authelia \
  -v /opt/authelia/config:/config \
  -p 9091:9091 \
  authelia/authelia:latest
```

```nginx
# Nginx: Auth-Request an Authelia
location / {
    auth_request /authelia;
    auth_request_set $user $upstream_http_remote_user;
    proxy_set_header Remote-User $user;
    proxy_pass http://127.0.0.1:3000;
}

location = /authelia {
    internal;
    proxy_pass http://127.0.0.1:9091/api/verify;
    proxy_set_header X-Original-URL $scheme://$host$request_uri;
}
```

**Vorteile:** MFA (TOTP/WebAuthn), Session-Management, Benutzer-Verwaltung, Brute-Force-Schutz.

### Option C: Fester IMAP-Host (Open Relay verhindern)

Wenn in `.env.local` ein `IMAP_HOST` gesetzt ist, kann der Nutzer den Host nicht ändern. Das verhindert, dass jemand die App als Scanner für beliebige IMAP-Server missbraucht.

```bash
# .env.local
IMAP_HOST=mail.cyon.ch     # ← Nutzer kann nur cyon-Konten verwenden
SMTP_HOST=mail.cyon.ch
```

---

## 12. Firewall & Netzwerk

```bash
# UFW (Uncomplicated Firewall)
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Erlaubte Ports
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 443/tcp     # HTTPS
# NICHT Port 80 – Nginx redirect reicht
sudo ufw allow 80/tcp      # Nur für Let's Encrypt Renewal

# Aktivieren
sudo ufw enable

# Status
sudo ufw status verbose
```

**NICHT erlauben:**
- ❌ Port 3000 (Express direkt) – nur über Nginx
- ❌ Port 6379 (Redis) – nur lokal
- ❌ UDP – nicht benötigt

### Hetzner Firewall (zusätzlich)

Im Hetzner Cloud Panel → Firewalls:
- Inbound: SSH (22), HTTP (80), HTTPS (443) erlauben
- Alles andere: Deny

---

## 13. DoS-Härtung

### Nginx-Level

```nginx
# Verbindungs-Limits
limit_conn_zone $binary_remote_addr zone=connlimit:10m;
limit_conn connlimit 20;        # Max 20 gleichzeitige Verbindungen pro IP

# Request-Rate
limit_req_zone $binary_remote_addr zone=global:10m rate=10r/s;
limit_req zone=global burst=50 nodelay;

# Grosse Request-Bodies ablehnen
client_max_body_size 2m;

# Slowloris: Timeouts
client_body_timeout   10s;
client_header_timeout 10s;
```

### Fail2ban

```ini
# /etc/fail2ban/jail.d/mailapp.conf
[mailapp-login]
enabled  = true
port     = https
filter   = mailapp-login
logpath  = /opt/mailapp/app/logs/security-*.log
maxretry = 5
bantime  = 3600
findtime = 900

[mailapp-csrf]
enabled  = true
port     = https
filter   = mailapp-csrf
logpath  = /opt/mailapp/app/logs/security-*.log
maxretry = 3
bantime  = 86400
findtime = 300
```

```ini
# /etc/fail2ban/filter.d/mailapp-login.conf
[Definition]
failregex = "event":"LOGIN_FAILED".*"ip":"<HOST>"

# /etc/fail2ban/filter.d/mailapp-csrf.conf
[Definition]
failregex = "event":"CSRF_VIOLATION".*"ip":"<HOST>"
```

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status mailapp-login
```

---

## 14. Logging & Monitoring

### Logs zentralisieren

Die App schreibt Security-Logs nach `logs/security-YYYY-MM-DD.log`. Auf einem Server reicht das nicht.

**Option A: Promtail → Loki → Grafana**

```yaml
# /etc/promtail/config.yml
scrape_configs:
  - job_name: mailapp
    static_configs:
      - targets: [localhost]
        labels:
          app: mailapp
          __path__: /opt/mailapp/app/logs/security-*.log
```

**Option B: Syslog-Weiterleitung**

```bash
# In PM2: Logs an syslog
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 30
```

### Alerting bei ALERT-Events

```bash
# Einfaches Monitoring-Script (cron alle 5 Min)
#!/bin/bash
ALERTS=$(grep '"level":"ALERT"' /opt/mailapp/app/logs/security-$(date +%Y-%m-%d).log | tail -5)
if [ -n "$ALERTS" ]; then
  echo "$ALERTS" | mail -s "[MAILAPP] Security Alert" admin@example.com
fi
```

### echte Client-IP loggen

Mit `trust proxy = 1` gibt `req.ip` die echte Client-IP statt der Nginx-IP zurück. Die Security-Logs enthalten dann die korrekte Adresse.

---

## 15. Automatische Updates

```bash
# Unattended Upgrades (OS-Sicherheitspatches)
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Node.js Dependencies (manuell, monatlich)
cd /opt/mailapp/app
npm audit
npm outdated
npm update
npm run security:test   # Tests nach Update!
pm2 restart mailapp
```

---

## 16. Backup & Recovery

```bash
# Was gesichert werden muss:
# 1. .env.local (Secrets!)
# 2. Nginx-Config
# 3. Let's Encrypt Zertifikate
# 4. Fail2ban-Config
# 5. Redis-Daten (optional, Sessions sind vergänglich)

# Backup-Script
#!/bin/bash
BACKUP_DIR=/opt/backups/mailapp/$(date +%Y%m%d)
mkdir -p $BACKUP_DIR
cp /opt/mailapp/app/.env.local $BACKUP_DIR/
cp /etc/nginx/sites-available/mailapp $BACKUP_DIR/
cp -r /etc/letsencrypt/live/mail.example.com $BACKUP_DIR/certs/
cp /etc/fail2ban/jail.d/mailapp.conf $BACKUP_DIR/

# Verschlüsselt auf externen Storage
tar czf - $BACKUP_DIR | gpg --symmetric --cipher-algo AES256 > /opt/backups/mailapp-$(date +%Y%m%d).tar.gz.gpg
```

---

## 17. Security-Audit-Zyklus

| Frequenz | Aktion |
|---|---|
| **Täglich** | Fail2ban-Status prüfen, Security-Logs auf ALERT scannen |
| **Wöchentlich** | `npm audit`, Hetzner-Security-Advisories checken |
| **Monatlich** | `npm outdated`, OS-Updates, SSL-Zertifikat prüfen |
| **Quartalsweise** | Penetration Test (manuell), Dependency Major-Updates evaluieren |
| **Bei CVE** | Sofort patchen, Tests, Restart |

### Penetration-Test-Checkliste

```bash
# 1. HTTPS erzwungen?
curl -I http://mail.example.com
# → 301 Redirect zu HTTPS

# 2. Security-Headers?
curl -sI https://mail.example.com | grep -E "Strict|Content-Security|Permissions|X-Content"

# 3. DNS Rebinding?
curl -H "Host: evil.com" https://IP-DES-SERVERS
# → 403

# 4. CSRF?
curl -X POST -H "Origin: https://evil.com" https://mail.example.com/api/send
# → 403

# 5. Rate Limiting?
for i in $(seq 1 12); do curl -s -o /dev/null -w "%{http_code}\n" -X POST https://mail.example.com/api/connect; done
# → Letzte Requests: 429

# 6. Cookie-Flags?
curl -sI https://mail.example.com/api/config | grep Set-Cookie
# → HttpOnly; Secure; SameSite=Strict

# 7. Kein direkter Express-Zugriff?
curl http://SERVER-IP:3000/
# → Connection refused (Firewall blockiert)

# 8. Node.js nicht als root?
ps aux | grep node
# → mailapp, nicht root

# 9. Security-Tests?
npm run security:test
# → 94/94 bestanden
```

---

## Architektur-Diagramm (Production)

```
                                     ┌─────────────────────┐
                                     │   Hetzner Firewall   │
                                     │  22/443 only         │
                                     └──────────┬──────────┘
                                                │
        ┌───────────────────────────────────────┼──────────────────┐
        │                           UFW Firewall│                  │
        │                                       │                  │
        │   ┌───────────────┐    ┌──────────────▼────────────┐     │
        │   │  Fail2ban     │◄───│      Nginx (443)          │     │
        │   │  Ban IPs      │    │  TLS Terminierung         │     │
        │   └───────────────┘    │  Rate Limiting            │     │
        │                        │  X-Forwarded-For          │     │
        │                        │  Request Size Limits      │     │
        │                        │  Slowloris Protection     │     │
        │                        │  Optional: Basic Auth     │     │
        │                        └──────────────┬────────────┘     │
        │                                       │ :3000            │
        │                        ┌──────────────▼────────────┐     │
        │                        │  PM2 → Node.js (mailapp)  │     │
        │                        │  Express + Helmet + CSP   │     │
        │                        │  Session → Redis          │     │
        │                        │  Per-Session IMAP/SMTP    │     │
        │                        └──────────────┬────────────┘     │
        │                                       │                  │
        │              ┌────────────────────────┼──────────┐       │
        │              │                        │          │       │
        │   ┌──────────▼──┐   ┌─────────────────▼──┐   ┌──▼────┐  │
        │   │   Redis     │   │  mail.cyon.ch      │   │ Logs  │  │
        │   │   Sessions  │   │  IMAP:993 SMTP:465 │   │ Loki  │  │
        │   │   :6379     │   │  (extern, TLS)     │   │       │  │
        │   └─────────────┘   └────────────────────┘   └───────┘  │
        │                                                          │
        │                      Hetzner VPS                         │
        └──────────────────────────────────────────────────────────┘
```

---

## Credential-Sicherheit auf dem Server

### Problem

Auf einem Server liegen die IMAP-Passwörter **aller** angemeldeten User im RAM des Node.js-Prozesses. Ein Memory Dump exponiert alle.

### Massnahmen

| Stufe | Massnahme | Aufwand |
|---|---|---|
| 1 (aktuell) | Passwörter nur im RAM, bei Disconnect gelöscht | ✅ Implementiert |
| 2 | Core Dumps deaktivieren | `ulimit -c 0` in PM2 |
| 3 | Node.js `--max-old-space-size` begrenzen | PM2 `max_memory_restart` |
| 4 | Vault-Integration (HashiCorp Vault) | Hoch – Passwörter verschlüsselt speichern |
| 5 | App-Passwörter statt echte Passwörter | Provider-abhängig (cyon unterstützt keine) |

```bash
# Core Dumps deaktivieren (PM2 ecosystem.config.cjs)
module.exports = {
  apps: [{
    // ...
    node_args: '--max-old-space-size=512',
    env: {
      NODE_ENV: 'production',
      // Node.js soll keine Core Dumps schreiben
      NODE_OPTIONS: '--abort-on-uncaught-exception=false',
    },
  }],
};
```

```bash
# Systemweit Core Dumps deaktivieren
echo 'kernel.core_pattern=|/bin/false' | sudo tee /etc/sysctl.d/50-coredump.conf
sudo sysctl -p /etc/sysctl.d/50-coredump.conf
```
