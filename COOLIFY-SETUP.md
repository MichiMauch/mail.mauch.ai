# Coolify Deployment – mail.mauch.ai

## Voraussetzungen
- ✅ Hetzner Server: `78.46.189.129`
- ✅ Coolify v4: `coolify.mauch.rocks`
- ✅ GitHub Repo: `git@github.com:MichiMauch/mail.mauch.ai.git`
- ✅ Cloudflare DNS für `mauch.ai`

---

## 1. Cloudflare DNS

1. → [dash.cloudflare.com](https://dash.cloudflare.com) → `mauch.ai` → **DNS**
2. Neuer Record:
   - **Typ:** A
   - **Name:** `mail`
   - **IPv4:** `78.46.189.129`
   - **Proxy:** An (orange Wolke) — oder Aus wenn Coolify SSL via Let's Encrypt macht
3. → **SSL/TLS** → Modus: **Full (strict)**

---

## 2. Coolify – Docker Compose Projekt

1. Öffne `https://coolify.mauch.rocks`
2. Wähle deinen Server (der Hetzner)
3. **+ Add New Resource** → **Docker Compose**
4. **Git Repository:** `https://github.com/MichiMauch/mail.mauch.ai`
   - Branch: `main`
   - Docker Compose Pfad: `docker-compose.yml` (Default)
5. Klicke **Continue**

---

## 3. Environment-Variablen

Im Coolify-Projekt unter **Environment Variables** diese setzen:

```
SESSION_SECRET=e4aea03501b1a3e26a51eab7e21b5648ee4a668cadc6c2b711931682299a87cf
```

> Das ist das einzige Secret, das nicht im Repo steht. Alles andere ist in der `docker-compose.yml` definiert.

---

## 4. Domain konfigurieren

Im Coolify-Projekt unter **Settings**:

1. **Domains:** `https://mail.mauch.ai`
2. **Port:** `3000`

### SSL-Varianten:

**Variante A: Cloudflare Proxy AN (orange Wolke)**
- Coolify SSL: Nicht nötig (Cloudflare macht das)
- Coolify → Settings → **SSL:** aus / Let's Encrypt nicht aktivieren
- Cloudflare SSL/TLS: **Full** oder **Full (strict)**

**Variante B: Cloudflare Proxy AUS (DNS only, graue Wolke)**
- Coolify → Settings → **Let's Encrypt** aktivieren
- Coolify kümmert sich um das Zertifikat

> **Empfehlung:** Variante A ist einfacher, wenn Cloudflare sowieso da ist.

---

## 5. Deploy

1. Klicke **Deploy** in Coolify
2. Warte bis beide Container (`mailapp` + `mailapp-redis`) grün sind
3. Öffne `https://mail.mauch.ai`

---

## 6. Verifizierung

Nach dem Deploy im Browser oder Terminal prüfen:

```bash
# App erreichbar?
curl -s https://mail.mauch.ai/api/config
# → {"hasImapConfig":true,"hasSmtpConfig":true,"production":true, ...}

# Security-Headers?
curl -sI https://mail.mauch.ai | grep -E "Strict|Content-Security|Permissions|X-Content"

# DNS Rebinding blockiert?
curl -s -H "Host: evil.com" https://mail.mauch.ai/api/config
# → 403 "Ungültiger Host-Header"

# CSRF blockiert?
curl -s -X POST -H "Origin: https://evil.com" https://mail.mauch.ai/api/send
# → 403 "Zugriff verweigert"
```

---

## 7. Updates deployen

```bash
# Lokal ändern, committen, pushen
cd /Users/michaelmauch/Documents/Development/imap-mail-client
git add -A && git commit -m "Update" && git push

# In Coolify: "Redeploy" klicken
# Oder: Webhook einrichten für Auto-Deploy bei Push
```

---

## Fehlerbehebung

### Container startet nicht
```bash
# SSH auf den Hetzner Server
ssh root@78.46.189.129

# Coolify-Logs des Containers
docker logs mailapp
docker logs mailapp-redis
```

### Redis-Verbindung schlägt fehl
Die Services kommunizieren über das Docker-Netzwerk. `redis://redis:6379` funktioniert nur, wenn beide im gleichen Compose-Stack sind.

### "Ungültiger Host-Header"
Falls Coolify/Traefik einen anderen Host-Header sendet, prüfe in den Logs welcher Header ankommt und passe `APP_DOMAIN` an.

### Session geht bei Redeploy verloren
Das ist normal beim ersten Deploy. Nach dem Redis-Setup bleiben Sessions persistent, auch bei Redeploy des App-Containers (Redis-Volume bleibt).
