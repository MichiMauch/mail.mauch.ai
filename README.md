# MAIL – Minimalistischer IMAP-Client

Schlanker IMAP-Mail-Client mit 4-Schichten-Architektur:

```
┌─────────────────────────────────────────────────┐
│  SCHICHT 4  │  Frontend + Sicherheit            │
│             │  HTML-Sanitization, Tracking-Schutz│
├─────────────┼────────────────────────────────────┤
│  SCHICHT 3  │  MIME-Parser (Core Logic)          │
│             │  Base64, Quoted-Printable, Charset │
├─────────────┼────────────────────────────────────┤
│  SCHICHT 2  │  Daten-Abfrage (Fetching Logic)   │
│             │  Header-Only, Lazy Loading         │
├─────────────┼────────────────────────────────────┤
│  SCHICHT 1  │  Connectivity Layer                │
│             │  IMAP/TLS, SASL, OAuth2-ready      │
└─────────────┴────────────────────────────────────┘
```

## Quick Start

```bash
npm install
npm start
# → http://localhost:3000
```

## Konfiguration

Entweder `config/default.json` editieren oder die Zugangsdaten über das Login-Formular im Browser eingeben.

### Gmail
1. 2FA aktivieren
2. App-Passwort erstellen: Google-Konto → Sicherheit → App-Passwörter
3. Host: `imap.gmail.com`, Port: `993`

### Outlook/Hotmail
- Host: `outlook.office365.com`, Port: `993`

## API-Endpunkte

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| POST | `/api/connect` | Verbindung herstellen |
| GET | `/api/folders` | Ordnerliste |
| GET | `/api/messages/:folder` | Header-Liste (schnell) |
| GET | `/api/message/:folder/:uid` | Vollständige Mail (lazy) |
| GET | `/api/attachment/:folder/:uid/:index` | Anhang-Download |
| POST | `/api/flags/:folder/:uid` | Flags setzen |
| POST | `/api/disconnect` | Abmelden |

## Sicherheitsfeatures

- **HTML-Sanitization**: `<script>`, `<iframe>`, `<object>` werden entfernt (DOMPurify)
- **Tracking-Schutz**: Externe Bilder standardmäßig blockiert
- **Tracking-Pixel**: 1×1-Bilder werden automatisch erkannt und entfernt
- **Sandboxed Iframe**: Mail-HTML wird isoliert vom Haupt-DOM gerendert
- **Download-Header**: `X-Content-Type-Options: nosniff` für Anhänge

## Architektur

```
Browser (SPA)  ←→  Express API (JSON)  ←→  IMAP Server (TLS:993)
                         ↓
                   MIME-Parser
                   HTML-Sanitizer
```

Das System arbeitet als Middleware: Es übersetzt die komplexen Rohdaten
vom Mailserver in sauberes, strukturiertes JSON.
