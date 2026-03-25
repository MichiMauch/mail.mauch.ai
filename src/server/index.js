/**
 * ╔══════════════════════════════════════════════════════════╗
 *  MIDDLEWARE / API-SERVER
 *  Express-basierte REST-API, die IMAP-Rohdaten in
 *  sauberes JSON transformiert für das Frontend.
 *
 *  Unterstützt zwei Modi:
 *  - localhost (Single-User, Entwicklung)
 *  - production (Multi-User, Hetzner/Nginx, HTTPS)
 * ╚══════════════════════════════════════════════════════════╝
 */

import express from 'express';
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { lookup as dnsLookup } from 'dns/promises';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import crypto from 'crypto';
import { IMAPClient } from './imap-client.js';
import { MIMEParser } from './mime-parser.js';
import { HTMLSanitizer } from './sanitizer.js';
import { SMTPClient } from './smtp-client.js';
import { AttachmentSecurity } from './attachment-security.js';
import { securityLog } from './security-logger.js';
import { createClient as createRedisClient } from 'redis';
import { RedisStore } from 'connect-redis';
import { AIService } from './ai-service.js';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = join(__dirname, '..', '..');

// ── .env.local laden ──────────────────────────────────────
const envPath = join(ROOT, '.env.local');
if (existsSync(envPath)) {
  dotenv.config({ path: envPath });
  console.log('[Config] .env.local geladen');
}

// ── Konfiguration laden ────────────────────────────────────
const config = JSON.parse(readFileSync(join(ROOT, 'config', 'default.json'), 'utf-8'));

const envConfig = {
  imapHost: process.env.IMAP_HOST || null,
  imapPort: parseInt(process.env.IMAP_PORT) || null,
  smtpHost: process.env.SMTP_HOST || null,
  smtpPort: parseInt(process.env.SMTP_PORT) || null,
};

// ── AI-Service (optional) ──────────────────────────────────
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || null;
let aiService = null;
if (OPENAI_API_KEY) {
  try {
    aiService = new AIService(OPENAI_API_KEY);
    console.log(`[AI] OpenAI aktiviert (Model: ${process.env.AI_MODEL || 'gpt-4o-mini'})`);
  } catch (e) {
    console.warn(`[AI] Initialisierung fehlgeschlagen: ${e.message}`);
  }
} else {
  console.log('[AI] Deaktiviert (OPENAI_API_KEY nicht gesetzt)');
}

const PORT = parseInt(process.env.PORT) || config.server.port || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const APP_DOMAIN = process.env.APP_DOMAIN || null;     // z.B. 'mail.example.com'
const BIND_ADDRESS = process.env.BIND_ADDRESS || (IS_PRODUCTION ? '127.0.0.1' : '0.0.0.0');

// ── Modus-Erkennung ────────────────────────────────────────
if (IS_PRODUCTION) {
  console.log('[Mode] PRODUCTION – Multi-User, HTTPS erwartet');
  if (!APP_DOMAIN) {
    console.warn('[WARN] APP_DOMAIN nicht gesetzt! Host-Header-Check wird unzuverlässig.');
  }
  if (!process.env.SESSION_SECRET) {
    console.warn('[WARN] SESSION_SECRET nicht gesetzt! Generiere zufälliges Secret (geht bei Restart verloren).');
  }
} else {
  console.log('[Mode] DEVELOPMENT – Single-User, localhost');
}

const app = express();

// ═══════════════════════════════════════════════════════════
//  MULTI-USER SESSION STORE
//  Jeder angemeldete User bekommt eine eigene IMAP/SMTP-
//  Verbindung. Sessions werden per Session-ID getrennt.
// ═══════════════════════════════════════════════════════════
const userConnections = new Map(); // sessionId → { imap, smtp, user, lastActivity }
const MAX_CONCURRENT_SESSIONS = parseInt(process.env.MAX_SESSIONS) || 50;
const SESSION_TIMEOUT = parseInt(process.env.SESSION_TIMEOUT) || 30 * 60 * 1000;

/**
 * Session-gebundene IMAP/SMTP-Verbindung abrufen
 */
function getConnection(sessionId) {
  const conn = userConnections.get(sessionId);
  if (!conn) return null;
  conn.lastActivity = Date.now();
  return conn;
}

/**
 * Neue Session-Verbindung registrieren
 */
function setConnection(sessionId, imap, smtp, user) {
  // Limit: Älteste Session räumen wenn voll
  if (userConnections.size >= MAX_CONCURRENT_SESSIONS) {
    let oldestId = null, oldestTime = Infinity;
    for (const [id, conn] of userConnections) {
      if (conn.lastActivity < oldestTime) {
        oldestTime = conn.lastActivity;
        oldestId = id;
      }
    }
    if (oldestId) {
      destroyConnection(oldestId);
      securityLog.info('SESSION_EVICTION', `Max Sessions (${MAX_CONCURRENT_SESSIONS}) erreicht, älteste entfernt`);
    }
  }
  userConnections.set(sessionId, { imap, smtp, user, lastActivity: Date.now() });
}

/**
 * Session-Verbindung sauber abbauen
 */
async function destroyConnection(sessionId) {
  const conn = userConnections.get(sessionId);
  if (!conn) return;
  try { if (conn.imap?.connected) await conn.imap.disconnect(); } catch {}
  try { if (conn.smtp) await conn.smtp.disconnect(); } catch {}
  userConnections.delete(sessionId);
}

// Inaktive Sessions alle 2 Minuten aufräumen
setInterval(async () => {
  const now = Date.now();
  for (const [id, conn] of userConnections) {
    if (now - conn.lastActivity > SESSION_TIMEOUT) {
      securityLog.sessionExpired(conn.user, 'periodic-sweep');
      await destroyConnection(id);
    }
  }
}, 120_000);

// ═══════════════════════════════════════════════════════════
//  ATTACHMENT-TOKEN-STORE (Session-gebunden)
//  Tokens sind an eine Session-ID gebunden.
//  User A kann keine Tokens von User B einlösen.
// ═══════════════════════════════════════════════════════════
const attachmentTokens = new Map();
const TOKEN_TTL = 10 * 60 * 1000;
const MAX_TOKENS = 10_000;

function createAttachmentToken(sessionId, folder, uid, index) {
  if (attachmentTokens.size >= MAX_TOKENS) {
    const oldest = attachmentTokens.keys().next().value;
    attachmentTokens.delete(oldest);
    securityLog.info('TOKEN_EVICTION', `Token-Store voll (${MAX_TOKENS}), ältestes entfernt`);
  }
  const token = crypto.randomBytes(32).toString('hex');
  attachmentTokens.set(token, {
    sessionId, folder, uid, index,
    expires: Date.now() + TOKEN_TTL,
  });
  return token;
}

function resolveAttachmentToken(token, requestSessionId) {
  if (!token || typeof token !== 'string' || token.length !== 64) return null;
  const entry = attachmentTokens.get(token);
  if (!entry) return null;
  attachmentTokens.delete(token);
  if (Date.now() > entry.expires) return null;
  // Session-Isolation: Token nur für die eigene Session gültig
  if (entry.sessionId !== requestSessionId) {
    securityLog.info('TOKEN_SESSION_MISMATCH', 'Attachment-Token von fremder Session');
    return null;
  }
  return entry;
}

setInterval(() => {
  const now = Date.now();
  let swept = 0;
  for (const [token, entry] of attachmentTokens) {
    if (now > entry.expires) { attachmentTokens.delete(token); swept++; }
  }
  if (swept > 0) {
    securityLog.info('TOKEN_SWEEP', `${swept} abgelaufene Tokens entfernt, ${attachmentTokens.size} verbleibend`);
  }
}, 60_000);

// ═══════════════════════════════════════════════════════════
//  SICHERHEITS-MIDDLEWARE
// ═══════════════════════════════════════════════════════════

// 0) Trust Proxy (für Hetzner/Nginx – echte Client-IP)
if (IS_PRODUCTION) {
  const trustLevel = parseInt(process.env.TRUST_PROXY) || 1;
  app.set('trust proxy', trustLevel);
  console.log(`[Proxy] trust proxy = ${trustLevel}`);
}

// 1) Host-Header-Check: DNS-Rebinding-Schutz
const ALLOWED_HOSTS = new Set([
  `localhost:${PORT}`,
  `127.0.0.1:${PORT}`,
  `[::1]:${PORT}`,
  'localhost',
  '127.0.0.1',
  '::1',
]);
// In Production: App-Domain erlauben
if (APP_DOMAIN) {
  ALLOWED_HOSTS.add(APP_DOMAIN);
  ALLOWED_HOSTS.add(`${APP_DOMAIN}:${PORT}`);
  ALLOWED_HOSTS.add(`${APP_DOMAIN}:443`);
}
// Extra Hosts (z.B. sslip.io für Coolify-Tests)
if (process.env.EXTRA_HOSTS) {
  process.env.EXTRA_HOSTS.split(',').forEach(h => ALLOWED_HOSTS.add(h.trim()));
}

app.use((req, res, next) => {
  const host = (req.headers.host || '').toLowerCase();
  if (!ALLOWED_HOSTS.has(host)) {
    securityLog.dnsRebinding(req.ip, host, req.path);
    return res.status(403).json({ error: 'Ungültiger Host-Header.' });
  }
  next();
});

// 1b) HTTP Basic Auth – vorgeschalteter Schutzlayer (optional)
//     Aktiviert wenn BASIC_AUTH_USER + BASIC_AUTH_PASS gesetzt sind.
//     Macht die gesamte App unsichtbar für unautorisierte Besucher.
const BASIC_AUTH_USER = process.env.BASIC_AUTH_USER;
const BASIC_AUTH_PASS = process.env.BASIC_AUTH_PASS;

if (BASIC_AUTH_USER && BASIC_AUTH_PASS) {
  app.use((req, res, next) => {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Basic ')) {
      res.setHeader('WWW-Authenticate', 'Basic realm="Mail Client"');
      return res.status(401).send('Authentifizierung erforderlich.');
    }
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf-8');
    const [user, ...passParts] = decoded.split(':');
    const pass = passParts.join(':'); // Passwort darf ":" enthalten
    const passBuffer = Buffer.from(pass);
    const expectedBuffer = Buffer.from(BASIC_AUTH_PASS);
    const passMatch = passBuffer.length === expectedBuffer.length &&
      crypto.timingSafeEqual(passBuffer, expectedBuffer);
    if (user === BASIC_AUTH_USER && passMatch) {
      return next();
    }
    securityLog.log('BASIC_AUTH_FAIL', { ip: req.ip, user });
    res.setHeader('WWW-Authenticate', 'Basic realm="Mail Client"');
    return res.status(401).send('Ungültige Zugangsdaten.');
  });
  console.log(`[BasicAuth] Vorgeschalteter Schutz aktiv (User: ${BASIC_AUTH_USER})`);
}

// 2) Helmet: Security-Header
//    In Production: CSP mit Nonce statt unsafe-inline
app.use((req, res, next) => {
  // Nonce pro Request generieren
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use((req, res, next) => {
  const nonce = res.locals.cspNonce;
  const styleSrc = IS_PRODUCTION
    ? ["'self'", `'nonce-${nonce}'`, "https://fonts.googleapis.com"]
    : ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"];

  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc,
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:"],
        frameSrc: ["'self'"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })(req, res, next);
});

// 2b) Permissions-Policy
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), ' +
    'magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), ' +
    'autoplay=(), encrypted-media=(), picture-in-picture=(), display-capture=()'
  );
  next();
});

// 3) Rate Limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: IS_PRODUCTION ? 5 : 10,    // Strenger in Produktion
  standardHeaders: true,
  handler: (req, res) => {
    securityLog.rateLimitHit(req.ip, req.path);
    res.status(429).json({ error: 'Zu viele Anmeldeversuche. Bitte 15 Minuten warten.' });
  },
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  handler: (req, res) => {
    securityLog.rateLimitHit(req.ip, req.path);
    res.status(429).json({ error: 'Zu viele Anfragen. Bitte kurz warten.' });
  },
});

const sendLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: IS_PRODUCTION ? 20 : 30,
  standardHeaders: true,
  handler: (req, res) => {
    securityLog.rateLimitHit(req.ip, req.path);
    res.status(429).json({ error: 'Sende-Limit erreicht. Bitte warten.' });
  },
});

app.use('/api/', apiLimiter);

// 4) Body-Grösse begrenzen
app.use(express.json({ limit: '1mb' }));

// 5) Sichere Session (mit optionalem Redis-Store)
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

let sessionStore = undefined; // undefined = MemoryStore (Dev-Fallback)
if (process.env.REDIS_URL) {
  try {
    const redisClient = createRedisClient({
      url: process.env.REDIS_URL,
      socket: { connectTimeout: 5000, reconnectStrategy: (retries) => retries > 3 ? false : 1000 },
    });
    redisClient.on('error', (err) => console.error('[Redis] Error:', err.message));

    // Timeout: Wenn Redis nach 5s nicht erreichbar ist → MemoryStore
    const connectPromise = redisClient.connect();
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Redis connect timeout (5s)')), 5000)
    );
    await Promise.race([connectPromise, timeoutPromise]);

    sessionStore = new RedisStore({ client: redisClient, prefix: 'mail:' });
    console.log(`[Redis] Session-Store verbunden (${process.env.REDIS_URL})`);
  } catch (err) {
    console.error('[Redis] Verbindung fehlgeschlagen:', err.message);
    console.warn('[Redis] Fallback auf MemoryStore');
  }
} else if (IS_PRODUCTION) {
  console.warn('[WARN] REDIS_URL nicht gesetzt – MemoryStore in Production (nicht empfohlen)');
}

app.use(session({
  store: sessionStore,
  name: 'mail.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: IS_PRODUCTION,
    maxAge: SESSION_TIMEOUT,
  },
}));

// 6) CORS: Nur eigener Origin erlaubt
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '');
  res.setHeader('Vary', 'Origin');
  next();
});

// 7) CSRF / Origin-Prüfung
const APP_SECRET = crypto.randomBytes(16).toString('hex');

function buildAllowedOrigins() {
  const origins = [
    `http://localhost:${PORT}`,
    `http://127.0.0.1:${PORT}`,
    `https://localhost:${PORT}`,
    `https://127.0.0.1:${PORT}`,
  ];
  if (APP_DOMAIN) {
    origins.push(`https://${APP_DOMAIN}`);
    origins.push(`http://${APP_DOMAIN}`);
  }
  return origins;
}
const ALLOWED_ORIGINS = buildAllowedOrigins();

app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const origin = req.headers.origin || '';
  const referer = req.headers.referer || '';

  const originOk = !origin || ALLOWED_ORIGINS.some(o => origin.startsWith(o));
  const refererOk = !referer || ALLOWED_ORIGINS.some(o => referer.startsWith(o));

  if (!originOk || !refererOk) {
    securityLog.csrfViolation(req.ip, origin || referer, req.path);
    return res.status(403).json({ error: 'Zugriff verweigert (CSRF-Schutz).' });
  }

  if (req.path !== '/api/connect') {
    const csrfToken = req.headers['x-csrf-token'] || '';
    const sessionToken = req.session?.csrfToken || '';
    if (!sessionToken || !timingSafeCompare(csrfToken, sessionToken)) {
      securityLog.csrfViolation(req.ip, 'invalid-token', req.path);
      return res.status(403).json({ error: 'Ungültiges CSRF-Token.' });
    }
  }

  next();
});

// 8) Session-Timeout: Auto-Logout
app.use((req, res, next) => {
  if (req.session?.lastActivity) {
    const elapsed = Date.now() - req.session.lastActivity;
    if (elapsed > SESSION_TIMEOUT) {
      const user = req.session.user;
      const sid = req.session.id;
      req.session.destroy(() => {});
      destroyConnection(sid);
      securityLog.sessionExpired(user, req.ip);
      return res.status(401).json({ error: 'Session abgelaufen. Bitte neu anmelden.' });
    }
  }
  if (req.session) req.session.lastActivity = Date.now();
  next();
});

// 9) Auth-Middleware
function requireAuth(req, res, next) {
  if (!req.session?.authenticated) {
    securityLog.unauthorizedAccess(req.ip, req.path, 'Keine aktive Session');
    return res.status(401).json({ error: 'Nicht angemeldet.' });
  }
  next();
}

// 10) Statische Dateien
app.use(express.static(join(ROOT, 'src', 'client')));

const parser = new MIMEParser();
const sanitizer = new HTMLSanitizer(config.security);
const attachSecurity = new AttachmentSecurity();

// ═══════════════════════════════════════════════════════════
//  INPUT-VALIDIERUNG
// ═══════════════════════════════════════════════════════════

function sanitizeString(str, maxLength = 500) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLength);
}

function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function validateHost(host) {
  if (!host || typeof host !== 'string') return false;
  return /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}[a-zA-Z0-9]$/.test(host);
}

function validatePort(port) {
  const p = parseInt(port);
  return Number.isInteger(p) && p > 0 && p <= 65535;
}

function validateFolder(folder) {
  if (!folder || typeof folder !== 'string') return false;
  if (folder.includes('..') || folder.includes('\0')) return false;
  return folder.length <= 200;
}

function validateUid(uid) {
  const u = parseInt(uid);
  return Number.isInteger(u) && u > 0;
}

// ── SSRF-Schutz ──────────────────────────────────────────
const PRIVATE_IP_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i,
  /^localhost$/i,
];

function isPrivateIP(ip) {
  return PRIVATE_IP_RANGES.some(p => p.test(ip));
}

async function isPrivateHost(host) {
  if (isPrivateIP(host)) return true;
  try {
    const { address } = await dnsLookup(host);
    if (isPrivateIP(address)) {
      securityLog.info('DNS_REBINDING_BLOCKED', `${host} → ${address} (privat)`);
      return true;
    }
  } catch {}
  return false;
}

function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function stripHeaderInjection(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[\r\n\x00]/g, '').trim();
}

// ── Threading: Messages nach Konversation gruppieren ───────
function buildThreads(messages) {
  // Map: messageId → message
  const byMsgId = new Map();
  for (const msg of messages) {
    if (msg.messageId) byMsgId.set(msg.messageId, msg);
  }

  // Jede Message ihrem Thread zuordnen
  const threadMap = new Map(); // threadId → [uids]
  const msgToThread = new Map(); // uid → threadId

  for (const msg of messages) {
    // Suche den Thread über inReplyTo
    let threadId = null;

    if (msg.inReplyTo) {
      const parent = byMsgId.get(msg.inReplyTo);
      if (parent && msgToThread.has(parent.uid)) {
        threadId = msgToThread.get(parent.uid);
      }
    }

    // Suche Thread über Subject-Match (Fallback: "Re: xxx" → "xxx")
    if (!threadId) {
      const baseSubject = (msg.subject || '')
        .replace(/^(Re|Fwd|Aw|Wg|Fw):\s*/gi, '')
        .trim()
        .toLowerCase();

      if (baseSubject) {
        for (const [tid, uids] of threadMap) {
          const firstMsg = messages.find(m => m.uid === uids[0]);
          if (firstMsg) {
            const firstBase = (firstMsg.subject || '')
              .replace(/^(Re|Fwd|Aw|Wg|Fw):\s*/gi, '')
              .trim()
              .toLowerCase();
            if (firstBase === baseSubject) {
              threadId = tid;
              break;
            }
          }
        }
      }
    }

    if (threadId) {
      threadMap.get(threadId).push(msg.uid);
      msgToThread.set(msg.uid, threadId);
    } else {
      // Neuer Thread
      const newThreadId = msg.messageId || `thread-${msg.uid}`;
      threadMap.set(newThreadId, [msg.uid]);
      msgToThread.set(msg.uid, newThreadId);
    }
  }

  // Threads als Array zurückgeben (neueste zuerst, nach neuestem Message im Thread)
  const threadList = [];
  for (const [threadId, uids] of threadMap) {
    const threadMsgs = uids.map(uid => messages.find(m => m.uid === uid)).filter(Boolean);
    // Sortiere innerhalb des Threads: älteste zuerst
    threadMsgs.sort((a, b) => new Date(a.date) - new Date(b.date));
    const newest = threadMsgs[threadMsgs.length - 1];
    threadList.push({
      id: threadId,
      subject: (newest.subject || '').replace(/^(Re|Fwd|Aw|Wg|Fw):\s*/gi, '').trim() || '(Kein Betreff)',
      count: threadMsgs.length,
      uids: threadMsgs.map(m => m.uid),
      newest: newest.date,
      from: newest.from,
      to: newest.to,
      hasUnread: threadMsgs.some(m => !m.seen),
      hasAttachments: threadMsgs.some(m => m.hasAttachments),
      flagged: threadMsgs.some(m => m.flagged),
      snippet: newest.snippet || '',
    });
  }

  // Sortiere Threads: neueste zuerst
  threadList.sort((a, b) => new Date(b.newest) - new Date(a.newest));
  return threadList;
}

// ── Middleware: Session-IMAP-Verbindung sicherstellen ─────
async function ensureConnection(req, res, next) {
  try {
    const conn = getConnection(req.session.id);
    if (!conn || !conn.imap?.connected) {
      return res.status(401).json({ error: 'Nicht verbunden. Bitte neu anmelden.' });
    }
    req.imap = conn.imap;
    req.smtp = conn.smtp;
    req.mailUser = conn.user;
    next();
  } catch (err) {
    res.status(503).json({
      error: 'IMAP-Verbindung fehlgeschlagen',
      details: err.message,
    });
  }
}

// ═══════════════════════════════════════════════════════════
//  API-ENDPUNKTE
// ═══════════════════════════════════════════════════════════

// ── GET /api/config ────────────────────────────────────────
app.get('/api/config', (req, res) => {
  res.json({
    hasImapConfig: !!envConfig.imapHost,
    hasSmtpConfig: !!envConfig.smtpHost,
    appSecret: APP_SECRET,
    production: IS_PRODUCTION,
  });
});

// ── GET /api/csrf ──────────────────────────────────────────
app.get('/api/csrf', (req, res) => {
  if (req.session?.csrfToken) {
    return res.json({ csrfToken: req.session.csrfToken });
  }
  res.status(401).json({ error: 'Keine aktive Session.' });
});

// ── GET /api/status ───────────────────────────────────────
// Prüft ob Session gültig ist und stellt Verbindung automatisch wieder her
app.get('/api/status', async (req, res) => {
  if (!req.session?.authenticated || !req.session.user) {
    return res.status(401).json({ error: 'Keine aktive Session.' });
  }

  const conn = getConnection(req.session.id);
  if (conn?.imap?.connected) {
    // Verbindung existiert noch
    return res.json({
      success: true,
      user: req.session.user,
      smtpReady: !!conn.smtp,
      csrfToken: req.session.csrfToken,
    });
  }

  // Verbindung verloren → Reconnect mit gespeicherten Params
  const params = req.session.connectParams;
  if (!params) {
    req.session.authenticated = false;
    return res.status(401).json({ error: 'Session abgelaufen, erneut anmelden.' });
  }

  try {
    const imapConfig = {
      host: params.imapHost,
      port: params.imapPort,
      secure: true,
      auth: params.authObj,
      tls: {
        rejectUnauthorized: process.env.TLS_REJECT_UNAUTHORIZED !== 'false',
        servername: params.imapHost,
        minVersion: 'TLSv1.2',
      },
    };

    const imapClient = new IMAPClient(imapConfig);
    await imapClient.connect();

    let smtpClient = null;
    try {
      smtpClient = new SMTPClient();
      const smtpSecure = parseInt(params.smtpPort) === 465;
      await smtpClient.connect({
        host: params.smtpHost,
        port: params.smtpPort,
        secure: smtpSecure,
        auth: params.authObj,
        tls: {
          rejectUnauthorized: process.env.TLS_REJECT_UNAUTHORIZED !== 'false',
          minVersion: 'TLSv1.2',
        },
      });
    } catch {
      smtpClient = null;
    }

    setConnection(req.session.id, imapClient, smtpClient, req.session.user);
    req.session.lastActivity = Date.now();
    console.log(`[Reconnect] OK – Session ${req.session.id.slice(0,8)}… für ${req.session.user}`);

    return res.json({
      success: true,
      user: req.session.user,
      smtpReady: !!smtpClient,
      csrfToken: req.session.csrfToken,
    });
  } catch (err) {
    console.warn(`[Reconnect] Fehlgeschlagen für ${req.session.user}: ${err.message}`);
    req.session.authenticated = false;
    return res.status(401).json({ error: 'Reconnect fehlgeschlagen, erneut anmelden.' });
  }
});

// ── POST /api/connect ──────────────────────────────────────
app.post('/api/connect', loginLimiter, async (req, res) => {
  try {
    const { user, pass, accessToken, host, port, smtpHost, smtpPort } = req.body;

    if (!user || !validateEmail(user)) {
      return res.status(400).json({ error: 'Ungültige E-Mail-Adresse.' });
    }
    if (!pass && !accessToken) {
      return res.status(400).json({ error: 'Passwort oder Access-Token erforderlich.' });
    }
    if (host && !validateHost(host)) {
      return res.status(400).json({ error: 'Ungültiger Hostname.' });
    }
    if (port && !validatePort(port)) {
      return res.status(400).json({ error: 'Ungültiger Port.' });
    }

    // Alte Verbindung dieser Session aufräumen
    if (req.session?.id) await destroyConnection(req.session.id);

    const authObj = accessToken
      ? { user: sanitizeString(user, 254), accessToken: sanitizeString(accessToken, 2000) }
      : { user: sanitizeString(user, 254), pass };

    const finalImapHost = envConfig.imapHost || host || config.imap.host;
    const finalImapPort = envConfig.imapPort || port || config.imap.port;

    if (await isPrivateHost(finalImapHost)) {
      securityLog.ssrfAttempt(req.ip, finalImapHost);
      return res.status(400).json({ error: 'Verbindung zu internen Adressen nicht erlaubt.' });
    }

    const imapConfig = {
      host: finalImapHost,
      port: finalImapPort,
      secure: true,
      auth: authObj,
      tls: {
        rejectUnauthorized: process.env.TLS_REJECT_UNAUTHORIZED !== 'false',
        servername: finalImapHost,
        minVersion: 'TLSv1.2',
      },
    };

    console.log(`[IMAP] Verbinde mit ${finalImapHost}:${finalImapPort} als ${user}...`);
    const imapClient = new IMAPClient(imapConfig);
    await imapClient.connect();

    // SMTP
    const finalSmtpHost = envConfig.smtpHost || smtpHost || finalImapHost.replace(/^imap\./, 'smtp.');
    const finalSmtpPort = envConfig.smtpPort || smtpPort || 465;

    if (await isPrivateHost(finalSmtpHost)) {
      securityLog.ssrfAttempt(req.ip, finalSmtpHost);
      return res.status(400).json({ error: 'Verbindung zu internen Adressen nicht erlaubt.' });
    }

    let smtpClient = null;
    try {
      console.log(`[SMTP] Verbinde mit ${finalSmtpHost}:${finalSmtpPort}...`);
      smtpClient = new SMTPClient();
      // Port 465 = implicit TLS (secure:true), Port 587 = STARTTLS (secure:false)
      const smtpSecure = parseInt(finalSmtpPort) === 465;
      const smtpTimeout = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('SMTP Timeout (10s)')), 10000)
      );
      await Promise.race([
        smtpClient.connect({
          host: finalSmtpHost,
          port: finalSmtpPort,
          secure: smtpSecure,
          auth: authObj,
          tls: {
            rejectUnauthorized: process.env.TLS_REJECT_UNAUTHORIZED !== 'false',
            minVersion: 'TLSv1.2',
          },
        }),
        smtpTimeout,
      ]);
      console.log(`[SMTP] Verbunden mit ${finalSmtpHost}:${finalSmtpPort} (${smtpSecure ? 'TLS' : 'STARTTLS'})`);
    } catch (smtpErr) {
      console.warn(`[SMTP] Verbindung fehlgeschlagen: ${smtpErr.message}`);
      smtpClient = null;
    }

    // Session Setup (ohne regenerate – MemoryStore-kompatibel)
    req.session.authenticated = true;
    req.session.user = user;
    req.session.lastActivity = Date.now();
    req.session.csrfToken = crypto.randomBytes(16).toString('hex');

    // Reconnect-Daten in Session speichern (serverseitig, nicht im Cookie)
    req.session.connectParams = {
      authObj,
      imapHost: finalImapHost,
      imapPort: finalImapPort,
      smtpHost: finalSmtpHost,
      smtpPort: finalSmtpPort,
    };

    // Verbindung an Session binden
    setConnection(req.session.id, imapClient, smtpClient, user);

    securityLog.loginAttempt(user, req.ip, true);
    console.log(`[Login] OK – Session ${req.session.id.slice(0,8)}… für ${user}`);

    return res.json({
      success: true,
      message: `Verbunden mit ${imapConfig.host}`,
      smtpReady: !!smtpClient,
      user,
      csrfToken: req.session.csrfToken,
    });
  } catch (err) {
    const user = req.body?.user || 'unknown';
    securityLog.loginAttempt(user, req.ip, false, err.message);
    res.status(401).json({ error: 'Anmeldung fehlgeschlagen', details: err.message });
  }
});

// ── GET /api/folders ───────────────────────────────────────
app.get('/api/folders', requireAuth, ensureConnection, async (req, res) => {
  try {
    const folders = await req.imap.listFolders();
    // Unread-Counts für alle Ordner laden
    try {
      const counts = await req.imap.getUnreadCounts(folders);
      for (const folder of folders) {
        folder.unseen = counts[folder.path] || 0;
      }
    } catch { /* Counts optional */ }
    res.json({ folders });
  } catch (err) {
    res.status(500).json({ error: 'Ordner konnten nicht geladen werden', details: err.message });
  }
});

// ── GET /api/messages/:folder ──────────────────────────────
app.get('/api/messages/:folder', requireAuth, ensureConnection, async (req, res) => {
  try {
    const folder = decodeURIComponent(req.params.folder);
    if (!validateFolder(folder)) {
      return res.status(400).json({ error: 'Ungültiger Ordnername.' });
    }
    const count = Math.min(Math.max(parseInt(req.query.count) || config.defaults.fetchCount, 1), 200);
    const since = req.query.since ? sanitizeString(req.query.since, 30) : null;

    const messages = await req.imap.fetchHeaders(folder, { count, since });

    // Threading: Messages nach Konversation gruppieren
    const threads = buildThreads(messages);
    res.json({ folder, total: messages.length, messages, threads });
  } catch (err) {
    res.status(500).json({ error: 'Nachrichten konnten nicht geladen werden', details: err.message });
  }
});

// ── GET /api/message/:folder/:uid ──────────────────────────
app.get('/api/message/:folder/:uid', requireAuth, ensureConnection, async (req, res) => {
  try {
    const folder = decodeURIComponent(req.params.folder);
    const uid = parseInt(req.params.uid);
    if (!validateFolder(folder) || !validateUid(uid)) {
      return res.status(400).json({ error: 'Ungültige Parameter.' });
    }
    const allowImages = req.query.allowImages === 'true';

    const rawBuffer = await req.imap.fetchBody(folder, uid);
    const parsed = await parser.parse(rawBuffer);
    const sanitized = sanitizer.sanitize(parsed.html, { allowExternalImages: allowImages });

    const securityWarnings = [...(sanitized.warnings || [])];
    for (const addr of [...(parsed.from || []), ...(parsed.replyTo || [])]) {
      const check = sanitizer.checkAddress(addr?.address);
      if (!check.safe) securityWarnings.push(check.warning);
    }

    await req.imap.setFlags(folder, uid, ['\\Seen'], 'add');

    res.json({
      ...parsed,
      html: sanitized.html,
      blockedImages: sanitized.blockedImages,
      securityWarnings,
      rawHtml: null,
      attachments: parsed.attachments.map((att, i) => {
        const analysis = attachSecurity.analyze(att.filename, att.contentType);
        if (analysis.risk === 'dangerous') {
          securityLog.dangerousAttachment(req.mailUser, att.filename, analysis.warnings.join('; '));
        }
        return {
          filename: analysis.sanitizedFilename,
          contentType: att.contentType,
          contentDisposition: att.contentDisposition,
          contentId: att.contentId,
          size: att.size,
          downloadToken: analysis.blocked ? null : createAttachmentToken(req.session.id, folder, uid, i),
          security: {
            risk: analysis.risk,
            warnings: analysis.warnings,
            blocked: analysis.blocked,
          },
        };
      }),
    });
  } catch (err) {
    res.status(500).json({ error: 'Nachricht konnte nicht geladen werden', details: err.message });
  }
});

// ── POST /api/thread-sent ─────────────────────────────────
// Lädt gesendete Antworten die zum Thread gehören (via messageIds)
app.post('/api/thread-sent', requireAuth, ensureConnection, async (req, res) => {
  try {
    const { messageIds } = req.body;
    if (!Array.isArray(messageIds) || messageIds.length === 0) {
      return res.json({ messages: [] });
    }

    // Max 50 messageIds um Missbrauch zu vermeiden
    const ids = messageIds.slice(0, 50).filter(id => typeof id === 'string' && id.length < 500);
    if (ids.length === 0) return res.json({ messages: [] });

    const sentMessages = await req.imap.fetchSentThreadMessages(ids);
    res.json({ messages: sentMessages });
  } catch (err) {
    res.status(500).json({ error: 'Thread-Nachrichten konnten nicht geladen werden', details: err.message });
  }
});

// ── GET /api/attachment/:token ─────────────────────────────
app.get('/api/attachment/:token', requireAuth, ensureConnection, async (req, res) => {
  try {
    const entry = resolveAttachmentToken(req.params.token, req.session.id);
    if (!entry) {
      securityLog.invalidToken(req.ip, req.path);
      return res.status(403).json({ error: 'Ungültiger oder abgelaufener Download-Link.' });
    }

    const { folder, uid, index } = entry;
    const rawBuffer = await req.imap.fetchBody(folder, uid);
    const parsed = await parser.parse(rawBuffer);

    if (index >= parsed.attachments.length) {
      return res.status(404).json({ error: 'Anhang nicht gefunden' });
    }

    const att = parsed.attachments[index];
    const buffer = Buffer.from(att.content, 'base64');

    res.setHeader('Content-Type', att.contentType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(att.filename)}"`);
    res.setHeader('Content-Length', buffer.length);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.end(buffer);
  } catch (err) {
    res.status(500).json({ error: 'Anhang konnte nicht geladen werden', details: err.message });
  }
});

// ── POST /api/flags/:folder/:uid ───────────────────────────
app.post('/api/flags/:folder/:uid', requireAuth, ensureConnection, async (req, res) => {
  try {
    const folder = decodeURIComponent(req.params.folder);
    const uid = parseInt(req.params.uid);
    if (!validateFolder(folder) || !validateUid(uid)) {
      return res.status(400).json({ error: 'Ungültige Parameter.' });
    }

    const { flags, mode } = req.body;
    const allowedFlags = ['\\Seen', '\\Flagged', '\\Deleted', '\\Draft', '\\Answered'];
    const allowedModes = ['add', 'remove', 'set'];
    if (!Array.isArray(flags) || !flags.every(f => allowedFlags.includes(f))) {
      return res.status(400).json({ error: 'Ungültige Flags.' });
    }
    if (mode && !allowedModes.includes(mode)) {
      return res.status(400).json({ error: 'Ungültiger Modus.' });
    }

    await req.imap.setFlags(folder, uid, flags, mode || 'add');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Flags konnten nicht gesetzt werden', details: err.message });
  }
});

// ── GET /api/search/:folder?q=... ──────────────────────────
app.get('/api/search/:folder', requireAuth, ensureConnection, async (req, res) => {
  try {
    const folder = decodeURIComponent(req.params.folder);
    const query = sanitizeString(req.query.q || '', 200);
    if (!validateFolder(folder)) {
      return res.status(400).json({ error: 'Ungültiger Ordnername.' });
    }
    if (!query || query.length < 2) {
      return res.status(400).json({ error: 'Suchbegriff muss mindestens 2 Zeichen lang sein.' });
    }
    const count = Math.min(Math.max(parseInt(req.query.count) || 50, 1), 200);
    const messages = await req.imap.search(folder, query, { count });
    res.json({ folder, query, total: messages.length, messages });
  } catch (err) {
    res.status(500).json({ error: 'Suche fehlgeschlagen', details: err.message });
  }
});

// ── POST /api/delete-bulk/:folder ──────────────────────────
app.post('/api/delete-bulk/:folder', requireAuth, ensureConnection, async (req, res) => {
  try {
    const folder = decodeURIComponent(req.params.folder);
    const { uids } = req.body;
    if (!validateFolder(folder)) {
      return res.status(400).json({ error: 'Ungültiger Ordnername.' });
    }
    if (!Array.isArray(uids) || uids.length === 0 || uids.length > 100) {
      return res.status(400).json({ error: 'Ungültige UIDs (1-100 erlaubt).' });
    }
    const validUids = uids.map(u => parseInt(u)).filter(u => u > 0 && u < 2 ** 32);
    if (validUids.length === 0) {
      return res.status(400).json({ error: 'Keine gültigen UIDs.' });
    }
    const result = await req.imap.deleteMessages(folder, validUids);
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ error: 'Bulk-Löschen fehlgeschlagen', details: err.message });
  }
});

// ── DELETE /api/message/:folder/:uid ───────────────────────
app.delete('/api/message/:folder/:uid', requireAuth, ensureConnection, async (req, res) => {
  try {
    const folder = decodeURIComponent(req.params.folder);
    const uid = parseInt(req.params.uid);
    if (!validateFolder(folder) || !validateUid(uid)) {
      return res.status(400).json({ error: 'Ungültige Parameter.' });
    }

    const result = await req.imap.deleteMessage(folder, uid);
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ error: 'Löschen fehlgeschlagen', details: err.message });
  }
});

// ── POST /api/send ─────────────────────────────────────────
app.post('/api/send', requireAuth, sendLimiter, async (req, res) => {
  try {
    const conn = getConnection(req.session.id);
    if (!conn?.smtp) {
      return res.status(503).json({ error: 'SMTP nicht verbunden. Senden nicht möglich.' });
    }

    const { to, cc, bcc, subject, text, html, inReplyTo, references } = req.body;

    if (!to || !to.trim()) {
      return res.status(400).json({ error: 'Empfänger (An) ist erforderlich.' });
    }

    const allAddresses = [to, cc, bcc].filter(Boolean).join(',');
    const addressList = allAddresses.split(',').map(a => a.trim()).filter(Boolean);
    for (const addr of addressList) {
      const match = addr.match(/<([^>]+)>/) || [null, addr];
      if (!validateEmail(match[1])) {
        return res.status(400).json({ error: `Ungültige E-Mail-Adresse: ${sanitizeString(addr, 50)}` });
      }
    }

    const safeTo = stripHeaderInjection(sanitizeString(to, 2000));
    const safeCc = cc ? stripHeaderInjection(sanitizeString(cc, 2000)) : undefined;
    const safeBcc = bcc ? stripHeaderInjection(sanitizeString(bcc, 2000)) : undefined;
    const safeSubject = stripHeaderInjection(sanitizeString(subject, 500));
    const safeText = sanitizeString(text, 100000);
    const safeInReplyTo = inReplyTo ? stripHeaderInjection(sanitizeString(inReplyTo, 500)) : undefined;
    const safeReferences = references ? stripHeaderInjection(sanitizeString(references, 2000)) : undefined;

    const result = await conn.smtp.send({
      from: conn.user,
      to: safeTo,
      cc: safeCc,
      bcc: safeBcc,
      subject: safeSubject,
      text: safeText,
      html: undefined,
      inReplyTo: safeInReplyTo,
      references: safeReferences,
    });

    // Gesendete Nachricht im Sent-Ordner speichern (best-effort)
    if (result.rawMessage && conn.imap) {
      try {
        await conn.imap.appendToSent(result.rawMessage);
      } catch (err) {
        console.warn('[SEND] Sent-Ordner speichern fehlgeschlagen:', err.message);
      }
    }

    res.json({ success: true, messageId: result.messageId, accepted: result.accepted, rejected: result.rejected });
  } catch (err) {
    res.status(500).json({ error: 'Senden fehlgeschlagen', details: err.message });
  }
});

// ── POST /api/save-draft ───────────────────────────────────
app.post('/api/save-draft', requireAuth, ensureConnection, async (req, res) => {
  try {
    const { to, cc, bcc, subject, text, inReplyTo, references, draftUid, draftFolder } = req.body;
    const conn = getConnection(req.session.id);

    // Raw RFC 2822 Message bauen (ohne zu senden)
    const mailOptions = {
      from: conn.user,
      to: to ? stripHeaderInjection(sanitizeString(to, 2000)) : undefined,
      cc: cc ? stripHeaderInjection(sanitizeString(cc, 2000)) : undefined,
      bcc: bcc ? stripHeaderInjection(sanitizeString(bcc, 2000)) : undefined,
      subject: subject ? stripHeaderInjection(sanitizeString(subject, 500)) : '(Kein Betreff)',
      text: sanitizeString(text || '', 100000),
      inReplyTo: inReplyTo ? stripHeaderInjection(sanitizeString(inReplyTo, 500)) : undefined,
      references: references ? stripHeaderInjection(sanitizeString(references, 2000)) : undefined,
    };

    const composer = new MailComposer(mailOptions);
    const rawMessage = await composer.compile().build();

    // Alten Draft löschen (falls vorhanden)
    if (draftUid && draftFolder) {
      try {
        await conn.imap.deleteDraft(draftFolder, parseInt(draftUid));
      } catch (err) {
        console.warn('[Draft] Alter Entwurf konnte nicht gelöscht werden:', err.message);
      }
    }

    // Neuen Draft speichern
    const result = await conn.imap.appendToDrafts(rawMessage);
    if (!result) {
      return res.status(500).json({ error: 'Kein Drafts-Ordner gefunden.' });
    }

    res.json({ success: true, draftUid: result.uid, draftFolder: result.folder });
  } catch (err) {
    res.status(500).json({ error: 'Entwurf speichern fehlgeschlagen', details: err.message });
  }
});

// ── POST /api/ai/generate ──────────────────────────────────
app.post('/api/ai/generate', requireAuth, async (req, res) => {
  if (!aiService) {
    return res.status(503).json({ error: 'AI-Funktion nicht verfügbar (OPENAI_API_KEY nicht konfiguriert).' });
  }
  try {
    const { instructions, originalFrom, originalSubject, originalBody, mode } = req.body;

    if (!instructions || !instructions.trim() || instructions.trim().length < 3) {
      return res.status(400).json({ error: 'Bitte Anweisungen eingeben (mind. 3 Zeichen).' });
    }

    const safeInstructions = sanitizeString(instructions, 2000);
    const safeFrom = sanitizeString(originalFrom || '', 200);
    const safeSubject = sanitizeString(originalSubject || '', 500);
    const safeBody = sanitizeString(originalBody || '', 5000);

    // Username aus E-Mail extrahieren für Kontext
    const userName = req.session.user?.split('@')[0] || '';

    let generatedText;
    if (mode === 'new') {
      generatedText = await aiService.generateNew({
        instructions: safeInstructions,
        recipient: safeFrom,
        userName,
      });
    } else {
      generatedText = await aiService.generateReply({
        originalFrom: safeFrom,
        originalSubject: safeSubject,
        originalBody: safeBody,
        instructions: safeInstructions,
        userName,
      });
    }

    res.json({ success: true, text: generatedText });
  } catch (err) {
    console.error(`[AI] Fehler: ${err.message}`);
    res.status(500).json({ error: 'AI-Generierung fehlgeschlagen', details: err.message });
  }
});

// ── GET /api/ai/status ─────────────────────────────────────
app.get('/api/ai/status', requireAuth, (req, res) => {
  res.json({ available: !!aiService, model: aiService?.model || null });
});

// ── POST /api/reply/:folder/:uid ───────────────────────────
app.post('/api/reply/:folder/:uid', requireAuth, ensureConnection, async (req, res) => {
  try {
    const conn = getConnection(req.session.id);
    if (!conn?.smtp) {
      return res.status(503).json({ error: 'SMTP nicht verbunden.' });
    }

    const folder = decodeURIComponent(req.params.folder);
    const uid = parseInt(req.params.uid);
    if (!validateFolder(folder) || !validateUid(uid)) {
      return res.status(400).json({ error: 'Ungültige Parameter.' });
    }
    const { replyAll = false } = req.body;

    const rawBuffer = await req.imap.fetchBody(folder, uid);
    const parsed = await parser.parse(rawBuffer);

    const reply = conn.smtp.buildReply(parsed, {
      replyAll,
      fromAddress: conn.user,
    });

    res.json({ from: conn.user, ...reply });
  } catch (err) {
    res.status(500).json({ error: 'Antwort konnte nicht vorbereitet werden', details: err.message });
  }
});

// ── POST /api/forward/:folder/:uid ─────────────────────────
app.post('/api/forward/:folder/:uid', requireAuth, ensureConnection, async (req, res) => {
  try {
    const conn = getConnection(req.session.id);
    if (!conn?.smtp) {
      return res.status(503).json({ error: 'SMTP nicht verbunden.' });
    }

    const folder = decodeURIComponent(req.params.folder);
    const uid = parseInt(req.params.uid);
    if (!validateFolder(folder) || !validateUid(uid)) {
      return res.status(400).json({ error: 'Ungültige Parameter.' });
    }

    const rawBuffer = await req.imap.fetchBody(folder, uid);
    const parsed = await parser.parse(rawBuffer);
    const forward = conn.smtp.buildForward(parsed);

    res.json({ from: conn.user, ...forward });
  } catch (err) {
    res.status(500).json({ error: 'Weiterleitung konnte nicht vorbereitet werden', details: err.message });
  }
});

// ── POST /api/disconnect ───────────────────────────────────
app.post('/api/disconnect', async (req, res) => {
  try {
    const user = req.session?.user;
    const sid = req.session?.id;

    if (sid) await destroyConnection(sid);

    if (req.session) {
      req.session.destroy(() => {});
    }
    res.clearCookie('mail.sid');

    securityLog.logout(user, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Fallback: SPA ──────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(join(ROOT, 'src', 'client', 'index.html'));
});

// ── Globaler Error-Handler ─────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Server] Unbehandelter Fehler:', err.message);
  res.status(500).json({ error: 'Interner Serverfehler' });
});

// ── Server starten ─────────────────────────────────────────
app.listen(PORT, BIND_ADDRESS, () => {
  console.log(`
  ╔══════════════════════════════════════════════════════════╗
  ║  IMAP Mail Client – Port ${PORT}                            ║
  ║  ${IS_PRODUCTION ? `https://${APP_DOMAIN || 'APP_DOMAIN nicht gesetzt'}` : `http://localhost:${PORT}`}${' '.repeat(Math.max(0, 39 - (IS_PRODUCTION ? (APP_DOMAIN || '').length + 8 : 16 + String(PORT).length)))}║
  ║  Modus: ${IS_PRODUCTION ? 'PRODUCTION (Multi-User)' : 'DEVELOPMENT (Single-User)'}${IS_PRODUCTION ? '   ' : '  '}║
  ║  Max Sessions: ${MAX_CONCURRENT_SESSIONS}${' '.repeat(Math.max(0, 40 - String(MAX_CONCURRENT_SESSIONS).length))}║
  ╚══════════════════════════════════════════════════════════╝
  `);
});

// ═══════════════════════════════════════════════════════════
//  SECURE SHUTDOWN
// ═══════════════════════════════════════════════════════════
async function secureShutdown(signal) {
  console.log(`\n[Server] ${signal} – sicheres Herunterfahren...`);
  securityLog.info('SHUTDOWN', `${signal} – Secure Shutdown, ${userConnections.size} aktive Sessions`);

  // 1. Attachment-Tokens löschen
  attachmentTokens.clear();

  // 2. Alle User-Verbindungen sauber trennen
  for (const [id] of userConnections) {
    await destroyConnection(id);
  }

  console.log('[Server] Shutdown abgeschlossen.');
  process.exit(0);
}

process.on('SIGINT', () => secureShutdown('SIGINT'));
process.on('SIGTERM', () => secureShutdown('SIGTERM'));

process.on('uncaughtException', (err) => {
  securityLog.info('UNCAUGHT_EXCEPTION', err.message);
  console.error('[Server] Unerwarteter Fehler:', err.message);
});

process.on('unhandledRejection', (reason) => {
  securityLog.info('UNHANDLED_REJECTION', String(reason));
  console.error('[Server] Unbehandeltes Promise:', reason);
});
