/**
 * ╔══════════════════════════════════════════════════════════╗
 *  SECURITY LOGGER
 *  Strukturierte Sicherheits-Logs mit Redaction,
 *  Retention-Policy und Audit-Trail
 * ╚══════════════════════════════════════════════════════════╝
 */

import { appendFileSync, existsSync, mkdirSync, readdirSync, unlinkSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LOG_DIR = join(__dirname, '..', '..', 'logs');
const LOG_RETENTION_DAYS = 30;

// Log-Verzeichnis erstellen
if (!existsSync(LOG_DIR)) mkdirSync(LOG_DIR, { recursive: true });

// ── Sensitive Daten redagieren ────────────────────────────
const REDACT_KEYS = ['pass', 'password', 'accessToken', 'token', 'secret', 'authorization', 'cookie'];

function redact(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const clean = {};
  for (const [key, value] of Object.entries(obj)) {
    if (REDACT_KEYS.some(k => key.toLowerCase().includes(k))) {
      clean[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      clean[key] = redact(value);
    } else {
      clean[key] = value;
    }
  }
  return clean;
}

function redactEmail(email) {
  if (!email || typeof email !== 'string') return email;
  const [local, domain] = email.split('@');
  if (!domain) return email;
  const masked = local.length > 2
    ? local[0] + '*'.repeat(local.length - 2) + local[local.length - 1]
    : '**';
  return `${masked}@${domain}`;
}

// ── Log-Eintrag schreiben ─────────────────────────────────
function writeLog(entry) {
  const date = new Date().toISOString().split('T')[0];
  const logFile = join(LOG_DIR, `security-${date}.log`);
  const line = JSON.stringify(entry) + '\n';

  // Console (ohne sensitive Daten)
  const level = entry.level || 'INFO';
  const prefix = {
    WARN: '\x1b[33m[SECURITY:WARN]\x1b[0m',
    ERROR: '\x1b[31m[SECURITY:ERROR]\x1b[0m',
    ALERT: '\x1b[31m\x1b[1m[SECURITY:ALERT]\x1b[0m',
    INFO: '\x1b[36m[SECURITY:INFO]\x1b[0m',
  }[level] || '[SECURITY]';

  console.log(`${prefix} ${entry.event} – ${entry.detail || ''}`);

  // Datei
  try {
    appendFileSync(logFile, line);
  } catch (err) {
    console.error('[SecurityLogger] Schreibfehler:', err.message);
  }
}

// ── Retention: Alte Logs löschen ──────────────────────────
function cleanOldLogs() {
  try {
    const files = readdirSync(LOG_DIR).filter(f => f.startsWith('security-'));
    const cutoff = Date.now() - LOG_RETENTION_DAYS * 86400000;
    for (const file of files) {
      const filePath = join(LOG_DIR, file);
      const stat = statSync(filePath);
      if (stat.mtimeMs < cutoff) {
        unlinkSync(filePath);
        console.log(`[SecurityLogger] Altes Log gelöscht: ${file}`);
      }
    }
  } catch { /* ignore */ }
}

// Beim Start und dann täglich aufräumen
cleanOldLogs();
setInterval(cleanOldLogs, 86400000);

// ═══════════════════════════════════════════════════════════
//  ÖFFENTLICHE API
// ═══════════════════════════════════════════════════════════

export const securityLog = {
  // ── Login-Events ────────────────────────────────────────
  loginAttempt(user, ip, success, detail = '') {
    writeLog({
      timestamp: new Date().toISOString(),
      level: success ? 'INFO' : 'WARN',
      event: success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED',
      user: redactEmail(user),
      ip,
      detail,
    });
  },

  logout(user, ip) {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'INFO',
      event: 'LOGOUT',
      user: redactEmail(user),
      ip,
    });
  },

  // ── Session-Events ──────────────────────────────────────
  sessionExpired(user, ip) {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'INFO',
      event: 'SESSION_EXPIRED',
      user: redactEmail(user),
      ip,
    });
  },

  // ── Zugriffsverletzungen ────────────────────────────────
  unauthorizedAccess(ip, path, reason) {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'WARN',
      event: 'UNAUTHORIZED_ACCESS',
      ip,
      path,
      detail: reason,
    });
  },

  dnsRebinding(ip, hostHeader, path) {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'ALERT',
      event: 'DNS_REBINDING_ATTEMPT',
      ip,
      detail: `Ungültiger Host-Header: "${hostHeader}" auf ${path}`,
    });
  },

  csrfViolation(ip, origin, path) {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'ALERT',
      event: 'CSRF_VIOLATION',
      ip,
      origin,
      path,
      detail: 'Request von fremdem Origin blockiert',
    });
  },

  // ── Rate Limit ──────────────────────────────────────────
  rateLimitHit(ip, path) {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'WARN',
      event: 'RATE_LIMIT_HIT',
      ip,
      path,
    });
  },

  // ── Token-Missbrauch ────────────────────────────────────
  invalidToken(ip, path) {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'WARN',
      event: 'INVALID_ATTACHMENT_TOKEN',
      ip,
      path,
      detail: 'Ungültiger oder abgelaufener Download-Token',
    });
  },

  // ── Verdächtige Hosts ───────────────────────────────────
  ssrfAttempt(ip, targetHost) {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'ALERT',
      event: 'SSRF_ATTEMPT',
      ip,
      detail: `Versuch, interne Adresse zu kontaktieren: ${targetHost}`,
    });
  },

  // ── Gefährlicher Anhang ─────────────────────────────────
  dangerousAttachment(user, filename, reason) {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'WARN',
      event: 'DANGEROUS_ATTACHMENT',
      user: redactEmail(user),
      detail: `${filename}: ${reason}`,
    });
  },

  // ── Sicherheitswarnungen (Punycode etc.) ────────────────
  securityWarning(user, warnings) {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'WARN',
      event: 'SECURITY_WARNING',
      user: redactEmail(user),
      detail: warnings.join('; '),
    });
  },

  // ── Generisches Event ───────────────────────────────────
  info(event, detail = '') {
    writeLog({
      timestamp: new Date().toISOString(),
      level: 'INFO',
      event,
      detail,
    });
  },
};

// .gitignore um logs/ erweitern
export const LOG_DIRECTORY = LOG_DIR;
