/**
 * ╔══════════════════════════════════════════════════════════╗
 *  AUTOMATISIERTE SECURITY-TESTS
 *  Ausführen: npm run security:test
 *  oder:     node --input-type=module < tests/security-test.js
 * ╚══════════════════════════════════════════════════════════╝
 */

import { HTMLSanitizer } from '../src/server/sanitizer.js';
import { AttachmentSecurity } from '../src/server/attachment-security.js';
import crypto from 'crypto';

let passed = 0;
let failed = 0;
const errors = [];

function assert(condition, name) {
  if (condition) {
    passed++;
    console.log(`  ✅ ${name}`);
  } else {
    failed++;
    errors.push(name);
    console.log(`  ❌ ${name}`);
  }
}

function section(title) {
  console.log(`\n━━━ ${title} ━━━`);
}

// ═══════════════════════════════════════════════════════════
//  1. HTML SANITIZATION
// ═══════════════════════════════════════════════════════════
section('HTML Sanitization');
const s = new HTMLSanitizer({ blockExternalImages: true });

// XSS
assert(!s.sanitize('<script>alert(1)</script>').html.includes('script'), 'Script-Tags entfernt');
assert(!s.sanitize('<img src=x onerror=alert(1)>').html.includes('onerror'), 'Event-Handler entfernt');
assert(!s.sanitize('<iframe src="evil.com"></iframe>').html.includes('iframe'), 'Iframes entfernt');
assert(!s.sanitize('<object data="x"></object>').html.includes('object'), 'Object-Tags entfernt');
assert(!s.sanitize('<embed src="x">').html.includes('embed'), 'Embed-Tags entfernt');
assert(!s.sanitize('<form action="x"><input></form>').html.includes('form'), 'Forms entfernt');
assert(!s.sanitize('<meta http-equiv="refresh">').html.includes('meta'), 'Meta-Tags entfernt');
assert(!s.sanitize('<base href="evil.com">').html.includes('base'), 'Base-Tags entfernt');
assert(!s.sanitize('<style>body{display:none}</style>').html.includes('style>'), 'Style-Tags entfernt');
assert(!s.sanitize('<a onclick="alert(1)">click</a>').html.includes('onclick'), 'onclick entfernt');
assert(!s.sanitize('<div onmouseover="x">').html.includes('onmouseover'), 'onmouseover entfernt');
assert(!s.sanitize('<input onfocus="x">').html.includes('onfocus'), 'onfocus entfernt');
assert(!s.sanitize('<div data-custom="x">').html.includes('data-'), 'Data-Attribute entfernt');

// ═══════════════════════════════════════════════════════════
//  2. CSS EXFILTRATION
// ═══════════════════════════════════════════════════════════
section('CSS Exfiltration');

assert(!s.sanitize('<div style="background:url(//evil.com)">').html.includes('url('), 'CSS url() blockiert');
assert(!s.sanitize('<span style="x:expression(alert())">').html.includes('expression'), 'CSS expression() blockiert');
assert(!s.sanitize('<p style="color:var(--x)">').html.includes('var('), 'CSS var() blockiert');
assert(!s.sanitize('<div style="-moz-binding:url(x)">').html.includes('moz-binding'), 'CSS moz-binding blockiert');
assert(!s.sanitize('<div style="behavior:url(x)">').html.includes('behavior'), 'CSS behavior blockiert');
assert(!s.sanitize('<div style="content:attr(data-x)">').html.includes('attr('), 'CSS attr() blockiert');
assert(!s.sanitize('<div style="@import url(x)">').html.includes('@import'), 'CSS @import blockiert');

// ═══════════════════════════════════════════════════════════
//  3. UNICODE / BOM / PUNYCODE
// ═══════════════════════════════════════════════════════════
section('Unicode & Punycode');

assert(!s.sanitize('\uFEFF<p>test</p>').html.includes('\uFEFF'), 'BOM entfernt');
assert(!s.sanitize('\uFFFE<p>test</p>').html.includes('\uFFFE'), 'Reverse BOM entfernt');
assert(!s.sanitize('<p>\u200B</p>').html.includes('\u200B'), 'Zero-Width Space entfernt');
assert(!s.sanitize('<p>\u202E</p>').html.includes('\u202E'), 'RTL Override entfernt');
assert(!s.sanitize('<p>\u00AD</p>').html.includes('\u00AD'), 'Soft Hyphen entfernt');

assert(s.detectHomograph('https://xn--80ak6aa92e.com') !== null, 'Punycode-Domain erkannt');
assert(s.detectHomograph('https://аpple.com') !== null, 'Kyrillisches a in apple.com erkannt');
assert(s.detectHomograph('https://google.com') === null, 'Legitime Domain nicht gewarnt');

// ═══════════════════════════════════════════════════════════
//  4. LINK SECURITY
// ═══════════════════════════════════════════════════════════
section('Link Security');

const linkResult = s.sanitize('<a href="https://example.com">link</a>');
assert(linkResult.html.includes('noopener'), 'Links haben noopener');
assert(linkResult.html.includes('noreferrer'), 'Links haben noreferrer');
assert(linkResult.html.includes('target="_blank"'), 'Links öffnen in neuem Tab');

// ═══════════════════════════════════════════════════════════
//  5. TRACKING PIXELS
// ═══════════════════════════════════════════════════════════
section('Tracking Pixel');

const tp = s.sanitize('<img src="https://t.co/p.gif" width="1" height="1">');
assert(tp.blockedImages.length > 0, '1x1 Tracking-Pixel erkannt');

// ═══════════════════════════════════════════════════════════
//  6. ATTACHMENT SECURITY
// ═══════════════════════════════════════════════════════════
section('Attachment Security');
const a = new AttachmentSecurity();

// Blockierte Typen
assert(a.analyze('virus.exe', 'application/octet-stream').blocked, '.exe blockiert');
assert(a.analyze('script.bat', 'application/octet-stream').blocked, '.bat blockiert');
assert(a.analyze('macro.docm', 'application/msword').blocked, '.docm blockiert');
assert(a.analyze('shell.ps1', 'text/plain').blocked, '.ps1 blockiert');
assert(a.analyze('run.vbs', 'text/plain').blocked, '.vbs blockiert');
assert(a.analyze('hack.scr', 'application/octet-stream').blocked, '.scr blockiert');
assert(a.analyze('link.lnk', 'application/octet-stream').blocked, '.lnk blockiert');
assert(a.analyze('app.jar', 'application/java-archive').blocked, '.jar blockiert');
assert(a.analyze('run.hta', 'text/html').blocked, '.hta blockiert');
assert(a.analyze('code.js', 'application/javascript').blocked, '.js blockiert');

// Sichere Typen
assert(!a.analyze('foto.jpg', 'image/jpeg').blocked, '.jpg erlaubt');
assert(!a.analyze('doc.pdf', 'application/pdf').blocked, '.pdf erlaubt');
assert(!a.analyze('text.txt', 'text/plain').blocked, '.txt erlaubt');
assert(!a.analyze('data.csv', 'text/csv').blocked, '.csv erlaubt');

// MIME-Diskrepanz
const mm = a.analyze('bild.jpg', 'text/html');
assert(mm.risk === 'suspicious', 'MIME-Mismatch jpg/html → suspicious');
assert(mm.warnings.some(w => w.includes('Diskrepanz')), 'Diskrepanz-Warnung vorhanden');

// Doppelte Erweiterungen
assert(a.analyze('rechnung.pdf.exe', 'application/octet-stream').blocked, 'Doppelte Erweiterung .pdf.exe blockiert');
assert(a.analyze('bild.jpg.scr', 'application/octet-stream').blocked, 'Doppelte Erweiterung .jpg.scr blockiert');

// Verdächtige Typen
assert(a.analyze('page.html', 'text/html').risk === 'suspicious', '.html → suspicious');
assert(a.analyze('logo.svg', 'image/svg+xml').risk === 'suspicious', '.svg → suspicious');
assert(a.analyze('archive.zip', 'application/zip').risk === 'suspicious', '.zip → suspicious');

// Dateinamen-Sanitization
assert(a.sanitizeFilename('../../../etc/passwd') === '______etc_passwd', 'Path-Traversal sanitized');
assert(a.sanitizeFilename('.hidden') === '_hidden', 'Versteckte Datei sanitized');
assert(a.sanitizeFilename('ok\x00evil') === 'ok_evil', 'Null-Byte entfernt');
assert(a.sanitizeFilename('a'.repeat(300)).length === 255, 'Länge auf 255 begrenzt');

// ═══════════════════════════════════════════════════════════
//  7. TIMING-SAFE COMPARE
// ═══════════════════════════════════════════════════════════
section('Timing-Safe Compare');

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

assert(timingSafeCompare('abc', 'abc') === true, 'Gleiche Strings → true');
assert(timingSafeCompare('abc', 'abd') === false, 'Verschiedene Strings → false');
assert(timingSafeCompare('abc', 'abcd') === false, 'Verschiedene Längen → false');
assert(timingSafeCompare('', '') === true, 'Leere Strings → true');
assert(timingSafeCompare(null, 'abc') === false, 'null → false');
assert(timingSafeCompare(123, 'abc') === false, 'Zahl → false');

// ═══════════════════════════════════════════════════════════
//  8. SMTP HEADER INJECTION
// ═══════════════════════════════════════════════════════════
section('SMTP Header Injection');

function stripHeaderInjection(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[\r\n\x00]/g, '').trim();
}

assert(!stripHeaderInjection('Hallo\r\nBCC: spy@evil.com').includes('\r\n'), 'CRLF entfernt');
assert(!stripHeaderInjection('Hallo\nBCC: spy@evil.com').includes('\n'), 'LF entfernt');
assert(!stripHeaderInjection('Hallo\rBCC: spy@evil.com').includes('\r'), 'CR entfernt');
assert(!stripHeaderInjection('test\x00evil').includes('\x00'), 'Null-Byte entfernt');
assert(stripHeaderInjection('Hallo\r\nBCC: spy@evil.com') === 'HalloBCC: spy@evil.com', 'Injection neutralisiert');
assert(stripHeaderInjection('Normal Subject') === 'Normal Subject', 'Normaler Text unverändert');

// ═══════════════════════════════════════════════════════════
//  9. INPUT VALIDATION
// ═══════════════════════════════════════════════════════════
section('Input Validation');

function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function validateHost(host) {
  if (!host || typeof host !== 'string') return false;
  return /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}[a-zA-Z0-9]$/.test(host);
}

function validateFolder(folder) {
  if (!folder || typeof folder !== 'string') return false;
  if (folder.includes('..') || folder.includes('\0')) return false;
  return folder.length <= 200;
}

assert(validateEmail('user@example.com'), 'Gültige E-Mail akzeptiert');
assert(!validateEmail('not-an-email'), 'Ungültige E-Mail abgelehnt');
assert(!validateEmail('a@b.' + 'c'.repeat(251)), 'Überlange E-Mail abgelehnt');
assert(!validateEmail(''), 'Leere E-Mail abgelehnt');
assert(!validateEmail(null), 'null E-Mail abgelehnt');

assert(validateHost('mail.example.com'), 'Gültiger Host akzeptiert');
assert(!validateHost(''), 'Leerer Host abgelehnt');
assert(!validateHost('host; rm -rf /'), 'Shell-Injection abgelehnt');
assert(!validateHost('../etc'), 'Path-Traversal-Host abgelehnt');

assert(validateFolder('INBOX'), 'INBOX akzeptiert');
assert(validateFolder('Gesendet/2024'), 'Unterordner akzeptiert');
assert(!validateFolder('../../../etc'), 'Path-Traversal Ordner abgelehnt');
assert(!validateFolder('folder\x00evil'), 'Null-Byte Ordner abgelehnt');
assert(!validateFolder(''), 'Leerer Ordner abgelehnt');
assert(!validateFolder('a'.repeat(201)), 'Überlanger Ordner abgelehnt');

// ═══════════════════════════════════════════════════════════
//  10. REGEX SAFETY (ReDoS)
// ═══════════════════════════════════════════════════════════
section('ReDoS Protection');

// Teste alle kritischen Regex mit langen/pathologischen Eingaben
const REDOS_TEST_INPUT = 'a'.repeat(100000);
const REDOS_PATTERNS = [
  { name: 'Email', regex: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
  { name: 'Host', regex: /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}[a-zA-Z0-9]$/ },
  { name: 'Loopback', regex: /^127\./ },
  { name: 'ClassA', regex: /^10\./ },
  { name: 'ClassB', regex: /^172\.(1[6-9]|2\d|3[01])\./ },
  { name: 'ClassC', regex: /^192\.168\./ },
  { name: 'CSS url', regex: /url\s*\(/gi },
  { name: 'CSS expression', regex: /expression\s*\(/gi },
  { name: 'CSS import', regex: /@import/gi },
  { name: 'CSS var', regex: /var\s*\(\s*--/gi },
];

for (const { name, regex } of REDOS_PATTERNS) {
  const start = performance.now();
  regex.test(REDOS_TEST_INPUT);
  const elapsed = performance.now() - start;
  assert(elapsed < 100, `Regex "${name}" – ${elapsed.toFixed(1)}ms (< 100ms, kein ReDoS)`);
}

// ═══════════════════════════════════════════════════════════
//  ERGEBNIS
// ═══════════════════════════════════════════════════════════
console.log(`\n${'═'.repeat(50)}`);
console.log(`  Ergebnis: ${passed} bestanden, ${failed} fehlgeschlagen`);
if (errors.length > 0) {
  console.log(`  Fehlgeschlagen:`);
  errors.forEach(e => console.log(`    ❌ ${e}`));
}
console.log(`${'═'.repeat(50)}\n`);

process.exit(failed > 0 ? 1 : 0);
