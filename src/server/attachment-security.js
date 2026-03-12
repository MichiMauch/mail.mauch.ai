/**
 * ╔══════════════════════════════════════════════════════════╗
 *  ATTACHMENT SECURITY
 *  Dateityp-Prüfung, MIME-Type vs. Extension Validation,
 *  Risikobewertung, aktive Inhalte blockieren
 * ╚══════════════════════════════════════════════════════════╝
 */

// ── Gefährliche Dateierweiterungen ────────────────────────
const DANGEROUS_EXTENSIONS = new Set([
  // Ausführbare Dateien
  '.exe', '.msi', '.com', '.cmd', '.bat', '.ps1', '.vbs', '.vbe',
  '.js', '.jse', '.ws', '.wsf', '.wsc', '.wsh', '.scr', '.pif',
  '.cpl', '.inf', '.reg', '.rgs', '.sct', '.shb', '.shs',
  // Skripte
  '.sh', '.bash', '.csh', '.ksh', '.py', '.pyw', '.rb', '.pl',
  '.php', '.asp', '.aspx', '.jsp',
  // Office-Makros
  '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm',
  // Archiv mit potenziellem AutoRun
  '.jar', '.app', '.action', '.command',
  // Andere
  '.lnk', '.url', '.desktop', '.hta', '.crt',
]);

// ── Verdächtige Erweiterungen (Warnung, kein Block) ───────
const SUSPICIOUS_EXTENSIONS = new Set([
  '.html', '.htm', '.svg', '.xml', '.xhtml', '.mhtml',
  '.pdf',  // Kann JavaScript enthalten
  '.doc', '.xls', '.ppt',  // Legacy-Formate (Makro-fähig)
  '.zip', '.rar', '.7z', '.tar', '.gz',  // Archive (Inhalt unklar)
  '.iso', '.img', '.dmg',  // Disk-Images
]);

// ── Erlaubte MIME-Types pro Erweiterung ───────────────────
const MIME_EXTENSION_MAP = {
  '.pdf':  ['application/pdf'],
  '.jpg':  ['image/jpeg'],
  '.jpeg': ['image/jpeg'],
  '.png':  ['image/png'],
  '.gif':  ['image/gif'],
  '.webp': ['image/webp'],
  '.svg':  ['image/svg+xml'],
  '.txt':  ['text/plain'],
  '.csv':  ['text/csv', 'text/plain', 'application/csv'],
  '.doc':  ['application/msword'],
  '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  '.xls':  ['application/vnd.ms-excel'],
  '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
  '.ppt':  ['application/vnd.ms-powerpoint'],
  '.pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
  '.zip':  ['application/zip', 'application/x-zip-compressed'],
  '.rar':  ['application/x-rar-compressed', 'application/vnd.rar'],
  '.7z':   ['application/x-7z-compressed'],
  '.gz':   ['application/gzip', 'application/x-gzip'],
  '.tar':  ['application/x-tar'],
  '.mp3':  ['audio/mpeg'],
  '.mp4':  ['video/mp4'],
  '.mov':  ['video/quicktime'],
  '.avi':  ['video/x-msvideo'],
  '.html': ['text/html'],
  '.htm':  ['text/html'],
  '.xml':  ['text/xml', 'application/xml'],
  '.json': ['application/json'],
  '.ics':  ['text/calendar'],
  '.eml':  ['message/rfc822'],
};

// ── MIME-Types die NIEMALS inline angezeigt werden dürfen ──
const NEVER_INLINE_MIMES = new Set([
  'application/javascript',
  'text/javascript',
  'application/x-javascript',
  'text/html',
  'application/xhtml+xml',
  'image/svg+xml',           // SVG kann JavaScript enthalten
  'application/pdf',          // PDF kann JavaScript enthalten
  'application/x-shockwave-flash',
  'application/java-archive',
  'application/x-msdownload',
  'application/x-msdos-program',
]);

export class AttachmentSecurity {

  /**
   * Anhang analysieren und Risikobewertung erstellen
   *
   * @returns {{ risk: 'safe'|'suspicious'|'dangerous', warnings: string[], blocked: boolean }}
   */
  analyze(filename, contentType) {
    const result = {
      risk: 'safe',
      warnings: [],
      blocked: false,
      forceDownload: true,  // Immer Content-Disposition: attachment
      sanitizedFilename: this.sanitizeFilename(filename),
    };

    const ext = this._getExtension(filename);
    const mime = (contentType || '').toLowerCase().split(';')[0].trim();

    // ── Check 1: Gefährliche Erweiterung ──────────────────
    if (DANGEROUS_EXTENSIONS.has(ext)) {
      result.risk = 'dangerous';
      result.blocked = true;
      result.warnings.push(`Gefährlicher Dateityp: ${ext} – Download blockiert`);
      return result;
    }

    // ── Check 2: Verdächtige Erweiterung ──────────────────
    if (SUSPICIOUS_EXTENSIONS.has(ext)) {
      result.risk = 'suspicious';
      result.warnings.push(`Verdächtiger Dateityp: ${ext} – Vorsicht beim Öffnen`);
    }

    // ── Check 3: MIME-Type vs. Erweiterung ────────────────
    const mismatch = this._checkMimeMismatch(ext, mime);
    if (mismatch) {
      result.risk = result.risk === 'safe' ? 'suspicious' : result.risk;
      result.warnings.push(mismatch);
    }

    // ── Check 4: Doppelte Erweiterungen ───────────────────
    if (this._hasDoubleExtension(filename)) {
      result.risk = 'dangerous';
      result.blocked = true;
      result.warnings.push(`Doppelte Erweiterung erkannt: "${filename}" – möglicher Verschleierungsversuch`);
    }

    // ── Check 5: MIME-Type der nie inline sein darf ───────
    if (NEVER_INLINE_MIMES.has(mime)) {
      result.forceDownload = true;
      if (result.risk === 'safe') result.risk = 'suspicious';
      result.warnings.push(`Aktiver Inhaltstyp (${mime}) – keine Vorschau, nur Download`);
    }

    return result;
  }

  /**
   * Dateinamen sanitizen
   */
  sanitizeFilename(filename) {
    if (!filename) return 'unbenannt';
    return filename
      .replace(/\.\./g, '_')
      .replace(/[/\\:*?"<>|\x00-\x1F]/g, '_')
      .replace(/^\.+/, '_')          // Keine versteckten Dateien
      .slice(0, 255);
  }

  /**
   * MIME-Type und Erweiterung gegeneinander prüfen
   */
  _checkMimeMismatch(ext, mime) {
    if (!ext || !mime) return null;

    const expected = MIME_EXTENSION_MAP[ext];
    if (!expected) return null;  // Unbekannte Erweiterung – kein Check möglich

    if (!expected.includes(mime)) {
      return `MIME-Type Diskrepanz: Datei ist "${ext}", aber Server sagt "${mime}"`;
    }
    return null;
  }

  /**
   * Doppelte Erweiterungen erkennen (z.B. "rechnung.pdf.exe")
   */
  _hasDoubleExtension(filename) {
    if (!filename) return false;
    const parts = filename.split('.');
    if (parts.length < 3) return false;

    // Die letzte echte Erweiterung
    const lastExt = '.' + parts[parts.length - 1].toLowerCase();
    // Die vorletzte
    const secondLastExt = '.' + parts[parts.length - 2].toLowerCase();

    // Gefährlich wenn letzte Erweiterung ausführbar ist
    if (DANGEROUS_EXTENSIONS.has(lastExt)) return true;

    // Verdächtig wenn beide bekannte Erweiterungen sind (z.B. .pdf.html)
    if (MIME_EXTENSION_MAP[lastExt] && MIME_EXTENSION_MAP[secondLastExt]) {
      // Nur wenn die Typen sehr unterschiedlich sind
      const cat1 = this._mimeCategory(MIME_EXTENSION_MAP[lastExt]?.[0]);
      const cat2 = this._mimeCategory(MIME_EXTENSION_MAP[secondLastExt]?.[0]);
      if (cat1 !== cat2) return true;
    }

    return false;
  }

  _mimeCategory(mime) {
    if (!mime) return 'unknown';
    return mime.split('/')[0]; // image, text, application, etc.
  }

  _getExtension(filename) {
    if (!filename) return '';
    const idx = filename.lastIndexOf('.');
    if (idx < 0) return '';
    return filename.substring(idx).toLowerCase();
  }
}
