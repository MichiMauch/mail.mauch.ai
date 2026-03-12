/**
 * ╔══════════════════════════════════════════════════════════╗
 *  SCHICHT 3: MIME-PARSER (CORE LOGIC)
 *  Multipart-Zerlegung, Base64/Quoted-Printable Decoding,
 *  Zeichensatz-Konvertierung, MIME-Bomben-Schutz
 * ╚══════════════════════════════════════════════════════════╝
 */

import { simpleParser } from 'mailparser';
import iconv from 'iconv-lite';

// ── Sicherheits-Limits gegen MIME-Bomben ──────────────────
const LIMITS = {
  MAX_MAIL_SIZE:        25 * 1024 * 1024,  // 25 MB max Gesamtgröße
  MAX_ATTACHMENTS:      50,                 // Max Anhänge pro Mail
  MAX_ATTACHMENT_SIZE:  20 * 1024 * 1024,   // 20 MB pro Anhang
  MAX_HTML_SIZE:        2 * 1024 * 1024,    // 2 MB HTML-Body
  MAX_TEXT_SIZE:        2 * 1024 * 1024,    // 2 MB Text-Body
  MAX_HEADER_COUNT:     200,                // Max Header-Felder
  MAX_SUBJECT_LENGTH:   1000,               // Max Betreff-Länge
  MAX_ADDRESS_COUNT:    100,                // Max Adressen pro Feld
  PARSE_TIMEOUT:        30_000,             // 30 Sekunden Parse-Timeout
};

export class MIMEParser {

  /**
   * Vollständiges Parsen einer rohen E-Mail (RFC 2822)
   * Mit Größen- und Rekursions-Limits.
   */
  async parse(rawBuffer) {
    // ── Größenprüfung VOR dem Parsing ─────────────────────
    if (Buffer.byteLength(rawBuffer) > LIMITS.MAX_MAIL_SIZE) {
      throw new Error(`Mail zu groß (${(Buffer.byteLength(rawBuffer) / 1024 / 1024).toFixed(1)} MB). Limit: ${LIMITS.MAX_MAIL_SIZE / 1024 / 1024} MB.`);
    }

    // ── Parsing mit Timeout (gegen Endlos-Rekursion) ──────
    const parsed = await this._parseWithTimeout(rawBuffer, LIMITS.PARSE_TIMEOUT);

    // ── Ergebnis mit Limits aufbereiten ───────────────────
    return {
      // ── Metadaten ──────────────────────────────────
      messageId: parsed.messageId,
      date: parsed.date,
      subject: this._truncate(parsed.subject || '(Kein Betreff)', LIMITS.MAX_SUBJECT_LENGTH),
      from: this._normalizeAddresses(parsed.from),
      to: this._normalizeAddresses(parsed.to),
      cc: this._normalizeAddresses(parsed.cc),
      bcc: this._normalizeAddresses(parsed.bcc),
      replyTo: this._normalizeAddresses(parsed.replyTo),
      inReplyTo: parsed.inReplyTo,
      references: parsed.references,
      priority: parsed.priority || 'normal',

      // ── Body: text/plain + text/html (mit Größenlimit) ─
      text: this._limitText(this._ensureUTF8(parsed.text), LIMITS.MAX_TEXT_SIZE),
      html: this._limitText(parsed.html, LIMITS.MAX_HTML_SIZE),
      textAsHtml: null, // Nicht mehr benötigt

      // ── Anhänge (begrenzt) ─────────────────────────
      attachments: this._processAttachments(parsed.attachments || []),

      // ── Header (begrenzt) ──────────────────────────
      headers: this._extractHeaders(parsed.headers),
    };
  }

  /**
   * Parsing mit Timeout – verhindert Endlos-Rekursion bei MIME-Bomben
   */
  async _parseWithTimeout(rawBuffer, timeoutMs) {
    return Promise.race([
      simpleParser(rawBuffer, {
        skipHtmlToText: true,
        skipTextToHtml: true,
        skipImageLinks: true,
        maxHtmlLengthToParse: LIMITS.MAX_HTML_SIZE,
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error(
          `MIME-Parsing Timeout (${timeoutMs / 1000}s). Möglicherweise eine MIME-Bombe.`
        )), timeoutMs)
      ),
    ]);
  }

  /**
   * Anhänge verarbeiten mit Limits
   */
  _processAttachments(attachments) {
    // Anzahl begrenzen
    const limited = attachments.slice(0, LIMITS.MAX_ATTACHMENTS);

    return limited.map(att => {
      const size = att.size || (att.content ? att.content.length : 0);

      // Überdimensionale Anhänge: nur Metadaten, kein Content
      if (size > LIMITS.MAX_ATTACHMENT_SIZE) {
        return {
          filename: att.filename || 'unbenannt',
          contentType: att.contentType,
          contentDisposition: att.contentDisposition || 'attachment',
          contentId: att.cid || null,
          size,
          content: null, // Zu groß – nicht laden
          oversized: true,
          headers: {},
        };
      }

      return {
        filename: this._sanitizeFilename(att.filename || 'unbenannt'),
        contentType: att.contentType,
        contentDisposition: att.contentDisposition || 'attachment',
        contentId: att.cid || null,
        size,
        content: att.content.toString('base64'),
        checksum: att.checksum,
        oversized: false,
        headers: Object.fromEntries(att.headers || []),
      };
    });
  }

  /**
   * Dateinamen sanitizen – Path-Traversal verhindern
   */
  _sanitizeFilename(filename) {
    return filename
      .replace(/\.\./g, '_')           // Path-Traversal
      .replace(/[/\\:*?"<>|]/g, '_')   // Ungültige Zeichen
      .replace(/\0/g, '')              // Null-Bytes
      .slice(0, 255);                  // Längenlimit
  }

  /**
   * Nur die Text-Teile extrahieren (für Vorschau)
   */
  async parsePreview(rawBuffer, maxLength = 200) {
    const parsed = await this.parse(rawBuffer);
    const text = parsed.text || '';
    return {
      subject: parsed.subject,
      from: parsed.from,
      date: parsed.date,
      preview: text.substring(0, maxLength).replace(/\s+/g, ' ').trim(),
    };
  }

  // ── Text auf Maximalgröße beschränken ───────────────────
  _limitText(text, maxSize) {
    if (!text) return null;
    if (typeof text === 'string' && text.length > maxSize) {
      return text.substring(0, maxSize) + '\n\n[… Inhalt gekürzt – Limit erreicht]';
    }
    return text;
  }

  _truncate(str, max) {
    if (!str) return str;
    return str.length > max ? str.substring(0, max) + '…' : str;
  }

  // ── Zeichensatz-Konvertierung ────────────────────────────
  _ensureUTF8(text) {
    if (!text) return null;
    if (typeof text === 'string') return text;
    if (Buffer.isBuffer(text)) {
      for (const enc of ['utf-8', 'iso-8859-1', 'windows-1252', 'iso-8859-15']) {
        try {
          return iconv.decode(text, enc);
        } catch { continue; }
      }
    }
    return String(text);
  }

  /**
   * Manuelles Decoding für einzelne MIME-Parts
   */
  static decodeTransferEncoding(buffer, encoding, charset = 'utf-8') {
    let decoded;

    switch ((encoding || '').toLowerCase()) {
      case 'base64':
        decoded = Buffer.from(buffer.toString('ascii'), 'base64');
        break;
      case 'quoted-printable':
        decoded = MIMEParser._decodeQuotedPrintable(buffer);
        break;
      case '7bit':
      case '8bit':
      case 'binary':
      default:
        decoded = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
        break;
    }

    if (charset && charset.toLowerCase() !== 'utf-8') {
      try {
        return iconv.decode(decoded, charset);
      } catch {
        return decoded.toString('utf-8');
      }
    }
    return decoded.toString('utf-8');
  }

  /**
   * Quoted-Printable Decoder (RFC 2045)
   */
  static _decodeQuotedPrintable(input) {
    const str = input.toString('ascii');
    const bytes = [];
    let i = 0;

    while (i < str.length) {
      if (str[i] === '=' && i + 2 < str.length) {
        const hex = str.substring(i + 1, i + 3);
        if (hex === '\r\n' || hex.startsWith('\n')) {
          i += (hex === '\r\n') ? 3 : 2;
          continue;
        }
        const byte = parseInt(hex, 16);
        if (!isNaN(byte)) {
          bytes.push(byte);
          i += 3;
          continue;
        }
      }
      bytes.push(str.charCodeAt(i));
      i++;
    }

    return Buffer.from(bytes);
  }

  // ── Adressen normalisieren (mit Limit) ─────────────────
  _normalizeAddresses(field) {
    if (!field) return [];
    const addrs = field.value || (Array.isArray(field) ? field : [field]);
    return addrs.slice(0, LIMITS.MAX_ADDRESS_COUNT).map(a => ({
      name: this._truncate(a.name || null, 200),
      address: a.address || null,
    }));
  }

  // ── Header als Key-Value Paare (mit Limit) ─────────────
  _extractHeaders(headersMap) {
    if (!headersMap) return {};
    const result = {};
    let count = 0;
    for (const [key, value] of headersMap) {
      if (count >= LIMITS.MAX_HEADER_COUNT) break;
      result[key] = value;
      count++;
    }
    return result;
  }
}
