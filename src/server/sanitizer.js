/**
 * ╔══════════════════════════════════════════════════════════╗
 *  SCHICHT 4: SICHERHEITS-SCHICHT
 *  HTML-Sanitization, CSS-Exfiltration-Schutz,
 *  Tracking-Pixel-Blockierung, Punycode-Erkennung,
 *  BOM-Stripping, Link-Sicherheit
 * ╚══════════════════════════════════════════════════════════╝
 */

import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// ── Gefährliche CSS-Patterns (Exfiltration + Exploits) ────
const DANGEROUS_CSS_PATTERNS = [
  /url\s*\(/gi,                        // url() – kann externe Requests auslösen
  /expression\s*\(/gi,                 // IE expression()
  /javascript\s*:/gi,                  // javascript: in CSS
  /-moz-binding/gi,                    // Firefox XBL Binding
  /behavior\s*:/gi,                    // IE behavior
  /@import/gi,                         // Externe Stylesheets laden
  /var\s*\(\s*--/gi,                   // CSS Custom Properties (Daten-Exfiltration)
  /-webkit-[\w-]*calc/gi,              // Webkit calc exploits
  /content\s*:\s*attr\s*\(/gi,         // attr() kann DOM-Daten lesen
];

// ── Punycode / Homograph Detection ──────────────────────
const PUNYCODE_REGEX = /xn--/i;
const MIXED_SCRIPT_REGEX = /[\u0400-\u04FF]|[\u0370-\u03FF]|[\u4E00-\u9FFF]|[\u0600-\u06FF]/;

// ── BOM + gefährliche Unicode-Steuerzeichen ─────────────
const DANGEROUS_UNICODE = /[\uFEFF\uFFFE\u200B-\u200F\u202A-\u202E\u2066-\u2069\u00AD\u034F\u115F\u1160\u17B4\u17B5]/g;

export class HTMLSanitizer {
  constructor(config = {}) {
    this.blockExternalImages = config.blockExternalImages ?? true;
    this.allowedTags = config.allowedTags || [
      'p', 'br', 'b', 'i', 'u', 'strong', 'em', 'a', 'ul', 'ol', 'li',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre', 'code',
      'table', 'thead', 'tbody', 'tr', 'td', 'th', 'span', 'div', 'img',
      'hr', 'sub', 'sup', 'dl', 'dt', 'dd',
    ];
    this.forbiddenTags = config.forbiddenTags || [
      'script', 'iframe', 'object', 'embed', 'form', 'input', 'textarea',
      'select', 'button', 'style', 'link', 'meta', 'base', 'applet',
    ];
  }

  /**
   * Haupt-Sanitization: HTML bereinigen + externe Inhalte blockieren
   * Gibt { html, blockedImages, warnings } zurück
   */
  sanitize(dirtyHtml, { allowExternalImages = false } = {}) {
    if (!dirtyHtml) return { html: '', blockedImages: [], warnings: [] };

    const blockedImages = [];
    const warnings = [];

    // ── Schritt 0: BOM + Steuerzeichen entfernen ─────────
    let cleanInput = this.stripDangerousUnicode(dirtyHtml);

    // ── Schritt 1: DOMPurify – XSS-Schutz ───────────────
    const clean = DOMPurify.sanitize(cleanInput, {
      ALLOWED_TAGS: this.allowedTags,
      ALLOWED_ATTR: [
        'href', 'src', 'alt', 'title', 'class', 'id',
        'width', 'height', 'style', 'target', 'rel',
        'colspan', 'rowspan', 'cellpadding', 'cellspacing',
        'border', 'align', 'valign', 'bgcolor', 'color',
      ],
      FORBID_TAGS: this.forbiddenTags,
      FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus',
                     'onblur', 'onsubmit', 'onreset', 'onchange', 'oninput',
                     'onkeydown', 'onkeyup', 'onkeypress', 'ondblclick',
                     'oncontextmenu', 'ondrag', 'ondrop', 'onmousedown',
                     'onmouseup', 'onmousemove', 'onwheel', 'onscroll',
                     'ontouchstart', 'ontouchend', 'ontouchmove',
                     'onanimationstart', 'ontransitionend', 'onpointerdown'],
      ALLOW_DATA_ATTR: false,
      ADD_ATTR: ['target'],
    });

    // ── Schritt 2: DOM-Level Bereinigung ─────────────────
    const dom = new JSDOM(clean);
    const doc = dom.window.document;

    // Links: target="_blank" + rel="noopener noreferrer"
    doc.querySelectorAll('a').forEach(a => {
      a.setAttribute('target', '_blank');
      a.setAttribute('rel', 'noopener noreferrer');

      // Punycode-/Homograph-Warnung auf Links
      const href = a.getAttribute('href') || '';
      const linkWarning = this.detectHomograph(href);
      if (linkWarning) {
        warnings.push(linkWarning);
        a.setAttribute('title', `⚠ ${linkWarning}`);
        a.setAttribute('class', (a.getAttribute('class') || '') + ' suspicious-link');
      }
    });

    // ── Schritt 3: CSS-Exfiltration-Schutz ───────────────
    doc.querySelectorAll('[style]').forEach(el => {
      const style = el.getAttribute('style') || '';
      const sanitized = this.sanitizeCSS(style);
      if (sanitized) {
        el.setAttribute('style', sanitized);
      } else {
        el.removeAttribute('style');
      }
    });

    // ── Schritt 4: Externe Bilder blockieren ─────────────
    if (this.blockExternalImages && !allowExternalImages) {
      doc.querySelectorAll('img').forEach(img => {
        const src = img.getAttribute('src') || '';
        if (this._isExternalUrl(src)) {
          blockedImages.push(src);
          img.setAttribute('data-blocked-src', src);
          img.removeAttribute('src');
          img.setAttribute('alt', `[Bild blockiert: ${img.getAttribute('alt') || 'extern'}]`);
          img.setAttribute('class', 'blocked-image');
        }
      });

      // Tracking-Pixel erkennen (1x1 Bilder)
      doc.querySelectorAll('img').forEach(img => {
        const w = parseInt(img.getAttribute('width') || '0');
        const h = parseInt(img.getAttribute('height') || '0');
        if ((w <= 1 && h <= 1) || (w === 0 && h === 0)) {
          const src = img.getAttribute('data-blocked-src') || img.getAttribute('src') || '';
          if (src) blockedImages.push(`[Tracking-Pixel] ${src}`);
          img.remove();
        }
      });

      // CSS background-image in Inline-Styles blockieren (bereits durch sanitizeCSS erledigt)
    }

    return {
      html: doc.body.innerHTML,
      blockedImages,
      warnings,
    };
  }

  /**
   * CSS-Inline-Styles bereinigen – alles mit url(), expression(), etc. entfernen
   * Erlaubt nur sichere visuellen Eigenschaften.
   */
  sanitizeCSS(style) {
    if (!style) return '';

    // Prüfe auf gefährliche Patterns
    for (const pattern of DANGEROUS_CSS_PATTERNS) {
      if (pattern.test(style)) {
        // Pattern gefunden → diese Property entfernen
        // Zerlege in einzelne Deklarationen und filtere
        const declarations = style.split(';').map(d => d.trim()).filter(Boolean);
        const safe = declarations.filter(decl => {
          for (const p of DANGEROUS_CSS_PATTERNS) {
            p.lastIndex = 0; // Regex-State zurücksetzen
            if (p.test(decl)) return false;
          }
          return true;
        });
        return safe.join('; ');
      }
    }
    return style;
  }

  /**
   * BOM + unsichtbare Unicode-Steuerzeichen entfernen
   * Verhindert Parser-Verwirrung und unsichtbare Textmanipulation
   */
  stripDangerousUnicode(text) {
    if (!text) return '';
    return text.replace(DANGEROUS_UNICODE, '');
  }

  /**
   * Punycode / Homograph-Angriff erkennen
   * Gibt Warnung zurück oder null
   */
  detectHomograph(urlOrAddress) {
    if (!urlOrAddress) return null;

    // Punycode in Domain erkennen (xn--...)
    if (PUNYCODE_REGEX.test(urlOrAddress)) {
      return `Verdächtige Domain (Punycode): ${urlOrAddress.substring(0, 60)}`;
    }

    // Gemischte Schriftsysteme erkennen
    // Prüfe den gesamten String UND extrahierte Domain
    const toCheck = [urlOrAddress];
    try {
      if (urlOrAddress.includes('//')) {
        toCheck.push(new URL(urlOrAddress).hostname);
      } else if (urlOrAddress.includes('@')) {
        toCheck.push(urlOrAddress.split('@').pop()?.split('/')[0] || '');
      }
    } catch { /* URL ungültig – prüfe trotzdem den Rohstring */ }

    for (const str of toCheck) {
      if (!str) continue;
      // Prüfe ob lateinische UND nicht-lateinische Zeichen gemischt sind
      const hasLatin = /[a-zA-Z]/.test(str);
      const hasNonLatin = MIXED_SCRIPT_REGEX.test(str);
      if (hasLatin && hasNonLatin) {
        return `Verdächtige Zeichen (Homograph-Angriff möglich): ${str.substring(0, 60)}`;
      }
      // Nur nicht-lateinisch in einer Domain die lateinisch aussehen soll
      if (hasNonLatin && /\.(com|net|org|de|ch|at|io|co)/.test(str)) {
        return `Verdächtige Domain (nicht-lateinische Zeichen): ${str.substring(0, 60)}`;
      }
    }

    return null;
  }

  /**
   * E-Mail-Adresse auf Homograph prüfen
   * Gibt { safe: boolean, warning: string|null } zurück
   */
  checkAddress(address) {
    if (!address) return { safe: true, warning: null };
    const warning = this.detectHomograph(address);
    return { safe: !warning, warning };
  }

  /**
   * Nur Text extrahieren (für sichere Vorschau)
   */
  stripToText(html) {
    if (!html) return '';
    const stripped = this.stripDangerousUnicode(html);
    const clean = DOMPurify.sanitize(stripped, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
    return clean.replace(/\s+/g, ' ').trim();
  }

  /**
   * Prüfe ob URL extern ist
   */
  _isExternalUrl(url) {
    if (!url) return false;
    return /^https?:\/\//i.test(url) || url.startsWith('//');
  }
}
