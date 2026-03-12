/**
 * ╔══════════════════════════════════════════════════════════╗
 *  SMTP-CLIENT
 *  Versand von E-Mails (Antworten, Weiterleiten, Neu)
 *  über TLS/STARTTLS via Nodemailer
 * ╚══════════════════════════════════════════════════════════╝
 */

import nodemailer from 'nodemailer';

export class SMTPClient {
  constructor() {
    this.transporter = null;
    this.config = null;
  }

  /**
   * SMTP-Verbindung konfigurieren
   * Wird beim Login automatisch mit aufgebaut
   */
  async connect(config) {
    this.config = config;

    this.transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port || 465,
      secure: config.secure ?? (config.port === 465),
      auth: config.auth.accessToken
        ? { type: 'OAuth2', user: config.auth.user, accessToken: config.auth.accessToken }
        : { user: config.auth.user, pass: config.auth.pass },
      tls: config.tls || { rejectUnauthorized: false },
    });

    // Verbindung testen
    await this.transporter.verify();
    console.log(`[SMTP] Verbunden mit ${config.host}:${config.port}`);
    return this;
  }

  /**
   * E-Mail senden
   *
   * @param {Object} mail
   * @param {string} mail.from     - Absender
   * @param {string} mail.to       - Empfänger (kommagetrennt)
   * @param {string} mail.cc       - CC (optional)
   * @param {string} mail.bcc      - BCC (optional)
   * @param {string} mail.subject  - Betreff
   * @param {string} mail.text     - Klartext-Body
   * @param {string} mail.html     - HTML-Body (optional)
   * @param {string} mail.inReplyTo    - Message-ID der Originalnachricht
   * @param {string} mail.references   - References-Header-Kette
   * @param {Array}  mail.attachments  - Anhänge [{filename, content, contentType}]
   */
  async send(mail) {
    if (!this.transporter) {
      throw new Error('SMTP nicht verbunden. Bitte zuerst connect() aufrufen.');
    }

    const result = await this.transporter.sendMail({
      from: mail.from,
      to: mail.to,
      cc: mail.cc || undefined,
      bcc: mail.bcc || undefined,
      subject: mail.subject,
      text: mail.text,
      html: mail.html || undefined,
      inReplyTo: mail.inReplyTo || undefined,
      references: mail.references || undefined,
      attachments: mail.attachments || undefined,
    });

    console.log(`[SMTP] Gesendet: ${result.messageId} → ${mail.to}`);
    return {
      messageId: result.messageId,
      accepted: result.accepted,
      rejected: result.rejected,
    };
  }

  /**
   * Antwort-Mail zusammenbauen
   * Setzt korrekte Header (In-Reply-To, References, Subject)
   */
  buildReply(originalMsg, { replyAll = false, fromAddress }) {
    // Empfänger bestimmen
    const replyTo = originalMsg.replyTo?.[0]?.address
      || originalMsg.from?.[0]?.address
      || '';

    let to = replyTo;
    let cc = '';

    if (replyAll) {
      // Alle Empfänger außer sich selbst
      const allTo = [
        ...(originalMsg.to || []),
        ...(originalMsg.from || []),
      ]
        .map(a => a.address)
        .filter(a => a && a.toLowerCase() !== fromAddress.toLowerCase());

      const allCc = (originalMsg.cc || [])
        .map(a => a.address)
        .filter(a => a && a.toLowerCase() !== fromAddress.toLowerCase());

      // Reply-To-Adresse als erster Empfänger
      to = [replyTo, ...allTo.filter(a => a !== replyTo)].filter(Boolean).join(', ');
      cc = allCc.join(', ');
    }

    // Betreff: "Re:" hinzufügen wenn nicht vorhanden
    const subject = originalMsg.subject?.match(/^Re:/i)
      ? originalMsg.subject
      : `Re: ${originalMsg.subject || ''}`;

    // References-Kette aufbauen
    const references = [
      ...(originalMsg.references ? [].concat(originalMsg.references) : []),
      originalMsg.messageId,
    ].filter(Boolean).join(' ');

    // Zitierter Text
    const date = originalMsg.date
      ? new Date(originalMsg.date).toLocaleString('de-DE')
      : '';
    const fromName = originalMsg.from?.[0]?.name || originalMsg.from?.[0]?.address || '';
    const quotedText = (originalMsg.text || '')
      .split('\n')
      .map(line => `> ${line}`)
      .join('\n');

    const quoteHeader = `\n\nAm ${date} schrieb ${fromName}:\n`;

    return {
      to,
      cc,
      subject,
      inReplyTo: originalMsg.messageId || '',
      references,
      quotedText: quoteHeader + quotedText,
      quotedHtml: originalMsg.html
        ? `<br><br><div style="border-left:2px solid #c4956a;padding-left:12px;margin-left:0;color:#666">
             <p style="font-size:12px;color:#999">Am ${date} schrieb ${fromName}:</p>
             ${originalMsg.html}
           </div>`
        : null,
    };
  }

  /**
   * Weiterleitung zusammenbauen
   */
  buildForward(originalMsg) {
    const subject = originalMsg.subject?.match(/^Fwd:/i)
      ? originalMsg.subject
      : `Fwd: ${originalMsg.subject || ''}`;

    const fromName = originalMsg.from?.[0]?.name || originalMsg.from?.[0]?.address || '';
    const toNames = (originalMsg.to || []).map(a => a.name || a.address).join(', ');
    const date = originalMsg.date
      ? new Date(originalMsg.date).toLocaleString('de-DE')
      : '';

    const forwardHeader = [
      '\n\n---------- Weitergeleitete Nachricht ----------',
      `Von: ${fromName}`,
      `Datum: ${date}`,
      `Betreff: ${originalMsg.subject || ''}`,
      `An: ${toNames}`,
      '------------------------------------------------\n',
    ].join('\n');

    return {
      to: '',
      cc: '',
      subject,
      inReplyTo: '',
      references: '',
      quotedText: forwardHeader + (originalMsg.text || ''),
      quotedHtml: originalMsg.html
        ? `<br><br><div style="border-top:1px solid #ccc;padding-top:12px;margin-top:12px">
             <p style="font-size:12px;color:#999">
               <b>Von:</b> ${fromName}<br>
               <b>Datum:</b> ${date}<br>
               <b>Betreff:</b> ${originalMsg.subject || ''}<br>
               <b>An:</b> ${toNames}
             </p>
             ${originalMsg.html}
           </div>`
        : null,
      // Anhänge der Originalnachricht mitliefern
      attachments: originalMsg.attachments || [],
    };
  }

  async disconnect() {
    if (this.transporter) {
      this.transporter.close();
      this.transporter = null;
      console.log('[SMTP] Verbindung getrennt');
    }
  }
}
