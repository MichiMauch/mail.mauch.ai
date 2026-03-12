/**
 * ╔══════════════════════════════════════════════════════════╗
 *  SCHICHT 1: CONNECTIVITY LAYER
 *  IMAP-Client mit TLS/SSL, Session-Management,
 *  SASL Plain/Login + OAuth2-Vorbereitung
 * ╚══════════════════════════════════════════════════════════╝
 */

import { ImapFlow } from 'imapflow';

export class IMAPClient {
  constructor(config) {
    this.config = config;
    this.client = null;
    this.connected = false;
    this.selectedFolder = null;
  }

  // ── Verbindungsaufbau über TLS (Port 993) ──────────────────
  async connect() {
    const authConfig = this.config.auth;

    // OAuth2-Pfad: Wenn ein accessToken vorhanden ist, nutze XOAUTH2
    const auth = authConfig.accessToken
      ? { user: authConfig.user, accessToken: authConfig.accessToken }
      : { user: authConfig.user, pass: authConfig.pass };

    this.client = new ImapFlow({
      host: this.config.host,
      port: this.config.port,
      secure: this.config.secure,
      auth,
      tls: this.config.tls || { rejectUnauthorized: false },
      logger: false,
    });

    await this.client.connect();
    this.connected = true;
    console.log(`[IMAP] Verbunden mit ${this.config.host}:${this.config.port} (TLS)`);
    return this;
  }

  // ── Ordner auflisten ───────────────────────────────────────
  async listFolders() {
    this._ensureConnected();
    const tree = await this.client.listTree();
    return this._flattenTree(tree);
  }

  _flattenTree(node, result = []) {
    if (node.path) {
      result.push({
        name: node.name,
        path: node.path,
        flags: node.flags || [],
        specialUse: node.specialUse || null,
        delimiter: node.delimiter,
      });
    }
    if (node.folders) {
      for (const child of node.folders) {
        this._flattenTree(child, result);
      }
    }
    return result;
  }

  // ── Ordner selektieren ─────────────────────────────────────
  async selectFolder(path = 'INBOX') {
    this._ensureConnected();
    const lock = await this.client.getMailboxLock(path);
    try {
      this.selectedFolder = this.client.mailbox;
      return {
        path: this.selectedFolder.path,
        exists: this.selectedFolder.exists,
        recent: this.selectedFolder.recent,
        uidNext: this.selectedFolder.uidNext,
        uidValidity: this.selectedFolder.uidValidity,
      };
    } finally {
      lock.release();
    }
  }

  // ── Header der letzten N Mails abrufen (Schicht 2) ────────
  async fetchHeaders(folder = 'INBOX', { count = 50, since = null } = {}) {
    this._ensureConnected();
    const lock = await this.client.getMailboxLock(folder);
    try {
      const messages = [];
      const range = since
        ? await this._buildDateRange(since)
        : `${Math.max(1, this.client.mailbox.exists - count + 1)}:*`;

      for await (const msg of this.client.fetch(range, {
        uid: true,
        flags: true,
        envelope: true,
        bodyStructure: true,
        internalDate: true,
      })) {
        messages.push({
          uid: msg.uid,
          seq: msg.seq,
          flags: [...msg.flags],
          seen: msg.flags.has('\\Seen'),
          flagged: msg.flags.has('\\Flagged'),
          date: msg.envelope.date,
          internalDate: msg.internalDate,
          subject: msg.envelope.subject || '(Kein Betreff)',
          from: this._formatAddresses(msg.envelope.from),
          to: this._formatAddresses(msg.envelope.to),
          cc: this._formatAddresses(msg.envelope.cc),
          messageId: msg.envelope.messageId,
          inReplyTo: msg.envelope.inReplyTo,
          hasAttachments: this._detectAttachments(msg.bodyStructure),
          bodyStructure: msg.bodyStructure,
        });
      }

      // Neueste zuerst
      messages.sort((a, b) => new Date(b.date) - new Date(a.date));
      return messages;
    } finally {
      lock.release();
    }
  }

  // ── Vollständigen Body einer Mail laden (Lazy Loading) ─────
  async fetchBody(folder = 'INBOX', uid) {
    this._ensureConnected();
    const lock = await this.client.getMailboxLock(folder);
    try {
      const raw = await this.client.download(String(uid), undefined, { uid: true });
      const chunks = [];
      for await (const chunk of raw.content) {
        chunks.push(chunk);
      }
      return Buffer.concat(chunks);
    } finally {
      lock.release();
    }
  }

  // ── Einzelnen Anhang streamen ──────────────────────────────
  async fetchAttachment(folder = 'INBOX', uid, part) {
    this._ensureConnected();
    const lock = await this.client.getMailboxLock(folder);
    try {
      const download = await this.client.download(String(uid), part, { uid: true });
      return download; // { content: ReadableStream, meta: {...} }
    } finally {
      lock.release();
    }
  }

  // ── Flags setzen (gelesen, markiert, etc.) ─────────────────
  async setFlags(folder, uid, flags, mode = 'add') {
    this._ensureConnected();
    const lock = await this.client.getMailboxLock(folder);
    try {
      if (mode === 'add') {
        await this.client.messageFlagsAdd(String(uid), flags, { uid: true });
      } else if (mode === 'remove') {
        await this.client.messageFlagsRemove(String(uid), flags, { uid: true });
      } else {
        await this.client.messageFlagsSet(String(uid), flags, { uid: true });
      }
    } finally {
      lock.release();
    }
  }

  // ── Nachricht löschen (in Papierkorb verschieben) ───────────
  async deleteMessage(folder, uid, trashFolder = null) {
    this._ensureConnected();

    // Papierkorb-Ordner finden falls nicht angegeben
    if (!trashFolder) {
      trashFolder = await this._findTrashFolder();
    }

    const lock = await this.client.getMailboxLock(folder);
    try {
      if (trashFolder && folder !== trashFolder) {
        // In Papierkorb verschieben
        await this.client.messageMove(String(uid), trashFolder, { uid: true });
        console.log(`[IMAP] Nachricht ${uid} verschoben → ${trashFolder}`);
        return { action: 'moved', destination: trashFolder };
      } else {
        // Schon im Papierkorb → endgültig löschen
        await this.client.messageFlagsAdd(String(uid), ['\\Deleted'], { uid: true });
        await this.client.messageDelete(String(uid), { uid: true });
        console.log(`[IMAP] Nachricht ${uid} endgültig gelöscht`);
        return { action: 'deleted' };
      }
    } finally {
      lock.release();
    }
  }

  // ── Papierkorb-Ordner automatisch erkennen ─────────────────
  async _findTrashFolder() {
    try {
      const folders = await this.listFolders();
      // Zuerst nach specialUse suchen
      const special = folders.find(f => f.specialUse === '\\Trash');
      if (special) return special.path;
      // Dann nach bekannten Namen
      const names = ['trash', 'papierkorb', 'deleted', 'deleted items', 'deleted messages', 'bin'];
      const byName = folders.find(f => names.includes(f.name.toLowerCase()));
      if (byName) return byName.path;
      return null;
    } catch {
      return null;
    }
  }

  // ── Verbindung trennen ─────────────────────────────────────
  async disconnect() {
    if (this.client) {
      await this.client.logout();
      this.connected = false;
      console.log('[IMAP] Verbindung getrennt');
    }
  }

  // ── Hilfsfunktionen ────────────────────────────────────────
  _ensureConnected() {
    if (!this.connected || !this.client) {
      throw new Error('IMAP-Client nicht verbunden. Bitte zuerst connect() aufrufen.');
    }
  }

  async _buildDateRange(since) {
    // IMAP SEARCH nach Datum
    const sinceDate = new Date(since);
    const results = await this.client.search({ since: sinceDate });
    if (results.length === 0) return '1:0'; // leeres Set
    return results.join(',');
  }

  _formatAddresses(addrs) {
    if (!addrs) return [];
    return addrs.map(a => ({
      name: a.name || null,
      address: a.address || `${a.user}@${a.host}`,
    }));
  }

  _detectAttachments(structure) {
    if (!structure) return false;
    if (structure.disposition === 'attachment') return true;
    if (structure.childNodes) {
      return structure.childNodes.some(child => this._detectAttachments(child));
    }
    return false;
  }
}
