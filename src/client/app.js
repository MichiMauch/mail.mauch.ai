/**
 * ╔══════════════════════════════════════════════════════════╗
 *  FRONTEND APPLICATION
 *  Steuert Login, Ordnerliste, Nachrichtenliste,
 *  Mail-Anzeige, Anhang-Download und Bild-Freigabe
 * ╚══════════════════════════════════════════════════════════╝
 */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ── State ────────────────────────────────────────────────
const state = {
  connected: false,
  currentFolder: 'INBOX',
  currentUid: null,
  messages: [],
  folders: [],
  smtpReady: false,
  user: '',
  csrfToken: '',
  selectedUids: new Set(),    // Multi-Select
  searchQuery: '',            // Aktive Suche
  isSearching: false,
  aiAvailable: false,         // AI-Funktion aktiv?
  composeContext: null,       // Original-Mail-Kontext für AI
};

// ═══════════════════════════════════════════════════════════
//  API LAYER (mit CSRF-Token)
// ═══════════════════════════════════════════════════════════
const api = {
  async post(url, data) {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': state.csrfToken,
      },
      body: JSON.stringify(data),
    });
    const json = await res.json();
    // Session abgelaufen?
    if (res.status === 401 && json.error?.includes('Session')) {
      handleSessionExpired();
    }
    return json;
  },

  async get(url) {
    const res = await fetch(url);
    const json = await res.json();
    if (res.status === 401 && json.error?.includes('Session')) {
      handleSessionExpired();
    }
    return json;
  },

  connect: (creds) => api.post('/api/connect', creds),
  disconnect: () => api.post('/api/disconnect'),
  folders: () => api.get('/api/folders'),
  messages: (folder, count = 50) => api.get(`/api/messages/${encodeURIComponent(folder)}?count=${count}`),
  message: (folder, uid, allowImages = false) =>
    api.get(`/api/message/${encodeURIComponent(folder)}/${uid}?allowImages=${allowImages}`),
  send: (mail) => api.post('/api/send', mail),
  deleteMsg: (folder, uid) => fetch(`/api/message/${encodeURIComponent(folder)}/${uid}`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': state.csrfToken },
  }).then(r => r.json()),
  reply: (folder, uid, replyAll = false) =>
    api.post(`/api/reply/${encodeURIComponent(folder)}/${uid}`, { replyAll }),
  forward: (folder, uid) =>
    api.post(`/api/forward/${encodeURIComponent(folder)}/${uid}`),
  search: (folder, query) =>
    api.get(`/api/search/${encodeURIComponent(folder)}?q=${encodeURIComponent(query)}`),
  deleteBulk: (folder, uids) =>
    api.post(`/api/delete-bulk/${encodeURIComponent(folder)}`, { uids }),
  aiStatus: () => api.get('/api/ai/status'),
  aiGenerate: (data) => api.post('/api/ai/generate', data),
};

// ═══════════════════════════════════════════════════════════
//  SESSION MANAGEMENT
// ═══════════════════════════════════════════════════════════
function handleSessionExpired() {
  state.connected = false;
  state.csrfToken = '';
  showToast('Sitzung abgelaufen – bitte neu anmelden', 'error', 5000);
  setTimeout(() => {
    $('#app-screen').classList.remove('active');
    $('#login-screen').classList.add('active');
    closeCompose();
    closeDetail();
  }, 1000);
}

// ═══════════════════════════════════════════════════════════
//  THEME & LAYOUT
// ═══════════════════════════════════════════════════════════
function applyTheme(name) {
  document.documentElement.setAttribute('data-theme', name);
  localStorage.setItem('mail-theme', name);
  $$('.theme-card').forEach(card => {
    card.classList.toggle('active', card.dataset.theme === name);
  });
}

function applyLayout(name) {
  document.documentElement.setAttribute('data-layout', name);
  localStorage.setItem('mail-layout', name);
  $$('.layout-card').forEach(card => {
    card.classList.toggle('active', card.dataset.layout === name);
  });
}

// Gespeichertes Theme + Layout beim Start laden
(function initThemeAndLayout() {
  const savedTheme = localStorage.getItem('mail-theme') || 'kupfer';
  document.documentElement.setAttribute('data-theme', savedTheme);
  const savedLayout = localStorage.getItem('mail-layout') || 'classic';
  document.documentElement.setAttribute('data-layout', savedLayout);
})();

// ═══════════════════════════════════════════════════════════
//  SETTINGS
// ═══════════════════════════════════════════════════════════
function openSettings() {
  const overlay = $('#settings-overlay');
  overlay.classList.add('open');
  // Aktives Theme markieren
  const currentTheme = localStorage.getItem('mail-theme') || 'kupfer';
  $$('.theme-card').forEach(card => {
    card.classList.toggle('active', card.dataset.theme === currentTheme);
  });
  // Aktives Layout markieren
  const currentLayout = localStorage.getItem('mail-layout') || 'classic';
  $$('.layout-card').forEach(card => {
    card.classList.toggle('active', card.dataset.layout === currentLayout);
  });
}

function closeSettings() {
  $('#settings-overlay').classList.remove('open');
}

// ═══════════════════════════════════════════════════════════
//  INIT: Server-Vorgaben laden
// ═══════════════════════════════════════════════════════════
(async function initConfig() {
  try {
    const cfg = await api.get('/api/config');
    if (cfg.hasImapConfig) {
      // Server-Felder ausblenden wenn per .env.local konfiguriert
      const hostGroup = $('#host-group');
      const portRow = $('#port-row');
      const smtpDetails = document.querySelector('.smtp-details');

      if (hostGroup) hostGroup.style.display = 'none';
      if (portRow) portRow.style.display = 'none';
      if (smtpDetails) smtpDetails.style.display = 'none';

      state.serverConfigured = true;
    }
  } catch {
    // Kein Problem – Felder bleiben sichtbar
  }
})();

// ═══════════════════════════════════════════════════════════
//  LOGIN
// ═══════════════════════════════════════════════════════════
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#login-btn');
  const btnText = btn.querySelector('.btn-text');
  const btnLoading = btn.querySelector('.btn-loading');
  const errorEl = $('#login-error');

  btn.disabled = true;
  btnText.style.display = 'none';
  btnLoading.style.display = 'inline-flex';
  errorEl.style.display = 'none';

  try {
    const result = await api.connect({
      host: $('#host').value.trim(),
      port: parseInt($('#port').value),
      user: $('#user').value.trim(),
      pass: $('#pass').value,
      smtpHost: $('#smtp-host').value.trim() || undefined,
      smtpPort: parseInt($('#smtp-port').value) || undefined,
    });

    if (result.error) throw new Error(result.details || result.error);

    state.connected = true;
    state.smtpReady = result.smtpReady || false;
    state.user = $('#user').value.trim();
    state.csrfToken = result.csrfToken || '';
    $('#connection-info').textContent = state.user;

    // Compose-Button aktivieren/deaktivieren
    const composeBtn = $('#compose-btn');
    if (composeBtn) {
      composeBtn.disabled = !state.smtpReady;
      composeBtn.title = state.smtpReady ? 'Neue E-Mail' : 'SMTP nicht verbunden';
    }

    // UI umschalten
    $('#login-screen').classList.remove('active');
    $('#app-screen').classList.add('active');

    // Ordner + Nachrichten laden
    await loadFolders();
    await loadMessages('INBOX');

    // AI-Status prüfen
    try {
      const aiStatus = await api.aiStatus();
      state.aiAvailable = aiStatus.available || false;
    } catch { state.aiAvailable = false; }

  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.style.display = '';
  } finally {
    btn.disabled = false;
    btnText.style.display = '';
    btnLoading.style.display = 'none';
  }
});

// ═══════════════════════════════════════════════════════════
//  ORDNER
// ═══════════════════════════════════════════════════════════
const FOLDER_ICONS = {
  '\\Inbox': '◼',
  '\\Sent': '△',
  '\\Drafts': '◇',
  '\\Trash': '✕',
  '\\Junk': '⚑',
  '\\Archive': '▤',
  '\\Flagged': '★',
  '\\All': '◉',
  '\\Important': '!',
};

function getFolderIcon(folder) {
  if (folder.specialUse) {
    return FOLDER_ICONS[folder.specialUse] || '▪';
  }
  const name = folder.name.toLowerCase();
  if (name === 'inbox') return '◼';
  if (name.includes('sent')) return '△';
  if (name.includes('draft')) return '◇';
  if (name.includes('trash') || name.includes('papierkorb')) return '✕';
  if (name.includes('spam') || name.includes('junk')) return '⚑';
  if (name.includes('archive') || name.includes('archiv')) return '▤';
  return '▪';
}

async function loadFolders() {
  const container = $('#folder-list');
  container.innerHTML = '<div class="loading-indicator">Lade Ordner…</div>';

  try {
    const data = await api.folders();
    state.folders = data.folders || [];

    container.innerHTML = '';
    for (const folder of state.folders) {
      const el = document.createElement('div');
      el.className = `folder-item${folder.path === state.currentFolder ? ' active' : ''}`;
      el.innerHTML = `
        <span class="folder-icon">${getFolderIcon(folder)}</span>
        <span class="folder-name">${escapeHtml(folder.name)}</span>
      `;
      el.addEventListener('click', () => selectFolder(folder.path));
      container.appendChild(el);
    }
  } catch (err) {
    container.innerHTML = `<div class="loading-indicator" style="color:var(--danger)">Fehler: ${escapeHtml(err.message)}</div>`;
  }
}

function selectFolder(path) {
  state.currentFolder = path;
  // Aktiven Ordner markieren
  $$('.folder-item').forEach(el => el.classList.remove('active'));
  $$('.folder-item').forEach(el => {
    if (el.querySelector('.folder-name').textContent === path.split('/').pop()) {
      el.classList.add('active');
    }
  });
  loadMessages(path);
}

// ═══════════════════════════════════════════════════════════
//  NACHRICHTEN-LISTE (Header Only – Schicht 2)
// ═══════════════════════════════════════════════════════════
async function loadMessages(folder) {
  const container = $('#message-list');
  const folderName = $('#current-folder-name');
  folderName.textContent = folder.split('/').pop().toUpperCase();

  container.innerHTML = '<div class="loading-indicator">Lade Nachrichten…</div>';

  // Detail schließen
  closeDetail();

  try {
    const data = await api.messages(folder);
    state.messages = data.messages || [];

    if (state.messages.length === 0) {
      container.innerHTML = '<div class="empty-state"><p>Keine Nachrichten</p></div>';
      return;
    }

    container.innerHTML = '';
    state.selectedUids.clear();
    updateBulkBar();
    const isGmail = document.documentElement.getAttribute('data-layout') === 'gmail';

    for (const msg of state.messages) {
      const el = document.createElement('div');
      el.className = `message-item${!msg.seen ? ' unread' : ''}`;
      el.dataset.uid = msg.uid;

      const fromName = msg.from?.[0]?.name || msg.from?.[0]?.address || 'Unbekannt';
      const date = formatDate(msg.date);
      const subject = msg.subject || '(Kein Betreff)';
      const snippet = msg.snippet || '';

      if (isGmail) {
        // Gmail-Layout: Checkbox + Star + From | Subject - Snippet | Icons | Date
        el.innerHTML = `
          <input type="checkbox" class="msg-checkbox" data-uid="${msg.uid}">
          <span class="msg-star">${msg.flagged ? '★' : '☆'}</span>
          <span class="msg-from">${escapeHtml(fromName)}</span>
          <span class="msg-subject-line">
            <span class="msg-subject">${escapeHtml(subject)}</span>${snippet ? `<span class="msg-snippet"> – ${escapeHtml(snippet)}</span>` : ''}
          </span>
          <span class="msg-icons">${msg.hasAttachments ? '📎' : ''}</span>
          <span class="msg-date">${date}</span>
        `;
      } else {
        // Klassisches Layout
        el.innerHTML = `
          <div class="msg-top-row">
            <span class="msg-from">${escapeHtml(fromName)}</span>
            <span class="msg-date">${date}</span>
          </div>
          <div class="msg-subject">${escapeHtml(subject)}</div>
          <div class="msg-indicators">
            ${msg.hasAttachments ? '<span class="indicator attachment">📎</span>' : ''}
            ${msg.flagged ? '<span class="indicator flagged">★</span>' : ''}
          </div>
        `;
      }

      el.addEventListener('click', (e) => {
        // Checkbox-Klick nicht als Mail-Öffnen behandeln
        if (e.target.classList.contains('msg-checkbox')) return;
        openMessage(msg.uid);
      });
      container.appendChild(el);
    }
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p style="color:var(--danger)">Fehler: ${escapeHtml(err.message)}</p></div>`;
  }
}

// ═══════════════════════════════════════════════════════════
//  NACHRICHT ÖFFNEN (Lazy Loading – Schicht 2+3+4)
// ═══════════════════════════════════════════════════════════
async function openMessage(uid, allowImages = false) {
  state.currentUid = uid;

  // Aktive Nachricht markieren
  $$('.message-item').forEach(el => {
    el.classList.toggle('active', parseInt(el.dataset.uid) === uid);
    if (parseInt(el.dataset.uid) === uid) el.classList.remove('unread');
  });

  const detailContent = $('#detail-content');
  const section = $('#message-detail');
  section.classList.add('has-message');
  detailContent.hidden = false;
  detailContent.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:center;height:100%">
      <span class="spinner" style="width:24px;height:24px;border-color:var(--accent);border-top-color:transparent"></span>
    </div>
  `;

  // Responsive: Detail anzeigen
  const layout = $('.app-layout');
  layout.classList.add('show-detail');
  // Gmail-Layout: Liste ausblenden, Detail einblenden
  if (document.documentElement.getAttribute('data-layout') === 'gmail') {
    layout.classList.add('gmail-show-detail');
  }

  try {
    const msg = await api.message(state.currentFolder, uid, allowImages);
    renderMessage(msg, uid);
  } catch (err) {
    detailContent.innerHTML = `<div class="empty-state"><p style="color:var(--danger)">Fehler: ${escapeHtml(err.message)}</p></div>`;
  }
}

function renderMessage(msg, uid) {
  const detailContent = $('#detail-content');

  // Adressen formatieren
  const fromStr = msg.from?.map(a => a.name ? `${a.name} <${a.address}>` : a.address).join(', ') || '–';
  const toStr = msg.to?.map(a => a.name ? `${a.name} <${a.address}>` : a.address).join(', ') || '–';
  const dateStr = msg.date ? new Date(msg.date).toLocaleString('de-DE', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  }) : '–';

  const hasBlockedImages = msg.blockedImages && msg.blockedImages.length > 0;
  const hasAttachments = msg.attachments && msg.attachments.length > 0;
  const hasSecurityWarnings = msg.securityWarnings && msg.securityWarnings.length > 0;

  detailContent.hidden = false;
  detailContent.innerHTML = `
    ${hasSecurityWarnings ? `
      <div class="security-warning-bar">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <div>
          <strong>Sicherheitswarnung</strong>
          ${msg.securityWarnings.map(w => `<div>${escapeHtml(w)}</div>`).join('')}
        </div>
      </div>
    ` : ''}
    <div class="detail-header">
      <button class="btn-icon btn-back" data-action="close-detail" title="Zurück">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
      </button>
      <div class="detail-meta">
        <h2>${escapeHtml(msg.subject || '(Kein Betreff)')}</h2>
        <div class="detail-addresses">
          <div class="detail-from">
            <span class="label">Von</span>
            <span>${escapeHtml(fromStr)}</span>
          </div>
          <div class="detail-to">
            <span class="label">An</span>
            <span>${escapeHtml(toStr)}</span>
          </div>
          <div class="detail-date">${dateStr}</div>
        </div>
      </div>
      <div class="detail-actions">
        ${hasBlockedImages ? `
          <button class="btn-small" data-action="allow-images" data-uid="${uid}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
            Bilder laden
          </button>
        ` : ''}
      </div>
    </div>

    <div class="detail-reply-actions">
      ${state.smtpReady ? `
        <button class="btn-reply" data-action="reply" data-uid="${uid}">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 00-4-4H4"/></svg>
          Antworten
        </button>
        <button class="btn-reply" data-action="reply-all" data-uid="${uid}">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="9 17 4 12 9 7"/><polyline points="15 17 10 12 15 7"/><path d="M20 18v-2a4 4 0 00-4-4H4"/></svg>
          Allen antworten
        </button>
        <button class="btn-reply" data-action="forward" data-uid="${uid}">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="15 17 20 12 15 7"/><path d="M4 18v-2a4 4 0 014-4h12"/></svg>
          Weiterleiten
        </button>
      ` : ''}
      <button class="btn-reply btn-delete" data-action="delete" data-uid="${uid}">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
        Löschen
      </button>
    </div>

    ${hasBlockedImages ? `
      <div class="blocked-images-bar">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span>${msg.blockedImages.length} externe(s) Bild(er) blockiert (Tracking-Schutz)</span>
        <button class="btn-tiny" data-action="allow-images" data-uid="${uid}">Freigeben</button>
      </div>
    ` : ''}

    ${hasAttachments ? `
      <div class="attachments-bar">
        <div class="attachments-label">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/></svg>
          ${msg.attachments.length} Anhang/Anhänge
        </div>
        <div class="attachments-list">
          ${msg.attachments.map((att, i) => {
            const sec = att.security || {};
            if (sec.blocked) {
              return `<span class="attachment-chip attachment-blocked" title="${escapeHtml(sec.warnings?.join('; ') || 'Blockiert')}">
                ⛔ ${escapeHtml(att.filename)}
                <span class="attachment-size">BLOCKIERT</span>
              </span>`;
            }
            const riskClass = sec.risk === 'suspicious' ? ' attachment-suspicious' : '';
            return `<a href="/api/attachment/${att.downloadToken}"
               class="attachment-chip${riskClass}" download="${escapeHtml(att.filename)}" target="_blank" rel="noopener noreferrer"
               ${sec.warnings?.length ? `title="${escapeHtml(sec.warnings.join('; '))}"` : ''}>
              ${getFileIcon(att.contentType)} ${escapeHtml(att.filename)}
              ${att.size ? `<span class="attachment-size">${formatSize(att.size)}</span>` : ''}
              ${sec.risk === 'suspicious' ? '<span class="attachment-warn">⚠</span>' : ''}
            </a>`;
          }).join('')}
        </div>
      </div>
    ` : ''}

    <div class="detail-body-wrapper">
      ${msg.html
        ? `<div class="detail-body active">
             <iframe id="html-frame" sandbox="allow-same-origin" class="mail-iframe"></iframe>
           </div>`
        : `<div class="detail-body active">
             <pre class="text-content">${escapeHtml(msg.text || '(Kein Text-Inhalt)')}</pre>
           </div>`
      }
    </div>
  `;

  // HTML in Iframe rendern (isoliert vom Haupt-DOM)
  const iframe = detailContent.querySelector('#html-frame');
  if (msg.html) {
    iframe.addEventListener('load', () => {
      const doc = iframe.contentDocument;
      doc.open();
      // Theme-Farben aus CSS-Variablen lesen
      const cs = getComputedStyle(document.documentElement);
      const mailBg = cs.getPropertyValue('--mail-body-bg').trim() || '#ffffff';
      const mailText = cs.getPropertyValue('--mail-body-text').trim() || '#333';
      const mailLink = cs.getPropertyValue('--mail-body-link').trim() || '#8b6b4a';
      const accentColor = cs.getPropertyValue('--accent').trim() || '#c4956a';

      doc.write(`
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body {
              font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
              font-size: 14px;
              line-height: 1.6;
              color: ${mailText};
              background: ${mailBg};
              padding: 1.5rem;
              margin: 0;
              word-break: break-word;
              max-width: 100%;
              overflow-x: hidden;
            }
            img { max-width: 100%; height: auto; }
            a { color: ${mailLink}; }
            table { max-width: 100%; border-collapse: collapse; }
            td, th { padding: 4px 8px; }
            pre, code { font-family: 'JetBrains Mono', monospace; font-size: 0.9em; }
            blockquote {
              border-left: 3px solid ${accentColor}44;
              margin: 0.5em 0;
              padding-left: 1em;
              opacity: 0.8;
            }
            .blocked-image {
              display: inline-block;
              background: ${accentColor}15;
              border: 1px dashed ${accentColor};
              color: ${mailLink};
              padding: 8px 12px;
              font-size: 12px;
              border-radius: 3px;
            }
          </style>
        </head>
        <body>${msg.html}</body>
        </html>
      `);
      doc.close();

      // Iframe-Höhe automatisch anpassen
      setTimeout(() => {
        try {
          const h = doc.body.scrollHeight;
          iframe.style.height = Math.max(400, h + 40) + 'px';
        } catch {}
      }, 100);
    });
    // Trigger load
    iframe.src = 'about:blank';
  }
}

function closeDetail() {
  state.currentUid = null;
  const detailContent = $('#detail-content');
  if (detailContent) detailContent.hidden = true;
  const section = $('#message-detail');
  if (section) section.classList.remove('has-message');
  $$('.message-item').forEach(el => el.classList.remove('active'));
  const layout = $('.app-layout');
  if (layout) {
    layout.classList.remove('show-detail');
    layout.classList.remove('gmail-show-detail');
  }
}

// ═══════════════════════════════════════════════════════════
//  UI HELPERS
// ═══════════════════════════════════════════════════════════
function formatDate(dateStr) {
  if (!dateStr) return '–';
  const d = new Date(dateStr);
  const now = new Date();
  const diff = now - d;

  if (diff < 86400000 && d.getDate() === now.getDate()) {
    return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
  }
  if (diff < 604800000) {
    return d.toLocaleDateString('de-DE', { weekday: 'short' });
  }
  if (d.getFullYear() === now.getFullYear()) {
    return d.toLocaleDateString('de-DE', { day: 'numeric', month: 'short' });
  }
  return d.toLocaleDateString('de-DE', { day: 'numeric', month: 'short', year: '2-digit' });
}

function formatSize(bytes) {
  if (!bytes) return '';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function getFileIcon(contentType) {
  if (!contentType) return '📄';
  if (contentType.startsWith('image/')) return '🖼';
  if (contentType.includes('pdf')) return '📕';
  if (contentType.includes('zip') || contentType.includes('archive')) return '📦';
  if (contentType.includes('spreadsheet') || contentType.includes('excel')) return '📊';
  if (contentType.includes('document') || contentType.includes('word')) return '📝';
  if (contentType.includes('audio')) return '🎵';
  if (contentType.includes('video')) return '🎬';
  return '📄';
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ═══════════════════════════════════════════════════════════
//  TOAST NOTIFICATIONS
// ═══════════════════════════════════════════════════════════
function showToast(message, type = 'info', duration = 3000) {
  let container = $('#toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ'}</span>
    <span class="toast-message">${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  // Einblenden
  requestAnimationFrame(() => toast.classList.add('visible'));

  // Ausblenden + entfernen
  setTimeout(() => {
    toast.classList.remove('visible');
    toast.addEventListener('transitionend', () => toast.remove());
  }, duration);
}

// ═══════════════════════════════════════════════════════════
//  COMPOSE / REPLY / FORWARD
// ═══════════════════════════════════════════════════════════

function openCompose({ title = 'Neue Nachricht', to = '', cc = '', subject = '', body = '', inReplyTo = '', references = '', aiContext = null } = {}) {
  const overlay = $('#compose-overlay');
  overlay.classList.add('open');

  $('#compose-title').textContent = title;
  $('#compose-from').value = state.user;
  $('#compose-to').value = to;
  $('#compose-cc').value = cc;
  $('#compose-bcc').value = '';
  $('#compose-subject').value = subject;
  $('#compose-body').value = body;
  $('#compose-in-reply-to').value = inReplyTo;
  $('#compose-references').value = references;
  $('#compose-status').textContent = '';
  $('#compose-status').className = 'compose-status';

  // AI-Kontext speichern
  state.composeContext = aiContext;

  // AI-Assist ein-/ausblenden
  const aiBlock = $('#ai-assist');
  if (aiBlock) {
    aiBlock.hidden = !state.aiAvailable;
    const instrInput = $('#ai-instructions');
    if (instrInput) instrInput.value = '';
  }

  // CC anzeigen wenn vorausgefüllt
  const hasCc = cc.trim().length > 0;
  $('.compose-cc-field').hidden = !hasCc;
  $('.compose-bcc-field').hidden = true;
  const toggleBtn = $('#toggle-cc');
  if (toggleBtn) toggleBtn.classList.toggle('active', hasCc);

  // Cursor ins richtige Feld setzen
  setTimeout(() => {
    if (to && state.aiAvailable) {
      $('#ai-instructions')?.focus();
    } else if (to) {
      $('#compose-body').focus();
      $('#compose-body').setSelectionRange(0, 0);
    } else {
      $('#compose-to').focus();
    }
  }, 100);
}

function closeCompose() {
  const overlay = $('#compose-overlay');
  overlay.classList.remove('open');
  // Formular zurücksetzen
  $('#compose-form').reset();
}

async function handleReply(uid, replyAll = false) {
  try {
    const data = await api.reply(state.currentFolder, uid, replyAll);
    if (data.error) throw new Error(data.details || data.error);

    // Original-Mail-Daten für AI-Kontext finden
    const origMsg = state.messages.find(m => m.uid === uid);

    openCompose({
      title: replyAll ? 'Allen antworten' : 'Antworten',
      to: data.to || '',
      cc: data.cc || '',
      subject: data.subject || '',
      body: '\n' + (data.quotedText || ''),
      inReplyTo: data.inReplyTo || '',
      references: data.references || '',
      aiContext: {
        mode: 'reply',
        originalFrom: origMsg?.from?.[0]?.name || origMsg?.from?.[0]?.address || data.to,
        originalSubject: data.subject || '',
        originalBody: data.quotedText?.replace(/^> /gm, '') || '',
      },
    });
  } catch (err) {
    console.error('Reply-Fehler:', err);
    showToast('Antwort konnte nicht vorbereitet werden: ' + err.message, 'error');
  }
}

async function handleForward(uid) {
  try {
    const data = await api.forward(state.currentFolder, uid);
    if (data.error) throw new Error(data.details || data.error);

    openCompose({
      title: 'Weiterleiten',
      to: '',
      cc: '',
      subject: data.subject || '',
      body: '\n' + (data.quotedText || ''),
      inReplyTo: '',
      references: '',
      aiContext: {
        mode: 'new',
        originalFrom: '',
        originalSubject: data.subject || '',
        originalBody: data.quotedText || '',
      },
    });
  } catch (err) {
    console.error('Forward-Fehler:', err);
    showToast('Weiterleitung konnte nicht vorbereitet werden: ' + err.message, 'error');
  }
}

function setSendLoading(loading) {
  const btn = $('#compose-send-btn');
  const btnText = btn.querySelector('.btn-text');
  const btnLoading = btn.querySelector('.btn-loading');
  btn.disabled = loading;
  btnText.style.display = loading ? 'none' : '';
  btnLoading.style.display = loading ? 'inline-flex' : 'none';
}

async function handleDelete(uid) {
  try {
    const result = await api.deleteMsg(state.currentFolder, uid);
    if (result.error) throw new Error(result.details || result.error);

    // Detail schließen
    closeDetail();

    // Nachricht aus der Liste entfernen
    const item = document.querySelector(`.message-item[data-uid="${uid}"]`);
    if (item) {
      item.style.transition = 'opacity 0.3s, transform 0.3s';
      item.style.opacity = '0';
      item.style.transform = 'translateX(20px)';
      setTimeout(() => item.remove(), 300);
    }

    // Aus State entfernen
    state.messages = state.messages.filter(m => m.uid !== uid);

    const info = result.action === 'moved'
      ? `In Papierkorb verschoben`
      : 'Endgültig gelöscht';
    showToast(info, 'success');
  } catch (err) {
    showToast('Löschen fehlgeschlagen: ' + err.message, 'error');
  }
}

async function sendMail() {
  const statusEl = $('#compose-status');
  setSendLoading(true);
  statusEl.textContent = '';

  try {
    const mail = {
      to: $('#compose-to').value.trim(),
      cc: $('#compose-cc').value.trim() || undefined,
      bcc: $('#compose-bcc').value.trim() || undefined,
      subject: $('#compose-subject').value,
      text: $('#compose-body').value,
      inReplyTo: $('#compose-in-reply-to').value || undefined,
      references: $('#compose-references').value || undefined,
    };

    if (!mail.to) throw new Error('Bitte einen Empfänger angeben.');

    const result = await api.send(mail);
    if (result.error) throw new Error(result.details || result.error);

    setSendLoading(false);
    statusEl.textContent = '✓ Gesendet';
    statusEl.className = 'compose-status success';

    // Nach 1.2s schließen
    setTimeout(() => closeCompose(), 1200);

  } catch (err) {
    setSendLoading(false);
    statusEl.textContent = `✕ ${err.message}`;
    statusEl.className = 'compose-status error';
  }
}

// ═══════════════════════════════════════════════════════════
//  EVENT LISTENERS
// ═══════════════════════════════════════════════════════════

// Refresh
document.addEventListener('click', (e) => {
  if (e.target.closest('#refresh-btn')) {
    loadMessages(state.currentFolder);
  }
});

// Zentrale Event-Delegation für dynamische Buttons (data-action)
// Nötig weil CSP inline onclick blockiert
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;
  const uid = parseInt(btn.dataset.uid);
  switch (action) {
    case 'close-detail': closeDetail(); break;
    case 'allow-images': openMessage(uid, true); break;
    case 'reply':        handleReply(uid, false); break;
    case 'reply-all':    handleReply(uid, true); break;
    case 'forward':      handleForward(uid); break;
    case 'delete':       handleDelete(uid); break;
  }
});

// Zurück-Button (auch .btn-back ohne data-action, z.B. aus statischem HTML)
document.addEventListener('click', (e) => {
  if (e.target.closest('#close-detail') || e.target.closest('.btn-back:not([data-action])')) {
    closeDetail();
  }
});

// Disconnect
document.addEventListener('click', (e) => {
  if (e.target.closest('#disconnect-btn')) {
    api.disconnect().then(() => {
      state.connected = false;
      state.smtpReady = false;
      $('#app-screen').classList.remove('active');
      $('#login-screen').classList.add('active');
      closeCompose();
    });
  }
});

// Settings
document.addEventListener('click', (e) => {
  if (e.target.closest('#settings-btn')) openSettings();
  if (e.target.closest('#settings-close')) closeSettings();
  if (e.target.id === 'settings-overlay') closeSettings();

  // Theme-Card geklickt
  const card = e.target.closest('.theme-card');
  if (card && card.dataset.theme) {
    applyTheme(card.dataset.theme);
  }
  // Layout-Card geklickt
  const layoutCard = e.target.closest('.layout-card');
  if (layoutCard && layoutCard.dataset.layout) {
    applyLayout(layoutCard.dataset.layout);
  }
});

// Compose: Neue E-Mail
document.addEventListener('click', (e) => {
  if (e.target.closest('#compose-btn')) {
    if (!state.smtpReady) {
      showToast('SMTP-Verbindung nicht aktiv. Senden ist nicht möglich.', 'error');
      return;
    }
    openCompose();
  }
});

// Compose: Schließen
document.addEventListener('click', (e) => {
  if (e.target.closest('#compose-close')) {
    closeCompose();
  }
});

// Compose: Overlay-Klick (außerhalb Modal) schließt
document.addEventListener('click', (e) => {
  if (e.target.id === 'compose-overlay') {
    closeCompose();
  }
});

// Compose: CC/BCC Toggle
document.addEventListener('click', (e) => {
  if (e.target.closest('#toggle-cc')) {
    const ccField = $('.compose-cc-field');
    const bccField = $('.compose-bcc-field');
    const isHidden = ccField.hidden;
    ccField.hidden = !isHidden;
    bccField.hidden = !isHidden;
    e.target.closest('#toggle-cc').classList.toggle('active', isHidden);
    if (isHidden) $('#compose-cc').focus();
  }
});

// Compose: Senden
$('#compose-form').addEventListener('submit', (e) => {
  e.preventDefault();
  sendMail();
});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  // Escape: Detail schließen oder Compose schließen
  if (e.key === 'Escape') {
    const composeOverlay = $('#compose-overlay');
    if (composeOverlay && composeOverlay.classList.contains('open')) {
      closeCompose();
    } else if (state.currentUid) {
      closeDetail();
    }
  }

  // Cmd/Ctrl+Enter: Senden (wenn Compose offen)
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
    const composeOverlay = $('#compose-overlay');
    if (composeOverlay && composeOverlay.classList.contains('open')) {
      e.preventDefault();
      sendMail();
    }
  }

  // R: Antworten (wenn Detail offen und kein Input fokussiert)
  if (e.key === 'r' && !e.metaKey && !e.ctrlKey && state.currentUid && !isInputFocused()) {
    e.preventDefault();
    handleReply(state.currentUid, e.shiftKey);
  }

  // F: Weiterleiten
  if (e.key === 'f' && !e.metaKey && !e.ctrlKey && state.currentUid && !isInputFocused()) {
    e.preventDefault();
    handleForward(state.currentUid);
  }

  // Delete/Backspace: Löschen
  if ((e.key === 'Delete' || e.key === 'Backspace') && state.currentUid && !isInputFocused()) {
    e.preventDefault();
    handleDelete(state.currentUid);
  }

  // N: Neue Mail
  if (e.key === 'n' && !e.metaKey && !e.ctrlKey && state.smtpReady && !isInputFocused()) {
    e.preventDefault();
    openCompose();
  }
});

function isInputFocused() {
  const tag = document.activeElement?.tagName?.toLowerCase();
  return tag === 'input' || tag === 'textarea' || tag === 'select';
}

// ═══════════════════════════════════════════════════════════
//  CHECKBOX / MULTI-SELECT
// ═══════════════════════════════════════════════════════════
document.addEventListener('change', (e) => {
  if (!e.target.classList.contains('msg-checkbox')) return;
  const uid = parseInt(e.target.dataset.uid);
  if (e.target.checked) {
    state.selectedUids.add(uid);
  } else {
    state.selectedUids.delete(uid);
  }
  // Zeile visuell markieren
  const row = e.target.closest('.message-item');
  if (row) row.classList.toggle('selected', e.target.checked);
  updateBulkBar();
});

function updateBulkBar() {
  const bar = $('#bulk-actions');
  const count = $('#bulk-count');
  if (!bar) return;
  if (state.selectedUids.size > 0) {
    bar.hidden = false;
    count.textContent = `${state.selectedUids.size} ausgewählt`;
  } else {
    bar.hidden = true;
  }
}

// Bulk Actions
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-action="bulk-delete"]');
  if (btn && state.selectedUids.size > 0) {
    handleBulkDelete();
  }
  const desel = e.target.closest('[data-action="bulk-deselect"]');
  if (desel) {
    state.selectedUids.clear();
    $$('.msg-checkbox').forEach(cb => { cb.checked = false; });
    $$('.message-item.selected').forEach(el => el.classList.remove('selected'));
    updateBulkBar();
  }
});

async function handleBulkDelete() {
  const uids = [...state.selectedUids];
  const count = uids.length;
  try {
    const result = await api.deleteBulk(state.currentFolder, uids);
    if (result.success) {
      showToast(`${count} Nachricht${count > 1 ? 'en' : ''} gelöscht`, 'success');
      state.selectedUids.clear();
      updateBulkBar();
      loadMessages(state.currentFolder);
    } else {
      showToast(result.error || 'Löschen fehlgeschlagen', 'error');
    }
  } catch (err) {
    showToast('Fehler: ' + err.message, 'error');
  }
}

// ═══════════════════════════════════════════════════════════
//  SEARCH
// ═══════════════════════════════════════════════════════════
(function initSearch() {
  const input = $('#search-input');
  const clearBtn = $('#search-clear');
  if (!input) return;

  let searchTimeout;

  input.addEventListener('input', () => {
    clearBtn.hidden = !input.value;
    clearTimeout(searchTimeout);
    if (input.value.length >= 2) {
      searchTimeout = setTimeout(() => performSearch(input.value), 400);
    } else if (input.value.length === 0) {
      clearSearch();
    }
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && input.value.length >= 2) {
      clearTimeout(searchTimeout);
      performSearch(input.value);
    }
    if (e.key === 'Escape') {
      clearSearch();
      input.blur();
    }
  });

  clearBtn.addEventListener('click', () => {
    clearSearch();
  });
})();

async function performSearch(query) {
  state.searchQuery = query;
  state.isSearching = true;
  const container = $('#message-list');
  const folderName = $('#current-folder-name');

  container.innerHTML = '<div class="loading-indicator">Suche…</div>';
  folderName.textContent = `Suche: "${query}"`;

  try {
    const data = await api.search(state.currentFolder, query);
    state.messages = data.messages || [];

    if (state.messages.length === 0) {
      container.innerHTML = '<div class="empty-state"><p>Keine Treffer</p></div>';
      return;
    }

    // Reuse existing render logic
    container.innerHTML = '';
    state.selectedUids.clear();
    updateBulkBar();
    const isGmail = document.documentElement.getAttribute('data-layout') === 'gmail';

    for (const msg of state.messages) {
      const el = document.createElement('div');
      el.className = `message-item${!msg.seen ? ' unread' : ''}`;
      el.dataset.uid = msg.uid;

      const fromName = msg.from?.[0]?.name || msg.from?.[0]?.address || 'Unbekannt';
      const date = formatDate(msg.date);
      const subject = msg.subject || '(Kein Betreff)';

      if (isGmail) {
        el.innerHTML = `
          <input type="checkbox" class="msg-checkbox" data-uid="${msg.uid}">
          <span class="msg-star">${msg.flagged ? '★' : '☆'}</span>
          <span class="msg-from">${escapeHtml(fromName)}</span>
          <span class="msg-subject-line">
            <span class="msg-subject">${escapeHtml(subject)}</span>
          </span>
          <span class="msg-icons">${msg.hasAttachments ? '📎' : ''}</span>
          <span class="msg-date">${date}</span>
        `;
      } else {
        el.innerHTML = `
          <div class="msg-top-row">
            <span class="msg-from">${escapeHtml(fromName)}</span>
            <span class="msg-date">${date}</span>
          </div>
          <div class="msg-subject">${escapeHtml(subject)}</div>
        `;
      }

      el.addEventListener('click', (e) => {
        if (e.target.classList.contains('msg-checkbox')) return;
        openMessage(msg.uid);
      });
      container.appendChild(el);
    }
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p style="color:var(--danger)">Suche fehlgeschlagen: ${escapeHtml(err.message)}</p></div>`;
  }
}

function clearSearch() {
  const input = $('#search-input');
  const clearBtn = $('#search-clear');
  if (input) input.value = '';
  if (clearBtn) clearBtn.hidden = true;
  state.searchQuery = '';
  state.isSearching = false;
  if (state.connected) {
    loadMessages(state.currentFolder);
  }
}

// ═══════════════════════════════════════════════════════════
//  AI GENERATE
// ═══════════════════════════════════════════════════════════
document.addEventListener('click', (e) => {
  if (!e.target.closest('[data-action="ai-generate"]')) return;
  handleAiGenerate();
});

// Enter in AI-Input = Generieren
document.addEventListener('keydown', (e) => {
  if (e.target.id === 'ai-instructions' && e.key === 'Enter') {
    e.preventDefault();
    handleAiGenerate();
  }
});

async function handleAiGenerate() {
  const input = $('#ai-instructions');
  const btn = $('#ai-generate-btn');
  const instructions = input?.value?.trim();

  if (!instructions || instructions.length < 3) {
    showToast('Bitte Anweisungen eingeben (mind. 3 Zeichen)', 'error');
    input?.focus();
    return;
  }

  // Loading-State
  const btnText = btn.querySelector('.btn-text');
  const btnLoading = btn.querySelector('.btn-loading');
  btn.disabled = true;
  btnText.style.display = 'none';
  btnLoading.style.display = 'inline-flex';

  try {
    const ctx = state.composeContext || {};
    const result = await api.aiGenerate({
      instructions,
      mode: ctx.mode || 'new',
      originalFrom: ctx.originalFrom || '',
      originalSubject: ctx.originalSubject || '',
      originalBody: ctx.originalBody || '',
    });

    if (result.error) throw new Error(result.details || result.error);

    // Generierten Text in den Body einsetzen (vor dem zitierten Text)
    const body = $('#compose-body');
    const existingText = body.value;
    const quoteStart = existingText.indexOf('\n\nAm ');
    const fwdStart = existingText.indexOf('\n\n---------- Weitergeleitete');

    const splitPos = quoteStart > 0 ? quoteStart : (fwdStart > 0 ? fwdStart : -1);

    if (splitPos > 0) {
      body.value = result.text + existingText.slice(splitPos);
    } else {
      body.value = result.text;
    }

    showToast('AI-Antwort generiert ✓', 'success');
    body.focus();
  } catch (err) {
    showToast('AI-Fehler: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btnText.style.display = '';
    btnLoading.style.display = 'none';
  }
}

// ── Make global ──
window.closeDetail = closeDetail;
window.openMessage = openMessage;
window.handleReply = handleReply;
window.handleForward = handleForward;
window.handleDelete = handleDelete;
window.openCompose = openCompose;
window.closeCompose = closeCompose;
