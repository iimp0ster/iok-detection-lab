'use strict';

/* ── Constants ──────────────────────────────────────────────────────── */
const API = '/api';   // all endpoints under /api/

const KNOWN_CDN_HOSTS = [
  'ajax.googleapis.com', 'cdnjs.cloudflare.com', 'cdn.jsdelivr.net',
  'code.jquery.com', 'cdn.jquery.com', 'maxcdn.bootstrapcdn.com',
  'stackpath.bootstrapcdn.com', 'fonts.googleapis.com', 'fonts.gstatic.com',
  'cdn.cloudflare.com', 'unpkg.com',
];
const SUSPICIOUS_TLDS = ['.ru', '.xyz', '.top', '.cn', '.tk', '.pw', '.cc', '.su'];
const GATE_RE = /gate|collect|post|send|submit/i;
const PHP_RE  = /\.php(\?|$)/i;

/* ── State ──────────────────────────────────────────────────────────── */
const S = {
  singleResult:   null,
  requestsAll:    [],
  scannedHost:    '',
  batchResults:   [],
  batchSSE:       null,
  historyData:    [],
};

/* ══ Tabs ═══════════════════════════════════════════════════════════════ */
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
    if (btn.dataset.tab === 'history') loadHistory();
  });
});

/* ══ Single Scan ════════════════════════════════════════════════════════ */
document.getElementById('scan-btn').addEventListener('click', doScan);
document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') doScan();
});

async function doScan() {
  const url = document.getElementById('url-input').value.trim();
  if (!url) return;

  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = '◌ Scanning…';
  show('scan-status');
  hide('verdict-panel');

  try {
    const res = await fetchJSON(`${API}/scan`, { method: 'POST', body: { url } });
    S.singleResult = res;
    renderSingle(res);
  } catch (err) {
    alert(`Scan failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = '▶ SCAN via NL';
    hide('scan-status');
  }
}

function renderSingle(data) {
  const level = normaliseLevel(data.threat_level || 'none');
  const badge = document.getElementById('verdict-badge');
  badge.textContent = level;
  badge.className   = `verdict-badge badge-${level}`;

  document.getElementById('verdict-matches').textContent =
    `${data.detection_count} rule${data.detection_count !== 1 ? 's' : ''} matched`;

  const exitStr = data.exit_country
    ? `${data.exit_country} · ${data.exit_ip || ''}`
    : (data.exit_node || 'N/A');
  document.getElementById('verdict-exit').textContent = exitStr;
  document.getElementById('verdict-time').textContent =
    data.elapsed_ms ? `${(data.elapsed_ms / 1000).toFixed(2)}s`
    : data.analysis_time ? `${Number(data.analysis_time).toFixed(2)}s` : '';

  /* Rule matches */
  const list = document.getElementById('rules-list');
  list.innerHTML = '';
  (data.detections || []).forEach(d => {
    const lvl = normaliseLevel(d.level || 'low');
    const row = el('div', `rule-row level-${lvl.toLowerCase()}`);
    row.innerHTML =
      `<span class="rule-row-title">▸ ${esc(d.title || d.rule || '(unnamed)')}</span>` +
      `<span class="rule-row-level badge-${lvl} verdict-badge">${lvl}</span>`;
    list.appendChild(row);
  });

  /* Surface stats */
  const formsCount = data.forms_count ?? (data.forms || []).length;
  document.getElementById('surface-stats').innerHTML =
    stat('JS',       data.js_count       ?? 0) +
    stat('CSS',      data.css_count      ?? 0) +
    stat('Requests', data.requests_count ?? 0) +
    stat('Forms',    formsCount)               +
    stat('Cookies',  data.cookies_count  ?? 0);

  renderForms(data.forms || [], data.hostname);

  S.requestsAll = data.requests_detail || [];
  S.scannedHost = data.hostname || '';
  renderRequests(S.requestsAll, S.scannedHost);

  show('verdict-panel');
}

function renderForms(forms, scannedHost) {
  const list = document.getElementById('forms-list');
  list.innerHTML = '';
  if (!forms.length) { hide('forms-section'); return; }

  forms.forEach(f => {
    const action     = f.action || '';
    const method     = (f.method || 'GET').toUpperCase();
    const fields     = (f.fields || []).join(', ') || '—';
    const suspicious = PHP_RE.test(action) || GATE_RE.test(action);
    const row = el('div', `form-row${suspicious ? ' suspicious' : ''}`);
    row.innerHTML =
      `<span class="form-method">${esc(method)}</span>` +
      `<span class="form-action">${esc(action || '(same page)')}</span>` +
      `<span class="form-fields">[${esc(fields)}]</span>` +
      (suspicious ? `<span class="form-flag">← flagged</span>` : '');
    list.appendChild(row);
  });
  show('forms-section');
}

document.getElementById('req-filter').addEventListener('input', function() {
  const q = this.value.toLowerCase();
  const filtered = q
    ? S.requestsAll.filter(r => (r.url || '').toLowerCase().includes(q))
    : S.requestsAll;
  renderRequests(filtered, S.scannedHost);
});

function renderRequests(requests, scannedHost) {
  const list = document.getElementById('requests-list');
  list.innerHTML = '';
  if (!requests.length) { hide('requests-section'); return; }

  requests.forEach(r => {
    const colour = classifyRequest(r, scannedHost);
    const dot    = colour === 'red' ? '●' : colour === 'amber' ? '●' : colour === 'gray' ? '●' : '·';
    const row    = el('div', `req-row req-${colour}`);
    row.innerHTML =
      `<span class="req-dot">${dot}</span>` +
      `<span class="req-method">${esc((r.method || 'GET').toUpperCase())}</span>` +
      `<span class="req-path" title="${esc(r.url || '')}">${esc(r.path || r.url || '')}</span>` +
      `<span class="req-host">${esc(r.host || '')}</span>`;
    list.appendChild(row);
  });
  show('requests-section');
}

function classifyRequest(r, scannedHost) {
  const host = (r.host || '').toLowerCase();
  const path = (r.path || '').toLowerCase();
  if (PHP_RE.test(path) && GATE_RE.test(path)) return 'red';
  if (PHP_RE.test(path) && GATE_RE.test(r.url || '')) return 'red';
  if (host && KNOWN_CDN_HOSTS.some(c => host === c || host.endsWith('.' + c))) return 'gray';
  if (host && scannedHost && host !== scannedHost) {
    if (SUSPICIOUS_TLDS.some(t => host.endsWith(t))) return 'amber';
    return 'amber';
  }
  return 'white';
}

/* ══ Batch Hunt ═════════════════════════════════════════════════════════ */
document.getElementById('import-file').addEventListener('change', function() {
  const file = this.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => { document.getElementById('url-list').value = e.target.result.trim(); };
  reader.readAsText(file);
  this.value = '';
});

document.getElementById('clear-btn').addEventListener('click', () => {
  document.getElementById('url-list').value = '';
});

document.getElementById('batch-btn').addEventListener('click', startBatch);
document.getElementById('stop-btn').addEventListener('click', stopBatch);
document.getElementById('export-json-btn').addEventListener('click', exportJSON);
document.getElementById('export-csv-btn').addEventListener('click', exportCSV);

async function startBatch() {
  const raw  = document.getElementById('url-list').value.trim();
  const urls = raw.split('\n').map(u => u.trim()).filter(Boolean);
  if (!urls.length) { alert('Enter at least one URL.'); return; }

  S.batchResults = [];
  document.getElementById('batch-btn').classList.add('hidden');
  document.getElementById('stop-btn').classList.remove('hidden');
  document.getElementById('batch-results').innerHTML = '';
  document.getElementById('batch-bar').value = 0;
  document.getElementById('batch-counter').textContent = `0/${urls.length}`;
  document.getElementById('batch-high').textContent  = 'HIGH:0';
  document.getElementById('batch-med').textContent   = 'MED:0';
  document.getElementById('batch-clean').textContent = 'CLEAN:0';
  show('batch-progress');

  urls.forEach(u => appendBatchRow({ url: u, status: 'scanning' }));

  const rotateMode = document.querySelector('input[name="rotate"]:checked')?.value || 'none';

  try {
    const res = await fetchJSON(`${API}/batch`, {
      method: 'POST',
      body: {
        urls,
        concurrency:    parseInt(document.getElementById('concurrency').value, 10),
        delay_ms:       parseInt(document.getElementById('delay-ms').value, 10),
        use_vpn:        document.getElementById('vpn-toggle').checked,
        rotate_mode:    rotateMode,
        rotate_every_n: 5,
      },
    });
    const batchId = res.batch_id;
    if (!batchId) throw new Error('No batch_id in response');
    openBatchSSE(batchId, urls.length);
  } catch (err) {
    alert(`Batch start failed: ${err.message}`);
    document.getElementById('batch-btn').classList.remove('hidden');
    document.getElementById('stop-btn').classList.add('hidden');
  }
}

function openBatchSSE(batchId, total) {
  if (S.batchSSE) S.batchSSE.close();

  const sse = new EventSource(`${API}/batch/${batchId}/stream`);
  S.batchSSE = sse;

  let completed = 0, highCount = 0, medCount = 0, cleanCount = 0;

  const rowMap = {};
  document.querySelectorAll('#batch-results .batch-result-row').forEach(row => {
    rowMap[row.dataset.url] = row;
  });

  sse.onmessage = function(ev) {
    let data;
    try { data = JSON.parse(ev.data); } catch { return; }

    if (data.done) {
      sse.close(); S.batchSSE = null;
      document.getElementById('batch-btn').classList.remove('hidden');
      document.getElementById('stop-btn').classList.add('hidden');
      return;
    }
    if (data.error && !data.url) return;

    // Use progress object from SSE event if present
    if (data.progress) {
      completed  = data.progress.complete;
      const failed = data.progress.failed || 0;
    } else {
      completed++;
    }

    S.batchResults.push(data);
    const level = normaliseLevel(data.verdict || data.threat_level || 'none');
    if      (level === 'HIGH') highCount++;
    else if (level === 'MED')  medCount++;
    else                       cleanCount++;

    document.getElementById('batch-bar').value = Math.round(completed / total * 100);
    document.getElementById('batch-counter').textContent = `${completed}/${total}`;
    document.getElementById('batch-high').textContent    = `HIGH:${highCount}`;
    document.getElementById('batch-med').textContent     = `MED:${medCount}`;
    document.getElementById('batch-clean').textContent   = `CLEAN:${cleanCount}`;

    const existingRow = rowMap[data.url];
    if (existingRow) updateBatchRow(existingRow, data);
    else             appendBatchRow(data);
  };

  sse.onerror = function() {
    sse.close(); S.batchSSE = null;
    document.getElementById('batch-btn').classList.remove('hidden');
    document.getElementById('stop-btn').classList.add('hidden');
  };
}

function stopBatch() {
  if (S.batchSSE) { S.batchSSE.close(); S.batchSSE = null; }
  document.getElementById('batch-btn').classList.remove('hidden');
  document.getElementById('stop-btn').classList.add('hidden');
}

function appendBatchRow(data) {
  const li = el('li', 'batch-result-row' + (data.status === 'scanning' ? ' scanning' : ''));
  li.dataset.url = data.url || '';
  li.innerHTML   = batchRowHTML(data);
  document.getElementById('batch-results').appendChild(li);
  return li;
}

function updateBatchRow(row, data) {
  const level = normaliseLevel(data.verdict || data.threat_level || 'none');
  row.className  = `batch-result-row level-${level}`;
  row.innerHTML  = batchRowHTML(data);
}

function batchRowHTML(data) {
  if (data.status === 'scanning') {
    return `<span class="br-url">${esc(data.url || '')}</span>` +
           `<span class="verdict-badge badge-NONE">…</span>`;
  }
  const level   = normaliseLevel(data.verdict || data.threat_level || 'none');
  const matches = data.detection_count ?? 0;
  const elapsed = data.elapsed_ms
    ? `${(data.elapsed_ms / 1000).toFixed(1)}s`
    : data.analysis_time ? `${Number(data.analysis_time).toFixed(1)}s` : '—';
  const exit    = data.exit_country ? `${data.exit_country}` : 'N/A';
  return `<span class="br-url" title="${esc(data.url || '')}">${esc(data.url || '')}</span>` +
         `<span class="verdict-badge badge-${level}">${level}</span>` +
         `<span class="verdict-meta">${matches} match${matches !== 1 ? 'es' : ''}</span>` +
         `<span class="br-exit">${esc(exit)}</span>` +
         `<span class="br-time">${elapsed}</span>`;
}

function exportJSON() {
  download('iok-batch-results.json', JSON.stringify(S.batchResults, null, 2), 'application/json');
}

function exportCSV() {
  const cols   = ['url', 'verdict', 'detection_count', 'exit_country', 'exit_ip', 'elapsed_ms', 'timestamp'];
  const header = cols.map(csvCell).join(',');
  const rows   = S.batchResults.map(r => cols.map(c => csvCell(r[c] ?? '')).join(','));
  download('iok-batch-results.csv', [header, ...rows].join('\n'), 'text/csv');
}

/* ══ History ════════════════════════════════════════════════════════════ */
document.getElementById('history-search').addEventListener('input', function() {
  const q = this.value.toLowerCase();
  const filtered = q
    ? S.historyData.filter(h =>
        (h.url || '').toLowerCase().includes(q) ||
        (h.hostname || '').toLowerCase().includes(q))
    : S.historyData;
  renderHistory(filtered);
});

document.getElementById('refresh-history-btn').addEventListener('click', loadHistory);
document.getElementById('export-history-btn').addEventListener('click', () => {
  download('iok-history.json', JSON.stringify(S.historyData, null, 2), 'application/json');
});

async function loadHistory() {
  try {
    const data = await fetchJSON(`${API}/history`);
    S.historyData = Array.isArray(data) ? data : (data.history || []);
    renderHistory(S.historyData);
  } catch (err) {
    console.warn('History load failed:', err.message);
  }
}

function renderHistory(items) {
  const tbody = document.getElementById('history-body');
  const empty = document.getElementById('history-empty');
  tbody.innerHTML = '';
  if (!items.length) { show('history-empty'); return; }
  hide('history-empty');

  items.forEach(h => {
    const level = normaliseLevel(h.verdict || h.threat_level || 'none');
    const tr    = document.createElement('tr');
    tr.dataset.id = h.id || '';
    tr.innerHTML =
      `<td class="td-muted">${esc(fmtTime(h.timestamp))}</td>` +
      `<td class="td-url" title="${esc(h.url || '')}">${esc(h.url || '')}</td>` +
      `<td><span class="verdict-badge badge-${level}">${level}</span></td>` +
      `<td>${h.detection_count ?? 0}</td>` +
      `<td class="td-muted">${esc(h.exit_country || 'N/A')}</td>` +
      `<td class="td-muted">${h.elapsed_ms ? `${(h.elapsed_ms/1000).toFixed(1)}s` : '—'}</td>`;
    tr.addEventListener('click', () => loadHistoryRow(h));
    tbody.appendChild(tr);
  });
}

async function loadHistoryRow(summary) {
  // History rows from SQLite are summaries; switch tab and show what we have
  switchToSingle({
    ...summary,
    threat_level: summary.verdict || summary.threat_level,
    detections:   [],   // full detections not in history summary
  });
}

function switchToSingle(result) {
  document.querySelector('.tab[data-tab="single"]').click();
  document.getElementById('url-input').value = result.url || '';
  S.singleResult = result;
  renderSingle(result);
}

/* ══ Utilities ══════════════════════════════════════════════════════════ */
function normaliseLevel(raw) {
  const m = { high: 'HIGH', medium: 'MED', med: 'MED', low: 'LOW', none: 'NONE', clean: 'CLEAN' };
  return m[(raw || '').toLowerCase()] || (raw || 'NONE').toUpperCase();
}
function stat(label, n) { return `<span><b>${n}</b> ${label}</span>`; }
function el(tag, cls) { const e = document.createElement(tag); if (cls) e.className = cls; return e; }
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function show(id) { document.getElementById(id)?.classList.remove('hidden'); }
function hide(id) { document.getElementById(id)?.classList.add('hidden'); }
function fmtTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
  catch { return iso; }
}
function csvCell(v) { return `"${String(v ?? '').replace(/"/g, '""')}"`; }
function download(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(url);
}
async function fetchJSON(url, opts = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    body:    opts.body ? JSON.stringify(opts.body) : undefined,
    method:  opts.method || 'GET',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
