/* ============================================================
 * ZEPHYRUS DIGI ART — client console
 * E2E: AES-256-GCM, key derived from your passphrase locally.
 * The relay only ever sees ciphertext. The gallery lives in
 * YOUR browser (IndexedDB). Nothing is stored server-side.
 * ============================================================ */
'use strict';

/* ---------------- crypto ---------------- */
const SALT = new TextEncoder().encode('zephyrus-digi-art-v1');
const PBKDF2_ITERS = 200000;
let aesKey = null;

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const te = (s) => new TextEncoder().encode(s);
const td = (buf) => new TextDecoder().decode(buf);

async function deriveKey(psk) {
  const base = await crypto.subtle.importKey('raw', te(psk), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: SALT, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function seal(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, te(JSON.stringify(obj)));
  return { data: b64(ct), nonce: b64(iv.buffer) };
}

async function unseal(dataB64, nonceB64) {
  const iv = unb64(nonceB64);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, unb64(dataB64));
  return JSON.parse(td(pt));
}

/* ---------------- gate ---------------- */
const $ = (id) => document.getElementById(id);
const gate = $('gate'), app = $('app');

function unlockUI() {
  gate.classList.add('hidden');
  app.classList.remove('hidden');
  connectWS();
  refreshGallery();
}

$('unlock').onclick = async () => {
  const psk = $('psk').value.trim();
  const opkey = $('opkey').value.trim();
  if (opkey.length < 8) { $('gateNote').textContent = 'operator key required — this authenticates you to the relay.'; return; }
  if (psk.length < 8) { $('gateNote').textContent = 'passphrase must be at least 8 characters — this is your encryption key.'; return; }
  try {
    aesKey = await deriveKey(psk);
    await seal({ probe: true }); // verify key usable
    localStorage.setItem('zephyrus_psk', psk);
    localStorage.setItem('zephyrus_opkey', opkey);
    unlockUI();
  } catch (e) {
    $('gateNote').textContent = 'key derivation failed: ' + e.message;
  }
};
$('psk').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('unlock').click(); });

$('lockBtn').onclick = () => {
  if (!confirm('Forget the passphrase from this browser?')) return;
  localStorage.removeItem('zephyrus_psk');
  location.reload();
};

(async function boot() {
  const saved = localStorage.getItem('zephyrus_psk');
  const opkey = localStorage.getItem('zephyrus_opkey');
  if (saved && opkey) {
    try {
      aesKey = await deriveKey(saved);
      unlockUI();
    } catch { localStorage.removeItem('zephyrus_psk'); }
  }
})();

/* ---------------- toasts ---------------- */
function toast(msg, cls = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + cls;
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .4s'; }, 5200);
  setTimeout(() => el.remove(), 5700);
}

/* ---------------- websocket ---------------- */
let ws = null, wsBackoff = 1000, relayHost = null, coldAnnounced = false;
const jobsUI = new Map(); // job_id -> {el, prompt, seed, ts, state}

// the relay lives in a codespace behind a rotating cloudflared quick tunnel;
// the relay publishes its current URL to the link repo, we re-discover it
const RELAY_LINK = 'https://raw.githubusercontent.com/zahidSkywalker/zephyrus-link/main/relay_url.json';

async function discoverRelay() {
  try {
    const r = await fetch(RELAY_LINK + '?t=' + Date.now(), { cache: 'no-store' });
    const j = await r.json();
    if (j.url) {
      relayHost = new URL(j.url).host;
      localStorage.setItem('zephyrus_relay', j.url);
    }
  } catch {
    relayHost = (localStorage.getItem('zephyrus_relay') || '').replace(/^https?:\/\//, '') || null;
  }
  return relayHost;
}

function setCold() {
  const badge = $('statusBadge');
  badge.className = 'badge offline';
  badge.textContent = 'RELAY COLD';
  $('wakeBtn').disabled = false;
  $('stopBtn').disabled = true;
}

async function connectWS() {
  const host = await discoverRelay();
  if (!host) {
    setCold();
    if (!coldAnnounced) {
      coldAnnounced = true;
      toast('relay is cold — say "wake relay" in #echo and Echo boots it', 'warn');
    }
    setTimeout(connectWS, wsBackoff = Math.min(wsBackoff * 1.6, 15000));
    return;
  }
  coldAnnounced = false;
  ws = new WebSocket(`wss://${host}/ws/ui`);
  ws.onopen = () => {
    wsBackoff = 1000;
    ws.send(JSON.stringify({ t: 'auth', token: localStorage.getItem('zephyrus_opkey') || '' }));
    ws.send(JSON.stringify({ t: 'status_req' }));
  };
  ws.onmessage = (e) => handleMsg(JSON.parse(e.data));
  ws.onclose = () => { setTimeout(connectWS, wsBackoff = Math.min(wsBackoff * 1.6, 15000)); };
  ws.onerror = () => ws.close();
}

function handleMsg(m) {
  switch (m.t) {
    case 'bye': {
      // operator key rejected — forget it and return to the gate
      localStorage.removeItem('zephyrus_opkey');
      ws.onclose = null;
      location.reload();
      return;
    }
    case 'status': renderStatus(m); break;
    case 'job_ack': trackAck(m); break;
    case 'result': onResult(m); break;
    case 'error': {
      const j = jobsUI.get(m.job_id);
      if (j) { j.state = 'err'; j.el.querySelector('.q-state').textContent = 'ERROR'; j.el.querySelector('.q-state').className = 'q-state err'; }
      toast(m.msg || 'engine error', 'err');
      break;
    }
    case 'info': toast(m.msg, 'warn'); break;
  }
}

function renderStatus(s) {
  const badge = $('statusBadge');
  if (s.engine_online) {
    badge.className = 'badge online';
    badge.textContent = `ENGINE ONLINE · ${s.workers} GPU${s.workers > 1 ? 's' : ''} · ${s.model || ''}`;
    $('wakeBtn').disabled = true;
    $('stopBtn').disabled = false;
  } else {
    badge.className = 'badge offline';
    badge.textContent = 'ENGINE OFFLINE';
    $('wakeBtn').disabled = false;
    $('stopBtn').disabled = true;
  }
  $('footStatus').textContent = `jobs ${s.stats.jobs_done} ok / ${s.stats.jobs_failed} err · queue ${s.queue_len}`;
  $('queueInfo').textContent = s.engine_online ? `engine up ${s.uptime}s` : 'engine down';
  $('queueEmpty').style.display = (s.queue_len || jobsUI.size) ? 'none' : 'block';
}

function trackAck(m) {
  const el = document.createElement('div');
  el.className = 'q-item';
  el.innerHTML = `<span class="q-pos">#${m.job_id.slice(0, 6)}</span><span class="q-state">${m.started ? 'RENDERING' : 'QUEUED ·' + m.pos}</span>`;
  $('queueList').prepend(el);
  jobsUI.set(m.job_id, { el, ts: Date.now() });
  $('queueEmpty').style.display = 'none';
}

/* ---------------- generate ---------------- */
function currentSize() {
  if ($('size').value === 'custom') {
    return [parseInt($('w').value) || 1024, parseInt($('h').value) || 1024];
  }
  return $('size').value.split('x').map(Number);
}

$('size').onchange = () => $('customSize').classList.toggle('hidden', $('size').value !== 'custom');
$('rollSeed').onclick = () => { $('seed').value = Math.floor(Math.random() * 2147483647); };
$('clearSeed').onclick = () => { $('seed').value = ''; };

$('gen').onclick = async () => {
  if (!aesKey) return toast('locked', 'err');
  const prompt = $('prompt').value.trim();
  if (!prompt) return toast('prompt is empty', 'err');
  if (!ws || ws.readyState !== 1) return toast('relay unreachable — retrying', 'err');

  const [w, h] = currentSize();
  const steps = Math.max(1, Math.min(12, parseInt($('steps').value) || 4));
  const cfg = Math.max(1, Math.min(10, parseFloat($('cfg').value) || 1.0));
  const batch = Math.max(1, Math.min(8, parseInt($('batch').value) || 1));
  const neg = $('neg').value.trim();
  const baseSeed = $('seed').value ? parseInt($('seed').value) || 0 : null;
  const lock = $('lockSeed').checked;

  for (let i = 0; i < batch; i++) {
    const seed = (baseSeed !== null && lock) ? baseSeed
               : (baseSeed !== null) ? baseSeed + i
               : Math.floor(Math.random() * 2147483647);
    const payload = await seal({ prompt, negative: neg, width: w, height: h, seed, steps, cfg });
    ws.send(JSON.stringify({ t: 'job', ...payload }));
  }
  toast(`${batch} job${batch > 1 ? 's' : ''} queued — encrypted before leaving this browser`, 'ok');
};

/* ---------------- wake / stop ---------------- */
$('wakeBtn').onclick = async () => {
  if (!relayHost) {
    toast('relay is cold — say "wake relay" in #echo; the keeper boots it in ~3 min', 'warn');
    return;
  }
  const badge = $('statusBadge');
  badge.className = 'badge waking';
  badge.textContent = 'WAKING — COLD START 4-8 MIN';
  try {
    const r = await fetch(`https://${relayHost}/api/wake`, { method: 'POST', headers: { 'X-Relay-Auth': localStorage.getItem('zephyrus_opkey') || '' } });
    const j = await r.json();
    toast(j.note || j.error || 'wake signal sent', j.ok ? 'ok' : 'err');
  } catch (e) { toast('wake failed: ' + e.message, 'err'); }
};

$('stopBtn').onclick = () => {
  if (!confirm('Stop the engine? Current render finishes, session ends, GPU quota is released.')) return;
  if (ws && ws.readyState === 1) ws.send(JSON.stringify({ t: 'stop_engine' }));
  toast('stop signal sent — engine will go offline shortly', 'warn');
};

/* ---------------- results ---------------- */
async function onResult(m) {
  try {
    const p = await unseal(m.image_b64, m.meta.nonce_b64);
    await saveImage({ id: m.job_id, ts: Date.now(), png_b64: p.png_b64, seed: p.seed, prompt: p.prompt, w: p.width, h: p.height, ms: p.ms });
    const j = jobsUI.get(m.job_id);
    if (j) { j.el.querySelector('.q-state').textContent = 'DONE'; j.el.querySelector('.q-state').className = 'q-state done'; }
    toast('render complete — stored locally', 'ok');
  } catch (e) {
    toast('decrypt failed: ' + e.message, 'err');
  }
}

/* ---------------- gallery (IndexedDB) ---------------- */
function idb() {
  return new Promise((res, rej) => {
    const rq = indexedDB.open('zephyrus', 1);
    rq.onupgradeneeded = () => rq.result.createObjectStore('images', { keyPath: 'id' });
    rq.onsuccess = () => res(rq.result);
    rq.onerror = () => rej(rq.error);
  });
}
const tx = async (mode, fn) => {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction('images', mode);
    const out = fn(t.objectStore('images'));
    t.oncomplete = () => res(out && out.result !== undefined ? out.result : out);
    t.onerror = () => rej(t.error);
  });
};

async function saveImage(rec) {
  const blob = new Blob([new Uint8Array(atob(rec.png_b64).match(/./g).map(c => c.charCodeAt(0)))], { type: 'image/png' });
  const row = { id: rec.id, ts: rec.ts, seed: rec.seed, prompt: rec.prompt, w: rec.w, h: rec.h, ms: rec.ms, blob };
  await tx('readwrite', (s) => s.put(row));
  addCard(row, true);
}

async function refreshGallery() {
  const db = await idb();
  const all = await new Promise((res, rej) => {
    const rq = db.transaction('images').objectStore('images').getAll();
    rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error);
  });
  all.sort((a, b) => b.ts - a.ts).forEach((r) => addCard(r, false));
}

function addCard(r, prepend) {
  $('galEmpty').style.display = 'none';
  const url = URL.createObjectURL(r.blob);
  const card = document.createElement('div');
  card.className = 'card';
  card.dataset.id = r.id;
  const ms = r.ms ? (r.ms / 1000).toFixed(1) + 's' : '';
  card.innerHTML = `
    <img src="${url}" loading="lazy">
    <div class="card-actions">
      <button class="btn small" data-act="dl" title="download">DL</button>
      <button class="btn small" data-act="reuse" title="reuse prompt + seed">↺</button>
      <button class="btn danger small" data-act="del" title="delete from this browser">✕</button>
    </div>
    <div class="prompt-line" title="${String(r.prompt).replace(/"/g, '&quot;')}">${String(r.prompt)}</div>
    <div class="card-meta"><span>seed ${r.seed}</span><span>${r.w}×${r.h} ${ms}</span></div>`;
  card.querySelector('img').onclick = () => openLightbox(r, url);
  card.addEventListener('click', async (e) => {
    const act = e.target.dataset && e.target.dataset.act;
    if (!act) return;
    if (act === 'del') {
      if (!confirm('Delete this image from your browser gallery?')) return;
      await tx('readwrite', (s) => s.delete(r.id));
      card.remove();
      if (!$('gallery').children.length) $('galEmpty').style.display = 'block';
      toast('deleted from this browser', 'warn');
    } else if (act === 'dl') {
      const a = document.createElement('a');
      a.href = url; a.download = `zephyrus_${r.seed || r.id}.png`; a.click();
    } else if (act === 'reuse') {
      $('prompt').value = r.prompt; $('seed').value = r.seed || '';
      $('prompt').focus();
      toast('prompt + seed restored to console', 'ok');
    }
  });
  const gal = $('gallery');
  prepend ? gal.prepend(card) : gal.appendChild(card);
  $('galCount').textContent = gal.children.length;
}

$('clearAll').onclick = async () => {
  if (!confirm('Delete ALL images from this browser? This cannot be undone.')) return;
  await tx('readwrite', (s) => s.clear());
  $('gallery').innerHTML = '';
  $('galCount').textContent = '';
  $('galEmpty').style.display = 'block';
  toast('gallery cleared — nothing was ever stored server-side', 'warn');
};

/* ---------------- lightbox ---------------- */
function openLightbox(r, url) {
  $('lbImg').src = url;
  $('lbMeta').textContent = `seed ${r.seed} · ${r.w}×${r.h} · ${r.ms ? (r.ms / 1000).toFixed(1) + 's' : ''}`;
  $('lightbox').classList.remove('hidden');
}
$('lbClose').onclick = () => $('lightbox').classList.add('hidden');
$('lightbox').onclick = (e) => { if (e.target === $('lightbox')) $('lightbox').classList.add('hidden'); };

/* persist console text between visits */
['prompt', 'neg'].forEach((id) => {
  const el = $(id);
  const k = 'zephyrus_' + id;
  if (localStorage.getItem(k)) el.value = localStorage.getItem(k);
  el.addEventListener('input', () => localStorage.setItem(k, el.value));
});
