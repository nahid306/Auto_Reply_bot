const express = require('express');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');
const { APP_ID, APP_SECRET, VERIFY_TOKEN, BASE_URL, TOKEN_ENC_KEY, SESSION_SECRET,
  GRAPH_VERSION = 'v23.0', PORT = 3000 } = process.env;
for (const [k, v] of Object.entries({ APP_ID, APP_SECRET, VERIFY_TOKEN, BASE_URL, TOKEN_ENC_KEY, SESSION_SECRET }))
  if (!v) { console.error(`Missing env var ${k}`); process.exit(1); }

const db = new DatabaseSync('bot.db');
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS pages(id TEXT PRIMARY KEY, name TEXT, owner_id TEXT, token_enc TEXT,
  enabled INT DEFAULT 0, needs_reauth INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS conversations(page_id TEXT, psid TEXT, last_user_msg_at INT, PRIMARY KEY(page_id, psid));
CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY, page_id TEXT, psid TEXT, message TEXT DEFAULT 'Hi',
  cooldown_min INT DEFAULT 1440, enabled INT DEFAULT 1, last_sent_at INT, UNIQUE(page_id, psid));
CREATE TABLE IF NOT EXISTS events(key TEXT PRIMARY KEY, at INT);
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY, at INT, page_id TEXT, psid TEXT, level TEXT, msg TEXT);`);

const log = (page_id, psid, level, msg) => {
  console.log(`[${level}] ${page_id || '-'} ${psid || '-'} ${msg}`);
  db.prepare('INSERT INTO logs(at,page_id,psid,level,msg) VALUES(?,?,?,?,?)').run(Date.now(), page_id, psid, level, msg);
};

// ---- token encryption (AES-256-GCM) and signed session cookie ----
const key = Buffer.from(TOKEN_ENC_KEY, 'base64');
if (key.length !== 32) { console.error('TOKEN_ENC_KEY must be 32 bytes, base64'); process.exit(1); }
const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const b = Buffer.concat([c.update(t, 'utf8'), c.final()]); return Buffer.concat([iv, c.getAuthTag(), b]).toString('base64'); };
const dec = s => { const b = Buffer.from(s, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'); };
const sign = v => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('base64url');
const mkSession = o => { const p = Buffer.from(JSON.stringify(o)).toString('base64url'); return `${p}.${sign(p)}`; };
const readSession = s => { const [p, g] = (s || '').split('.'); if (!p || !g) return null;
  const e = sign(p); if (e.length !== g.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(g))) return null;
  const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() ? o : null; };
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map(c => c.split('=')));
const cookieOpts = `Path=/; HttpOnly; SameSite=Lax${BASE_URL.startsWith('https') ? '; Secure' : ''}`;

// ---- Graph API helper ----
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function graph(path, { method = 'GET', token, body, params = {} } = {}) {
  const u = new URL(`https://graph.facebook.com/${GRAPH_VERSION}/${path}`);
  if (token) params.appsecret_proof = crypto.createHmac('sha256', APP_SECRET).update(token).digest('hex');
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  const r = await fetch(u, { method, signal: AbortSignal.timeout(10000),
    headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }) },
    body: body && JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(j.error?.message || `HTTP ${r.status}`);
    Object.assign(e, { code: j.error?.code, sub: j.error?.error_subcode, status: r.status }); throw e; }
  return j;
}
const transient = e => !e.status || e.status >= 500 || [1, 2, 4, 17, 32, 613].includes(e.code);
async function sendText(page, psid, text) {
  for (let i = 0; ; i++) {
    try {
      return await graph('me/messages', { method: 'POST', token: dec(page.token_enc),
        body: { recipient: { id: psid }, messaging_type: 'RESPONSE', message: { text } } });
    } catch (e) { if (!transient(e) || i === 3) throw e; await sleep(1000 * 2 ** i); }
  }
}

const app = express();

// ---- Webhook (raw body needed for signature check) ----
app.get('/webhook', (req, res) => {
  if (req.query['hub.mode'] === 'subscribe' && req.query['hub.verify_token'] === VERIFY_TOKEN)
    return res.status(200).send(req.query['hub.challenge']);
  res.sendStatus(403);
});
app.post('/webhook', express.raw({ type: '*/*', limit: '1mb' }), (req, res) => {
  const sig = req.get('x-hub-signature-256') || '';
  const exp = 'sha256=' + crypto.createHmac('sha256', APP_SECRET).update(req.body).digest('hex');
  if (sig.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp))) return res.sendStatus(403);
  res.sendStatus(200); // ack fast; Meta retries slow or failed deliveries
  let body; try { body = JSON.parse(req.body); } catch { return; }
  if (body.object !== 'page') return;
  for (const entry of body.entry || []) for (const m of entry.messaging || [])
    handleEvent(entry.id, m).catch(e => log(entry.id, m.sender?.id, 'error', `Event failed: ${e.message}`));
});

async function handleEvent(pageId, m) {
  const psid = m.sender?.id;
  if (m.message && !m.message.is_echo) { // tracks the 24h window
    db.prepare(`INSERT INTO conversations VALUES(?,?,?) ON CONFLICT(page_id,psid) DO UPDATE SET last_user_msg_at=excluded.last_user_msg_at`)
      .run(pageId, psid, m.timestamp || Date.now());
    return;
  }
  if (!m.read) return;
  // Dedupe: same page + person + watermark is processed once, even if Meta redelivers.
  const k = `${pageId}:${psid}:${m.read.watermark}`;
  if (db.prepare('INSERT OR IGNORE INTO events VALUES(?,?)').run(k, Date.now()).changes === 0) return;

  const page = db.prepare('SELECT * FROM pages WHERE id=?').get(pageId);
  const rule = db.prepare('SELECT * FROM rules WHERE page_id=? AND psid=?').get(pageId, psid);
  if (!page || !page.enabled || !rule || !rule.enabled) return; // not configured: stay silent
  if (page.needs_reauth) return log(pageId, psid, 'warn', 'Skipped: page needs to be reconnected');

  const conv = db.prepare('SELECT last_user_msg_at FROM conversations WHERE page_id=? AND psid=?').get(pageId, psid);
  if (!conv || Date.now() - conv.last_user_msg_at > 24 * 3600e3)
    return log(pageId, psid, 'warn', 'Skipped: outside Meta\'s 24-hour messaging window (they must message the Page first)');

  // Atomic claim: also the loop guard (they will "see" our Hi, which fires another read event).
  const now = Date.now(), cutoff = now - rule.cooldown_min * 60e3;
  const claim = db.prepare('UPDATE rules SET last_sent_at=? WHERE id=? AND (last_sent_at IS NULL OR last_sent_at<?)').run(now, rule.id, cutoff);
  if (claim.changes === 0) return log(pageId, psid, 'info', 'Skipped: cooldown active');

  try {
    await sendText(page, psid, rule.message);
    log(pageId, psid, 'info', `Sent "${rule.message}"`);
  } catch (e) {
    db.prepare('UPDATE rules SET last_sent_at=? WHERE id=?').run(rule.last_sent_at, rule.id); // release claim
    if (e.code === 190) db.prepare('UPDATE pages SET needs_reauth=1 WHERE id=?').run(pageId);
    log(pageId, psid, 'error', `Send failed (code ${e.code ?? e.status ?? 'network'}${e.sub ? '/' + e.sub : ''}): ${e.message}`);
  }
}

// ---- Facebook Login ----
app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  res.setHeader('Set-Cookie', `st=${state}; Max-Age=600; ${cookieOpts}`);
   const u = new URL(`https://www.facebook.com/${GRAPH_VERSION}/dialog/oauth`);
  const q = { client_id: APP_ID, redirect_uri: `${BASE_URL}/auth/callback`, state, response_type: 'code' };
  if (process.env.FB_CONFIG_ID) { q.config_id = process.env.FB_CONFIG_ID; q.override_default_response_type = 'true'; }
  else q.scope = 'pages_show_list,pages_messaging,pages_manage_metadata';
  u.search = new URLSearchParams(q);
  res.redirect(u.toString());
});
app.get('/auth/callback', async (req, res) => {
  try {
    if (!req.query.code || req.query.state !== cookies(req).st) return res.status(400).send('Login failed: invalid state');
    const redirect_uri = `${BASE_URL}/auth/callback`;
    const short = await graph('oauth/access_token', { params: { client_id: APP_ID, client_secret: APP_SECRET, redirect_uri, code: req.query.code } });
    const long = await graph('oauth/access_token', { params: { grant_type: 'fb_exchange_token', client_id: APP_ID, client_secret: APP_SECRET, fb_exchange_token: short.access_token } }).catch(() => short);
    const me = await graph('me', { token: long.access_token, params: { fields: 'id,name' } });
    const accts = await graph('me/accounts', { token: long.access_token, params: { fields: 'id,name,access_token' } });
    for (const p of accts.data || []) {
      db.prepare(`INSERT INTO pages(id,name,owner_id,token_enc) VALUES(?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET name=excluded.name, owner_id=excluded.owner_id, token_enc=excluded.token_enc, needs_reauth=0`)
        .run(p.id, p.name, me.id, enc(p.access_token));
      await graph(`${p.id}/subscribed_apps`, { method: 'POST', token: p.access_token, params: { subscribed_fields: 'messages,message_reads' } })
        .catch(e => log(p.id, null, 'error', `Webhook subscribe failed: ${e.message}`));
    }
    res.setHeader('Set-Cookie', [`s=${mkSession({ uid: me.id, exp: Date.now() + 7 * 864e5 })}; Max-Age=604800; ${cookieOpts}`, `st=; Max-Age=0; ${cookieOpts}`]);
    res.redirect('/');
  } catch (e) { console.error(e); res.status(500).send(`Login failed: ${e.message}`); }
});
app.post('/auth/logout', (req, res) => { res.setHeader('Set-Cookie', `s=; Max-Age=0; ${cookieOpts}`); res.sendStatus(204); });

// ---- Dashboard API ----
app.use('/api', express.json(), (req, res, next) => {
  const s = readSession(cookies(req).s);
  if (!s) return res.status(401).json({ error: 'Not signed in' });
  if (req.method !== 'GET' && req.get('x-csrf') !== '1') return res.status(403).json({ error: 'Bad request' });
  req.uid = s.uid; next();
});
const owned = (req, id) => db.prepare('SELECT * FROM pages WHERE id=? AND owner_id=?').get(id, req.uid);

app.get('/api/state', (req, res) => {
  const pages = db.prepare('SELECT id,name,enabled,needs_reauth FROM pages WHERE owner_id=?').all(req.uid);
  const ids = pages.map(p => p.id), q = ids.map(() => '?').join(',') || "''";
  res.json({ pages,
    rules: db.prepare(`SELECT * FROM rules WHERE page_id IN (${q})`).all(...ids),
    conversations: db.prepare(`SELECT * FROM conversations WHERE page_id IN (${q}) ORDER BY last_user_msg_at DESC LIMIT 50`).all(...ids),
    logs: db.prepare(`SELECT * FROM logs WHERE page_id IN (${q}) ORDER BY id DESC LIMIT 100`).all(...ids) });
});
app.post('/api/pages/:id/enabled', (req, res) => {
  if (!owned(req, req.params.id)) return res.sendStatus(404);
  db.prepare('UPDATE pages SET enabled=? WHERE id=?').run(req.body.enabled ? 1 : 0, req.params.id);
  log(req.params.id, null, 'info', `Bot ${req.body.enabled ? 'enabled' : 'disabled'}`); res.sendStatus(204);
});
app.post('/api/rules', (req, res) => {
  const { pageId, psid, message = 'Hi', cooldownMin = 1440 } = req.body;
  if (!owned(req, pageId) || !/^\d+$/.test(psid || '')) return res.status(400).json({ error: 'Pick a page and a recipient' });
  const text = String(message).trim().slice(0, 640), cd = Math.max(1, Math.min(10080, +cooldownMin || 1440));
  if (!text) return res.status(400).json({ error: 'Message is empty' });
  db.prepare(`INSERT INTO rules(page_id,psid,message,cooldown_min) VALUES(?,?,?,?)
    ON CONFLICT(page_id,psid) DO UPDATE SET message=excluded.message, cooldown_min=excluded.cooldown_min`).run(pageId, psid, text, cd);
  res.sendStatus(204);
});
app.post('/api/rules/:id/enabled', (req, res) => {
  db.prepare('UPDATE rules SET enabled=? WHERE id=? AND page_id IN (SELECT id FROM pages WHERE owner_id=?)').run(req.body.enabled ? 1 : 0, req.params.id, req.uid);
  res.sendStatus(204);
});
app.delete('/api/rules/:id', (req, res) => {
  db.prepare('DELETE FROM rules WHERE id=? AND page_id IN (SELECT id FROM pages WHERE owner_id=?)').run(req.params.id, req.uid);
  res.sendStatus(204);
});

app.use(express.static('public'));
setInterval(() => db.prepare('DELETE FROM events WHERE at<?').run(Date.now() - 30 * 864e5), 36e5).unref();
app.listen(PORT, () => console.log(`Listening on :${PORT}`));
