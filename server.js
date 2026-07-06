const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const ROOT = __dirname;
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || ADMIN_PASSWORD;
const PLAUSIBLE_SHARE_URL = process.env.PLAUSIBLE_SHARE_URL || '';
const COOKIE_NAME = 'siyal_admin';
const SESSION_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24h

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

function sign(payload) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
}

function makeToken() {
  const expires = Date.now() + SESSION_MAX_AGE_MS;
  const payload = `ok.${expires}`;
  return `${payload}.${sign(payload)}`;
}

function verifyToken(token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const payload = parts[0] + '.' + parts[1];
  const sig = parts[2];
  const expected = sign(payload);
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return false;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return false;
  return Date.now() < Number(parts[1]);
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

function isAuthed(req) {
  const cookies = parseCookies(req.headers.cookie);
  return verifyToken(cookies[COOKIE_NAME]);
}

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function serveFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url);
  const pathname = decodeURIComponent(parsed.pathname);

  // --- verifye modpas la sèvè-side, konpare tan-konstan ---
  if (pathname === '/api/admin-login' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1e4) req.destroy(); });
    req.on('end', () => {
      let password = '';
      try { password = JSON.parse(body).password || ''; } catch (e) {}
      const a = Buffer.from(password);
      const b = Buffer.from(ADMIN_PASSWORD);
      const match = ADMIN_PASSWORD.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
      if (match) {
        const token = makeToken();
        res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${SESSION_MAX_AGE_MS / 1000}; SameSite=Strict; Secure`);
        sendJSON(res, 200, { ok: true });
      } else {
        sendJSON(res, 401, { ok: false });
      }
    });
    return;
  }

  // --- lyen Plausible la sòti isit la sèlman AK sesyon valid; li pa janm nan HTML/JS statik ---
  if (pathname === '/api/admin-stats' && req.method === 'GET') {
    if (!isAuthed(req)) { sendJSON(res, 401, { ok: false }); return; }
    sendJSON(res, 200, { ok: true, shareUrl: PLAUSIBLE_SHARE_URL });
    return;
  }

  if (pathname === '/api/admin-logout' && req.method === 'POST') {
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict; Secure`);
    sendJSON(res, 200, { ok: true });
    return;
  }

  // --- fichye statik ---
  let safePath = path.normalize(pathname).replace(/^(\.\.[/\\])+/, '');
  if (safePath === '/' || safePath === '') safePath = '/index.html';
  const filePath = path.join(ROOT, safePath);
  if (!filePath.startsWith(ROOT)) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) { res.writeHead(404); res.end('Not found'); return; }
    serveFile(res, filePath);
  });
});

server.listen(PORT, () => console.log(`SIYAL server ap koute sou pò ${PORT}`));
