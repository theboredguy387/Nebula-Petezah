import { baremuxPath } from '@mercuryworkshop/bare-mux/node';
import { epoxyPath } from '@mercuryworkshop/epoxy-transport';
import { scramjetPath } from '@mercuryworkshop/scramjet/path';
import { server as wisp } from '@mercuryworkshop/wisp-js/server';
import bareServerPkg from '@tomphttp/bare-server-node';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { createHmac, randomBytes, randomUUID } from 'crypto';
import { Client, GatewayIntentBits } from 'discord.js';
import dotenv from 'dotenv';
import express from 'express';
import fileUpload from 'express-fileupload';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import session from 'express-session';
import fs from 'fs';
import { createProxyMiddleware } from 'http-proxy-middleware';
import fetch from 'node-fetch';
import { createServer } from 'node:http';
import { hostname } from 'node:os';
import path, { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ddosShield } from './secure.js';
import { adminUserActionHandler } from './server/api/admin-user-action.js';
import { addCommentHandler, getCommentsHandler } from './server/api/comments.js';
import { getLikesHandler, likeHandler } from './server/api/likes.js';
import { signinHandler } from './server/api/signin.js';
import { signupHandler } from './server/api/signup.js';
import db from './server/db.js';

const { createBareServer } = bareServerPkg;

dotenv.config();

const envFile = `.env.${process.env.NODE_ENV || 'production'}`;
if (fs.existsSync(envFile)) {
  dotenv.config({ path: envFile });
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const publicPath = 'public';

const bare = createBareServer('/bare/', {
  websocket: { maxPayloadLength: 4096 }
});

const barePremium = createBareServer('/api/bare-premium/', {
  websocket: { maxPayloadLength: 4096 }
});

const app = express();

const discordClient = new Client({
  intents: [GatewayIntentBits.Guilds]
});

const shield = ddosShield(discordClient);

discordClient.login(process.env.BOT_TOKEN).catch((err) => {
  console.error('Failed to login Discord bot:', err.message);
});

shield.registerCommands(discordClient);

if (!process.env.TOKEN_SECRET) {
  throw new Error('CRITICAL: TOKEN_SECRET environment variable must be set');
}
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const TOKEN_VALIDITY = 3600000;
const POW_DIFFICULTY = 18;

const systemState = {
  cpuHigh: false,
  activeConnections: 0,
  totalWS: 0,
  totalRequests: 0,
  lastCheck: Date.now()
};

function createToken(features = { http: true, ws: true }) {
  const now = Date.now();
  const expiry = now + TOKEN_VALIDITY;
  const payload = JSON.stringify({
    iat: now,
    exp: expiry,
    features
  });
  const hmac = createHmac('sha256', TOKEN_SECRET);
  hmac.update(payload);
  const signature = hmac.digest('base64url');
  return `${Buffer.from(payload).toString('base64url')}.${signature}`;
}

function verifyToken(token, req) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  try {
    const payload = Buffer.from(parts[0], 'base64url').toString('utf8');
    const signature = parts[1];

    const hmac = createHmac('sha256', TOKEN_SECRET);
    hmac.update(payload);
    const expected = hmac.digest('base64url');

    if (signature !== expected) return null;

    const data = JSON.parse(payload);
    if (data.exp < Date.now()) return null;

    if (req && data.fp) {
      const ip = toIPv4(req.socket.remoteAddress);
      const currentFP = createHmac('sha256', TOKEN_SECRET)
        .update(ip + (req.headers['user-agent'] || ''))
        .digest('hex')
        .slice(0, 16);
      if (data.fp !== currentFP) return null;
    }

    return data;
  } catch {
    return null;
  }
}

function checkSystemPressure() {
  const now = Date.now();
  if (now - systemState.lastCheck < 1000) return systemState.cpuHigh;

  systemState.lastCheck = now;
  const load = systemState.totalRequests / 10;
  systemState.cpuHigh = load > 5000 || systemState.activeConnections > 25000;
  systemState.totalRequests = 0;

  return systemState.cpuHigh;
}

function extractToken(req) {
  const authHeader = req.headers['authorization'];
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    const match = cookieHeader.match(/bot_token=([^;]+)/);
    if (match) return match[1];
  }

  return null;
}

app.use(cookieParser());
app.use(express.static(publicPath));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
app.use(
  '/storage/data',
  express.static(path.join(__dirname, 'storage', 'data'), {
    setHeaders: (res, path) => {
      if (path.endsWith('.json')) {
        res.setHeader('Cache-Control', 'public, max-age=3600');
      } else if (/\.(png|jpg|jpeg|gif|webp|avif|svg)$/i.test(path)) {
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      } else {
        res.setHeader('Cache-Control', 'public, max-age=86400');
      }
    }
  })
);

app.use('/scram/', express.static(scramjetPath));
app.get('/scramjet.all.js', (req, res) => res.sendFile(path.join(scramjetPath, 'scramjet.all.js')));
app.get('/scramjet.sync.js', (req, res) => res.sendFile(path.join(scramjetPath, 'scramjet.sync.js')));
app.get('/scramjet.wasm.wasm', (req, res) => res.sendFile(path.join(scramjetPath, 'scramjet.wasm.wasm')));
app.get('/scramjet.all.js.map', (req, res) => res.sendFile(path.join(scramjetPath, 'scramjet.all.js.map')));

app.use('/baremux/', express.static(baremuxPath));
app.use('/epoxy/', express.static(epoxyPath));

app.get('/api/bot-challenge', rateLimit({ windowMs: 60000, max: 10 }), (req, res) => {
  const challenge = randomBytes(16).toString('hex');
  const difficulty = POW_DIFFICULTY;
  res.json({ challenge, difficulty });
});

app.post('/api/bot-verify', express.json(), (req, res) => {
  const { challenge, nonce, timing } = req.body;

  if (!challenge || !nonce || !timing) {
    return res.status(400).json({ error: 'Invalid proof' });
  }

  if (checkSystemPressure()) {
    return res.status(503).json({ error: 'System under load' });
  }

  const hash = createHmac('sha256', challenge).update(nonce).digest('hex');
  const leadingZeros = hash.match(/^0+/)?.[0].length || 0;
  const timingValid = timing > 10 && timing < 30000;

  if (leadingZeros >= Math.floor(POW_DIFFICULTY / 4) && timingValid) {
    const ip = toIPv4(req.socket.remoteAddress);
    const fingerprint = createHmac('sha256', TOKEN_SECRET)
      .update(ip + (req.headers['user-agent'] || ''))
      .digest('hex')
      .slice(0, 16);

    const token = createToken({ http: true, ws: true, fp: fingerprint });
    res.cookie('bot_token', token, {
      maxAge: TOKEN_VALIDITY,
      httpOnly: true,
      sameSite: 'Lax',
      secure: true
    });
    return res.json({ success: true, token });
  }

  res.status(403).json({ error: 'Verification failed' });
});

const gateMiddleware = (req, res, next) => {
  systemState.totalRequests++;

  const ua = req.headers['user-agent'] || '';
  const isBrowser = /Mozilla|Chrome|Safari|Firefox|Edge/i.test(ua);

  // Whitelist legitimate bots
  const goodBots = [
    /googlebot/i,
    /bingbot/i,
    /slurp/i, // Yahoo
    /duckduckbot/i,
    /baiduspider/i,
    /yandexbot/i,
    /facebookexternalhit/i,
    /twitterbot/i,
    /discordbot/i,
    /telegrambot/i,
    /whatsapp/i,
    /linkedinbot/i,
    /slackbot/i,
    /archive\.org_bot/i,
    /ia_archiver/i, 
    /semrushbot/i,
    /ahrefsbot/i,
    /mj12bot/i, 
    /dotbot/i
  ];

  const isGoodBot = goodBots.some((pattern) => pattern.test(ua));

  if (!isBrowser && !isGoodBot && req.path !== '/api/bot-challenge' && req.path !== '/api/bot-verify') {
    return res.status(403).send('Forbidden');
  }

  if (isGoodBot) {
    return next();
  }

  const token = extractToken(req);
  const tokenData = verifyToken(token, req);

  if (tokenData?.features?.http) {
    return next();
  }

  if (checkSystemPressure()) {
    return res.status(503).send('Service temporarily unavailable');
  }

  const acceptsHtml = req.headers.accept?.includes('text/html');
  if (acceptsHtml && isBrowser) {
    return res.send(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Loading...</title></head>
<body>
<script>
(async()=>{
const r=await fetch('/api/bot-challenge');
const {challenge,difficulty}=await r.json();
const start=performance.now();
let nonce=0;
let hash='';
while(true){
const data=challenge+nonce;
const buf=new TextEncoder().encode(data);
const hashBuf=await crypto.subtle.digest('SHA-256',buf);
hash=Array.from(new Uint8Array(hashBuf)).map(b=>b.toString(16).padStart(2,'0')).join('');
const zeros=hash.match(/^0+/)?.[0].length||0;
if(zeros>=Math.floor(difficulty/4))break;
nonce++;
if(nonce>1000000)break;
}
const timing=performance.now()-start;
const v=await fetch('/api/bot-verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challenge,nonce,timing})});
if(v.ok)location.reload();
})();
</script>
</body>
</html>`);
  }

  next();
};

const authRoutes = ['/api/signin', '/api/signup', '/api/bot-challenge', '/api/bot-verify'];
const conditionalGate = (req, res, next) => {
  if (authRoutes.includes(req.path)) {
    return next();
  }

  if (!req.route && req.app._router) {
    const matched = req.app._router.stack.some((layer) => {
      if (layer.route) return layer.route.path === req.path;
      return false;
    });
    if (!matched) return next();
  }

  return gateMiddleware(req, res, next);
};
app.use(conditionalGate);

const apiLimiter = rateLimit({
  windowMs: 15000,
  max: (req) => {
    const token = extractToken(req);
    return verifyToken(token, req) ? 200 : 50;
  },
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, slow down'
});

app.use('/bare/', apiLimiter);
app.use('/api/', apiLimiter);

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { secure: false } }));

app.use(
  '/api/gn-math/covers',
  createProxyMiddleware({
    target: 'https://cdn.jsdelivr.net/gh/gn-math/covers@main',
    changeOrigin: true,
    pathRewrite: { '^/api/gn-math/covers': '' }
  })
);
app.use(
  '/api/gn-math/html',
  createProxyMiddleware({ target: 'https://cdn.jsdelivr.net/gh/gn-math/html@main', changeOrigin: true, pathRewrite: { '^/api/gn-math/html': '' } })
);

function toIPv4(ip) {
  if (!ip) return '127.0.0.1';
  if (ip.includes(',')) ip = ip.split(',')[0].trim();
  if (ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');
  return ip.match(/^(\d{1,3}\.){3}\d{1,3}$/) ? ip : '127.0.0.1';
}

const wsConnections = new Map();
const MAX_WS_PER_IP = 180;
const MAX_TOTAL_WS = 30000;

function cleanupWS(ip) {
  const count = wsConnections.get(ip) || 0;
  if (count <= 1) wsConnections.delete(ip);
  else wsConnections.set(ip, count - 1);
  systemState.activeConnections--;
  systemState.totalWS--;
  shield.trackWS(ip, -1);
}

app.get('/ip', (req, res) => res.sendFile(path.join(__dirname, 'public/pages/other/roblox/ip.html')));

app.get('/results/:query', async (req, res) => {
  try {
    const query = req.params.query.toLowerCase();
    const response = await fetch(`http://api.duckduckgo.com/ac?q=${encodeURIComponent(query)}&format=json`);
    if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
    const data = await response.json();
    const suggestions = data.map((item) => ({ phrase: item.phrase })).slice(0, 8);
    res.status(200).json(suggestions);
  } catch (error) {
    console.error('Error generating suggestions:', error.message);
    res.status(500).json({ error: 'Failed to fetch suggestions' });
  }
});

const signupLimiter = rateLimit({ windowMs: 3600000, max: 3, message: 'Too many accounts created from this IP, try again later.' });
app.post('/api/signup', signupLimiter, signupHandler);

const pfpLimiter = rateLimit({
  windowMs: 3600000,
  max: 5,
  keyGenerator: (req) => req.session.user?.id || ipKeyGenerator(req.ip),
  message: 'Too many profile picture uploads, try again later.'
});
app.post('/api/upload-profile-pic', pfpLimiter, (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const file = req.files?.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    const userId = req.session.user.id;
    const uploadsDir = path.join(__dirname, 'public', 'uploads', 'profile-pics', userId);
    if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
    const fileName = `${Date.now()}-${file.name}`;
    const filePath = path.join(uploadsDir, fileName);
    fs.writeFileSync(filePath, file.data);
    const avatarUrl = `/uploads/profile-pics/${userId}/${fileName}`;
    const now = Date.now();
    db.prepare('UPDATE users SET avatar_url = ?, updated_at = ? WHERE id = ?').run(avatarUrl, now, userId);
    req.session.user.avatar_url = avatarUrl;
    res.status(200).json({ url: avatarUrl });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const localStorageLimiter = rateLimit({
  windowMs: 60000,
  max: 10,
  keyGenerator: (req) => req.session.user?.id || ipKeyGenerator(req.ip),
  message: 'Too many localstorage saves, slow down'
});
app.post('/api/save-localstorage', localStorageLimiter, (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { data } = req.body;
    if (!data || typeof data !== 'string') return res.status(400).json({ error: 'Invalid data format' });
    if (data.length > 5 * 1024 * 1024) return res.status(400).json({ error: 'Data too large. Maximum size is 5MB' });
    JSON.parse(data);
    const sanitizedData = data;
    const now = Date.now();
    db.prepare(
      `INSERT INTO user_settings (user_id, localstorage_data, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET localstorage_data = ?, updated_at = ?`
    ).run(req.session.user.id, sanitizedData, now, sanitizedData, now);
    res.status(200).json({ message: 'LocalStorage saved' });
  } catch (error) {
    console.error('Save error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/signin', signinHandler);
app.post('/api/admin/user-action', adminUserActionHandler);
app.post('/api/comment', addCommentHandler);
app.get('/api/comments', getCommentsHandler);
app.post('/api/like', likeHandler);
app.get('/api/likes', getLikesHandler);

app.get('/api/verify-email', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('<html><body><h1>Invalid verification link</h1></body></html>');
  try {
    const user = db.prepare('SELECT id FROM users WHERE verification_token = ?').get(token);
    if (!user) return res.status(400).send('<html><body><h1>Invalid or expired verification link</h1></body></html>');
    const now = Date.now();
    db.prepare('UPDATE users SET email_verified = 1, verification_token = NULL, updated_at = ? WHERE id = ?').run(now, user.id);
    res
      .status(200)
      .send(
        '<html><body style="background:#0a1d37;color:#fff;font-family:Arial;text-align:center;padding:50px;"><h1>Email verified successfully!</h1><p>You can now log in to your account.</p><a href="/pages/settings/p.html" style="color:#3b82f6;">Go to Login</a></body></html>'
      );
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).send('<html><body><h1>Verification failed</h1></body></html>');
  }
});

app.post('/api/signout', (req, res) => {
  req.session.destroy();
  res.status(200).json({ message: 'Signout successful' });
});

app.get('/api/profile', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const user = db.prepare('SELECT id, email, username, bio, avatar_url, is_admin, created_at FROM users WHERE id = ?').get(req.session.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    let role = 'User';
    if (user.is_admin === 1 && user.email === process.env.ADMIN_EMAIL) role = 'Owner';
    else if (user.is_admin === 3) role = 'Admin';
    else if (user.is_admin === 2) role = 'Staff';
    res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
        user_metadata: { name: user.username, bio: user.bio, avatar_url: user.avatar_url },
        app_metadata: { provider: 'email', is_admin: user.is_admin, role }
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/update-profile', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { username, bio, age, school, favgame, mood } = req.body;
    const now = Date.now();
    db.prepare('UPDATE users SET username = ?, bio = ?, age = ?, school = ? WHERE id = ?').run(
      username || null,
      bio || null,
      age || null,
      school || null,
      req.session.user.id
    );
    req.session.user.username = username;
    req.session.user.bio = bio;
    res.status(200).json({ message: 'Profile updated' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/load-localstorage', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const result = db.prepare('SELECT localstorage_data FROM user_settings WHERE user_id = ?').get(req.session.user.id);
    res.status(200).json({ data: result?.localstorage_data || '{}' });
  } catch (error) {
    console.error('Load error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/delete-account', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    db.prepare('DELETE FROM users WHERE id = ?').run(req.session.user.id);
    req.session.destroy();
    res.status(200).json({ message: 'Account deleted' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/changelog', (req, res) => {
  try {
    const changelogs = db
      .prepare(`SELECT c.*, u.username as author_name FROM changelog c LEFT JOIN users u ON c.author_id = u.id ORDER BY c.created_at DESC LIMIT 50`)
      .all();
    res.status(200).json({ changelogs });
  } catch (error) {
    console.error('Changelog error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/feedback', (req, res) => {
  try {
    const isAdmin = req.session.user
      ? (() => {
          try {
            const user = db.prepare('SELECT is_admin, email FROM users WHERE id = ?').get(req.session.user.id);
            return user && ((user.is_admin === 1 && user.email === process.env.ADMIN_EMAIL) || user.is_admin === 2 || user.is_admin === 3);
          } catch {
            return false;
          }
        })()
      : false;
    const feedback = db
      .prepare(
        `SELECT f.*, u.username${isAdmin ? ', u.email' : ''} FROM feedback f LEFT JOIN users u ON f.user_id = u.id ORDER BY f.created_at DESC LIMIT 100`
      )
      .all();
    const sanitizedFeedback = feedback.map((f) => {
      const safe = { id: f.id, content: f.content, created_at: f.created_at, username: f.username || 'Anonymous' };
      if (isAdmin && f.email) safe.email = f.email;
      return safe;
    });
    res.status(200).json({ feedback: sanitizedFeedback });
  } catch (error) {
    console.error('Feedback list error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/changelog', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const user = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.user.id);
    if (!user || !user.is_admin) return res.status(403).json({ error: 'Admin access required' });
    const { title, content } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Title and content are required' });
    const id = randomUUID();
    const now = Date.now();
    db.prepare('INSERT INTO changelog (id, title, content, author_id, created_at) VALUES (?, ?, ?, ?, ?)').run(
      id,
      title,
      content,
      req.session.user.id,
      now
    );
    res.status(201).json({ message: 'Changelog created', id });
  } catch (error) {
    console.error('Changelog create error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/feedback', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { content } = req.body;
    if (!content || content.trim().length === 0) return res.status(400).json({ error: 'Feedback content is required' });
    const id = randomUUID();
    const now = Date.now();
    db.prepare('INSERT INTO feedback (id, user_id, content, created_at) VALUES (?, ?, ?, ?)').run(id, req.session.user.id, content.trim(), now);
    res.status(201).json({ message: 'Feedback submitted', id });
  } catch (error) {
    console.error('Feedback error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/feedback', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const user = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.user.id);
    if (!user || !user.is_admin) return res.status(403).json({ error: 'Admin access required' });
    const feedback = db
      .prepare(`SELECT f.*, u.email, u.username FROM feedback f LEFT JOIN users u ON f.user_id = u.id ORDER BY f.created_at DESC LIMIT 100`)
      .all();
    res.status(200).json({ feedback });
  } catch (error) {
    console.error('Admin feedback error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/stats', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const user = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.user.id);
    if (!user || !user.is_admin) return res.status(403).json({ error: 'Admin access required' });
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    const feedbackCount = db.prepare('SELECT COUNT(*) as count FROM feedback').get().count;
    const changelogCount = db.prepare('SELECT COUNT(*) as count FROM changelog').get().count;
    res.status(200).json({ userCount, feedbackCount, changelogCount });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/users', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const user = db.prepare('SELECT is_admin, email FROM users WHERE id = ?').get(req.session.user.id);
    if (!user || !((user.is_admin === 1 && user.email === process.env.ADMIN_EMAIL) || user.is_admin === 2 || user.is_admin === 3))
      return res.status(403).json({ error: 'Admin access required' });
    const users = db
      .prepare(`SELECT id, email, username, created_at, is_admin, avatar_url, bio, school, age, ip FROM users ORDER BY created_at DESC LIMIT 10000`)
      .all();
    const usersWithExtras = users.map((u) => {
      let ip = 'N/A';
      if (user.is_admin === 1 && user.email === process.env.ADMIN_EMAIL) ip = u.ip || 'N/A';
      return {
        ...u,
        ip,
        signup_link: null,
        role: u.is_admin === 1 && u.email === process.env.ADMIN_EMAIL ? 'Owner' : u.is_admin === 3 ? 'Admin' : u.is_admin === 2 ? 'Staff' : 'User'
      };
    });
    res.status(200).json({ users: usersWithExtras });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/change-password', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.session.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!passwordMatch) return res.status(401).json({ error: 'Current password is incorrect' });
    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    const now = Date.now();
    db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').run(newPasswordHash, now, req.session.user.id);
    res.status(200).json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.use((req, res) => res.status(404).sendFile(join(__dirname, publicPath, '404.html')));

const server = createServer((req, res) => {
  const ip = toIPv4(req.socket.remoteAddress);
  shield.trackRequest(ip);

  const handleBareRequest = (bareServer) => {
    try {
      bareServer.routeRequest(req, res);
    } catch (error) {
      console.error('Bare server error:', error.message);
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' }).end('Internal server error');
    }
  };

  if (bare.shouldRoute(req)) handleBareRequest(bare);
  else if (barePremium.shouldRoute(req)) handleBareRequest(barePremium);
  else app.handle(req, res);
});

server.on('upgrade', (req, socket, head) => {
  const ip = toIPv4(req.socket.remoteAddress);
  const current = wsConnections.get(ip) || 0;

  if (systemState.totalWS >= MAX_TOTAL_WS || current >= MAX_WS_PER_IP) {
    shield.trackWS(ip, 1);
    return socket.destroy();
  }

  const token = extractToken(req);
  const tokenData = verifyToken(token, req);

  const wispPaths = ['/wisp/', '/api/wisp-premium/', '/api/alt-wisp-1/', '/api/alt-wisp-2/', '/api/alt-wisp-3/', '/api/alt-wisp-4/'];
  const isWisp = wispPaths.some((p) => req.url.startsWith(p));

  if (isWisp && !tokenData?.features?.ws) {
    if (checkSystemPressure()) {
      return socket.destroy();
    }
  }

  shield.trackWS(ip, 1);
  wsConnections.set(ip, current + 1);
  systemState.activeConnections++;
  systemState.totalWS++;

  socket.on('close', () => cleanupWS(ip));
  socket.on('error', () => cleanupWS(ip));

  const handleBareUpgrade = (bareServer) => {
    try {
      bareServer.routeUpgrade(req, socket, head);
    } catch (error) {
      console.error('Bare server upgrade error:', error.message);
      socket.destroy();
      cleanupWS(ip);
    }
  };

  if (bare.shouldRoute(req)) handleBareUpgrade(bare);
  else if (barePremium.shouldRoute(req)) handleBareUpgrade(barePremium);
  else if (isWisp) {
    if (req.url.startsWith('/api/wisp-premium/')) req.url = req.url.replace('/api/wisp-premium/', '/wisp/');
    if (req.url.startsWith('/api/alt-wisp-1/')) req.url = req.url.replace('/api/alt-wisp-1/', '/wisp/');
    if (req.url.startsWith('/api/alt-wisp-2/')) req.url = req.url.replace('/api/alt-wisp-2/', '/wisp/');
    if (req.url.startsWith('/api/alt-wisp-3/')) req.url = req.url.replace('/api/alt-wisp-3/', '/wisp/');
    if (req.url.startsWith('/api/alt-wisp-4/')) req.url = req.url.replace('/api/alt-wisp-4/', '/wisp/');
    try {
      wisp.routeRequest(req, socket, head);
    } catch (error) {
      console.error('WISP server error:', error.message);
      socket.destroy();
      cleanupWS(ip);
    }
  } else {
    cleanupWS(ip);
    socket.destroy();
  }
});

const port = parseInt(process.env.PORT || '3000');
server.keepAliveTimeout = 30000;
server.headersTimeout = 31000;
server.requestTimeout = 30000;
server.timeout = 30000;

server.listen({ port }, () => {
  const address = server.address();
  console.log('Listening on:');
  console.log(`\thttp://localhost:${address.port}`);
  console.log(`\thttp://${hostname()}:${address.port}`);
  console.log(`\thttp://${address.family === 'IPv6' ? `[${address.address}]` : address.address}:${address.port}`);
});

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

function shutdown() {
  console.log('Shutting down...');
  if (shield.isUnderAttack) shield.endAttackAlert();
  server.close();
  bare.close();
  process.exit(0);
}
