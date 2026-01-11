import { baremuxPath } from '@mercuryworkshop/bare-mux/node';
import { epoxyPath } from '@mercuryworkshop/epoxy-transport';
import { scramjetPath } from '@mercuryworkshop/scramjet/path';
import { server as wisp } from '@mercuryworkshop/wisp-js/server';
import bareServerPkg from '@tomphttp/bare-server-node';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'crypto';
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
import { performance } from 'perf_hooks';
import process from 'process';
import v8 from 'v8';
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

const MAX_REQUEST_SIZE = 10 * 1024 * 1024;
const MAX_JSON_SIZE = 5 * 1024 * 1024;
const MAX_HEADER_SIZE = 16384;
const MEMORY_THRESHOLD = 1024 * 1024 * 1024 * 2;
const MEMORY_CRITICAL = 1024 * 1024 * 1024 * 1.5;
const REQUEST_TIMEOUT = 60000;
const PAYLOAD_TIMEOUT = 30000;

const memoryPressure = { active: false, lastCheck: 0, consecutiveHigh: 0 };
const requestFingerprints = new Map();
const ipReputation = new Map();
const circuitBreakers = new Map();
const activeRequests = new Map();
let requestIdCounter = 0;

function getMemoryUsage() {
  const usage = process.memoryUsage();
  return {
    rss: usage.rss,
    heapTotal: usage.heapTotal,
    heapUsed: usage.heapUsed,
    external: usage.external,
    arrayBuffers: usage.arrayBuffers
  };
}

function checkMemoryPressure() {
  const now = Date.now();
  if (now - memoryPressure.lastCheck < 5000) return memoryPressure.active;
  memoryPressure.lastCheck = now;

  const mem = getMemoryUsage();
  const isHigh = mem.heapUsed > MEMORY_CRITICAL || mem.rss > MEMORY_THRESHOLD;

  if (isHigh) {
    memoryPressure.consecutiveHigh++;
    if (memoryPressure.consecutiveHigh >= 3) {
      memoryPressure.active = true;
      if (global.gc && mem.heapUsed > MEMORY_CRITICAL * 1.1) {
        global.gc();
      }
    }
  } else {
    memoryPressure.consecutiveHigh = 0;
    memoryPressure.active = false;
  }

  return memoryPressure.active;
}

function createFingerprint(req) {
  const ip = toIPv4(null, req);
  const ua = req.headers['user-agent'] || '';
  const accept = req.headers['accept'] || '';
  const lang = req.headers['accept-language'] || '';
  const encoding = req.headers['accept-encoding'] || '';
  const data = `${ip}:${ua}:${accept}:${lang}:${encoding}`;
  return createHash('sha256').update(data).digest('hex').slice(0, 32);
}

function updateIPReputation(ip, score) {
  const current = ipReputation.get(ip) || { score: 0, lastSeen: 0, violations: [] };
  current.score += score;
  current.lastSeen = Date.now();
  if (score < 0) {
    current.violations.push({ time: Date.now(), score });
    current.violations = current.violations.filter((v) => Date.now() - v.time < 3600000);
  }
  ipReputation.set(ip, current);

  if (current.score < -100) {
    circuitBreakers.set(ip, { open: true, until: Date.now() + 3600000, violations: current.violations.length });
  }
}

function checkCircuitBreaker(ip) {
  const breaker = circuitBreakers.get(ip);
  if (!breaker) return false;
  if (breaker.open && Date.now() > breaker.until) {
    circuitBreakers.delete(ip);
    return false;
  }
  return breaker.open;
}

function toIPv4(ip, req = null) {
  if (req) {
    const xForwardedFor = req.headers['x-forwarded-for'];
    const xRealIP = req.headers['x-real-ip'];
    const cfConnectingIP = req.headers['cf-connecting-ip'];
    const trueClientIP = req.headers['true-client-ip'];

    if (xForwardedFor) {
      ip = xForwardedFor.split(',')[0].trim();
    } else if (cfConnectingIP) {
      ip = cfConnectingIP;
    } else if (trueClientIP) {
      ip = trueClientIP;
    } else if (xRealIP) {
      ip = xRealIP;
    } else if (req.socket?.remoteAddress) {
      ip = req.socket.remoteAddress;
    } else if (req.connection?.remoteAddress) {
      ip = req.connection.remoteAddress;
    }
  }

  if (!ip) return '127.0.0.1';
  if (typeof ip === 'string' && ip.includes(',')) ip = ip.split(',')[0].trim();
  if (typeof ip === 'string' && ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');
  const match = typeof ip === 'string' ? ip.match(/^(\d{1,3}\.){3}\d{1,3}$/) : null;
  return match ? match[0] : '127.0.0.1';
}

const bare = createBareServer('/bare/', {
  websocket: { maxPayloadLength: 4096 }
});

const barePremium = createBareServer('/api/bare-premium/', {
  websocket: { maxPayloadLength: 4096 }
});

const app = express();

app.set('trust proxy', true);

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
const BASE_POW_DIFFICULTY = 16;
const MAX_POW_DIFFICULTY = 22;

const baselineMetrics = {
  cpuSamples: [],
  requestRateSamples: [],
  blockRateSamples: [],
  uniqueIpSamples: [],
  lastBaselineUpdate: Date.now(),
  baselineCpu: 30,
  baselineRequestRate: 100,
  baselineBlockRate: 5,
  baselineUniqueIps: 50
};

const requestRateTracker = {
  requests: [],
  lastMinuteStart: Date.now()
};

const systemState = {
  state: 'NORMAL',
  cpuHigh: false,
  activeConnections: 0,
  totalWS: 0,
  totalRequests: 0,
  lastCheck: Date.now(),
  currentPowDifficulty: BASE_POW_DIFFICULTY,
  recentBlockRate: 0,
  lastDifficultyAdjust: Date.now(),
  trustedClients: new Set(),
  lastPowSolve: new Map(),
  requestRatePerMinute: 0
};

discordClient.systemState = systemState;

const botVerificationCache = new Map();
const VERIFICATION_CACHE_TTL = 3600000;

function updateBaseline() {
  const now = Date.now();
  if (now - baselineMetrics.lastBaselineUpdate < 60000) return;

  baselineMetrics.lastBaselineUpdate = now;
  const cpuUsage = shield.getCpuUsage();
  const blockRate = shield.getRecentBlockRate();
  const requestRate = systemState.totalRequests / ((now - systemState.lastCheck) / 1000) || 0;
  const { uniqueIps } = shield.getChallengeSpike();

  baselineMetrics.cpuSamples.push(cpuUsage);
  baselineMetrics.requestRateSamples.push(requestRate);
  baselineMetrics.blockRateSamples.push(blockRate);
  baselineMetrics.uniqueIpSamples.push(uniqueIps);

  const maxSamples = 10;
  if (baselineMetrics.cpuSamples.length > maxSamples) {
    baselineMetrics.cpuSamples.shift();
    baselineMetrics.requestRateSamples.shift();
    baselineMetrics.blockRateSamples.shift();
    baselineMetrics.uniqueIpSamples.shift();
  }

  if (baselineMetrics.cpuSamples.length >= 3) {
    baselineMetrics.baselineCpu = baselineMetrics.cpuSamples.reduce((a, b) => a + b, 0) / baselineMetrics.cpuSamples.length;
    baselineMetrics.baselineRequestRate = baselineMetrics.requestRateSamples.reduce((a, b) => a + b, 0) / baselineMetrics.requestRateSamples.length;
    baselineMetrics.baselineBlockRate = baselineMetrics.blockRateSamples.reduce((a, b) => a + b, 0) / baselineMetrics.blockRateSamples.length;
    baselineMetrics.baselineUniqueIps = baselineMetrics.uniqueIpSamples.reduce((a, b) => a + b, 0) / baselineMetrics.uniqueIpSamples.length;
  }
}

function adjustPowDifficulty(req = null) {
  const now = Date.now();
  if (now - systemState.lastDifficultyAdjust < 10000) return;

  systemState.lastDifficultyAdjust = now;
  updateBaseline();

  const token = req ? extractToken(req) : null;
  const tokenData = req ? verifyToken(token, req) : null;
  const isTrusted = tokenData?.features?.http || (req && req.session?.user) || false;

  if (isTrusted) {
    systemState.currentPowDifficulty = BASE_POW_DIFFICULTY;
    return;
  }

  if (baselineMetrics.baselineCpu === 0 || baselineMetrics.cpuSamples.length < 3) {
    systemState.currentPowDifficulty = BASE_POW_DIFFICULTY;
    return;
  }

  const blockRate = shield.getRecentBlockRate();
  const cpuUsage = shield.getCpuUsage();
  const { uniqueIps } = shield.getChallengeSpike();

  const cpuSpike = cpuUsage > baselineMetrics.baselineCpu * 1.2;
  const cpuBusy = cpuUsage > baselineMetrics.baselineCpu * 1.1;
  const ipChurnHigh = uniqueIps > baselineMetrics.baselineUniqueIps * 2;

  const isAttack = shield.isUnderAttack || systemState.state === 'ATTACK';
  const isBusy = systemState.state === 'BUSY' || (cpuBusy && !isAttack);

  if (isBusy && !isAttack) {
    systemState.currentPowDifficulty = BASE_POW_DIFFICULTY;
    return;
  }

  let targetDifficulty = BASE_POW_DIFFICULTY;

  if (isAttack && ipChurnHigh) {
    targetDifficulty = MAX_POW_DIFFICULTY;
  } else if (isAttack) {
    targetDifficulty = 20;
  } else if (ipChurnHigh && blockRate > baselineMetrics.baselineBlockRate * 2) {
    targetDifficulty = 18;
  }

  targetDifficulty = Math.min(Math.max(targetDifficulty, BASE_POW_DIFFICULTY), MAX_POW_DIFFICULTY);

  if (targetDifficulty > systemState.currentPowDifficulty) {
    systemState.currentPowDifficulty = Math.min(targetDifficulty, MAX_POW_DIFFICULTY);
  } else if (targetDifficulty < systemState.currentPowDifficulty) {
    systemState.currentPowDifficulty = Math.max(systemState.currentPowDifficulty - 1, BASE_POW_DIFFICULTY);
  }
}

async function verifyLegitimateBot(ua, ip) {
  const cacheKey = `${ip}:${ua}`;
  const cached = botVerificationCache.get(cacheKey);

  if (cached && Date.now() - cached.timestamp < VERIFICATION_CACHE_TTL) {
    return cached.isLegit;
  }

  let isLegit = false;
  let expectedDomains = [];

  try {
    if (/googlebot/i.test(ua)) {
      expectedDomains = ['.googlebot.com.', '.google.com.'];
    } else if (/bingbot/i.test(ua)) {
      expectedDomains = ['.search.msn.com.'];
    } else if (/duckduckbot/i.test(ua)) {
      expectedDomains = ['.duckduckgo.com.'];
    } else if (/slurp/i.test(ua)) {
      expectedDomains = ['.crawl.yahoo.net.'];
    } else if (/baiduspider/i.test(ua)) {
      expectedDomains = ['.crawl.baidu.com.', '.crawl.baidu.jp.'];
    } else if (/yandexbot/i.test(ua)) {
      expectedDomains = ['.yandex.com.', '.yandex.ru.', '.yandex.net.'];
    } else if (/facebookexternalhit/i.test(ua)) {
      expectedDomains = ['.facebook.com.', '.fbsv.net.'];
    } else if (/twitterbot/i.test(ua)) {
      expectedDomains = ['.twitter.com.'];
    } else if (/discordbot/i.test(ua)) {
      expectedDomains = ['.discord.com.'];
    } else if (/telegrambot/i.test(ua)) {
      expectedDomains = ['.telegram.org.'];
    } else if (/whatsapp/i.test(ua)) {
      expectedDomains = ['.facebook.com.', '.whatsapp.net.'];
    } else if (/linkedinbot/i.test(ua)) {
      expectedDomains = ['.linkedin.com.'];
    } else if (/slackbot/i.test(ua)) {
      expectedDomains = ['.slack.com.'];
    } else if (/archive\.org_bot|ia_archiver/i.test(ua)) {
      expectedDomains = ['.archive.org.'];
    } else if (/semrushbot/i.test(ua)) {
      expectedDomains = ['.semrush.com.'];
    } else if (/ahrefsbot/i.test(ua)) {
      expectedDomains = ['.ahrefs.com.'];
    } else if (/mj12bot/i.test(ua)) {
      expectedDomains = ['.mj12bot.com.'];
    } else if (/dotbot/i.test(ua)) {
      expectedDomains = ['.opensiteexplorer.org.', '.moz.com.'];
    } else {
      isLegit = false;
      botVerificationCache.set(cacheKey, { isLegit, timestamp: Date.now() });
      return isLegit;
    }

    const response = await fetch(`https://dns.google/resolve?name=${ip.split('.').reverse().join('.')}.in-addr.arpa&type=PTR`, { timeout: 2000 });

    const data = await response.json();

    if (data.Answer) {
      const ptr = data.Answer.find((a) => a.type === 12)?.data;
      if (ptr) {
        isLegit = expectedDomains.some((domain) => ptr.includes(domain));
      }
    }

    if (!isLegit) {
      console.log(`[SECURITY] Fake bot detected: UA="${ua.substring(0, 50)}" IP=${ip} PTR=${data.Answer?.[0]?.data || 'none'}`);
    }
  } catch (err) {
    isLegit = false;
    console.log(`[SECURITY] Bot verification failed for IP=${ip}: ${err.message}`);
  }

  botVerificationCache.set(cacheKey, {
    isLegit,
    timestamp: Date.now()
  });

  return isLegit;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, value] of botVerificationCache.entries()) {
    if (now - value.timestamp > VERIFICATION_CACHE_TTL) {
      botVerificationCache.delete(key);
    }
  }
}, 300000);

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
  if (!token || typeof token !== 'string' || token.length > 512) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  try {
    if (parts[0].length > 512 || parts[1].length > 128) return null;

    const payload = Buffer.from(parts[0], 'base64url').toString('utf8');
    const signature = parts[1];

    if (payload.length > 1024) return null;

    const hmac = createHmac('sha256', TOKEN_SECRET);
    hmac.update(payload);
    const expected = hmac.digest('base64url');

    if (signature.length !== expected.length) return null;
    if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;

    const data = JSON.parse(payload);
    if (!data.iat || !data.exp || typeof data.iat !== 'number' || typeof data.exp !== 'number') return null;
    if (data.exp < Date.now()) return null;
    if (data.iat > Date.now() + 1000) return null;
    if (data.exp - data.iat > TOKEN_VALIDITY + 1000) return null;

    if (req && data.fp) {
      const ip = toIPv4(null, req);
      const ua = req.headers['user-agent'] || '';
      const currentFP = createHmac('sha256', TOKEN_SECRET)
        .update(ip + ua)
        .digest('hex')
        .slice(0, 16);
      if (data.fp.length !== currentFP.length) return null;
      if (!timingSafeEqual(Buffer.from(data.fp), Buffer.from(currentFP))) return null;
    }

    return data;
  } catch {
    return null;
  }
}

function checkSystemPressure() {
  const now = Date.now();
  const timeDelta = (now - systemState.lastCheck) / 1000;
  if (timeDelta < 1) return systemState.cpuHigh;

  const previousCheck = systemState.lastCheck;
  systemState.lastCheck = now;
  updateBaseline();

  requestRateTracker.requests.push(now);
  requestRateTracker.requests = requestRateTracker.requests.filter((t) => now - t < 60000);
  systemState.requestRatePerMinute = requestRateTracker.requests.length;

  const cpuUsage = shield.getCpuUsage();
  const requestRate = timeDelta > 0 ? systemState.totalRequests / timeDelta : 0;
  const blockRate = shield.getRecentBlockRate();
  const blockRatio = requestRate > 0 ? blockRate / requestRate : 0;

  const cpuSpike = cpuUsage > baselineMetrics.baselineCpu * 1.2;
  const cpuBusy = cpuUsage > baselineMetrics.baselineCpu * 1.1;
  const blockRatioHigh = blockRatio > 0.3;

  if (cpuSpike && blockRatioHigh && systemState.state !== 'ATTACK') {
    systemState.state = 'ATTACK';
  } else if (cpuBusy && !blockRatioHigh && systemState.state === 'NORMAL') {
    systemState.state = 'BUSY';
  } else if (!cpuBusy && systemState.state !== 'NORMAL') {
    systemState.state = 'NORMAL';
  }

  systemState.cpuHigh = cpuUsage > CPU_THRESHOLD || systemState.activeConnections > 25000;
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

app.get(
  '/api/bot-challenge',
  rateLimit({
    windowMs: 60000,
    max: 10,
    keyGenerator: (req) => toIPv4(null, req)
  }),
  (req, res) => {
    const ip = toIPv4(null, req);
    const fingerprint = createFingerprint(req);
    const lastSolve = systemState.lastPowSolve.get(ip);
    const isRecentlySolved = lastSolve && Date.now() - lastSolve < 3600000;
    const isTrusted = systemState.trustedClients.has(fingerprint);

    const difficulty = isTrusted || isRecentlySolved ? BASE_POW_DIFFICULTY : systemState.currentPowDifficulty;

    shield.trackChallengeHit(ip);
    res.json({ challenge: randomBytes(16).toString('hex'), difficulty });
  }
);

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
  const requiredZeros = Math.floor(systemState.currentPowDifficulty / 4);
  const timingValid = timing > 10 && timing < 60000;

  if (leadingZeros >= requiredZeros && timingValid) {
    const ip = toIPv4(null, req);
    const fingerprint = createHmac('sha256', TOKEN_SECRET)
      .update(ip + (req.headers['user-agent'] || ''))
      .digest('hex')
      .slice(0, 16);

    const token = createToken({ http: true, ws: true, fp: fingerprint });
    systemState.lastPowSolve.set(ip, Date.now());
    systemState.trustedClients.add(fingerprint);

    res.cookie('bot_token', token, {
      maxAge: TOKEN_VALIDITY,
      httpOnly: true,
      sameSite: 'Lax',
      secure: process.env.NODE_ENV === 'production'
    });
    return res.json({ success: true, token });
  }

  shield.incrementBlocked(toIPv4(null, req), 'pow_fail');
  res.status(403).json({ error: 'Verification failed' });
});

const gateMiddleware = async (req, res, next) => {
  systemState.totalRequests++;

  const ua = req.headers['user-agent'] || '';
  const ip = toIPv4(null, req);
  const isBrowser = /Mozilla|Chrome|Safari|Firefox|Edge/i.test(ua);

  const goodBots = [
    /googlebot/i,
    /bingbot/i,
    /slurp/i,
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

  const botMatch = goodBots.find((pattern) => pattern.test(ua));
  const isClaimingBot = !!botMatch;

  if (!isBrowser && isClaimingBot && req.path !== '/api/bot-challenge' && req.path !== '/api/bot-verify') {
    const isVerified = await verifyLegitimateBot(ua, ip);

    if (!isVerified) {
      shield.incrementBlocked(ip, 'fake_bot');
      return res.status(403).send('Forbidden');
    }

    return next();
  }

  if (!isBrowser && !isClaimingBot && req.path !== '/api/bot-challenge' && req.path !== '/api/bot-verify') {
    shield.incrementBlocked(ip, 'no_ua');
    return res.status(403).send('Forbidden');
  }

  if (isBrowser && isClaimingBot) {
    const isVerified = await verifyLegitimateBot(ua, ip);
    if (!isVerified) {
      shield.incrementBlocked(ip, 'fake_bot');
    } else {
      return next();
    }
  }

  const token = extractToken(req);
  const tokenData = verifyToken(token, req);
  const fingerprint = createFingerprint(req);
  const isTrusted = tokenData?.features?.http || req.session?.user || systemState.trustedClients.has(fingerprint);

  if (isTrusted) {
    return next();
  }

  const pressureState = checkSystemPressure();
  if (pressureState && systemState.state === 'ATTACK') {
    shield.incrementBlocked(ip, 'pressure');
    return res.status(503).send('Service temporarily unavailable');
  }

  const baseline = {
    baselineCpu: baselineMetrics.baselineCpu,
    baselineRequestRate: baselineMetrics.baselineRequestRate,
    baselineBlockRate: baselineMetrics.baselineBlockRate,
    baselineUniqueIps: baselineMetrics.baselineUniqueIps
  };

  shield.checkAttackConditions(ip, { ...systemState, ...baseline });

  adjustPowDifficulty(req);

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
if(nonce>2000000)break;
}
const timing=performance.now()-start;
const v=await fetch('/api/bot-verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challenge,nonce,timing})});
if(v.ok)location.reload();
else document.body.innerHTML='<p>Verification failed. Please refresh.</p>';
})();
</script>
</body>
</html>`);
  }

  shield.incrementBlocked(ip, 'no_token');
  return res.status(403).send('Forbidden');
};

const authRoutes = ['/api/signin', '/api/signup', '/api/bot-challenge', '/api/bot-verify', '/api/verify-email'];
const apiRoutes = [
  '/api/signin',
  '/api/signup',
  '/api/bot-challenge',
  '/api/bot-verify',
  '/api/verify-email',
  '/api/signout',
  '/api/profile',
  '/api/update-profile',
  '/api/load-localstorage',
  '/api/delete-account',
  '/api/changelog',
  '/api/feedback',
  '/api/comment',
  '/api/comments',
  '/api/like',
  '/api/likes',
  '/api/upload-profile-pic',
  '/api/save-localstorage',
  '/api/change-password',
  '/api/admin/user-action',
  '/api/admin/feedback',
  '/api/admin/stats',
  '/api/admin/users'
];
const authPaths = new Set(authRoutes);
const apiPaths = new Set(apiRoutes);

const memoryProtection = (req, res, next) => {
  if (checkMemoryPressure()) {
    const ip = toIPv4(null, req);
    updateIPReputation(ip, -5);
    shield.trackMemoryPressure(ip);
    if (!apiPaths.has(req.path)) {
      return res.status(503).json({ error: 'Service temporarily unavailable' });
    }
  }

  const reqId = ++requestIdCounter;
  const startTime = performance.now();
  activeRequests.set(reqId, { ip: toIPv4(null, req), path: req.path, startTime });

  req.on('close', () => activeRequests.delete(reqId));
  req.on('end', () => activeRequests.delete(reqId));

  res.on('finish', () => {
    activeRequests.delete(reqId);
    const duration = performance.now() - startTime;
    if (duration > REQUEST_TIMEOUT) {
      const ip = toIPv4(null, req);
      updateIPReputation(ip, -2);
    }
  });

  const contentLength = parseInt(req.headers['content-length'] || '0');
  if (contentLength > MAX_REQUEST_SIZE) {
    const ip = toIPv4(null, req);
    updateIPReputation(ip, -10);
    shield.incrementBlocked(ip, 'payload_oversized');
    return res.status(413).json({ error: 'Request too large' });
  }

  const totalHeaderSize = Object.entries(req.headers).reduce(
    (sum, [k, v]) => sum + k.length + (Array.isArray(v) ? v.join('').length : String(v).length),
    0
  );
  if (totalHeaderSize > MAX_HEADER_SIZE) {
    const ip = toIPv4(null, req);
    updateIPReputation(ip, -15);
    shield.incrementBlocked(ip, 'header_oversized');
    return res.status(431).json({ error: 'Headers too large' });
  }

  const fingerprint = createFingerprint(req);
  const ip = toIPv4(null, req);
  const fpData = requestFingerprints.get(fingerprint) || { count: 0, lastSeen: 0, ip };
  fpData.count++;
  fpData.lastSeen = Date.now();
  requestFingerprints.set(fingerprint, fpData);

  if (fpData.count > 1000 && Date.now() - fpData.lastSeen < 60000) {
    updateIPReputation(ip, -20);
    shield.incrementBlocked(ip, 'fingerprint_abuse');
    return res.status(429).json({ error: 'Too many requests' });
  }

  next();
};

const assetExtensions = new Set([
  '.js',
  '.css',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.avif',
  '.svg',
  '.woff',
  '.woff2',
  '.ttf',
  '.otf',
  '.eot',
  '.ico',
  '.wasm',
  '.map',
  '.json',
  '.xml',
  '.txt',
  '.pdf',
  '.mp3',
  '.mp4',
  '.ogg',
  '.wav',
  '.avi',
  '.mov',
  '.zip',
  '.rar',
  '.bin'
]);
const assetPaths = [
  '/storage/',
  '/static/',
  '/uploads/',
  '/scram/',
  '/baremux/',
  '/epoxy/',
  '/bare/',
  '/api/bare-premium/',
  '/wisp/',
  '/api/wisp-premium/',
  '/api/alt-wisp-1/',
  '/api/alt-wisp-2/',
  '/api/alt-wisp-3/',
  '/api/alt-wisp-4/',
  '/pages/'
];

const conditionalGate = (req, res, next) => {
  const path = req.path.split('?')[0].toLowerCase();
  const extIndex = path.lastIndexOf('.');
  const hasExtension = extIndex > 0 && extIndex < path.length - 1;
  const extension = hasExtension ? path.substring(extIndex) : '';

  const isAsset =
    (hasExtension && assetExtensions.has(extension)) ||
    assetPaths.some((p) => path.startsWith(p.toLowerCase())) ||
    /\.(js|css|png|jpg|jpeg|gif|webp|svg|woff|woff2|ttf|otf|ico|wasm|map|json|xml|mp3|mp4|ogg|wav|bin)$/i.test(path);

  if (isAsset) {
    return next();
  }

  const ip = toIPv4(null, req);

  if (checkCircuitBreaker(ip)) {
    shield.incrementBlocked(ip, 'circuit_open');
    return res.status(429).json({ error: 'Too many requests' });
  }

  if (apiPaths.has(req.path)) {
    return next();
  }

  if (req.path.startsWith('/api/')) {
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

app.use(memoryProtection);
app.use(conditionalGate);

const authLimiter = rateLimit({
  windowMs: 60000,
  max: 20,
  keyGenerator: (req) => toIPv4(null, req),
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    const ip = toIPv4(null, req);
    const reputation = ipReputation.get(ip);
    return reputation && reputation.score < -50;
  },
  handler: (req, res) => {
    const ip = toIPv4(null, req);
    updateIPReputation(ip, -5);
    res.status(429).json({ error: 'Too many authentication attempts' });
  }
});

const apiLimiter = rateLimit({
  windowMs: 15000,
  max: (req) => {
    const token = extractToken(req);
    const ip = toIPv4(null, req);
    const reputation = ipReputation.get(ip);
    if (reputation && reputation.score < -50) return 10;
    if (authPaths.has(req.path)) return 20;
    return verifyToken(token, req) ? 200 : 50;
  },
  keyGenerator: (req) => {
    const token = extractToken(req);
    if (verifyToken(token, req)) return `token:${token.slice(0, 16)}`;
    const ip = toIPv4(null, req);
    if (req.session?.user?.id) return `user:${req.session.user.id}`;
    return ip;
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => false,
  handler: (req, res) => {
    const ip = toIPv4(null, req);
    updateIPReputation(ip, -3);
    shield.incrementBlocked(ip, 'rate_limit');
    res.status(429).json({ error: 'Too many requests, slow down' });
  }
});

app.use('/bare/', apiLimiter);
app.use('/api/', (req, res, next) => {
  if (authPaths.has(req.path)) {
    return authLimiter(req, res, next);
  }
  return apiLimiter(req, res, next);
});

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));

app.use(
  express.json({
    limit: MAX_JSON_SIZE,
    verify: (req, res, buf, encoding) => {
      if (buf && buf.length > MAX_JSON_SIZE) {
        const ip = toIPv4(req.socket.remoteAddress);
        updateIPReputation(ip, -10);
        shield.incrementBlocked(ip, 'json_oversized');
        throw new Error('JSON payload too large');
      }
      const startTime = Date.now();
      try {
        JSON.parse(buf.toString());
      } catch {
        const ip = toIPv4(req.socket.remoteAddress);
        if (Date.now() - startTime > 100) {
          updateIPReputation(ip, -5);
          shield.incrementBlocked(ip, 'json_parse_attack');
        }
      }
    }
  })
);

app.use(express.urlencoded({ extended: true, limit: MAX_JSON_SIZE, parameterLimit: 100 }));

app.use(
  fileUpload({
    limits: { fileSize: 10 * 1024 * 1024, files: 1 },
    abortOnLimit: true,
    limitHandler: (req, res) => {
      const ip = toIPv4(req.socket.remoteAddress);
      updateIPReputation(ip, -10);
      shield.incrementBlocked(ip, 'file_oversized');
      res.status(413).json({ error: 'File too large' });
    }
  })
);

app.use(
  session({
    secret: process.env.SESSION_SECRET || randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    name: 'session',
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 86400000
    },
    rolling: true
  })
);

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

const wsConnections = new Map();
const MAX_WS_PER_IP = 1000;
const MAX_TOTAL_WS = 2000000;

function cleanupWS(ip, req = null) {
  const actualIP = req ? toIPv4(null, req) : ip;
  const count = wsConnections.get(actualIP) || 0;
  if (count <= 1) wsConnections.delete(actualIP);
  else wsConnections.set(actualIP, count - 1);
  systemState.activeConnections--;
  systemState.totalWS--;
  shield.trackWS(actualIP, -1);
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
  const ip = toIPv4(null, req);
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
  const ip = toIPv4(null, req);
  
  const wispPaths = ['/wisp/', '/api/wisp-premium/', '/api/alt-wisp-1/', '/api/alt-wisp-2/', '/api/alt-wisp-3/', '/api/alt-wisp-4/'];
  const isWisp = wispPaths.some((p) => req.url.startsWith(p));
  const isBare = bare.shouldRoute(req) || barePremium.shouldRoute(req);
  
  if (!isWisp && !isBare) {
    return socket.destroy();
  }
  
  if (checkCircuitBreaker(ip) && !isWisp && !isBare) {
    shield.incrementBlocked(ip, 'circuit_open');
    return socket.destroy();
  }
  
  const current = wsConnections.get(ip) || 0;

  if (!isWisp && !isBare && systemState.totalWS >= MAX_TOTAL_WS) {
    shield.trackWS(ip, 1);
    shield.incrementBlocked(ip, 'ws_limit');
    updateIPReputation(ip, -5);
    return socket.destroy();
  }

  shield.trackWS(ip, 1);
  wsConnections.set(ip, current + 1);
  systemState.activeConnections++;
  systemState.totalWS++;

  socket.setNoDelay(true);
  socket.setKeepAlive(true, 60000);
  socket.setTimeout(0);

  wsFlushSockets.add(socket);

  socket.on('close', () => {
    cleanupWS(ip, req);
    wsFlushSockets.delete(socket);
  });
  socket.on('error', () => {
    cleanupWS(ip, req);
    wsFlushSockets.delete(socket);
  });

  const handleBareUpgrade = (bareServer) => {
    try {
      bareServer.routeUpgrade(req, socket, head);
    } catch (error) {
      console.error('Bare server upgrade error:', error.message);
      socket.destroy();
      cleanupWS(ip, req);
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
      cleanupWS(ip, req);
    }
  } else {
    cleanupWS(ip, req);
    socket.destroy();
  }
});

const port = parseInt(process.env.PORT || '3000');
server.keepAliveTimeout = 120000;
server.headersTimeout = 125000;
server.requestTimeout = 120000;
server.timeout = 0;
server.maxHeadersCount = 100;
server.maxHeaderSize = MAX_HEADER_SIZE;

const wsFlushSockets = new Set();
let wsFlushPending = false;
let memoryMonitorInterval = null;
let cleanupInterval = null;

function flushWebSockets() {
  if (wsFlushPending || wsFlushSockets.size === 0) return;

  const mem = getMemoryUsage();
  if (mem.heapUsed < MEMORY_CRITICAL * 0.8 && !memoryPressure.active) return;

  wsFlushPending = true;
  shield.sendLog('⚡ WebSocket flush initiated due to memory pressure', null);

  let flushed = 0;
  const maxFlush = Math.floor(systemState.totalWS * 0.3);

  for (const socket of wsFlushSockets) {
    if (flushed >= maxFlush) break;
    try {
      if (socket.readyState === 1) {
        socket.close(1001, 'Memory management');
        flushed++;
      }
    } catch {}
  }

  wsFlushSockets.clear();
  wsFlushPending = false;

  if (global.gc && mem.heapUsed > MEMORY_CRITICAL) {
    global.gc();
  }

  shield.sendLog(`✅ WebSocket flush complete: ${flushed} connections closed`, null);
}

function startMemoryMonitoring() {
  if (memoryMonitorInterval) return;

  memoryMonitorInterval = setInterval(() => {
    const mem = getMemoryUsage();
    checkMemoryPressure();
    checkSystemPressure();

    shield.updateMemoryStats(mem, memoryPressure.active, activeRequests.size);

    const baseline = {
      baselineCpu: baselineMetrics.baselineCpu,
      baselineRequestRate: baselineMetrics.baselineRequestRate,
      baselineBlockRate: baselineMetrics.baselineBlockRate,
      baselineUniqueIps: baselineMetrics.baselineUniqueIps
    };

    shield.checkAttackConditions('system', { ...systemState, ...baseline });

    if (memoryPressure.active && systemState.totalWS > 1000 && systemState.state === 'ATTACK') {
      flushWebSockets();
    }

    if (mem.heapUsed > MEMORY_CRITICAL * 1.2) {
      shield.sendLog('🚨 CRITICAL: Memory usage extremely high, forcing cleanup', null);
      if (systemState.state === 'ATTACK') {
        flushWebSockets();
      }
      if (global.gc) global.gc();

      const now = Date.now();
      for (const [key, value] of requestFingerprints.entries()) {
        if (now - value.lastSeen > 300000) requestFingerprints.delete(key);
      }

      for (const [ip, solveTime] of systemState.lastPowSolve.entries()) {
        if (now - solveTime > 86400000) systemState.lastPowSolve.delete(ip);
      }
    }
  }, 5000);
}

function startCleanupInterval() {
  if (cleanupInterval) return;

  cleanupInterval = setInterval(() => {
    const now = Date.now();

    for (const [key, value] of requestFingerprints.entries()) {
      if (now - value.lastSeen > 300000) requestFingerprints.delete(key);
    }

    for (const [ip, rep] of ipReputation.entries()) {
      if (now - rep.lastSeen > 86400000) {
        ipReputation.delete(ip);
        circuitBreakers.delete(ip);
      }
    }

    for (const [reqId, req] of activeRequests.entries()) {
      if (now - req.startTime > REQUEST_TIMEOUT * 2) {
        activeRequests.delete(reqId);
      }
    }

    if (systemState.trustedClients.size > 10000) {
      systemState.trustedClients.clear();
    }

    for (const [ip, solveTime] of systemState.lastPowSolve.entries()) {
      if (now - solveTime > 86400000) {
        systemState.lastPowSolve.delete(ip);
      }
    }
  }, 60000);
}

if (process.env.NODE_OPTIONS && process.env.NODE_OPTIONS.includes('--expose-gc')) {
  v8.setFlagsFromString('--expose-gc');
}

process.setMaxListeners(0);
process.on('uncaughtException', (err) => {
  shield.sendLog(`💥 Uncaught Exception: ${err.message}`, null);
  console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  shield.sendLog(`⚠️ Unhandled Rejection: ${reason}`, null);
  console.error('Unhandled Rejection:', reason);
});

server.listen({ port }, () => {
  const address = server.address();
  console.log('Listening on:');
  console.log(`\thttp://localhost:${address.port}`);
  console.log(`\thttp://${hostname()}:${address.port}`);
  console.log(`\thttp://${address.family === 'IPv6' ? `[${address.address}]` : address.address}:${address.port}`);

  startMemoryMonitoring();
  startCleanupInterval();
});

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

function shutdown() {
  console.log('Shutting down...');

  if (memoryMonitorInterval) clearInterval(memoryMonitorInterval);
  if (cleanupInterval) clearInterval(cleanupInterval);

  for (const socket of wsFlushSockets) {
    try {
      if (socket.readyState === 1) socket.close(1001, 'Server shutdown');
    } catch {}
  }

  if (shield.isUnderAttack) {
    const baseline = {
      baselineCpu: baselineMetrics.baselineCpu,
      baselineRequestRate: baselineMetrics.baselineRequestRate,
      baselineBlockRate: baselineMetrics.baselineBlockRate,
      baselineUniqueIps: baselineMetrics.baselineUniqueIps
    };
    shield.endAttackAlert({ ...systemState, ...baseline });
  }

  server.close(() => {
    bare.close();
    process.exit(0);
  });

  setTimeout(() => {
    bare.close();
    process.exit(1);
  }, 500);
}
