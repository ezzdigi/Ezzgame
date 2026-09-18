// EzzDigi Gaming — Membership Verification Server
// -------------------------------------------------
// One job: given a Telegram Mini App `initData` string, prove it really
// came from Telegram (HMAC signature check), then ask the Telegram Bot API
// whether that exact user is currently a member of the EzzDigi channel.
// Nothing about membership is ever trusted from the client.

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const { upsertScore, getTop, getPlayerWithRank, getTotalPlayers } = require('./lib/db');

const {
  BOT_TOKEN,           // Telegram bot token, from @BotFather
  CHANNEL_USERNAME,     // e.g. "@ezzdigii" (must include the @)
  ALLOWED_ORIGIN,       // e.g. "https://yourname.github.io" — where index.html is hosted
  PORT = 3000,
  INITDATA_MAX_AGE_SECONDS = 86400, // reject initData older than this (replay protection)
} = process.env;

if (!BOT_TOKEN) {
  console.error('FATAL: BOT_TOKEN is not set. Copy .env.example to .env and fill it in.');
  process.exit(1);
}
if (!CHANNEL_USERNAME) {
  console.error('FATAL: CHANNEL_USERNAME is not set (e.g. "@ezzdigii").');
  process.exit(1);
}

const app = express();
app.use(express.json());

// Only allow the mini app's own origin to call this API. If ALLOWED_ORIGIN
// is left empty, all origins are allowed (fine for quick testing, not for
// production — set it once you know your GitHub Pages / domain URL).
app.use(cors({
  origin: ALLOWED_ORIGIN ? ALLOWED_ORIGIN.split(',').map(s => s.trim()) : true,
}));

// Basic abuse protection: this endpoint hits the Telegram API, so it's
// worth capping how often any single IP can call it.
const membershipLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { member: false, error: 'too_many_requests' },
});

// Score syncs happen more often than membership checks (every ~8s while
// tapping), so this one is a bit more generous.
const scoreLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'too_many_requests' },
});

/**
 * Validates a Telegram Mini App `initData` string per Telegram's spec:
 * https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
 * Returns the parsed `user` object if valid, or null if the signature is
 * missing/invalid/expired.
 */
function validateInitData(initData, botToken) {
  if (!initData || typeof initData !== 'string') return null;

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');

  const pairs = [];
  for (const [key, value] of params.entries()) pairs.push(`${key}=${value}`);
  pairs.sort();
  const dataCheckString = pairs.join('\n');

  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const computedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  // Constant-time compare to avoid timing attacks.
  const a = Buffer.from(computedHash, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  const authDate = Number(params.get('auth_date'));
  const now = Math.floor(Date.now() / 1000);
  if (!authDate || now - authDate > Number(INITDATA_MAX_AGE_SECONDS)) return null;

  const userJson = params.get('user');
  if (!userJson) return null;
  try {
    return JSON.parse(userJson);
  } catch {
    return null;
  }
}

/**
 * Asks the Telegram Bot API whether `userId` is currently a member of
 * CHANNEL_USERNAME. The bot must be an admin of the channel for this to
 * work reliably (see README). Throws on Telegram API errors.
 */
async function isChannelMember(userId) {
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember` +
    `?chat_id=${encodeURIComponent(CHANNEL_USERNAME)}&user_id=${encodeURIComponent(userId)}`;
  const res = await fetch(url);
  const data = await res.json();
  if (!data.ok) {
    throw new Error(data.description || 'telegram_api_error');
  }
  const status = data.result.status; // creator | administrator | member | restricted | left | kicked
  return ['creator', 'administrator', 'member'].includes(status);
}

app.post('/api/check-membership', membershipLimiter, async (req, res) => {
  const { initData } = req.body || {};

  const user = validateInitData(initData, BOT_TOKEN);
  if (!user) {
    return res.status(401).json({ member: false, error: 'invalid_or_expired_init_data' });
  }

  try {
    const member = await isChannelMember(user.id);
    return res.json({ member, userId: user.id });
  } catch (err) {
    console.error('getChatMember failed:', err.message);
    return res.status(502).json({ member: false, error: 'telegram_api_unreachable' });
  }
});

// NOTE on trust: coins/level here come from the client, so a modified
// client could report an inflated score. This is fine for a casual,
// low-stakes leaderboard; if the monthly cash/battle-pass prizes need to
// be cheat-resistant, the tap logic itself needs to move server-side
// (server tracks energy/taps and computes coins, client just displays it).
app.post('/api/score/sync', scoreLimiter, (req, res) => {
  const { initData, coins, level } = req.body || {};

  const user = validateInitData(initData, BOT_TOKEN);
  if (!user) {
    return res.status(401).json({ ok: false, error: 'invalid_or_expired_init_data' });
  }

  // The display name is derived from the *validated* Telegram identity, not
  // from anything the client sends — this keeps the leaderboard free of
  // spoofed names. This also matches "Telegram username = in-game name".
  const name = user.username
    ? '@' + user.username
    : [user.first_name, user.last_name].filter(Boolean).join(' ') || `Player ${user.id}`;

  upsertScore({
    telegramId: user.id,
    username: user.username,
    name,
    level: Number(level),
    coins: Number(coins),
  });

  res.json({ ok: true });
});

app.get('/api/leaderboard', scoreLimiter, (req, res) => {
  // Show every member who has ever synced a score (not just a top-20 cut),
  // since the request is "show everyone who's a member, with their scores".
  const top = getTop(1000);

  let you = null;
  if (req.query.initData) {
    const user = validateInitData(String(req.query.initData), BOT_TOKEN);
    if (user) you = getPlayerWithRank(user.id);
  }

  res.json({ top, you, total: getTotalPlayers() });
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`EzzDigi membership server listening on port ${PORT}`);
});
