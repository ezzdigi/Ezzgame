// EzzDigi Gaming — Membership + Leaderboard Worker (Cloudflare Workers)
// -----------------------------------------------------------------------
// Same job as the earlier Node/Express server, rewritten for the Workers
// runtime: Web Crypto instead of Node's `crypto`, D1 instead of SQLite-on-
// disk, and a plain fetch handler instead of Express routes. This runs on
// Cloudflare's edge — no "server going to sleep" and no filesystem needed.

const JSON_HEADERS = { 'Content-Type': 'application/json' };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const cors = buildCorsHeaders(origin, env.ALLOWED_ORIGIN);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: cors });
    }

    try {
      if (url.pathname === '/health') {
        return json({ ok: true }, 200, cors);
      }

      if (url.pathname === '/api/check-membership' && request.method === 'POST') {
        return await handleCheckMembership(request, env, cors);
      }

      if (url.pathname === '/api/score/sync' && request.method === 'POST') {
        return await handleScoreSync(request, env, cors);
      }

      if (url.pathname === '/api/leaderboard' && request.method === 'GET') {
        return await handleLeaderboard(request, env, cors);
      }

      if (url.pathname === '/api/referral/claim' && request.method === 'POST') {
        return await handleReferralClaim(request, env, cors);
      }

      return json({ error: 'not_found' }, 404, cors);
    } catch (err) {
      return json({ error: 'internal_error', detail: String(err && err.message || err) }, 500, cors);
    }
  },
};

// ---------- Route handlers ----------

async function handleCheckMembership(request, env, cors) {
  const body = await safeJson(request);
  const user = await validateInitData(body.initData, env.BOT_TOKEN, maxAge(env));
  if (!user) {
    return json({ member: false, error: 'invalid_or_expired_init_data' }, 401, cors);
  }

  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await rateLimit(env, `membership:${clientIp}`, 20, 60))) {
    return json({ member: false, error: 'too_many_requests' }, 429, cors);
  }

  try {
    const member = await isChannelMember(user.id, env.BOT_TOKEN, env.CHANNEL_USERNAME);
    await setMembershipStatus(env.DB, user.id, member);
    return json({ member, userId: user.id }, 200, cors);
  } catch (e) {
    return json({ member: false, error: 'telegram_api_unreachable' }, 502, cors);
  }
}

// NOTE on trust: coins/level come from the client, so a modified client
// could report an inflated score. Fine for a casual leaderboard; if the
// monthly cash/battle-pass prizes need to be cheat-resistant, the tap
// logic itself needs to move server-side (Worker tracks energy/taps and
// computes coins, client just displays it).
async function handleScoreSync(request, env, cors) {
  const body = await safeJson(request);
  const user = await validateInitData(body.initData, env.BOT_TOKEN, maxAge(env));
  if (!user) {
    return json({ ok: false, error: 'invalid_or_expired_init_data' }, 401, cors);
  }

  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await rateLimit(env, `sync:${clientIp}`, 60, 60))) {
    return json({ ok: false, error: 'too_many_requests' }, 429, cors);
  }

  // Display name comes from the *validated* Telegram identity, not from
  // anything the client sends — nobody can spoof a fake leaderboard name.
  const name = user.username
    ? '@' + user.username
    : [user.first_name, user.last_name].filter(Boolean).join(' ') || `Player ${user.id}`;

  const level = clampInt(body.level, 1, 1);
  const coins = clampInt(body.coins, 0, 0);

  await upsertScore(env.DB, { telegramId: user.id, username: user.username, name, level, coins });
  return json({ ok: true }, 200, cors);
}

async function handleLeaderboard(request, env, cors) {
  const url = new URL(request.url);

  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await rateLimit(env, `board:${clientIp}`, 60, 60))) {
    return json({ error: 'too_many_requests' }, 429, cors);
  }

  // Only real, confirmed channel members appear here (see
  // setMembershipStatus), and only the top 10 scores are shown.
  const top = await getTop(env.DB, 10);

  let you = null;
  const initData = url.searchParams.get('initData');
  if (initData) {
    const user = await validateInitData(initData, env.BOT_TOKEN, maxAge(env));
    if (user) you = await getPlayerWithRank(env.DB, user.id);
  }

  const total = await getTotalPlayers(env.DB);
  return json({ top, you, total }, 200, cors);
}

// A new player opened the mini app via someone's referral link
// (?start=ref_<telegramId>). Credits the referrer with coins — but only
// once ever per new user, enforced by the referrals table's primary key.
async function handleReferralClaim(request, env, cors) {
  const body = await safeJson(request);
  const user = await validateInitData(body.initData, env.BOT_TOKEN, maxAge(env));
  if (!user) {
    return json({ ok: false, error: 'invalid_or_expired_init_data' }, 401, cors);
  }

  const referrerId = String(body.ref || '').trim();
  if (!/^\d+$/.test(referrerId) || referrerId === String(user.id)) {
    return json({ ok: false, error: 'invalid_referrer' }, 400, cors);
  }

  const reward = Number(env.REFERRAL_REWARD_COINS || 500);
  const result = await claimReferral(env.DB, { newUserId: user.id, referrerId, rewardCoins: reward });
  return json({ ok: true, credited: result.credited }, 200, cors);
}

// ---------- Telegram initData validation (Web Crypto, no Node APIs) ----------

async function validateInitData(initData, botToken, maxAgeSeconds) {
  if (!initData || typeof initData !== 'string' || !botToken) return null;

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');

  const pairs = [];
  for (const [key, value] of params.entries()) pairs.push(`${key}=${value}`);
  pairs.sort();
  const dataCheckString = pairs.join('\n');

  const enc = new TextEncoder();

  // secret_key = HMAC_SHA256(key="WebAppData", data=botToken)
  const webAppDataKey = await crypto.subtle.importKey(
    'raw', enc.encode('WebAppData'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const secretKeyBytes = await crypto.subtle.sign('HMAC', webAppDataKey, enc.encode(botToken));

  const secretKey = await crypto.subtle.importKey(
    'raw', secretKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const computedHashBytes = await crypto.subtle.sign('HMAC', secretKey, enc.encode(dataCheckString));
  const computedHash = bufferToHex(computedHashBytes);

  if (!timingSafeEqualHex(computedHash, hash)) return null;

  const authDate = Number(params.get('auth_date'));
  const now = Math.floor(Date.now() / 1000);
  if (!authDate || now - authDate > maxAgeSeconds) return null;

  const userJson = params.get('user');
  if (!userJson) return null;
  try {
    return JSON.parse(userJson);
  } catch {
    return null;
  }
}

function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqualHex(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------- Telegram Bot API ----------

async function isChannelMember(userId, botToken, channelUsername) {
  const url = `https://api.telegram.org/bot${botToken}/getChatMember` +
    `?chat_id=${encodeURIComponent(channelUsername)}&user_id=${encodeURIComponent(userId)}`;
  const res = await fetch(url);
  const data = await res.json();
  if (!data.ok) throw new Error(data.description || 'telegram_api_error');
  const status = data.result.status; // creator | administrator | member | restricted | left | kicked
  return ['creator', 'administrator', 'member'].includes(status);
}

// ---------- D1 (leaderboard storage) ----------

async function upsertScore(db, { telegramId, username, name, level, coins }) {
  const now = Date.now();
  await db.prepare(`
    INSERT INTO scores (telegram_id, username, name, level, coins, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(telegram_id) DO UPDATE SET
      username = excluded.username,
      name = excluded.name,
      level = excluded.level,
      coins = excluded.coins,
      updated_at = excluded.updated_at
  `).bind(String(telegramId), username || null, name, level, coins, now).run();
}

async function getTop(db, limit) {
  const { results } = await db.prepare(
    `SELECT telegram_id AS telegramId, name, level, coins FROM scores WHERE is_member = 1 ORDER BY coins DESC LIMIT ?`
  ).bind(limit).all();
  return results || [];
}

async function getPlayerWithRank(db, telegramId) {
  const row = await db.prepare(
    `SELECT name, level, coins, is_member AS isMember, referral_count AS referralCount FROM scores WHERE telegram_id = ?`
  ).bind(String(telegramId)).first();
  if (!row) return null;
  let rank = null;
  if (row.isMember) {
    const rankRow = await db.prepare(
      `SELECT COUNT(*) AS n FROM scores WHERE coins > ? AND is_member = 1`
    ).bind(row.coins).first();
    rank = (rankRow ? rankRow.n : 0) + 1;
  }
  return { name: row.name, level: row.level, coins: row.coins, referralCount: row.referralCount, rank };
}

async function getTotalPlayers(db) {
  const row = await db.prepare(`SELECT COUNT(*) AS n FROM scores WHERE is_member = 1`).first();
  return row ? row.n : 0;
}

// Records the real, server-confirmed channel-membership result for a user.
// Only members ever appear on the public leaderboard (see getTop/getPlayerWithRank).
async function setMembershipStatus(db, telegramId, isMember) {
  await db.prepare(`
    INSERT INTO scores (telegram_id, username, name, level, coins, is_member, updated_at)
    VALUES (?, NULL, ?, 1, 0, ?, ?)
    ON CONFLICT(telegram_id) DO UPDATE SET
      is_member = excluded.is_member,
      updated_at = excluded.updated_at
  `).bind(String(telegramId), `Player ${telegramId}`, isMember ? 1 : 0, Date.now()).run();
}

// One-time credit per new user, enforced by the referrals table's primary
// key (the INSERT only succeeds the first time for a given new_user_id).
async function claimReferral(db, { newUserId, referrerId, rewardCoins }) {
  const insertResult = await db.prepare(
    `INSERT OR IGNORE INTO referrals (new_user_id, referrer_id, created_at) VALUES (?, ?, ?)`
  ).bind(String(newUserId), String(referrerId), Date.now()).run();

  const changes = insertResult.meta ? insertResult.meta.changes : insertResult.changes;
  if (!changes) return { credited: false }; // already claimed before

  const now = Date.now();
  await db.prepare(`
    INSERT INTO scores (telegram_id, username, name, level, coins, referral_count, updated_at)
    VALUES (?, NULL, ?, 1, ?, 1, ?)
    ON CONFLICT(telegram_id) DO UPDATE SET
      coins = coins + ?,
      referral_count = referral_count + 1,
      updated_at = excluded.updated_at
  `).bind(String(referrerId), `Player ${referrerId}`, rewardCoins, now, rewardCoins).run();

  return { credited: true };
}

// ---------- Optional rate limiting (only active if RATE_LIMIT_KV is bound) ----------

async function rateLimit(env, key, limit, windowSeconds) {
  const kv = env.RATE_LIMIT_KV;
  if (!kv) return true; // no KV bound => rate limiting is skipped
  const now = Math.floor(Date.now() / 1000);
  const windowKey = `${key}:${Math.floor(now / windowSeconds)}`;
  const current = Number((await kv.get(windowKey)) || '0');
  if (current >= limit) return false;
  await kv.put(windowKey, String(current + 1), { expirationTtl: windowSeconds * 2 });
  return true;
}

// ---------- Small helpers ----------

function maxAge(env) {
  return Number(env.INITDATA_MAX_AGE_SECONDS || 86400);
}

function clampInt(value, min, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(min, Math.floor(n)) : fallback;
}

async function safeJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function json(data, status, corsHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...corsHeaders },
  });
}

function buildCorsHeaders(origin, allowedOriginSetting) {
  const allowed = (allowedOriginSetting || '').split(',').map((s) => s.trim()).filter(Boolean);
  const allowOrigin = allowed.length === 0 || allowed.includes(origin) ? (origin || '*') : allowed[0];
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
}
