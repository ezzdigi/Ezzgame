// EzzDigi Ezzgame — Cloudflare Worker API
// Membership verification + D1 leaderboard + score sync
// Required secrets/vars:
//   BOT_TOKEN       -> Telegram bot token (Secret)
//   CHANNEL_USERNAME -> @ezzdigii (Variable)
// D1 binding:
//   DB

const CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
};

function corsHeaders(request) {
  const h = new Headers(CORS_HEADERS);
  const origin = request.headers.get("Origin");
  if (origin) h.set("Access-Control-Allow-Origin", origin);
  else h.set("Access-Control-Allow-Origin", "*");
  h.set("Vary", "Origin");
  return h;
}

function json(request, data, status = 200) {
  const h = corsHeaders(request);
  h.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers: h });
}

function text(request, body, status = 200) {
  const h = corsHeaders(request);
  h.set("Content-Type", "text/plain; charset=utf-8");
  return new Response(body, { status, headers: h });
}

function normalizeChannel(value) {
  let v = String(value || "").trim();
  if (!v) return "";
  if (!v.startsWith("@") && !v.startsWith("-100")) v = "@" + v;
  return v;
}

function safeString(value, max = 200) {
  return String(value ?? "").trim().slice(0, max);
}

function safeInt(value, fallback = 0, min = 0, max = 2147483647) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function base64UrlToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64 + pad);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function hmacSha256(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, dataBytes));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a[i] ^ b[i];
  return x === 0;
}

// Telegram Mini App initData validation.
// Telegram: secret_key = HMAC-SHA256("WebAppData", bot_token)
// hash = HMAC-SHA256(secret_key, data_check_string)
async function validateInitData(initData, botToken, maxAgeSeconds = 86400) {
  if (!initData || !botToken) {
    return { ok: false, code: "missing_initdata_or_token" };
  }

  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");
    if (!receivedHash) return { ok: false, code: "missing_hash" };

    const authDate = Number(params.get("auth_date") || 0);
    if (!authDate || !Number.isFinite(authDate)) {
      return { ok: false, code: "missing_auth_date" };
    }

    const age = Math.floor(Date.now() / 1000) - authDate;
    if (age > maxAgeSeconds || age < -300) {
      return { ok: false, code: "initdata_expired", age };
    }

    params.delete("hash");
    const pairs = [...params.entries()].sort(([a], [b]) => a.localeCompare(b));
    const dataCheckString = pairs.map(([k, v]) => `${k}=${v}`).join("\n");

    const enc = new TextEncoder();
    const secretKey = await hmacSha256(enc.encode("WebAppData"), enc.encode(botToken));
    const calculated = await hmacSha256(secretKey, enc.encode(dataCheckString));

    const received = hexToBytes(receivedHash);
    if (!timingSafeEqual(calculated, received)) {
      return { ok: false, code: "invalid_initdata_hash" };
    }

    let user = null;
    const rawUser = params.get("user");
    if (rawUser) {
      try { user = JSON.parse(rawUser); } catch {}
    }

    if (!user?.id) return { ok: false, code: "user_missing" };

    return {
      ok: true,
      user,
      authDate,
      age,
    };
  } catch (e) {
    return { ok: false, code: "initdata_parse_error", detail: String(e?.message || e) };
  }
}

async function telegramApi(env, method, params = {}) {
  if (!env.BOT_TOKEN) {
    return { ok: false, code: "bot_token_missing" };
  }

  const url = `https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
    });

    const raw = await response.text();
    let data;
    try { data = JSON.parse(raw); } catch {
      return {
        ok: false,
        code: "telegram_invalid_json",
        httpStatus: response.status,
        raw: raw.slice(0, 500),
      };
    }

    if (!response.ok || data.ok !== true) {
      return {
        ok: false,
        code: "telegram_api_error",
        httpStatus: response.status,
        errorCode: data.error_code ?? null,
        description: data.description ?? "Telegram API error",
      };
    }

    return { ok: true, data };
  } catch (e) {
    return {
      ok: false,
      code: "telegram_fetch_error",
      detail: String(e?.message || e),
    };
  }
}

async function isChannelMember(env, userId) {
  const channel = normalizeChannel(env.CHANNEL_USERNAME);

  if (!channel) {
    return { ok: false, member: false, code: "channel_username_missing" };
  }

  const result = await telegramApi(env, "getChatMember", {
    chat_id: channel,
    user_id: Number(userId),
  });

  if (!result.ok) {
    return {
      ok: false,
      member: false,
      code: result.code,
      telegram: {
        httpStatus: result.httpStatus ?? null,
        errorCode: result.errorCode ?? null,
        description: result.description ?? null,
      },
    };
  }

  const status = result.data?.result?.status || "unknown";
  const member = ["creator", "administrator", "member"].includes(status);

  return {
    ok: true,
    member,
    status,
    userId: Number(userId),
  };
}

async function ensureSchema(env) {
  if (!env.DB) return false;

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS scores (
      telegram_id TEXT PRIMARY KEY,
      username TEXT,
      name TEXT NOT NULL,
      level INTEGER NOT NULL DEFAULT 1,
      coins INTEGER NOT NULL DEFAULT 0,
      updated_at INTEGER NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_scores_coins
    ON scores(coins DESC)
  `).run();

  return true;
}

async function checkMembership(request, env) {
  if (!env.BOT_TOKEN || !env.CHANNEL_USERNAME) {
    return json(request, {
      ok: false,
      member: false,
      error: "telegram_not_configured",
      details: {
        botToken: !!env.BOT_TOKEN,
        channel: !!env.CHANNEL_USERNAME,
      }
    }, 500);
  }

  const body = await request.json().catch(() => null);
  const initData = body?.initData;

  if (!initData) {
    return json(request, {
      ok: false,
      member: false,
      error: "initData_missing"
    }, 400);
  }

  const maxAge = safeInt(env.INITDATA_MAX_AGE_SECONDS, 86400, 60, 604800);
  const validation = await validateInitData(initData, env.BOT_TOKEN, maxAge);

  if (!validation.ok) {
    return json(request, {
      ok: false,
      member: false,
      error: "initData_invalid",
      reason: validation.code,
      age: validation.age ?? null
    }, 401);
  }

  const membership = await isChannelMember(env, validation.user.id);

  if (!membership.ok) {
    return json(request, {
      ok: false,
      member: false,
      error: "telegram_membership_check_failed",
      reason: membership.code,
      telegram: membership.telegram || null,
      userId: Number(validation.user.id)
    }, 502);
  }

  return json(request, {
    ok: true,
    member: membership.member,
    status: membership.status,
    userId: Number(validation.user.id),
    username: validation.user.username || "",
    firstName: validation.user.first_name || ""
  });
}

async function scoreSync(request, env) {
  if (!env.DB) {
    return json(request, { ok: false, error: "d1_not_configured" }, 500);
  }

  if (!env.BOT_TOKEN || !env.CHANNEL_USERNAME) {
    return json(request, { ok: false, error: "telegram_not_configured" }, 500);
  }

  const body = await request.json().catch(() => null);
  const initData = body?.initData;

  const validation = await validateInitData(
    initData,
    env.BOT_TOKEN,
    safeInt(env.INITDATA_MAX_AGE_SECONDS, 86400, 60, 604800)
  );

  if (!validation.ok) {
    return json(request, {
      ok: false,
      error: "initData_invalid",
      reason: validation.code
    }, 401);
  }

  const membership = await isChannelMember(env, validation.user.id);

  if (!membership.ok) {
    return json(request, {
      ok: false,
      error: "telegram_membership_check_failed",
      reason: membership.code,
      telegram: membership.telegram || null
    }, 502);
  }

  if (!membership.member) {
    // Do not delete the server score here; the frontend will reset its state.
    return json(request, {
      ok: true,
      member: false,
      reset: true,
      coins: 0,
      level: 1
    });
  }

  await ensureSchema(env);

  const id = String(validation.user.id);
  const username = safeString(validation.user.username || body?.username, 100);
  const name = safeString(body?.name || [validation.user.first_name, validation.user.last_name].filter(Boolean).join(" ") || username || "Player", 100) || "Player";
  const level = safeInt(body?.level, 1, 1, 1000000);
  const coins = safeInt(body?.coins, 0, 0, 2147483647);
  const now = Math.floor(Date.now() / 1000);

  const existing = await env.DB.prepare(
    `SELECT coins, level FROM scores WHERE telegram_id = ?`
  ).bind(id).first();

  if (existing && coins < Number(existing.coins)) {
    return json(request, {
      ok: true,
      member: true,
      accepted: false,
      coins: Number(existing.coins),
      level: Number(existing.level)
    });
  }

  await env.DB.prepare(`
    INSERT INTO scores (telegram_id, username, name, level, coins, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(telegram_id) DO UPDATE SET
      username=excluded.username,
      name=excluded.name,
      level=excluded.level,
      coins=excluded.coins,
      updated_at=excluded.updated_at
  `).bind(id, username, name, level, coins, now).run();

  return json(request, {
    ok: true,
    member: true,
    accepted: true,
    coins,
    level
  });
}

async function leaderboard(request, env) {
  if (!env.DB) {
    return json(request, { ok: false, error: "d1_not_configured" }, 500);
  }

  await ensureSchema(env);

  const url = new URL(request.url);
  const initData = url.searchParams.get("initData") || "";

  let userId = null;

  if (initData && env.BOT_TOKEN) {
    const validation = await validateInitData(
      initData,
      env.BOT_TOKEN,
      safeInt(env.INITDATA_MAX_AGE_SECONDS, 86400, 60, 604800)
    );
    if (validation.ok) userId = String(validation.user.id);
  }

  const top = await env.DB.prepare(`
    SELECT telegram_id, username, name, level, coins
    FROM scores
    ORDER BY coins DESC, updated_at ASC
    LIMIT 20
  `).all();

  let player = null;

  if (userId) {
    player = await env.DB.prepare(`
      SELECT
        telegram_id,
        username,
        name,
        level,
        coins,
        (
          SELECT COUNT(*) + 1
          FROM scores s2
          WHERE s2.coins > s1.coins
        ) AS rank
      FROM scores s1
      WHERE telegram_id = ?
    `).bind(userId).first();
  }

  const total = await env.DB.prepare(`SELECT COUNT(*) AS count FROM scores`).first();

  return json(request, {
    ok: true,
    leaderboard: top.results || [],
    player: player || null,
    totalPlayers: Number(total?.count || 0)
  });
}

async function health(request, env) {
  let d1 = false;
  let d1Error = null;

  if (env.DB) {
    try {
      await ensureSchema(env);
      await env.DB.prepare(`SELECT 1 AS ok`).first();
      d1 = true;
    } catch (e) {
      d1Error = String(e?.message || e);
    }
  }

  return json(request, {
    ok: true,
    service: "EzzDigi Ezzgame API",
    d1,
    telegramConfigured: !!(env.BOT_TOKEN && env.CHANNEL_USERNAME),
    channelConfigured: !!env.CHANNEL_USERNAME,
    diagnostics: {
      channel: env.CHANNEL_USERNAME ? normalizeChannel(env.CHANNEL_USERNAME) : null,
      botTokenConfigured: !!env.BOT_TOKEN,
      d1Error
    }
  });
}

export default {
  async fetch(request, env) {
    try {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders(request) });
      }

      const url = new URL(request.url);
      const path = url.pathname.replace(/\/+$/, "") || "/";

      if (path === "/api/health" && request.method === "GET") {
        return health(request, env);
      }

      // Membership endpoint. POST is used by the Mini App.
      // GET is intentionally supported as a safe route diagnostic so opening
      // the URL in a browser does not look like a missing endpoint.
      if (path === "/api/check-membership") {
        if (request.method === "GET") {
          return json(request, {
            ok: true,
            endpoint: "check-membership",
            method: "POST_REQUIRED",
            configured: !!(env.BOT_TOKEN && env.CHANNEL_USERNAME),
            channel: env.CHANNEL_USERNAME ? normalizeChannel(env.CHANNEL_USERNAME) : null
          });
        }
        if (request.method === "POST") {
          return checkMembership(request, env);
        }
      }

      if (path === "/api/score/sync" && request.method === "POST") {
        return scoreSync(request, env);
      }

      if (path === "/api/leaderboard" && request.method === "GET") {
        return leaderboard(request, env);
      }

      // Keep the Telegram Mini App/static site available.
      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return json(request, { ok: false, error: "not_found" }, 404);
    } catch (e) {
      return json(request, {
        ok: false,
        error: "internal_error",
        detail: String(e?.message || e)
      }, 500);
    }
  }
};
