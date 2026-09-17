const TG_API = "https://api.telegram.org";

async function hmac(keyBytes, message) {
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}

function hex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyInitData(initData, botToken) {
  if (!initData || !botToken) return null;
  const p = new URLSearchParams(initData);
  const receivedHash = p.get("hash");
  if (!receivedHash) return null;
  p.delete("hash");

  const dataCheckString = [...p.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const secret = await hmac(
    new TextEncoder().encode("WebAppData"),
    botToken
  );
  const calculated = await hmac(secret, dataCheckString);

  if (hex(calculated) !== receivedHash) return null;

  const authDate = Number(p.get("auth_date") || 0);
  if (!authDate || Math.abs(Math.floor(Date.now() / 1000) - authDate) > 86400) return null;

  let user = null;
  try { user = JSON.parse(p.get("user") || "null"); } catch {}
  return user;
}

async function checkMembership(env, userId) {
  const url = `${TG_API}/bot${env.BOT_TOKEN}/getChatMember`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ chat_id: "@ezzdigii", user_id: userId })
  });
  const data = await r.json();

  if (!data.ok) {
    return { member: false, error: "telegram_api_error" };
  }

  const m = data.result;
  const member = ["creator", "administrator", "member"].includes(m.status) ||
                 (m.status === "restricted" && m.is_member === true);

  return { member };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/check-membership") {
      if (request.method !== "POST") {
        return Response.json({ member: false, error: "method_not_allowed" }, { status: 405 });
      }

      try {
        const body = await request.json();
        const user = await verifyInitData(body.initData, env.BOT_TOKEN);

        if (!user?.id) {
          return Response.json({ member: false, error: "invalid_init_data" }, { status: 401 });
        }

        const result = await checkMembership(env, user.id);
        return Response.json(result, {
          headers: { "cache-control": "no-store" }
        });
      } catch {
        return Response.json({ member: false, error: "server_error" }, { status: 500 });
      }
    }

    // Static Mini App files are served by Cloudflare Assets.
    return env.ASSETS.fetch(request);
  }
};
