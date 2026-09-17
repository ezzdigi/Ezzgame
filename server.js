/**
 * EzzDigi — Telegram Channel Membership Server
 * ------------------------------------------------
 * Standalone Express server exposing POST /api/check-membership.
 *
 * Flow:
 *  1. Mini App sends { initData } (raw Telegram.WebApp.initData string).
 *  2. Server verifies initData's HMAC signature using your Bot Token,
 *     so a user can never fake being someone else.
 *  3. Server extracts the verified Telegram user id and calls the
 *     Bot API's getChatMember for your channel (@ezzdigii).
 *  4. Server responds { member: true|false, user: {...} }.
 *
 * The Bot Token NEVER goes to the browser — it only lives here.
 *
 * Requirements:
 *  - Your bot must be an ADMIN of the channel (Telegram requires this
 *    for getChatMember to reliably report membership status).
 *  - Node.js 18+ (uses the built-in fetch).
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const {
  BOT_TOKEN,
  CHANNEL_ID = '@ezzdigii',
  PORT = 3000,
  ALLOWED_ORIGIN = '*',
  INITDATA_MAX_AGE_SECONDS = 86400, // 24h; set '' to disable the freshness check
} = process.env;

if (!BOT_TOKEN) {
  console.error('❌ BOT_TOKEN is missing. Create a .env file (see .env.example) and set BOT_TOKEN.');
  process.exit(1);
}

const app = express();
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json());

/**
 * Validates Telegram WebApp initData per Telegram's official spec:
 * https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
 */
function validateInitData(initData, botToken) {
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return { valid: false, reason: 'no_hash' };
  params.delete('hash');

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');

  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  if (calculatedHash !== hash) return { valid: false, reason: 'bad_signature' };

  if (INITDATA_MAX_AGE_SECONDS) {
    const authDate = Number(params.get('auth_date') || 0);
    const ageSeconds = Date.now() / 1000 - authDate;
    if (ageSeconds > Number(INITDATA_MAX_AGE_SECONDS)) {
      return { valid: false, reason: 'expired' };
    }
  }

  let user = null;
  try {
    user = JSON.parse(params.get('user') || 'null');
  } catch {
    return { valid: false, reason: 'bad_user_json' };
  }
  if (!user || !user.id) return { valid: false, reason: 'no_user' };

  return { valid: true, user };
}

async function getChatMemberStatus(userId) {
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(CHANNEL_ID)}&user_id=${userId}`;
  const res = await fetch(url);
  const data = await res.json();

  if (!data.ok) {
    // Common causes: bot is not admin/member of the channel, or wrong CHANNEL_ID.
    throw new Error('telegram_api_error: ' + (data.description || 'unknown'));
  }
  return data.result.status; // creator | administrator | member | restricted | left | kicked
}

app.post('/api/check-membership', async (req, res) => {
  try {
    const { initData } = req.body || {};
    if (!initData) return res.status(400).json({ member: false, error: 'missing_initData' });

    const check = validateInitData(initData, BOT_TOKEN);
    if (!check.valid) return res.status(401).json({ member: false, error: check.reason });

    const status = await getChatMemberStatus(check.user.id);
    const isMember = ['creator', 'administrator', 'member', 'restricted'].includes(status);

    return res.json({
      member: isMember,
      status,
      user: { id: check.user.id, first_name: check.user.first_name, username: check.user.username },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ member: false, error: 'server_error' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`✅ Membership server running on port ${PORT}`);
  console.log(`   Checking membership against ${CHANNEL_ID}`);
});
