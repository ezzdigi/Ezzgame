// Tiny SQLite wrapper for storing each player's latest known score.
// Uses better-sqlite3 (synchronous, no extra async ceremony needed for a
// table this small). The DB file lives in ./data/scores.db by default.
//
// NOTE on hosting: on Render's free tier the filesystem is ephemeral — the
// DB resets on every redeploy/restart unless you attach a persistent disk
// (Render → your service → Disks). For a small leaderboard this is usually
// fine to start with; add a persistent disk once it matters to you.

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'scores.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS scores (
    telegram_id TEXT PRIMARY KEY,
    username    TEXT,
    name        TEXT NOT NULL,
    level       INTEGER NOT NULL DEFAULT 1,
    coins       INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_scores_coins ON scores (coins DESC);
`);

const upsertStmt = db.prepare(`
  INSERT INTO scores (telegram_id, username, name, level, coins, updated_at)
  VALUES (@telegramId, @username, @name, @level, @coins, @updatedAt)
  ON CONFLICT(telegram_id) DO UPDATE SET
    username = excluded.username,
    name = excluded.name,
    level = excluded.level,
    coins = excluded.coins,
    updated_at = excluded.updated_at
`);

function upsertScore({ telegramId, username, name, level, coins }) {
  upsertStmt.run({
    telegramId: String(telegramId),
    username: username || null,
    name: name || username || `Player ${telegramId}`,
    level: Number.isFinite(level) ? Math.max(1, Math.floor(level)) : 1,
    coins: Number.isFinite(coins) ? Math.max(0, Math.floor(coins)) : 0,
    updatedAt: Date.now(),
  });
}

const topStmt = db.prepare(`
  SELECT telegram_id AS telegramId, name, level, coins
  FROM scores ORDER BY coins DESC LIMIT ?
`);

function getTop(limit = 20) {
  return topStmt.all(limit);
}

const oneStmt = db.prepare(`SELECT name, level, coins FROM scores WHERE telegram_id = ?`);
const rankStmt = db.prepare(`SELECT COUNT(*) AS n FROM scores WHERE coins > ?`);
const totalStmt = db.prepare(`SELECT COUNT(*) AS n FROM scores`);

function getPlayerWithRank(telegramId) {
  const row = oneStmt.get(String(telegramId));
  if (!row) return null;
  const { n: higherCount } = rankStmt.get(row.coins);
  return { ...row, rank: higherCount + 1 };
}

function getTotalPlayers() {
  return totalStmt.get().n;
}

module.exports = { upsertScore, getTop, getPlayerWithRank, getTotalPlayers };
