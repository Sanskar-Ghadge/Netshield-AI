import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

let DatabaseClass;
try {
  const { DatabaseSync } = await import('node:sqlite');
  DatabaseClass = DatabaseSync;
} catch {
  const { default: BetterSqlite } = await import('better-sqlite3');
  DatabaseClass = BetterSqlite;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Read-write SQLite wrapper for dashboard and auth queries.
 */
class DB {
  /**
   * Open the SQLite database in read-write mode.
   *
   * @param {string} dbPath - Path to the netshield.db file.
   */
  constructor(dbPath) {
    const serverRoot = path.resolve(__dirname, '../..');
    const resolved = path.isAbsolute(dbPath)
      ? dbPath
      : path.resolve(serverRoot, dbPath);

    // Ensure directory exists
    const dir = path.dirname(resolved);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new DatabaseClass(resolved);
    try {
      this.db.exec('PRAGMA journal_mode = WAL;');
    } catch {
      // WAL pragma might be ignored in memory
    }
    this._initTables();
  }

  /**
   * Initialize user and agent tables if they do not exist.
   * @private
   */
  _initTables() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        created_at REAL NOT NULL,
        last_login REAL
      );

      CREATE TABLE IF NOT EXISTS user_agents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        agent_name TEXT NOT NULL,
        api_key TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'OFFLINE',
        last_seen REAL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
    `);
  }

  // ── User Authentication Methods ─────────────────────────────────

  /**
   * Create a new user record.
   */
  createUser({ username, email, passwordHash, apiKey }) {
    const stmt = this.db.prepare(`
      INSERT INTO users (username, email, password_hash, api_key, created_at, last_login)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const info = stmt.run(username, email, passwordHash, apiKey, Date.now(), Date.now());
    return this.findUserById(info.lastInsertRowid);
  }

  /**
   * Find user by email address (case-insensitive).
   */
  findUserByEmail(email) {
    const stmt = this.db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)');
    return stmt.get(email);
  }

  /**
   * Find user by username or email.
   */
  findUserByUsernameOrEmail(identifier) {
    const stmt = this.db.prepare(
      'SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)'
    );
    return stmt.get(identifier, identifier);
  }

  /**
   * Find user by primary key ID.
   */
  findUserById(id) {
    const stmt = this.db.prepare('SELECT id, username, email, api_key, created_at, last_login FROM users WHERE id = ?');
    return stmt.get(id);
  }

  /**
   * Find user by API key.
   */
  findUserByApiKey(apiKey) {
    const stmt = this.db.prepare('SELECT id, username, email, api_key, created_at, last_login FROM users WHERE api_key = ?');
    return stmt.get(apiKey);
  }

  /**
   * Update user last login timestamp.
   */
  updateLastLogin(id) {
    const stmt = this.db.prepare('UPDATE users SET last_login = ? WHERE id = ?');
    stmt.run(Date.now(), id);
  }

  /**
   * Regenerate and update API key for a user.
   */
  updateApiKey(id, newApiKey) {
    const stmt = this.db.prepare('UPDATE users SET api_key = ? WHERE id = ?');
    stmt.run(newApiKey, id);
    return this.findUserById(id);
  }

  // ── Attack & Threat Statistics Methods ──────────────────────────

  /**
   * Get paginated attack/prediction records.
   *
   * @param {number} [limit=50] - Max rows.
   * @param {number} [offset=0] - Pagination offset.
   * @param {string|null} [attackType=null] - Filter by label.
   * @returns {Array<object>} Array of row objects.
   */
  getAttacks(limit = 50, offset = 0, attackType = null, onlyAttacks = true) {
    if (attackType && attackType !== 'All') {
      const stmt = this.db.prepare(
        'SELECT * FROM attacks WHERE attack_type = ? ORDER BY timestamp_utc DESC LIMIT ? OFFSET ?'
      );
      return stmt.all(attackType, limit, offset);
    }
    if (onlyAttacks) {
      const stmt = this.db.prepare(
        'SELECT * FROM attacks WHERE is_attack = 1 ORDER BY timestamp_utc DESC LIMIT ? OFFSET ?'
      );
      return stmt.all(limit, offset);
    }
    const stmt = this.db.prepare(
      'SELECT * FROM attacks ORDER BY timestamp_utc DESC LIMIT ? OFFSET ?'
    );
    return stmt.all(limit, offset);
  }

  /**
   * Get aggregate statistics.
   *
   * @returns {object} { total, normal, attacks, attack_distribution }
   */
  getStats() {
    const total = this.db.prepare('SELECT COUNT(*) as c FROM attacks').get().c;
    const normal = this.db.prepare('SELECT COUNT(*) as c FROM attacks WHERE is_attack = 0').get().c;
    const attacks = this.db.prepare('SELECT COUNT(*) as c FROM attacks WHERE is_attack = 1').get().c;

    const distRows = this.db.prepare(
      'SELECT attack_type, COUNT(*) as cnt FROM attacks WHERE is_attack = 1 GROUP BY attack_type ORDER BY cnt DESC'
    ).all();

    return {
      total,
      normal,
      attacks,
      attack_distribution: distRows.map((r) => ({ attack_type: r.attack_type, count: r.cnt })),
    };
  }

  /**
   * Get top attacker IPs by frequency.
   *
   * @param {number} [limit=10] - Max entries.
   * @returns {Array<object>} Array of { src_ip, count }.
   */
  getTopAttackers(limit = 10) {
    const stmt = this.db.prepare(
      'SELECT src_ip, COUNT(*) as cnt FROM attacks WHERE is_attack = 1 GROUP BY src_ip ORDER BY cnt DESC LIMIT ?'
    );
    return stmt.all(limit).map((r) => ({ src_ip: r.src_ip, count: r.cnt }));
  }

  /**
   * Get recent attacks/predictions.
   *
   * @param {number} [limit=10] - Max rows.
   * @returns {Array<object>} Array of row objects.
   */
  getRecentAttacks(limit = 10) {
    const stmt = this.db.prepare(
      'SELECT * FROM attacks WHERE is_attack = 1 ORDER BY timestamp_utc DESC LIMIT ?'
    );
    return stmt.all(limit);
  }

  /**
   * Get per-attack-type summary with percentages.
   *
   * @returns {Array<object>} Array of { attack_type, count, percentage }.
   */
  getAttackSummary() {
    const rows = this.db.prepare(
      'SELECT attack_type, COUNT(*) as cnt FROM attacks WHERE is_attack = 1 GROUP BY attack_type ORDER BY cnt DESC'
    ).all();
    const total = rows.reduce((sum, r) => sum + r.cnt, 0);
    return rows.map((r) => ({
      attack_type: r.attack_type,
      count: r.cnt,
      percentage: total > 0 ? Math.round((r.cnt / total) * 100 * 100) / 100 : 0,
    }));
  }

  /**
   * Close the database connection.
   */
  close() {
    this.db.close();
  }
}

export default DB;
