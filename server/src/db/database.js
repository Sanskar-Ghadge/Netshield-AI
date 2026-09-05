/**
 * Database module — read-only access to the shared SQLite file.
 *
 * Python writes all predictions; Node.js reads them for the dashboard.
 *
 * @module db/database
 */

import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Read-only SQLite wrapper for dashboard queries.
 */
class DB {
  /**
   * Open the SQLite database in read-only mode.
   *
   * @param {string} dbPath - Path to the netshield.db file.
   */
  constructor(dbPath) {
    const resolved = path.isAbsolute(dbPath)
      ? dbPath
      : path.resolve(__dirname, '../../..', dbPath);
    this.db = new Database(resolved, { readonly: true });
  }

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
