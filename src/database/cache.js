import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * SQLite Cache for storing scan results
 * Caches results for 1 hour to reduce API calls and improve response time
 */

class CacheDB {
  constructor(dbPath = null) {
    const path = dbPath || join(__dirname, '../../cache.db');
    this.db = new Database(path);
    this.initTables();
  }

  /**
   * Initialize database tables
   */
  initTables() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        contract_address TEXT NOT NULL,
        chain TEXT NOT NULL,
        scan_depth TEXT NOT NULL,
        result TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        UNIQUE(contract_address, chain, scan_depth)
      );

      CREATE INDEX IF NOT EXISTS idx_address_chain
        ON scan_results(contract_address, chain);

      CREATE INDEX IF NOT EXISTS idx_created_at
        ON scan_results(created_at);
    `);

    // Clean old entries on startup
    this.cleanOldEntries();
  }

  /**
   * Store scan result in cache
   */
  set(contractAddress, chain, scanDepth, result) {
    const stmt = this.db.prepare(`
      INSERT INTO scan_results (contract_address, chain, scan_depth, result, created_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(contract_address, chain, scan_depth)
      DO UPDATE SET result = ?, created_at = ?
    `);

    const now = Date.now();
    const resultJson = JSON.stringify(result);

    stmt.run(
      contractAddress.toLowerCase(),
      chain.toLowerCase(),
      scanDepth,
      resultJson,
      now,
      resultJson,
      now
    );
  }

  /**
   * Get cached scan result
   */
  get(contractAddress, chain, scanDepth) {
    const stmt = this.db.prepare(`
      SELECT result, created_at
      FROM scan_results
      WHERE contract_address = ? AND chain = ? AND scan_depth = ?
    `);

    const row = stmt.get(
      contractAddress.toLowerCase(),
      chain.toLowerCase(),
      scanDepth
    );

    if (!row) {
      return null;
    }

    // Check if cache is still valid (1 hour = 3600000ms)
    const age = Date.now() - row.created_at;
    const maxAge = 60 * 60 * 1000; // 1 hour

    if (age > maxAge) {
      // Cache expired, delete it
      this.delete(contractAddress, chain, scanDepth);
      return null;
    }

    try {
      return JSON.parse(row.result);
    } catch (error) {
      console.error('Error parsing cached result:', error);
      return null;
    }
  }

  /**
   * Delete specific cache entry
   */
  delete(contractAddress, chain, scanDepth) {
    const stmt = this.db.prepare(`
      DELETE FROM scan_results
      WHERE contract_address = ? AND chain = ? AND scan_depth = ?
    `);

    stmt.run(
      contractAddress.toLowerCase(),
      chain.toLowerCase(),
      scanDepth
    );
  }

  /**
   * Clean entries older than 1 hour
   */
  cleanOldEntries() {
    const maxAge = 60 * 60 * 1000; // 1 hour
    const cutoff = Date.now() - maxAge;

    const stmt = this.db.prepare(`
      DELETE FROM scan_results WHERE created_at < ?
    `);

    const result = stmt.run(cutoff);
    if (result.changes > 0) {
      console.log(`Cleaned ${result.changes} old cache entries`);
    }
  }

  /**
   * Get cache statistics
   */
  getStats() {
    const total = this.db.prepare('SELECT COUNT(*) as count FROM scan_results').get();

    const byChain = this.db.prepare(`
      SELECT chain, COUNT(*) as count
      FROM scan_results
      GROUP BY chain
    `).all();

    const recent = this.db.prepare(`
      SELECT COUNT(*) as count
      FROM scan_results
      WHERE created_at > ?
    `).get(Date.now() - 60 * 60 * 1000);

    return {
      total: total.count,
      byChain: byChain.reduce((acc, row) => {
        acc[row.chain] = row.count;
        return acc;
      }, {}),
      recentHour: recent.count
    };
  }

  /**
   * Clear all cache
   */
  clear() {
    this.db.exec('DELETE FROM scan_results');
  }

  /**
   * Close database connection
   */
  close() {
    this.db.close();
  }
}

// Singleton instance
let cacheInstance = null;

/**
 * Get cache instance
 */
export function getCache() {
  if (!cacheInstance) {
    cacheInstance = new CacheDB();
  }
  return cacheInstance;
}

export default CacheDB;
