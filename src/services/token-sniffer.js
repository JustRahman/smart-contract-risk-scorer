import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config();

/**
 * Token Sniffer API Client
 * Checks tokens against known scam database
 * NOTE: Requires paid API key - no free tier available
 * Disabled by default - set ENABLE_TOKEN_SNIFFER=true and add API key to enable
 */

const API_BASE_URL = 'https://tokensniffer.com/api/v2';

// Map our chain names to Token Sniffer chain names
const CHAIN_MAPPING = {
  ethereum: 'eth',
  polygon: 'polygon',
  arbitrum: 'arbitrum',
  optimism: 'optimism',
  base: 'base'
};

class TokenSnifferClient {
  constructor() {
    this.apiKey = process.env.TOKEN_SNIFFER_API_KEY; // Required - paid API only
    this.enabled = process.env.ENABLE_TOKEN_SNIFFER === 'true' && this.apiKey; // Disabled by default
  }

  /**
   * Check token against Token Sniffer database
   */
  async checkToken(address, chain) {
    if (!this.enabled) {
      console.log('Token Sniffer check disabled');
      return null;
    }

    try {
      const snifferChain = CHAIN_MAPPING[chain] || 'eth';
      const url = `${API_BASE_URL}/tokens/${snifferChain}/${address}`;

      console.log(`Checking Token Sniffer: ${url}`);

      const headers = {
        'Accept': 'application/json'
      };

      // Add API key if provided
      if (this.apiKey) {
        headers['Authorization'] = `Bearer ${this.apiKey}`;
      }

      const response = await fetch(url, {
        method: 'GET',
        headers,
        timeout: 10000 // 10 second timeout
      });

      if (response.status === 404) {
        // Token not in database - not necessarily bad
        return {
          checked: true,
          in_database: false,
          score: null,
          scam: false,
          warnings: []
        };
      }

      if (response.status === 401) {
        console.warn('Token Sniffer API requires authentication. Add TOKEN_SNIFFER_API_KEY to .env');
        console.warn('Get free API key at: https://tokensniffer.com/TokenSnifferAPI');
        return {
          checked: false,
          error: 'API key required',
          score: null,
          warnings: []
        };
      }

      if (response.status === 429) {
        console.warn('Token Sniffer rate limit reached');
        return {
          checked: false,
          error: 'Rate limit reached',
          score: null
        };
      }

      if (!response.ok) {
        console.error(`Token Sniffer API error: ${response.status} - ${response.statusText}`);
        throw new Error(`Token Sniffer API error: ${response.status}`);
      }

      const data = await response.json();

      return this.parseResponse(data);

    } catch (error) {
      console.error('Token Sniffer API error:', error.message);
      return {
        checked: false,
        error: error.message,
        score: null
      };
    }
  }

  /**
   * Parse Token Sniffer response
   */
  parseResponse(data) {
    const result = {
      checked: true,
      in_database: true,
      score: data.score || 0,
      scam: data.scam || false,
      audit_status: data.audit || 'not_audited',
      warnings: data.warnings || [],
      exploits: data.exploits || [],
      tests: data.tests || {}
    };

    // Extract specific test results if available
    if (data.tests) {
      result.details = {
        is_honeypot: data.tests.is_honeypot || false,
        high_buy_tax: data.tests.high_buy_tax || false,
        high_sell_tax: data.tests.high_sell_tax || false,
        hidden_owner: data.tests.hidden_owner || false,
        can_take_back_ownership: data.tests.can_take_back_ownership || false
      };
    }

    return result;
  }

  /**
   * Calculate risk contribution from Token Sniffer results
   */
  calculateRisk(snifferResult) {
    if (!snifferResult || !snifferResult.checked) {
      return {
        score: 0,
        findings: []
      };
    }

    let score = 0;
    const findings = [];

    // Not in database is neutral (new tokens)
    if (!snifferResult.in_database) {
      return { score: 0, findings: [] };
    }

    // Flagged as scam
    if (snifferResult.scam) {
      score += 25;
      findings.push({
        type: 'scam_database_flagged',
        severity: 'critical',
        source: 'Token Sniffer',
        description: 'Token flagged as scam in Token Sniffer database',
        evidence: `Scam flag: true`,
        score: 25
      });
    }

    // High scam score (>70%)
    if (snifferResult.score && snifferResult.score > 70) {
      score += 20;
      findings.push({
        type: 'high_scam_score',
        severity: 'high',
        source: 'Token Sniffer',
        description: 'High scam probability score detected',
        evidence: `Scam score: ${snifferResult.score}/100`,
        score: 20
      });
    } else if (snifferResult.score && snifferResult.score > 50) {
      score += 10;
      findings.push({
        type: 'moderate_scam_score',
        severity: 'medium',
        source: 'Token Sniffer',
        description: 'Moderate scam probability detected',
        evidence: `Scam score: ${snifferResult.score}/100`,
        score: 10
      });
    }

    // Warnings
    if (snifferResult.warnings && snifferResult.warnings.length > 0) {
      const warningScore = Math.min(snifferResult.warnings.length * 3, 15);
      score += warningScore;

      findings.push({
        type: 'token_sniffer_warnings',
        severity: 'medium',
        source: 'Token Sniffer',
        description: `Multiple warnings detected: ${snifferResult.warnings.join(', ')}`,
        evidence: `${snifferResult.warnings.length} warning(s)`,
        score: warningScore
      });
    }

    // Exploits detected
    if (snifferResult.exploits && snifferResult.exploits.length > 0) {
      score += 30;
      findings.push({
        type: 'known_exploits',
        severity: 'critical',
        source: 'Token Sniffer',
        description: 'Known exploits detected in contract',
        evidence: snifferResult.exploits.join(', '),
        score: 30
      });
    }

    // Specific test failures
    if (snifferResult.details) {
      if (snifferResult.details.is_honeypot) {
        score += 25;
        findings.push({
          type: 'honeypot_token_sniffer',
          severity: 'critical',
          source: 'Token Sniffer',
          description: 'Honeypot mechanism detected',
          score: 25
        });
      }

      if (snifferResult.details.hidden_owner) {
        score += 15;
        findings.push({
          type: 'hidden_owner_token_sniffer',
          severity: 'high',
          source: 'Token Sniffer',
          description: 'Hidden owner detected',
          score: 15
        });
      }
    }

    return { score, findings };
  }
}

/**
 * Create Token Sniffer client
 */
export function createTokenSnifferClient() {
  return new TokenSnifferClient();
}

export default TokenSnifferClient;
