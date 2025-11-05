import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config();

/**
 * GoPlus Security API Client
 * Professional-grade honeypot and security detection
 * Free tier: Unlimited with rate limits
 */

const API_BASE_URL = 'https://api.gopluslabs.io/api/v1';

// Map our chain names to GoPlus chain IDs
const CHAIN_ID_MAPPING = {
  ethereum: '1',
  bsc: '56',
  polygon: '137',
  arbitrum: '42161',
  optimism: '10',
  base: '8453'
};

class GoPlusClient {
  constructor() {
    this.apiKey = process.env.GOPLUS_API_KEY; // Optional for now
    this.enabled = process.env.ENABLE_GOPLUS !== 'false';
  }

  /**
   * Check token security via GoPlus API
   */
  async checkTokenSecurity(address, chain) {
    if (!this.enabled) {
      console.log('GoPlus check disabled');
      return null;
    }

    try {
      const chainId = CHAIN_ID_MAPPING[chain] || '1';
      const url = `${API_BASE_URL}/token_security/${chainId}?contract_addresses=${address.toLowerCase()}`;

      console.log(`Checking GoPlus Security: ${url}`);

      const headers = {
        'Accept': 'application/json'
      };

      if (this.apiKey) {
        headers['Authorization'] = `Bearer ${this.apiKey}`;
      }

      const response = await fetch(url, {
        method: 'GET',
        headers,
        timeout: 15000 // 15 second timeout
      });

      if (response.status === 429) {
        console.warn('GoPlus rate limit reached');
        return {
          checked: false,
          error: 'Rate limit reached'
        };
      }

      if (!response.ok) {
        throw new Error(`GoPlus API error: ${response.status}`);
      }

      const data = await response.json();

      return this.parseResponse(data, address);

    } catch (error) {
      console.error('GoPlus API error:', error.message);
      return {
        checked: false,
        error: error.message
      };
    }
  }

  /**
   * Parse GoPlus response
   */
  parseResponse(data, address) {
    if (data.code !== 1 || !data.result) {
      return {
        checked: false,
        error: 'Invalid response from GoPlus'
      };
    }

    const tokenData = data.result[address.toLowerCase()];

    if (!tokenData) {
      return {
        checked: false,
        error: 'Token not found in GoPlus database'
      };
    }

    // GoPlus returns "1" for true, "0" for false, null for unknown
    return {
      checked: true,

      // Critical honeypot indicators
      is_honeypot: tokenData.is_honeypot === '1',
      honeypot_with_same_creator: tokenData.honeypot_with_same_creator === '1',

      // Ownership risks
      is_open_source: tokenData.is_open_source === '1',
      is_proxy: tokenData.is_proxy === '1',
      can_take_back_ownership: tokenData.can_take_back_ownership === '1',
      owner_change_balance: tokenData.owner_change_balance === '1',
      hidden_owner: tokenData.hidden_owner === '1',

      // Trading restrictions
      cannot_buy: tokenData.cannot_buy === '1',
      cannot_sell_all: tokenData.cannot_sell_all === '1',
      trading_cooldown: tokenData.trading_cooldown === '1',
      is_blacklisted: tokenData.is_blacklisted === '1',
      is_whitelisted: tokenData.is_whitelisted === '1',

      // Dangerous functions
      selfdestruct: tokenData.selfdestruct === '1',
      external_call: tokenData.external_call === '1',

      // Mint and transfer
      is_mintable: tokenData.is_mintable === '1',
      can_be_minted: tokenData.can_be_minted === '1',
      transfer_pausable: tokenData.transfer_pausable === '1',

      // Tax information
      buy_tax: tokenData.buy_tax ? parseFloat(tokenData.buy_tax) : 0,
      sell_tax: tokenData.sell_tax ? parseFloat(tokenData.sell_tax) : 0,
      slippage_modifiable: tokenData.slippage_modifiable === '1',

      // Other risks
      is_true_token: tokenData.is_true_token === '1',
      is_airdrop_scam: tokenData.is_airdrop_scam === '1',
      trust_list: tokenData.trust_list,

      // Holder info
      holder_count: tokenData.holder_count ? parseInt(tokenData.holder_count) : 0,
      total_supply: tokenData.total_supply,

      // LP info
      lp_holder_count: tokenData.lp_holder_count ? parseInt(tokenData.lp_holder_count) : 0,
      lp_total_supply: tokenData.lp_total_supply,

      // Creator info
      creator_address: tokenData.creator_address,
      creator_balance: tokenData.creator_balance,
      creator_percent: tokenData.creator_percent ? parseFloat(tokenData.creator_percent) : 0,

      // Owner info
      owner_address: tokenData.owner_address,
      owner_balance: tokenData.owner_balance,
      owner_percent: tokenData.owner_percent ? parseFloat(tokenData.owner_percent) : 0
    };
  }

  /**
   * Calculate risk contribution from GoPlus results
   */
  calculateRisk(goplusResult) {
    if (!goplusResult || !goplusResult.checked) {
      return {
        score: 0,
        findings: []
      };
    }

    let score = 0;
    const findings = [];

    // CRITICAL: Honeypot detected
    if (goplusResult.is_honeypot) {
      score += 30;
      findings.push({
        type: 'honeypot_detected',
        severity: 'critical',
        source: 'GoPlus Security',
        description: 'Honeypot mechanism detected - tokens cannot be sold',
        evidence: 'is_honeypot: true',
        score: 30
      });
    }

    // CRITICAL: Cannot sell all tokens
    if (goplusResult.cannot_sell_all) {
      score += 25;
      findings.push({
        type: 'cannot_sell_all',
        severity: 'critical',
        source: 'GoPlus Security',
        description: 'Cannot sell all tokens - potential honeypot',
        evidence: 'cannot_sell_all: true',
        score: 25
      });
    }

    // CRITICAL: Selfdestruct present
    if (goplusResult.selfdestruct) {
      score += 20;
      findings.push({
        type: 'selfdestruct_goplus',
        severity: 'critical',
        source: 'GoPlus Security',
        description: 'Contract contains self-destruct function',
        evidence: 'selfdestruct: true',
        score: 20
      });
    }

    // HIGH: Hidden owner
    if (goplusResult.hidden_owner) {
      score += 15;
      findings.push({
        type: 'hidden_owner_goplus',
        severity: 'high',
        source: 'GoPlus Security',
        description: 'Contract has hidden owner',
        evidence: 'hidden_owner: true',
        score: 15
      });
    }

    // HIGH: Can take back ownership
    if (goplusResult.can_take_back_ownership) {
      score += 15;
      findings.push({
        type: 'ownership_takeback',
        severity: 'high',
        source: 'GoPlus Security',
        description: 'Owner can take back ownership after renouncing',
        evidence: 'can_take_back_ownership: true',
        score: 15
      });
    }

    // HIGH: Owner can change balance
    if (goplusResult.owner_change_balance) {
      score += 15;
      findings.push({
        type: 'owner_change_balance',
        severity: 'high',
        source: 'GoPlus Security',
        description: 'Owner can modify user balances',
        evidence: 'owner_change_balance: true',
        score: 15
      });
    }

    // HIGH: Buy tax > 10%
    if (goplusResult.buy_tax > 10) {
      score += 10;
      findings.push({
        type: 'high_buy_tax_goplus',
        severity: 'high',
        source: 'GoPlus Security',
        description: `High buy tax: ${goplusResult.buy_tax}%`,
        evidence: `buy_tax: ${goplusResult.buy_tax}%`,
        score: 10
      });
    }

    // HIGH: Sell tax > 10%
    if (goplusResult.sell_tax > 10) {
      score += 10;
      findings.push({
        type: 'high_sell_tax_goplus',
        severity: 'high',
        source: 'GoPlus Security',
        description: `High sell tax: ${goplusResult.sell_tax}%`,
        evidence: `sell_tax: ${goplusResult.sell_tax}%`,
        score: 10
      });
    }

    // MEDIUM: Transfer pausable
    if (goplusResult.transfer_pausable) {
      score += 8;
      findings.push({
        type: 'transfer_pausable_goplus',
        severity: 'medium',
        source: 'GoPlus Security',
        description: 'Transfers can be paused by owner',
        evidence: 'transfer_pausable: true',
        score: 8
      });
    }

    // MEDIUM: Trading cooldown
    if (goplusResult.trading_cooldown) {
      score += 5;
      findings.push({
        type: 'trading_cooldown_goplus',
        severity: 'medium',
        source: 'GoPlus Security',
        description: 'Trading cooldown mechanism present',
        evidence: 'trading_cooldown: true',
        score: 5
      });
    }

    // MEDIUM: Blacklist function
    if (goplusResult.is_blacklisted) {
      score += 7;
      findings.push({
        type: 'blacklist_goplus',
        severity: 'medium',
        source: 'GoPlus Security',
        description: 'Blacklist function present',
        evidence: 'is_blacklisted: true',
        score: 7
      });
    }

    // MEDIUM: External call risk
    if (goplusResult.external_call) {
      score += 5;
      findings.push({
        type: 'external_call_risk',
        severity: 'medium',
        source: 'GoPlus Security',
        description: 'Contract makes external calls - potential risk',
        evidence: 'external_call: true',
        score: 5
      });
    }

    // HIGH: Same creator has honeypots
    if (goplusResult.honeypot_with_same_creator) {
      score += 20;
      findings.push({
        type: 'creator_honeypot_history',
        severity: 'high',
        source: 'GoPlus Security',
        description: 'Creator has deployed honeypots before',
        evidence: 'honeypot_with_same_creator: true',
        score: 20
      });
    }

    // CRITICAL: Airdrop scam
    if (goplusResult.is_airdrop_scam) {
      score += 25;
      findings.push({
        type: 'airdrop_scam',
        severity: 'critical',
        source: 'GoPlus Security',
        description: 'Identified as airdrop scam',
        evidence: 'is_airdrop_scam: true',
        score: 25
      });
    }

    // INFO: Not open source (if proxy)
    if (goplusResult.is_proxy && !goplusResult.is_open_source) {
      score += 5;
      findings.push({
        type: 'proxy_not_verified',
        severity: 'medium',
        source: 'GoPlus Security',
        description: 'Proxy contract without verified source code',
        evidence: 'is_proxy: true, is_open_source: false',
        score: 5
      });
    }

    return { score, findings };
  }
}

/**
 * Create GoPlus client
 */
export function createGoPlusClient() {
  return new GoPlusClient();
}

export default GoPlusClient;
