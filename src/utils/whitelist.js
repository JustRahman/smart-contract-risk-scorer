/**
 * Whitelist of well-known legitimate tokens
 * These tokens get special handling for centralized ownership
 */

// Known safe tokens that should have LOW risk scores regardless of centralization
export const KNOWN_SAFE_TOKENS = new Set([
  // Stablecoins
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', // USDC
  '0xdac17f958d2ee523a2206206994597c13d831ec7', // USDT
  '0x6b175474e89094c44da98b954eedeac495271d0f', // DAI
  '0x4fabb145d64652a948d72533023f6e7a623c7c53', // BUSD

  // Wrapped assets
  '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', // WETH
  '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599', // WBTC

  // DeFi blue chips
  '0x514910771af9ca656af840dff83e8264ecf986ca', // LINK (Chainlink)
  '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984', // UNI (Uniswap)
  '0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0', // MATIC (Polygon)
  '0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9', // AAVE
  '0x6b3595068778dd592e39a122f4f5a5cf09c90fe2', // SUSHI (SushiSwap)
  '0xc00e94cb662c3520282e6f5717214004a7f26888', // COMP (Compound)
  '0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2', // MKR (Maker)

  // Exchange tokens
  '0xb8c77482e45f1f44de1745f52c74426c631bdd52', // BNB (Binance)
  '0x50d1c9771902476076ecfc8b2a83ad6b9355a4c9', // FTT (FTX) - historic
  '0xa0b73e1ff0b80914ab6fe0444e65848c4c34450b', // CRO (Crypto.com)
  '0x75231f58b43240c9718dd58b4967c5114342a86c', // OKB (OKX)
  '0x6f259637dcd74c767781e37bc6133cd6a68aa161', // HT (Huobi)
  '0x4a220e6096b25eadb88358cb44068a3248254675', // QNT (Quant)
]);

export const KNOWN_TOKENS = {
  // Stablecoins
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': {
    name: 'USD Coin',
    symbol: 'USDC',
    type: 'stablecoin',
    issuer: 'Circle',
    allowCentralized: true
  },
  '0xdac17f958d2ee523a2206206994597c13d831ec7': {
    name: 'Tether USD',
    symbol: 'USDT',
    type: 'stablecoin',
    issuer: 'Tether',
    allowCentralized: true
  },
  '0x6b175474e89094c44da98b954eedeac495271d0f': {
    name: 'Dai Stablecoin',
    symbol: 'DAI',
    type: 'stablecoin',
    issuer: 'MakerDAO',
    allowCentralized: false
  },
  '0x4fabb145d64652a948d72533023f6e7a623c7c53': {
    name: 'Binance USD',
    symbol: 'BUSD',
    type: 'stablecoin',
    issuer: 'Binance/Paxos',
    allowCentralized: true
  },

  // Major tokens
  '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': {
    name: 'Wrapped Ether',
    symbol: 'WETH',
    type: 'wrapped',
    issuer: 'WETH9',
    allowCentralized: false
  },
  '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599': {
    name: 'Wrapped BTC',
    symbol: 'WBTC',
    type: 'wrapped',
    issuer: 'BitGo',
    allowCentralized: true
  },
  '0x514910771af9ca656af840dff83e8264ecf986ca': {
    name: 'ChainLink Token',
    symbol: 'LINK',
    type: 'utility',
    issuer: 'Chainlink',
    allowCentralized: false
  },
  '0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0': {
    name: 'Polygon',
    symbol: 'MATIC',
    type: 'L2',
    issuer: 'Polygon',
    allowCentralized: false
  },
  '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984': {
    name: 'Uniswap',
    symbol: 'UNI',
    type: 'governance',
    issuer: 'Uniswap',
    allowCentralized: false
  }
};

/**
 * Check if address is a known safe token
 */
export function isKnownSafeToken(address) {
  const normalized = address.toLowerCase();
  return KNOWN_SAFE_TOKENS.has(normalized);
}

/**
 * Check if address is a known legitimate token
 */
export function isKnownToken(address) {
  const normalized = address.toLowerCase();
  return KNOWN_TOKENS[normalized] || null;
}

/**
 * Check if centralized ownership is acceptable for this token
 */
export function allowsCentralizedOwnership(address) {
  const token = isKnownToken(address);
  return token ? token.allowCentralized : false;
}

/**
 * Check if token is a stablecoin based on symbol/name
 */
export function isStablecoin(symbol, name) {
  if (!symbol && !name) return false;

  const text = `${symbol || ''} ${name || ''}`.toLowerCase();
  const stablecoinKeywords = ['usd', 'usdc', 'usdt', 'dai', 'busd', 'tusd', 'gusd', 'pax'];

  return stablecoinKeywords.some(keyword => text.includes(keyword));
}
