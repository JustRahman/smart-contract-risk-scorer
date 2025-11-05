# SMART CONTRACT RISK SCORER - ENHANCEMENT SPECIFICATION

## OBJECTIVE

Add 12 advanced security checks to make this the most comprehensive contract scanner available.

**Current:** 15 basic checks (code patterns, ownership, liquidity)
**After:** 27 comprehensive checks (external APIs, simulations, multi-chain)

---

## PRIORITY 1: EXTERNAL API INTEGRATIONS (90 minutes)

### 1. Token Sniffer API Integration

**Purpose:** Check against known scam database

**API Endpoint:**
```
GET https://tokensniffer.com/api/v2/tokens/{chain}/{address}
```

**Free tier:** 100 requests/day

**Implementation:**
- Create new file: `src/services/token-sniffer.js`
- Function: `async checkTokenSniffer(address, chain)`
- Extract: scam_score, audit_status, warnings
- If scam_score > 0.7 → Add +20 to risk score
- Cache results for 24 hours

**Response format:**
```json
{
  "score": 85,
  "status": "ok",
  "scam": false,
  "audit": "not_audited",
  "warnings": ["high_buy_tax"]
}
```

---

### 2. GoPlus Security API Integration

**Purpose:** Professional-grade honeypot detection

**API Endpoint:**
```
GET https://api.gopluslabs.io/api/v1/token_security/{chainId}?contract_addresses={address}
```

**Free tier:** Unlimited (with rate limits)

**Chain IDs:**
- Ethereum: 1
- BSC: 56
- Polygon: 137
- Arbitrum: 42161
- Base: 8453

**Implementation:**
- Create function: `async checkGoPlus(address, chain)`
- Extract key fields:
  - `is_honeypot` (critical)
  - `is_open_source`
  - `can_take_back_ownership`
  - `cannot_sell_all`
  - `hidden_owner`
  - `selfdestruct`
  - `external_call`
  - `buy_tax`, `sell_tax`

**Risk calculation:**
- `is_honeypot === "1"` → +30 risk
- `hidden_owner === "1"` → +15 risk
- `selfdestruct === "1"` → +20 risk
- `cannot_sell_all === "1"` → +25 risk
- `buy_tax > 10` → +10 risk
- `sell_tax > 10` → +10 risk

---

### 3. Creator Wallet Analysis

**Purpose:** Check deployer's history for past scams

**Implementation:**
- Function: `async analyzeCreatorWallet(deployerAddress, chain)`
- Steps:
  1. Get all contracts deployed by this address (Etherscan API)
  2. Count total contracts created
  3. For each contract:
     - Check if it still has liquidity
     - Check if ownership transferred/renounced
     - Calculate age
  4. Identify patterns:
     - Created 10+ tokens = serial deployer (suspicious)
     - Multiple abandoned contracts = red flag
     - Recent rug pull = critical alert

**Etherscan API:**
```
GET https://api.etherscan.io/api?module=account&action=txlist&address={deployer}&startblock=0&endblock=99999999&sort=asc
```

Filter for contract creation transactions (where `to` is empty).

**Risk calculation:**
- 10+ contracts deployed → +15 risk
- 3+ abandoned contracts → +20 risk
- Confirmed past rug pull → +30 risk

---

## PRIORITY 2: ADVANCED PATTERN DETECTION (2-3 hours)

### 4. Contract Similarity Checker

**Purpose:** Detect clones of known scam contracts

**Implementation:**
- Function: `async checkSimilarity(sourceCode)`
- Steps:
  1. Hash the source code (remove whitespace/comments)
  2. Compare to database of known scam contracts
  3. Calculate Levenshtein distance
  4. If >90% similar → flag as clone

**Known scam patterns to track:**
- SafeMoon forks
- Squid Game clones
- Common honeypot templates

**Data source:**
- Build database from: https://github.com/ethereum-scam-database
- Update weekly

**Risk calculation:**
- >95% similarity → +40 risk
- >90% similarity → +25 risk
- >80% similarity → +10 risk

---

### 5. Social Media Verification

**Purpose:** Check project legitimacy via social presence

**Implementation:**
- Function: `async verifySocialMedia(contractAddress)`
- Sources:
  1. **Token metadata** (often includes links)
  2. **CoinGecko API** (if listed)
  3. **Twitter API** (follower count)

**Checks:**
- Twitter account exists?
- Followers > 1000? (legit projects have community)
- Telegram group > 500 members?
- Website exists and loads?
- GitHub repo exists? (for open source)

**Risk calculation:**
- No social media → +15 risk
- Twitter < 100 followers → +10 risk
- No website → +5 risk
- All social missing → +25 risk

---

### 6. Trading Simulation

**Purpose:** Honeypot detection via simulation

**Implementation:**
- Function: `async simulateTrade(contractAddress, chain)`
- Use Tenderly or Hardhat fork
- Steps:
  1. Fork current blockchain state
  2. Create test wallet with 0.1 ETH
  3. Buy 1 wei of token
  4. Try to sell 1 wei of token
  5. If sell reverts → HONEYPOT

**Risk calculation:**
- Cannot sell → +50 risk (critical)
- High slippage (>20%) → +15 risk

**API options:**
- Tenderly API (free tier)
- Or use GoPlus (already checks this)

---

### 7. Liquidity Pool Analysis

**Purpose:** Assess liquidity health and rug risk

**Implementation:**
- Function: `async analyzeLiquidity(tokenAddress, chain)`
- Query Uniswap/Sushiswap subgraph
- Extract:
  - Total liquidity (USD)
  - LP token holders
  - Liquidity add date
  - Liquidity locked?

**Calculations:**
- Market cap to liquidity ratio
- If MC/Liquidity > 10 → low liquidity warning
- If liquidity < $10K → high rug risk

**LP Lock Check:**
- Query known lock contracts (Unicrypt, Team.Finance)
- If unlocked → +20 risk
- If locked < 30 days → +10 risk

**Risk calculation:**
- No liquidity lock → +20 risk
- Liquidity < $10K → +15 risk
- Recent liquidity add (< 7 days) → +10 risk
- MC/Liq ratio > 20 → +10 risk

---

## PRIORITY 3: EXPERT-LEVEL CHECKS (3-4 hours)

### 8. Bytecode Analysis

**Purpose:** Analyze unverified contracts

**Implementation:**
- Function: `async analyzeBytecode(contractAddress, chain)`
- Steps:
  1. Get bytecode from blockchain
  2. Decompile using panoramix or similar
  3. Look for suspicious opcodes:
     - `SELFDESTRUCT`
     - `DELEGATECALL` (proxy risk)
     - `CALLCODE` (deprecated, risky)
  4. Compare bytecode to source (if verified)

**Risk calculation:**
- Unverified contract → +10 risk
- Contains SELFDESTRUCT → +20 risk
- Bytecode doesn't match source → +30 risk

---

### 9. Multi-Chain Rug Detection

**Purpose:** Check if deployer rugged on other chains

**Implementation:**
- Function: `async checkMultiChainHistory(deployerAddress)`
- Query 5 chains: ETH, BSC, Polygon, Arbitrum, Base
- For each chain:
  - Get contracts deployed by this address
  - Check liquidity status
  - Identify abandoned projects

**Risk calculation:**
- Rugged on another chain → +35 risk (critical)
- Same contract deployed on 3+ chains → +10 risk (farm behavior)

---

### 10. DexTools/DexScreener Integration

**Purpose:** Live trading data analysis

**API Endpoint (DexScreener):**
```
GET https://api.dexscreener.com/latest/dex/tokens/{address}
```

**Free tier:** Unlimited

**Extract:**
- Price change (24h)
- Volume (24h)
- Number of transactions
- Unique wallets
- Liquidity

**Suspicious patterns:**
- Price pump >1000% in 24h → +15 risk
- Very low volume (< $1K/day) → +10 risk
- Few unique wallets (< 50) → +10 risk
- Large price swings (>50% hourly) → +15 risk

---

## IMPLEMENTATION PLAN

### Phase 1: Quick Wins (Day 1)
1. Token Sniffer API (30 min)
2. GoPlus Security API (30 min)
3. Creator Wallet Analysis (30 min)

**Total: 90 minutes**

### Phase 2: Advanced Checks (Day 2)
4. Contract Similarity Checker (2 hours)
5. Social Media Verification (1 hour)
6. DexScreener Integration (1 hour)

**Total: 4 hours**

### Phase 3: Expert Checks (Day 3)
7. Liquidity Pool Analysis (2 hours)
8. Trading Simulation (2 hours)
9. Multi-Chain Detection (2 hours)

**Total: 6 hours**

### Phase 4: Polish (Day 4)
10. Bytecode Analysis (3 hours)
11. Testing all checks (2 hours)
12. Documentation (1 hour)

**Total: 6 hours**

---

## FILE STRUCTURE CHANGES

**New files to create:**

```
src/services/
├── token-sniffer.js       # Token Sniffer API
├── goplus.js              # GoPlus Security API
├── dexscreener.js         # DexScreener API
├── similarity.js          # Contract similarity checker
├── social-verifier.js     # Social media checks
└── trade-simulator.js     # Trading simulation

src/analyzers/
├── creator-history.js     # Deployer analysis
├── liquidity-analyzer.js  # LP analysis
└── bytecode-analyzer.js   # Bytecode checks

src/database/
└── scam-patterns.js       # Known scam database
```

---

## UPDATED RISK SCORING

**New total possible score components:**

**Original checks (0-50 points):**
- Hidden mint: +15
- Honeypot (code): +15
- Pausable: +10
- High tax: +10

**New external checks (0-80 points):**
- Token Sniffer scam detected: +20
- GoPlus honeypot: +30
- Cannot sell (simulation): +50
- Creator past rugs: +30
- Liquidity not locked: +20
- Multi-chain rug: +35

**New calculation:**
```
Final score = min(
  (original_checks × 0.4) + (external_checks × 0.6),
  100
)
```

This weights external professional checks more heavily.

---

## TESTING STRATEGY

**Test with known contracts:**

1. **Safe contracts:**
   - USDC: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
   - WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
   - Expected: <20 risk

2. **Known scams:**
   - Squid Game: 0x87230146E138d3F296a9a77e497A2A83012e9Bc5
   - SafeMoon forks (search on BSC)
   - Expected: >85 risk

3. **Recent honeypots:**
   - Check GoPlus database for current honeypots
   - Expected: 95+ risk, CRITICAL alerts

---

## ENVIRONMENT VARIABLES

**Add to .env:**

```bash
# External APIs (all have free tiers)
TOKEN_SNIFFER_API_KEY=optional  # Optional, free tier works without key
GOPLUS_API_KEY=optional         # Optional for now
DEXSCREENER_API_KEY=optional    # Free tier unlimited

# Rate limiting
MAX_REQUESTS_PER_MINUTE=30
CACHE_TTL_HOURS=24

# Feature flags (enable/disable checks)
ENABLE_TOKEN_SNIFFER=true
ENABLE_GOPLUS=true
ENABLE_SOCIAL_VERIFICATION=true
ENABLE_TRADING_SIMULATION=true
ENABLE_BYTECODE_ANALYSIS=true
```

---

## ACCEPTANCE CRITERIA

✅ All 10 new checks implemented
✅ Risk score accuracy >95% on test set
✅ Response time < 8 seconds (with caching)
✅ Handles API failures gracefully
✅ Clear alerts for each new risk detected
✅ Comprehensive test coverage
✅ Documentation updated

---

## EXPECTED OUTPUT AFTER ENHANCEMENTS

```json
{
  "risk_score": 92,
  "risk_level": "critical",
  "vulnerabilities": [
    {
      "type": "honeypot_detected",
      "severity": "critical",
      "source": "GoPlus Security API",
      "description": "Token cannot be sold - honeypot mechanism detected",
      "evidence": "Trading simulation failed: sell transaction reverted"
    },
    {
      "type": "creator_past_rugs",
      "severity": "critical",
      "source": "Creator Wallet Analysis",
      "description": "Deployer has 3 abandoned contracts on Ethereum",
      "evidence": "0xABC... deployed 12 tokens, 3 have zero liquidity"
    },
    {
      "type": "liquidity_not_locked",
      "severity": "high",
      "source": "Liquidity Analysis",
      "description": "LP tokens held by deployer - high rug pull risk",
      "evidence": "85% of LP tokens in deployer wallet"
    },
    {
      "type": "scam_database_match",
      "severity": "high",
      "source": "Token Sniffer",
      "description": "Token flagged in scam database",
      "evidence": "Scam score: 87/100"
    }
  ],
  "external_checks": {
    "token_sniffer": {
      "checked": true,
      "scam_score": 87,
      "flagged": true
    },
    "goplus": {
      "checked": true,
      "is_honeypot": "1",
      "hidden_owner": "1",
      "buy_tax": "12",
      "sell_tax": "99"
    },
    "creator_history": {
      "total_contracts": 12,
      "abandoned_contracts": 3,
      "confirmed_rugs": 1
    },
    "liquidity": {
      "total_usd": 5420,
      "locked": false,
      "market_cap_ratio": 45.2
    },
    "social_media": {
      "twitter": false,
      "telegram": false,
      "website": false
    }
  },
  "recommendations": [
    "🚨 CRITICAL: DO NOT INTERACT - Honeypot detected",
    "🚨 CRITICAL: Creator has history of rug pulls",
    "⚠️ HIGH: Liquidity not locked - can be removed anytime",
    "⚠️ HIGH: Flagged in multiple scam databases"
  ]
}
```

---

## START IMPLEMENTATION

**Tell Claude CLI:**

```
Read this enhancement spec and implement all Priority 1 checks first (Token Sniffer, GoPlus, Creator Analysis).

Reference existing code in src/services/ for API call patterns.

Create proper error handling for API failures.

Add results to risk scoring in src/utils/scoring.js.

Update output format to include external_checks section.

No code needed from you - just confirm when ready to start.
```

---

**This will make your scanner 10x better than competition.**

Estimated total time: 2-3 days for all enhancements.

Start with Priority 1 (90 min) and deploy that first, then add Priority 2 and 3 incrementally.