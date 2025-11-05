# SMART CONTRACT RISK SCORER - BUILD SPECIFICATION

## PROJECT OVERVIEW

Build an AI agent that analyzes smart contracts for security risks and rug pull indicators. Returns risk score (0-100) with specific vulnerabilities and recommendations.

**Bounty Value:** $1,000-2,000
**Build Time:** 5-7 days
**Payment:** $0.15 per scan (USDC on Base)

---

## CORE FUNCTIONALITY

### Input Schema

User provides:
- `contract_address` - Smart contract address to analyze (required)
- `chain` - Blockchain network (ethereum, polygon, arbitrum, optimism, base)
- `scan_depth` - Analysis depth: "quick" or "deep" (optional, default: "quick")

### Output Schema

Return:
- `risk_score` - Overall risk (0-100, higher = more risky)
- `risk_level` - low / medium / high / critical
- `vulnerabilities` - Array of specific issues found
- `contract_info` - Basic contract details (name, symbol, creator, age)
- `security_checks` - Results of 15+ security tests
- `recommendations` - What users should do (interact, avoid, investigate)
- `confidence` - Analysis confidence level (0-1)

---

## DETECTION PATTERNS

### Critical Red Flags (80-100 risk):

1. **Hidden Mint Functions**
   - Unlimited token minting capability
   - Owner can create tokens out of thin air

2. **Honeypot Mechanisms**
   - Can receive tokens but can't sell
   - Blacklist functions that prevent transfers

3. **Backdoor Functions**
   - Hidden admin functions
   - Self-destruct capabilities

4. **Proxy Without Timelock**
   - Upgradeable contract with no delay
   - Owner can change logic instantly

### High Risk (60-79):

5. **Pausable Transfers**
   - Owner can freeze all trading
   - Emergency stop without governance

6. **High Tax Functions**
   - Buy/sell tax > 10%
   - Taxes can be changed by owner

7. **Centralized Ownership**
   - Single address controls everything
   - No multi-sig or timelock

8. **Liquidity Not Locked**
   - LP tokens not locked/burned
   - Owner can rug pull liquidity

### Medium Risk (40-59):

9. **Modifiable Fees**
   - Owner can change fees anytime
   - No maximum fee limit

10. **Blacklist Function**
    - Addresses can be blocked
    - Centralized censorship

11. **Max Transaction Limit**
    - Limits on buy/sell amounts
    - Can trap large holders

12. **Recent Deployment**
    - Contract < 7 days old
    - No battle-testing yet

### Low Risk Indicators (0-39):

13. **Renounced Ownership**
    - Owner address = 0x000...
    - No admin control

14. **Open Source + Verified**
    - Code verified on Etherscan
    - Readable and audited

15. **Liquidity Locked**
    - LP tokens locked > 6 months
    - Team can't rug

16. **Time-Tested**
    - Contract > 30 days old
    - High transaction count

---

## DATA SOURCES

### Primary: Etherscan API (Free Tier)

**What to query:**
- Contract source code (if verified)
- Contract creation transaction
- Total transactions
- Token info (name, symbol, decimals)
- Contract ABI

**API Endpoints:**
```
https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}
https://api.etherscan.io/api?module=account&action=txlist&address={address}
```

### Secondary: Chain RPC (Infura/Alchemy)

**What to query:**
- Current owner address
- Liquidity pool balances
- Token total supply
- Real-time holder count

### Tertiary: DEX APIs (Optional)

**Uniswap/Sushiswap:**
- Liquidity pool info
- Trading volume
- Price history

---

## ANALYSIS LOGIC

### Step 1: Basic Contract Info

Fetch:
- Contract age (creation date)
- Total transactions
- Is verified on Etherscan?
- Source code availability

### Step 2: Code Pattern Analysis

If source code available, scan for:

**Red flag keywords:**
- `mint(` + `onlyOwner`
- `pause(` / `unpause(`
- `selfdestruct(`
- `transferOwnership(`
- `setTaxFee(`
- `blacklist[`
- `_isExcludedFromFee[`

**Safe keywords:**
- `renounceOwnership()`
- Timelock implementation
- Multi-sig patterns

### Step 3: Ownership Analysis

Check:
- Current owner address
- Is owner = 0x000...000? (renounced)
- Is owner a multi-sig contract?
- Is owner a timelock contract?

### Step 4: Liquidity Analysis

For tokens:
- Find Uniswap/Sushiswap pool
- Check LP token holder (is it burned/locked?)
- Calculate liquidity value
- Check if team wallet holds LP tokens

### Step 5: Historical Behavior

- Has ownership been transferred before?
- Have taxes been changed?
- Any suspicious large transfers?
- Contract upgrade history (if proxy)

### Step 6: Risk Scoring

```
Base score = 50

For each critical red flag: +15 points
For each high risk flag: +10 points  
For each medium risk flag: +5 points
For each low risk indicator: -10 points

Final score = clamp(base_score + adjustments, 0, 100)
```

---

## TECHNICAL IMPLEMENTATION

### Use Bridge-Route-Pinger Pattern

**File Structure:**
```
smart-contract-risk-scorer/
├── src/
│   ├── agent.js              # Main agent-kit setup (like bridge)
│   ├── index.js              # Server startup (like bridge)
│   ├── analyzers/
│   │   ├── code-analyzer.js  # Source code pattern matching
│   │   ├── ownership.js      # Ownership centralization checks
│   │   ├── liquidity.js      # LP lock and rug pull detection
│   │   └── behavioral.js     # Historical transaction analysis
│   ├── services/
│   │   ├── etherscan.js      # Etherscan API client
│   │   ├── rpc.js            # Blockchain RPC calls
│   │   └── dex.js            # DEX liquidity queries
│   ├── utils/
│   │   ├── scoring.js        # Risk score calculations
│   │   └── recommendations.js # User recommendations
│   └── database/
│       └── cache.js          # Cache results (SQLite)
├── .env
├── package.json
└── README.md
```

### Agent Configuration (like bridge-route-pinger)

Use createAgentApp() with:
- useConfigPayments: true
- facilitatorUrl: https://facilitator.daydreams.systems
- payTo: 0x992920386E3D950BC260f99C81FDA12419eD4594
- defaultPrice: "0.15" (slightly higher than MEV scanner)
- network: "base"

### Dependencies

Same as MEV scanner + bridge:
- @lucid-dreams/agent-kit@0.2.22
- @hono/node-server@1.19.5
- ethers@6.9.0
- node-fetch@3.3.2
- better-sqlite3@9.2.2 (for caching)
- zod@3.22.4
- dotenv@16.3.1

---

## ACCEPTANCE CRITERIA

✅ Analyzes any ERC-20 token contract
✅ Detects 10+ common vulnerabilities
✅ Risk score accuracy > 85% (test against known scams)
✅ Response time < 5 seconds for quick scan
✅ Supports 5 chains (Ethereum, Polygon, Arbitrum, Optimism, Base)
✅ X402 payment integration ($0.15 per scan)
✅ Deployed on Railway
✅ Returns actionable recommendations

---

## TESTING STRATEGY

### Test Cases:

**Known Scam Contracts:**
- Should return risk score > 80
- Should detect specific vulnerabilities
- Should recommend "DO NOT INTERACT"

**Known Safe Contracts:**
- USDC: Should return risk score < 20
- Uniswap: Should return risk score < 15
- Should recommend "SAFE TO USE"

**Recently Deployed:**
- Should flag as medium risk (untested)
- Should warn about newness

**Honeypots:**
- Should detect blacklist functions
- Should warn about transfer restrictions

---

## EXAMPLE OUTPUT

```json
{
  "risk_score": 85,
  "risk_level": "critical",
  "contract_info": {
    "address": "0x123...",
    "name": "SafeMoon Clone",
    "symbol": "SCAM",
    "chain": "ethereum",
    "created": "2025-10-28",
    "age_days": 5,
    "verified": false
  },
  "vulnerabilities": [
    {
      "type": "hidden_mint",
      "severity": "critical",
      "description": "Contract owner can mint unlimited tokens",
      "evidence": "Function mint() with onlyOwner modifier found"
    },
    {
      "type": "pausable",
      "severity": "high", 
      "description": "Owner can pause all transfers",
      "evidence": "pause() function detected"
    },
    {
      "type": "liquidity_not_locked",
      "severity": "high",
      "description": "LP tokens held by deployer wallet",
      "evidence": "92% of LP tokens in 0xABC..."
    }
  ],
  "security_checks": {
    "ownership_renounced": false,
    "liquidity_locked": false,
    "source_verified": false,
    "proxy_contract": false,
    "pausable": true,
    "blacklist_function": true,
    "mint_function": true,
    "high_tax": false,
    "max_tx_limit": true
  },
  "recommendations": [
    "🚨 CRITICAL: DO NOT INTERACT - Multiple red flags detected",
    "⚠️ Hidden mint function allows unlimited token creation",
    "⚠️ Owner can pause trading at any time",
    "⚠️ Liquidity not locked - high rug pull risk",
    "✅ Wait for: Ownership renounced, liquidity locked, source verified"
  ],
  "confidence": 0.95
}
```

---

## DEPLOYMENT

Same as MEV scanner:
1. Build with agent-kit
2. Deploy to Railway
3. Test with x402 payments
4. Submit PR to agent-bounties

---

## MARKETING ANGLE

**Target Users:**
- DeFi traders checking new tokens
- Wallet apps (MetaMask, Rainbow) for in-app warnings
- DEX aggregators (1inch, Matcha)
- Telegram/Discord trading bots

**Value Proposition:**
"Don't get rugged. $0.15 scan can save you $1000s."

---

## SUCCESS METRICS

**Week 1:**
- 50+ scans
- 90%+ accuracy on test contracts
- $7.50+ revenue

**Month 1:**
- 500+ scans  
- Featured in 1 trading community
- $75+ revenue

**Month 3:**
- 3,000+ scans
- Integration with 1 wallet/bot
- $450+ revenue

---

## PRIORITY BUILD ORDER

**Day 1-2:** Core infrastructure
- Agent setup (copy from MEV scanner/bridge pattern)
- Etherscan API integration
- Basic contract info fetching

**Day 3-4:** Detection logic
- Code pattern analyzer
- Ownership checks
- Liquidity analysis

**Day 5:** Testing & refinement
- Test against known scams
- Test against safe contracts
- Adjust scoring weights

**Day 6:** Deployment
- Deploy to Railway
- End-to-end payment testing
- Documentation

**Day 7:** Submission
- Create PR
- Post to Twitter
- Promote on Reddit

---

## NOTES

- Focus on accuracy over speed (5s response time is fine)
- False positives hurt trust - better to be conservative
- Cache results for 1 hour (contracts don't change often)
- Show evidence for each vulnerability (build trust)
- Clear recommendations (not just scores)

---

## START BUILDING

Reference projects:
- MEV Protection Scanner (your current project)
- Bridge Route Pinger (payment pattern)

Use same agent-kit setup, different analysis logic.

**Begin with Step 1: Agent infrastructure setup.**