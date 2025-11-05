# Smart Contract Risk Scorer

AI agent that analyzes smart contracts for security risks and rug pull indicators. Returns risk score (0-100) with specific vulnerabilities and actionable recommendations.

## Features

### Core Security Checks (15+)
- **Internal Analysis**: Code patterns, ownership, liquidity, transaction history
- Detects hidden mint functions, honeypot mechanisms, backdoors, pausable transfers, high taxes

### **External Security Checks**
- **GoPlus Security API**: Professional honeypot detection (FREE - unlimited with rate limits)
- **Creator History Analysis**: Analyzes deployer wallet for past scams and serial deployment patterns
- **Token Sniffer Integration**: Scam database checking (PAID API - disabled by default)

### Other Features
- **Multi-Chain Support**: Ethereum (primary), Polygon/Arbitrum/Optimism/Base (in development)
- **X402 Payments**: $0.15 per scan (USDC on Base) - disabled for testing
- **Fast Response**: 4-15 seconds (cached requests < 0.01s)
- **Smart Caching**: Results cached for 1 hour to improve performance
- **Weighted Scoring**: Intelligent risk calculation with whitelist for known-safe tokens (USDC, USDT, DAI, WETH, etc.)

## Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd smart-contract-risk-scorer

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env and add your API keys
```

## Configuration

Edit `.env` file with your settings:

```bash
# Payment Configuration (X402)
FACILITATOR_URL=https://facilitator.daydreams.systems
PAY_TO_WALLET=0x992920386E3D950BC260f99C81FDA12419eD4594
PAYMENT_NETWORK=base
PAYMENT_AMOUNT=0.15

# API Keys - Block Explorers (Get free keys from respective explorers)
ETHERSCAN_API_KEY=your_etherscan_api_key_here
POLYGONSCAN_API_KEY=your_polygonscan_api_key_here
ARBISCAN_API_KEY=your_arbiscan_api_key_here
OPTIMISM_API_KEY=your_optimism_api_key_here
BASESCAN_API_KEY=your_basescan_api_key_here

# External Security APIs
TOKEN_SNIFFER_API_KEY=  # https://tokensniffer.com/api (PAID - leave empty to disable)
GOPLUS_API_KEY=         # https://gopluslabs.io (FREE - leave empty for anonymous)

# Feature Flags (enable/disable external checks)
ENABLE_TOKEN_SNIFFER=false  # Disabled by default (requires paid API key)
ENABLE_GOPLUS=true          # Enabled by default (free tier available)

# RPC URLs (Optional - uses public RPCs by default)
ETHEREUM_RPC_URL=
POLYGON_RPC_URL=
ARBITRUM_RPC_URL=
OPTIMISM_RPC_URL=
BASE_RPC_URL=

# Server
PORT=3000
```

### Getting API Keys

Get free API keys from these block explorers:

- **Etherscan**: https://etherscan.io/apis
- **Polygonscan**: https://polygonscan.com/apis
- **Arbiscan**: https://arbiscan.io/apis
- **Optimism**: https://optimistic.etherscan.io/apis
- **Basescan**: https://basescan.org/apis

## Usage

### Start the Server

```bash
npm start
```

The server will start on `http://localhost:3000`

### Make a Request

```bash
curl -X POST http://localhost:3000/entrypoints/analyze_contract \
  -H "Content-Type: application/json" \
  -H "X-PAYMENT: <payment-data>" \
  -d '{
    "contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "chain": "ethereum",
    "scan_depth": "quick"
  }'
```

### Input Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `contract_address` | string | Yes | - | Smart contract address (0x...) |
| `chain` | string | No | `ethereum` | Blockchain network (ethereum, polygon, arbitrum, optimism, base) |
| `scan_depth` | string | No | `quick` | Analysis depth: "quick" (fast) or "deep" (includes liquidity analysis) |

### Response Format

```json
{
  "risk_score": 15,
  "risk_level": "low",
  "contract_info": {
    "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "name": "USD Coin",
    "symbol": "USDC",
    "chain": "ethereum",
    "creator": "0x...",
    "created": "2018-09-08",
    "age_days": 2247,
    "verified": true,
    "is_proxy": true,
    "transaction_count": 1000000
  },
  "vulnerabilities": [],
  "security_checks": {
    "ownership_renounced": false,
    "liquidity_locked": false,
    "source_verified": true,
    "proxy_contract": true,
    "pausable": true,
    "blacklist_function": true,
    "mint_function": true,
    "high_tax": false,
    "max_tx_limit": false,
    "self_destruct": false,
    "honeypot_risk": false,
    "centralized_ownership": false
  },
  "external_checks": {
    "token_sniffer": {
      "checked": true,
      "in_database": true,
      "scam_score": 0,
      "scam_flagged": false,
      "warnings": []
    },
    "goplus": {
      "checked": true,
      "is_honeypot": false,
      "cannot_sell_all": false,
      "hidden_owner": false,
      "buy_tax": 0,
      "sell_tax": 0,
      "selfdestruct": false,
      "is_open_source": true
    },
    "creator_history": {
      "analyzed": true,
      "total_contracts": 5,
      "abandoned_contracts": 0,
      "recent_deployments": 1,
      "suspicious_pattern": false
    }
  },
  "recommendations": [
    "SAFE: Low risk detected - Contract appears legitimate",
    "Source code is verified and can be audited",
    "Contract has been active for 2247 days - battle-tested",
    "RECOMMENDATION: Contract appears safe, but always verify independently"
  ],
  "confidence": 0.95,
  "scan_depth": "quick",
  "analysis_time_ms": 7250
}
```

## Risk Levels

| Score | Level | Description |
|-------|-------|-------------|
| 80-100 | Critical | DO NOT INTERACT - Multiple critical red flags |
| 60-79 | High | HIGH RISK - Proceed with extreme caution |
| 40-59 | Medium | MEDIUM RISK - Some concerns identified |
| 0-39 | Low | Low risk detected - Contract appears legitimate |

## Security Checks

### Critical Red Flags (80-100 risk)

1. **Hidden Mint Functions**: Unlimited token minting capability
2. **Honeypot Mechanisms**: Can receive tokens but can't sell
3. **Backdoor Functions**: Hidden admin functions or self-destruct
4. **Proxy Without Timelock**: Upgradeable with no delay

### High Risk (60-79)

5. **Pausable Transfers**: Owner can freeze all trading
6. **High Tax Functions**: Buy/sell tax > 10%
7. **Centralized Ownership**: Single address controls everything
8. **Liquidity Not Locked**: LP tokens can be rug pulled

### Medium Risk (40-59)

9. **Modifiable Fees**: Owner can change fees anytime
10. **Blacklist Function**: Addresses can be blocked
11. **Max Transaction Limit**: Limits on buy/sell amounts
12. **Recent Deployment**: Contract < 7 days old

### Low Risk Indicators (0-39)

13. **Renounced Ownership**: No admin control
14. **Open Source + Verified**: Code verified on block explorer
15. **Liquidity Locked**: LP tokens locked > 6 months
16. **Time-Tested**: Contract > 30 days old with high transaction count

## Development

### Project Structure

```
smart-contract-risk-scorer/
├── src/
│   ├── agent.js              # Main agent setup with X402 payments
│   ├── index.js              # Server startup
│   ├── analyzers/
│   │   ├── code-analyzer.js  # Source code pattern matching
│   │   ├── ownership.js      # Ownership centralization checks
│   │   ├── liquidity.js      # LP lock and rug pull detection
│   │   └── behavioral.js     # Historical transaction analysis
│   ├── services/
│   │   ├── etherscan.js      # Etherscan API client
│   │   └── rpc.js            # Blockchain RPC calls
│   ├── utils/
│   │   ├── scoring.js        # Risk score calculations
│   │   └── recommendations.js # User recommendations
│   └── database/
│       └── cache.js          # SQLite cache for results
├── .env
├── package.json
└── README.md
```

### Run in Development Mode

```bash
npm run dev
```

## Testing

### Automated Test Suite

Run the automated test script to verify all functionality:

```bash
# Make sure server is running first
npm start

# In another terminal, run the test script
./test-analysis.sh
```

This tests analysis of 5 major contracts (USDC, USDT, DAI, WETH, Uniswap Router).

### Manual Testing

```bash
# USDC - Safe stablecoin (expected: LOW risk ~15)
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"}'

# USDT - Centralized but safe (expected: LOW risk ~15)
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"contract_address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "chain": "ethereum"}'

# Test deep scan mode
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum", "scan_depth": "deep"}'
```

## Deployment

### Deploy to Railway

1. Create Railway account at https://railway.app
2. Create new project
3. Connect your GitHub repository
4. Add environment variables from `.env`
5. Deploy

Railway will automatically:
- Install dependencies
- Build the project
- Start the server
- Provide a public URL

## Payment Integration

This agent uses the X402 protocol for payments:

- **Network**: Base (Layer 2 Ethereum)
- **Currency**: USDC
- **Price**: $0.15 per scan
- **Facilitator**: Daydreams.systems

Payment is verified before each scan using the X-PAYMENT header. No valid payment = no analysis.

## Caching

Results are cached for 1 hour to:
- Reduce API calls to block explorers
- Improve response time for repeated queries
- Lower costs

Cache is automatically cleaned on startup and periodically.

## Limitations

- Requires verified source code for full analysis
- Liquidity analysis only in "deep" scan mode
- Relies on block explorer APIs (rate limits may apply)
- Cache may return slightly outdated results (max 1 hour old)

### 🚀 Automatic Fallback System (NEW!)
When block explorer APIs are unavailable, the system **automatically falls back** to decentralized analysis using:
- **Direct RPC calls** - No centralized API dependency
- **GoPlus Security API** - Professional honeypot detection
- **Bytecode pattern analysis** - Detects dangerous opcodes (selfdestruct, delegatecall)

**Result:** Full functionality even when Etherscan is down! Fallback analysis completes in ~1.5-2 seconds.

## Roadmap

- [ ] Support for more chains (BSC, Avalanche, Fantom)
- [ ] Integration with Coingecko for price data
- [ ] Machine learning-based pattern detection
- [ ] Historical rug pull database
- [ ] Webhook notifications for risky contracts
- [ ] API rate limit optimization

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT

## Support

For issues and questions:
- Open an issue on GitHub
- Contact via [your contact method]

## Disclaimer

This tool provides automated analysis but should not be the sole factor in investment decisions. Always do your own research (DYOR) before interacting with any smart contract. The developers are not responsible for any financial losses.
