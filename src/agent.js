import { Hono } from 'hono';
import { z } from 'zod';
import dotenv from 'dotenv';
import { createEtherscanClient } from './services/etherscan.js';
import { createRPCClient } from './services/rpc.js';
import { analyzeSourceCode, isProxyContract } from './analyzers/code-analyzer.js';
import { analyzeOwnership } from './analyzers/ownership.js';
import { analyzeLiquidity } from './analyzers/liquidity.js';
import { analyzeBehavior } from './analyzers/behavioral.js';
import { analyzeCreatorHistory } from './analyzers/creator-history.js';
import { analyzeHolderConcentration, analyzeCreatorHolding } from './analyzers/holder-analysis.js';
import {
  calculateRiskScore,
  getRiskLevel,
  calculateConfidence,
  compileVulnerabilities,
  compileSecurityChecks
} from './utils/scoring.js';
import { generateRecommendations } from './utils/recommendations.js';
import { getCache } from './database/cache.js';
import { createTokenSnifferClient } from './services/token-sniffer.js';
import { createGoPlusClient } from './services/goplus.js';
import { analyzeContractViaRPC, analyzeBytecode, calculateRPCOnlyRiskScore } from './services/fallback-analyzer.js';
import { createSourcifyClient } from './services/sourcify.js';
import { rateLimiter } from './middleware/rate-limit.js';
import { createPaymentMiddleware } from './middleware/x402-payment.js';

dotenv.config();

/**
 * Smart Contract Risk Scorer Agent with X402 Payment Integration
 * Analyzes smart contracts for security risks and rug pull indicators
 */

// Input validation schema
const ScanInputSchema = z.object({
  contract_address: z.string().regex(/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum address'),
  chain: z.enum(['ethereum', 'polygon', 'arbitrum', 'optimism', 'base']).default('ethereum'),
  scan_depth: z.enum(['quick', 'deep']).default('quick')
});

// Create Hono app
const app = new Hono();

// Apply rate limiting to all routes
app.use('*', rateLimiter());

// Apply X402 payment middleware (if enabled)
const paymentMiddleware = createPaymentMiddleware();
app.use('/analyze', paymentMiddleware);
app.use('/analyze-batch', paymentMiddleware);

const paymentsEnabled = process.env.ENABLE_PAYMENTS === 'true';
if (!paymentsEnabled) {
  console.log(`💰 Payment system: DISABLED (free for testing)`);
}

/**
 * Main analysis function
 */
async function analyzeContract({ contract_address, chain, scan_depth }) {
  const cache = getCache();

  // Check cache first
  const cached = cache.get(contract_address, chain, scan_depth);
  if (cached) {
    console.log(`Returning cached result for ${contract_address} on ${chain}`);
    return cached;
  }

  console.log(`Analyzing contract ${contract_address} on ${chain} (${scan_depth} scan)`);

  const startTime = Date.now();

  try {
    // Initialize clients
    const etherscanClient = createEtherscanClient(chain);
    const rpcClient = createRPCClient(chain);

    // Step 1: Get basic contract info
    console.log('Fetching contract info...');
    let contractInfo;
    let usingFallback = false;

    try {
      contractInfo = await etherscanClient.getContractInfo(contract_address);
    } catch (etherscanError) {
      console.warn(`Etherscan API unavailable: ${etherscanError.message}`);

      // Try Sourcify (decentralized verification) before pure RPC fallback
      console.log('Trying Sourcify (decentralized verification)...');
      const sourcifyClient = createSourcifyClient();
      const sourcifyData = await sourcifyClient.getSourceCode(contract_address, chain);

      if (sourcifyData && sourcifyData.verified) {
        console.log('✅ Contract verified on Sourcify!');
        // Get basic info from RPC
        const rpcInfo = await analyzeContractViaRPC(rpcClient, contract_address);
        // Merge with Sourcify data
        contractInfo = {
          ...rpcInfo,
          verified: true,
          sourceCode: sourcifyData.sourceCode,
          contractName: sourcifyData.contractName || rpcInfo.contractName,
          abi: sourcifyData.abi,
          fallbackMode: false // We have source code!
        };
        usingFallback = false; // We got source code from Sourcify
      } else {
        console.log('Contract not found on Sourcify, falling back to RPC-only analysis...');
        contractInfo = await analyzeContractViaRPC(rpcClient, contract_address);
        usingFallback = true;
      }
    }

    // Step 2: Analyze source code (if available) or bytecode (fallback)
    let codeAnalysis = { analyzed: false, vulnerabilities: [], safePatterns: [], score: 0 };
    let bytecodeFindings = [];

    if (contractInfo.verified && contractInfo.sourceCode) {
      console.log('Analyzing source code patterns...');
      // Detect proxy first
      contractInfo.isProxy = isProxyContract(contractInfo.sourceCode);
      // Pass isProxy flag to analyzer
      codeAnalysis = analyzeSourceCode(contractInfo.sourceCode, contractInfo.isProxy);
    } else if (usingFallback) {
      console.log('Analyzing contract bytecode (fallback mode)...');
      const bytecode = await rpcClient.provider.getCode(contract_address);
      bytecodeFindings = analyzeBytecode(bytecode);
    } else {
      console.log('Contract not verified - skipping code analysis');
    }

    // Step 3: Analyze ownership
    console.log('Analyzing ownership...');
    let ownershipAnalysis = { hasOwner: false, isRenounced: false, score: 0, findings: [] };

    if (!usingFallback) {
      try {
        ownershipAnalysis = await analyzeOwnership(rpcClient, etherscanClient, contract_address);
      } catch (ownerError) {
        console.warn('Ownership analysis failed, using basic checks:', ownerError.message);
        // Try basic RPC ownership check
        try {
          const owner = await rpcClient.getOwner(contract_address);
          ownershipAnalysis = {
            hasOwner: owner && owner !== ethers.ZeroAddress,
            isRenounced: owner === ethers.ZeroAddress,
            owner,
            score: 0,
            findings: []
          };
        } catch (e) {
          // No owner function, that's ok
        }
      }
    }

    // Step 4: Analyze liquidity (if quick scan, skip for speed)
    let liquidityAnalysis = { hasLiquidity: false, lpLocked: false, score: 0, findings: [] };

    if (scan_depth === 'deep') {
      console.log('Analyzing liquidity...');
      liquidityAnalysis = await analyzeLiquidity(rpcClient, etherscanClient, contract_address, contractInfo);
    } else {
      console.log('Skipping liquidity analysis (quick scan)');
    }

    // Step 5: Analyze behavioral patterns
    console.log('Analyzing transaction history...');
    const behaviorAnalysis = await analyzeBehavior(etherscanClient, contract_address, contractInfo);

    // Step 6: Get token info
    let tokenInfo = { name: 'Unknown', symbol: 'UNKNOWN', decimals: 18, totalSupply: '0' };

    try {
      tokenInfo = await rpcClient.getTokenInfo(contract_address);
    } catch (error) {
      console.log('Not an ERC20 token or error fetching token info');
    }

    // ========== PRIORITY 1 EXTERNAL CHECKS ==========

    // External Check 1: Token Sniffer API
    console.log('Checking Token Sniffer database...');
    let tokenSnifferResult = null;
    let tokenSnifferRisk = { score: 0, findings: [] };

    try {
      const tokenSnifferClient = createTokenSnifferClient();
      tokenSnifferResult = await tokenSnifferClient.checkToken(contract_address, chain);
      tokenSnifferRisk = tokenSnifferClient.calculateRisk(tokenSnifferResult);
    } catch (error) {
      console.error('Token Sniffer check failed:', error.message);
    }

    // External Check 2: GoPlus Security API
    console.log('Checking GoPlus Security...');
    let goplusResult = null;
    let goplusRisk = { score: 0, findings: [] };

    try {
      const goplusClient = createGoPlusClient();
      goplusResult = await goplusClient.checkTokenSecurity(contract_address, chain);
      goplusRisk = goplusClient.calculateRisk(goplusResult);
    } catch (error) {
      console.error('GoPlus check failed:', error.message);
    }

    // External Check 3: Creator History Analysis
    console.log('Analyzing creator wallet history...');
    let creatorHistoryAnalysis = { analyzed: false, score: 0, findings: [] };

    if (contractInfo.creator && scan_depth === 'deep') {
      try {
        creatorHistoryAnalysis = await analyzeCreatorHistory(
          etherscanClient,
          rpcClient,
          contractInfo.creator
        );
      } catch (error) {
        console.error('Creator history analysis failed:', error.message);
      }
    } else if (scan_depth === 'quick') {
      console.log('Skipping creator history (quick scan)');
    }

    // External Check 4: Holder Concentration Analysis
    console.log('Analyzing holder concentration...');
    let holderAnalysis = { analyzed: false, score: 0, findings: [] };
    let creatorHoldingAnalysis = { analyzed: false, score: 0, findings: [] };

    if (!usingFallback && scan_depth === 'deep') {
      try {
        holderAnalysis = await analyzeHolderConcentration(rpcClient, etherscanClient, contract_address);

        if (contractInfo.creator) {
          creatorHoldingAnalysis = await analyzeCreatorHolding(rpcClient, contract_address, contractInfo.creator);
        }
      } catch (error) {
        console.error('Holder analysis failed:', error.message);
      }
    } else if (scan_depth === 'quick') {
      console.log('Skipping holder concentration (quick scan)');
    }

    // ========== END EXTERNAL CHECKS ==========

    // Step 7: Calculate risk score
    let riskScore, vulnerabilities;

    if (usingFallback) {
      // Use simplified RPC-only scoring
      console.log('Using fallback risk calculation (RPC + GoPlus only)...');
      const fallbackResult = calculateRPCOnlyRiskScore(contractInfo, goplusResult, bytecodeFindings);
      riskScore = fallbackResult.score;
      vulnerabilities = fallbackResult.vulnerabilities;
    } else {
      // Use full analysis scoring
      const analyses = {
        codeAnalysis,
        ownershipAnalysis,
        liquidityAnalysis,
        behaviorAnalysis,
        contractInfo: {
          ...contractInfo,
          symbol: tokenInfo.symbol,
          name: tokenInfo.name
        },
        // External checks
        tokenSnifferResult,
        tokenSnifferRisk,
        goplusResult,
        goplusRisk,
        creatorHistoryAnalysis,
        holderAnalysis,
        creatorHoldingAnalysis
      };

      riskScore = calculateRiskScore(analyses);
      vulnerabilities = compileVulnerabilities(analyses);
    }

    const riskLevel = getRiskLevel(riskScore);
    const confidence = usingFallback ? 0.7 : calculateConfidence({ codeAnalysis, ownershipAnalysis });
    const securityChecks = compileSecurityChecks({ codeAnalysis, ownershipAnalysis, goplusResult });

    const analysesForRecommendations = usingFallback ? { contractInfo, goplusResult } : {
      codeAnalysis,
      ownershipAnalysis,
      liquidityAnalysis,
      behaviorAnalysis,
      contractInfo,
      goplusResult
    };
    const recommendations = generateRecommendations(riskScore, riskLevel, analysesForRecommendations, vulnerabilities);

    // Build result
    const result = {
      risk_score: riskScore,
      risk_level: riskLevel,
      contract_info: {
        address: contract_address,
        name: contractInfo.contractName || tokenInfo.name,
        symbol: tokenInfo.symbol,
        chain: chain,
        creator: contractInfo.creator,
        created: contractInfo.creationDate
          ? contractInfo.creationDate.toISOString().split('T')[0]
          : 'Unknown',
        age_days: contractInfo.ageInDays || 0,
        verified: contractInfo.verified,
        is_proxy: contractInfo.isProxy || false,
        transaction_count: contractInfo.transactionCount || 0
      },
      vulnerabilities: vulnerabilities.map(v => ({
        type: v.type,
        severity: v.severity,
        description: v.description,
        evidence: v.evidence || '',
        source: v.source || 'Internal'
      })),
      security_checks: securityChecks,
      external_checks: {
        token_sniffer: tokenSnifferResult ? {
          checked: tokenSnifferResult.checked,
          in_database: tokenSnifferResult.in_database,
          scam_score: tokenSnifferResult.score,
          scam_flagged: tokenSnifferResult.scam,
          warnings: tokenSnifferResult.warnings || []
        } : { checked: false },
        goplus: goplusResult ? {
          checked: goplusResult.checked,
          is_honeypot: goplusResult.is_honeypot,
          cannot_sell_all: goplusResult.cannot_sell_all,
          hidden_owner: goplusResult.hidden_owner,
          buy_tax: goplusResult.buy_tax,
          sell_tax: goplusResult.sell_tax,
          selfdestruct: goplusResult.selfdestruct,
          is_open_source: goplusResult.is_open_source
        } : { checked: false },
        creator_history: creatorHistoryAnalysis.analyzed ? {
          analyzed: true,
          total_contracts: creatorHistoryAnalysis.total_contracts_deployed,
          abandoned_contracts: creatorHistoryAnalysis.abandoned_contracts,
          recent_deployments: creatorHistoryAnalysis.recent_deployments,
          suspicious_pattern: creatorHistoryAnalysis.suspicious_pattern
        } : { analyzed: false },
        holder_concentration: holderAnalysis.analyzed ? {
          analyzed: true,
          holder_count: holderAnalysis.holderCount,
          risk_level: holderAnalysis.score > 15 ? 'high' : holderAnalysis.score > 5 ? 'medium' : 'low',
          findings: holderAnalysis.findings
        } : { analyzed: false },
        creator_holding: creatorHoldingAnalysis.analyzed ? {
          analyzed: true,
          percentage: creatorHoldingAnalysis.creatorPercentage,
          findings: creatorHoldingAnalysis.findings
        } : { analyzed: false }
      },
      recommendations,
      confidence,
      scan_depth,
      analysis_time_ms: Date.now() - startTime
    };

    // Cache result
    cache.set(contract_address, chain, scan_depth, result);

    console.log(`Analysis complete in ${result.analysis_time_ms}ms - Risk Score: ${riskScore} (${riskLevel})`);

    return result;

  } catch (error) {
    console.error('Error during analysis:', error);

    return {
      error: 'Analysis failed',
      message: error.message,
      contract_address,
      chain
    };
  }
}

// Root endpoint - API information
app.get('/', async (c) => {
  return c.json({
    service: "Smart Contract Risk Scorer",
    version: "1.0.0",
    status: "online",
    payment: {
      enabled: paymentsEnabled,
      amount: paymentsEnabled ? "$0.01 USDC" : "Free",
      network: paymentsEnabled ? "base" : "N/A"
    },
    endpoints: {
      health: {
        method: "GET",
        path: "/health",
        description: "Health check endpoint"
      },
      analyze: {
        method: "POST",
        path: "/analyze",
        description: "Analyze a single smart contract",
        requiresPayment: paymentsEnabled
      },
      analyzeBatch: {
        method: "POST",
        path: "/analyze-batch",
        description: "Analyze multiple smart contracts (max 10)",
        requiresPayment: paymentsEnabled
      }
    },
    example: {
      endpoint: "/analyze",
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: {
        contract_address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        chain: "ethereum",
        scan_depth: "quick"
      }
    },
    supportedChains: ["ethereum", "polygon", "arbitrum", "optimism", "base"]
  });
});

// Add POST endpoint for contract analysis (no payment required)
app.post('/analyze', async (c) => {
  try {
    const body = await c.req.json();

    // Validate input
    const input = ScanInputSchema.parse(body);

    // Run analysis
    const result = await analyzeContract(input);

    // Check if analysis failed
    if (result.error) {
      return c.json(result, 500);
    }

    return c.json(result);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid input',
        message: 'Please provide a valid Ethereum address and chain',
        details: error.errors.map(e => ({
          field: e.path.join('.'),
          message: e.message
        }))
      }, 400);
    }

    console.error('Analysis error:', error);
    return c.json({
      error: 'Analysis failed',
      message: error.message || 'An unexpected error occurred'
    }, 500);
  }
});

// Batch analysis endpoint - analyze multiple contracts at once
app.post('/analyze-batch', async (c) => {
  try {
    const body = await c.req.json();

    // Validate input
    if (!body.contracts || !Array.isArray(body.contracts) || body.contracts.length === 0) {
      return c.json({
        error: 'Invalid input',
        message: 'Please provide an array of contracts to analyze'
      }, 400);
    }

    // Limit batch size
    if (body.contracts.length > 10) {
      return c.json({
        error: 'Batch too large',
        message: 'Maximum 10 contracts per batch request'
      }, 400);
    }

    const chain = body.chain || 'ethereum';
    const scan_depth = body.scan_depth || 'quick';

    console.log(`\n📊 Batch analysis started: ${body.contracts.length} contracts on ${chain}`);

    // Analyze all contracts in parallel
    const results = await Promise.allSettled(
      body.contracts.map(async (address) => {
        try {
          const input = ScanInputSchema.parse({
            contract_address: address,
            chain,
            scan_depth
          });
          return await analyzeContract(input);
        } catch (error) {
          return {
            error: 'Analysis failed',
            message: error.message,
            contract_address: address,
            chain
          };
        }
      })
    );

    // Compile results
    const analyzed = results.map((result, index) => ({
      contract_address: body.contracts[index],
      status: result.status,
      result: result.status === 'fulfilled' ? result.value : result.reason
    }));

    const successful = analyzed.filter(r => r.status === 'fulfilled' && !r.result.error).length;
    const failed = analyzed.length - successful;

    console.log(`✅ Batch analysis complete: ${successful} successful, ${failed} failed\n`);

    return c.json({
      batch_size: body.contracts.length,
      successful,
      failed,
      results: analyzed
    });

  } catch (error) {
    console.error('Batch analysis error:', error);
    return c.json({
      error: 'Batch analysis failed',
      message: error.message || 'An unexpected error occurred'
    }, 500);
  }
});

// Enhanced health check endpoint
app.get('/health', async (c) => {
  const health = {
    status: 'ok',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    services: {}
  };

  // Check RPC connectivity
  try {
    const rpcClient = createRPCClient('ethereum');
    const blockNumber = await rpcClient.getBlockNumber();
    health.services.rpc = {
      status: 'ok',
      current_block: blockNumber
    };
  } catch (error) {
    health.services.rpc = {
      status: 'error',
      message: error.message
    };
    health.status = 'degraded';
  }

  // Check Etherscan API
  try {
    const etherscanClient = createEtherscanClient('ethereum');
    await etherscanClient.makeRequest({ module: 'stats', action: 'ethprice' });
    health.services.etherscan = { status: 'ok' };
  } catch (error) {
    health.services.etherscan = {
      status: 'error',
      message: 'API unavailable - using fallback mode'
    };
  }

  // Check GoPlus API
  try {
    const goplusClient = createGoPlusClient();
    health.services.goplus = { status: 'ok' };
  } catch (error) {
    health.services.goplus = {
      status: 'error',
      message: error.message
    };
  }

  // Check cache
  try {
    const cache = getCache();
    health.services.cache = {
      status: 'ok',
      type: 'SQLite'
    };
  } catch (error) {
    health.services.cache = {
      status: 'error',
      message: error.message
    };
  }

  const statusCode = health.status === 'ok' ? 200 : 503;
  return c.json(health, statusCode);
});

export { app };
