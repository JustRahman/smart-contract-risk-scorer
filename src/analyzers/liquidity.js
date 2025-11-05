import { ethers } from 'ethers';

/**
 * Liquidity Analyzer
 * Detects LP lock status and rug pull risks
 */

// Uniswap V2 Factory addresses for different chains
const UNISWAP_V2_FACTORIES = {
  ethereum: '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f',
  polygon: '0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32',
  arbitrum: '0xf1D7CC64Fb4452F05c498126312eBE29f30Fbcf9',
  optimism: '0x0c3c1c532F1e39EdF36BE9Fe0bE1410313E074Bf',
  base: '0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6'
};

// Known DEX router addresses (where liquidity is often added)
const DEX_ROUTERS = {
  ethereum: ['0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'], // Uniswap V2
  polygon: ['0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff'], // QuickSwap
  arbitrum: ['0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506'], // SushiSwap
  optimism: ['0x4A7b5Da61326A6379179b40d00F57E5bbDC962c2'], // Velodrome
  base: ['0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24'] // BaseSwap
};

// Common LP lock contract addresses
const KNOWN_LOCKERS = [
  '0x663a5c229c09b049e36dcc11a9b0d4a8eb9db214', // Unicrypt (multiple chains)
  '0x71B5759d73262FBb223956913ecF4ecC51057641', // PinkLock BSC
  '0x407993575c91ce7643a4d4cCACc9A98c36eE1BBE', // PinkLock ETH
  '0x000000000000000000000000000000000000dead'  // Burn address
];

/**
 * Analyze liquidity and LP token distribution
 */
export async function analyzeLiquidity(rpcClient, etherscanClient, contractAddress, contractInfo) {
  const analysis = {
    hasLiquidity: false,
    liquidityPairs: [],
    lpLocked: false,
    lpBurned: false,
    lpHolders: [],
    score: 0,
    findings: []
  };

  try {
    // Find liquidity pairs
    const pairs = await findLiquidityPairs(etherscanClient, contractAddress, rpcClient.chain);

    if (pairs.length === 0) {
      analysis.findings.push({
        type: 'no_liquidity_found',
        severity: 'medium',
        description: 'No liquidity pools found for this token',
        score: 5
      });
      analysis.score += 5;
      return analysis;
    }

    analysis.hasLiquidity = true;
    analysis.liquidityPairs = pairs;

    // Analyze each pair
    for (const pair of pairs) {
      const pairAnalysis = await analyzeLiquidityPair(
        rpcClient,
        etherscanClient,
        pair.address,
        contractInfo.creator
      );

      if (pairAnalysis.locked) {
        analysis.lpLocked = true;
      }

      if (pairAnalysis.burned) {
        analysis.lpBurned = true;
      }

      analysis.lpHolders.push(...pairAnalysis.holders);
      analysis.findings.push(...pairAnalysis.findings);
    }

    // Calculate score based on findings
    if (analysis.lpLocked || analysis.lpBurned) {
      analysis.score -= 10;
      analysis.findings.push({
        type: 'liquidity_locked',
        severity: 'safe',
        description: analysis.lpBurned
          ? 'LP tokens burned - liquidity is locked permanently'
          : 'LP tokens locked - reduced rug pull risk',
        score: -10
      });
    } else {
      // Check if creator/owner holds significant LP tokens
      const creatorHoldsLP = analysis.lpHolders.some(holder =>
        holder.address.toLowerCase() === contractInfo.creator?.toLowerCase() &&
        holder.percentage > 50
      );

      if (creatorHoldsLP) {
        analysis.score += 15;
        analysis.findings.push({
          type: 'liquidity_not_locked',
          severity: 'high',
          description: 'LP tokens held by deployer - high rug pull risk',
          evidence: `Creator holds ${analysis.lpHolders[0]?.percentage}% of LP tokens`,
          score: 15
        });
      } else {
        analysis.score += 10;
        analysis.findings.push({
          type: 'liquidity_not_locked',
          severity: 'high',
          description: 'LP tokens not locked - rug pull risk',
          score: 10
        });
      }
    }

  } catch (error) {
    console.error('Error analyzing liquidity:', error.message);
    analysis.findings.push({
      type: 'analysis_error',
      severity: 'info',
      description: `Could not analyze liquidity: ${error.message}`,
      score: 0
    });
  }

  return analysis;
}

/**
 * Find liquidity pairs for a token
 */
async function findLiquidityPairs(etherscanClient, tokenAddress, chain) {
  const pairs = [];

  try {
    // Get token transfer events to find pair creation
    const transfers = await etherscanClient.getTokenTransfers(tokenAddress, 0, 99999999, 1, 1000);

    // Track potential pair addresses (addresses that have received large amounts of tokens)
    const pairCandidates = new Map();

    for (const transfer of transfers) {
      const to = transfer.to.toLowerCase();
      const value = BigInt(transfer.value || 0);

      // Skip if it's a transfer to zero address
      if (to === '0x0000000000000000000000000000000000000000') continue;

      // Accumulate transfers to each address
      const current = pairCandidates.get(to) || BigInt(0);
      pairCandidates.set(to, current + value);
    }

    // Find addresses with significant token balances (likely pairs)
    const sortedCandidates = Array.from(pairCandidates.entries())
      .sort((a, b) => (b[1] > a[1] ? 1 : -1))
      .slice(0, 5); // Top 5 candidates

    // Verify if these are actually Uniswap pairs
    for (const [address, balance] of sortedCandidates) {
      try {
        // Try to call pair functions to verify it's a Uniswap pair
        const pairInfo = await etherscanClient.getSourceCode(address);

        if (pairInfo && (
          pairInfo.contractName.includes('Pair') ||
          pairInfo.contractName.includes('LP')
        )) {
          pairs.push({
            address,
            balance: balance.toString(),
            name: pairInfo.contractName
          });
        }
      } catch (error) {
        // Not a valid pair contract, skip
        continue;
      }
    }

  } catch (error) {
    console.error('Error finding liquidity pairs:', error.message);
  }

  return pairs;
}

/**
 * Analyze a specific liquidity pair
 */
async function analyzeLiquidityPair(rpcClient, etherscanClient, pairAddress, creatorAddress) {
  const analysis = {
    locked: false,
    burned: false,
    holders: [],
    findings: []
  };

  try {
    // Get LP token holders by checking transfers
    const lpTransfers = await etherscanClient.getTokenTransfers(pairAddress, 0, 99999999, 1, 1000);

    // Calculate holder balances
    const balances = new Map();

    for (const transfer of lpTransfers) {
      const from = transfer.from.toLowerCase();
      const to = transfer.to.toLowerCase();
      const value = BigInt(transfer.value || 0);

      // Subtract from sender
      if (from !== '0x0000000000000000000000000000000000000000') {
        const currentFrom = balances.get(from) || BigInt(0);
        balances.set(from, currentFrom - value);
      }

      // Add to receiver
      const currentTo = balances.get(to) || BigInt(0);
      balances.set(to, currentTo + value);
    }

    // Get total supply
    const totalSupply = await rpcClient.getContract(pairAddress, [
      'function totalSupply() view returns (uint256)'
    ]).totalSupply();

    // Calculate percentages and check for locks
    const burnAddress = '0x000000000000000000000000000000000000dead';

    for (const [address, balance] of balances.entries()) {
      if (balance <= 0) continue;

      const percentage = Number((balance * BigInt(10000)) / totalSupply) / 100;

      if (percentage < 1) continue; // Ignore holders with <1%

      // Check if LP is burned
      if (address === burnAddress || address === '0x0000000000000000000000000000000000000000') {
        analysis.burned = true;
        analysis.locked = true;
      }

      // Check if LP is in a known locker
      if (KNOWN_LOCKERS.includes(address)) {
        analysis.locked = true;
      }

      analysis.holders.push({
        address,
        balance: balance.toString(),
        percentage: percentage.toFixed(2),
        isLocker: KNOWN_LOCKERS.includes(address),
        isBurned: address === burnAddress || address === '0x0000000000000000000000000000000000000000'
      });
    }

    // Sort holders by balance
    analysis.holders.sort((a, b) => Number(BigInt(b.balance) - BigInt(a.balance)));

  } catch (error) {
    console.error('Error analyzing liquidity pair:', error.message);
  }

  return analysis;
}

/**
 * Calculate liquidity score
 */
export function calculateLiquidityScore(liquidityAnalysis) {
  return liquidityAnalysis.score;
}

export default {
  analyzeLiquidity,
  calculateLiquidityScore
};
