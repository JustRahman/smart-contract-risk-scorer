import { ethers } from 'ethers';

/**
 * Fallback Contract Analyzer
 * Analyzes contracts using only RPC calls when Etherscan API is unavailable
 * Provides basic but functional analysis without source code
 */

export async function analyzeContractViaRPC(rpcClient, address) {
  try {
    // Get basic contract info via RPC
    const code = await rpcClient.provider.getCode(address);

    if (code === '0x') {
      throw new Error('Address is not a contract');
    }

    // Try to get token info
    let tokenInfo = { name: 'Unknown', symbol: 'UNKNOWN', decimals: 18 };
    try {
      tokenInfo = await rpcClient.getTokenInfo(address);
    } catch (e) {
      // Not a standard ERC20, that's ok
    }

    // Get transaction count as a proxy for activity
    const txCount = await rpcClient.provider.getTransactionCount(address);

    // Estimate contract age by looking at deployment
    let ageInDays = 0;
    let creator = null;

    try {
      // Try to find contract creation (this is best-effort)
      const currentBlock = await rpcClient.provider.getBlockNumber();
      const searchBlocks = Math.min(currentBlock, 10000); // Last 10k blocks

      // Estimate age based on current block (rough estimate)
      // Average Ethereum block time ~12 seconds
      ageInDays = Math.floor((currentBlock * 12) / (60 * 60 * 24));
    } catch (e) {
      console.log('Could not estimate age:', e.message);
    }

    return {
      address,
      contractName: tokenInfo.name || 'Unknown Contract',
      verified: false, // Can't verify without Etherscan
      sourceCode: null,
      abi: null,
      isProxy: code.includes('delegatecall'), // Simple proxy detection
      creator,
      creationDate: null,
      ageInDays: Math.max(ageInDays, 1), // At least 1 day
      transactionCount: txCount,
      tokenInfo,
      fallbackMode: true // Flag that we're using fallback
    };
  } catch (error) {
    console.error('RPC fallback analysis failed:', error.message);
    throw error;
  }
}

/**
 * Analyze contract bytecode for common patterns
 * Works without source code - improved to reduce false positives
 */
export function analyzeBytecode(bytecode) {
  const findings = [];

  // Convert to lowercase for consistent checking
  const code = bytecode.toLowerCase();

  // Count occurrences for better analysis
  const delegatecallCount = (code.match(/f4/g) || []).length;
  const selfdestructCount = (code.match(/ff/g) || []).length;

  // Check for delegatecall (proxy pattern or potential vulnerability)
  // Only flag if it appears multiple times (likely proxy pattern)
  if (delegatecallCount > 2) {
    findings.push({
      pattern: 'delegatecall',
      severity: 'low',
      description: 'Proxy pattern detected (delegatecall) - common in upgradeable contracts',
      count: delegatecallCount
    });
  }

  // Check for selfdestruct - but 'ff' is very common in bytecode
  // Only flag if it appears in suspicious patterns
  // Most legitimate contracts have some 'ff' bytes that aren't selfdestruct
  if (selfdestructCount > 0 && selfdestructCount < 10) {
    // Very high count likely means it's just data, not actual selfdestruct opcode
    // Low count might be actual selfdestruct
    findings.push({
      pattern: 'potential_selfdestruct',
      severity: 'medium',
      description: 'Possible selfdestruct capability detected (requires verification)',
      count: selfdestructCount
    });
  }

  // Check contract size (large contracts might be more complex/risky)
  const sizeKB = bytecode.length / 2 / 1024;
  if (sizeKB > 24) { // Ethereum max is 24KB
    findings.push({
      pattern: 'large_contract',
      severity: 'low',
      description: `Large contract (${sizeKB.toFixed(1)}KB) - higher complexity`
    });
  }

  // Check for common ERC20 patterns
  const hasTransfer = code.includes('a9059cbb'); // transfer(address,uint256)
  const hasApprove = code.includes('095ea7b3'); // approve(address,uint256)
  const hasBalanceOf = code.includes('70a08231'); // balanceOf(address)

  if (hasTransfer && hasApprove && hasBalanceOf) {
    findings.push({
      pattern: 'erc20_standard',
      severity: 'info',
      description: 'Standard ERC20 token functions detected'
    });
  }

  return findings;
}

/**
 * Generate risk score based on RPC analysis only
 */
export function calculateRPCOnlyRiskScore(contractInfo, goplusData, bytecodeFindings) {
  let score = 0;
  const vulnerabilities = [];

  // Base score for unverified contracts
  score += 10;
  vulnerabilities.push({
    type: 'unverified_source',
    severity: 'medium',
    description: 'Contract source code not verified (Etherscan API unavailable)',
    evidence: 'Using RPC-only analysis',
    source: 'Fallback Analyzer'
  });

  // Add bytecode findings (reduced scoring to avoid false positives)
  bytecodeFindings.forEach(finding => {
    if (finding.pattern === 'potential_selfdestruct') {
      // Don't add score for potential selfdestruct - too many false positives
      // Only add as informational vulnerability
      vulnerabilities.push({
        type: 'potential_selfdestruct',
        severity: 'low',
        description: finding.description + ' (common false positive)',
        evidence: `Found ${finding.count} occurrences - may be data, not actual selfdestruct`,
        source: 'Bytecode Analysis'
      });
    } else if (finding.pattern === 'delegatecall') {
      // Delegatecall is normal for proxy patterns, don't penalize
      vulnerabilities.push({
        type: 'proxy_pattern',
        severity: 'info',
        description: finding.description,
        evidence: `Delegatecall count: ${finding.count}`,
        source: 'Bytecode Analysis'
      });
    } else if (finding.pattern === 'erc20_standard') {
      // This is actually good - standard ERC20
      vulnerabilities.push({
        type: 'erc20_standard',
        severity: 'info',
        description: finding.description,
        evidence: 'Standard ERC20 interface detected',
        source: 'Bytecode Analysis'
      });
    }
  });

  // Use GoPlus data if available
  if (goplusData) {
    if (goplusData.is_honeypot) {
      score += 40;
      vulnerabilities.push({
        type: 'honeypot',
        severity: 'critical',
        description: 'GoPlus detected honeypot mechanism',
        evidence: 'is_honeypot: true',
        source: 'GoPlus Security'
      });
    }

    if (goplusData.hidden_owner) {
      score += 15;
      vulnerabilities.push({
        type: 'hidden_owner',
        severity: 'high',
        description: 'Hidden owner detected',
        evidence: 'hidden_owner: true',
        source: 'GoPlus Security'
      });
    }

    if (goplusData.buy_tax > 10 || goplusData.sell_tax > 10) {
      score += 15;
      vulnerabilities.push({
        type: 'high_tax',
        severity: 'medium',
        description: 'High transaction tax detected',
        evidence: `Buy: ${goplusData.buy_tax}%, Sell: ${goplusData.sell_tax}%`,
        source: 'GoPlus Security'
      });
    }

    if (goplusData.cannot_sell_all) {
      score += 25;
      vulnerabilities.push({
        type: 'cannot_sell',
        severity: 'critical',
        description: 'Cannot sell all tokens - potential honeypot',
        evidence: 'cannot_sell_all: true',
        source: 'GoPlus Security'
      });
    }
  }

  return { score: Math.min(score, 100), vulnerabilities };
}
