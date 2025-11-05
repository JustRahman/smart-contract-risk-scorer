/**
 * Code Pattern Analyzer
 * Scans smart contract source code for red flags and vulnerabilities
 */

/**
 * Red flag patterns to search for in source code
 */
const RED_FLAG_PATTERNS = {
  // CRITICAL (80-100 risk)
  hiddenMint: {
    patterns: [
      /function\s+mint\s*\([^)]*\)[^{]*{/gi,
      /_mint\s*\(/gi,
      /\.mint\s*\(/gi
    ],
    modifiers: ['onlyOwner', 'onlyAdmin', 'onlyMinter'],
    severity: 'critical',
    description: 'Contract owner can mint unlimited tokens',
    score: 15
  },

  selfDestruct: {
    patterns: [
      /selfdestruct\s*\(/gi,
      /suicide\s*\(/gi
    ],
    severity: 'critical',
    description: 'Contract can be destroyed by owner',
    score: 15
  },

  honeypot: {
    patterns: [
      /blacklist\s*\[/gi,
      /isBlacklisted/gi,
      /_isExcluded/gi,
      /canSell\s*\(/gi,
      /canTransfer\s*\(/gi
    ],
    severity: 'critical',
    description: 'Potential honeypot - can block transfers',
    score: 15
  },

  delegatecall: {
    patterns: [
      /delegatecall\s*\(/gi,
      /\.delegatecall\s*\(/gi
    ],
    severity: 'critical',
    description: 'Uses delegatecall - potential backdoor',
    score: 15
  },

  // HIGH RISK (60-79)
  pausable: {
    patterns: [
      /function\s+pause\s*\(/gi,
      /function\s+unpause\s*\(/gi,
      /_pause\s*\(/gi,
      /whenNotPaused/gi
    ],
    severity: 'high',
    description: 'Owner can pause all transfers',
    score: 10
  },

  modifiableTax: {
    patterns: [
      /setTaxFee/gi,
      /setBuyFee/gi,
      /setSellFee/gi,
      /setFee\s*\(/gi,
      /updateFee/gi
    ],
    severity: 'high',
    description: 'Owner can modify trading fees',
    score: 10
  },

  highTax: {
    patterns: [
      /_taxFee\s*=\s*([1-9][0-9]|100)/gi,
      /taxFee\s*=\s*([1-9][0-9]|100)/gi,
      /buyFee\s*=\s*([1-9][0-9]|100)/gi,
      /sellFee\s*=\s*([1-9][0-9]|100)/gi
    ],
    severity: 'high',
    description: 'High trading fees detected (>10%)',
    score: 10
  },

  ownership: {
    patterns: [
      /transferOwnership\s*\(/gi,
      /renounceOwnership\s*\(/gi
    ],
    severity: 'medium',
    description: 'Ownership can be transferred',
    score: 5
  },

  // MEDIUM RISK (40-59)
  maxTransaction: {
    patterns: [
      /maxTxAmount/gi,
      /_maxTxAmount/gi,
      /setMaxTx/gi,
      /maxTransactionAmount/gi
    ],
    severity: 'medium',
    description: 'Maximum transaction limits enforced',
    score: 5
  },

  maxWallet: {
    patterns: [
      /maxWallet/gi,
      /_maxWalletSize/gi,
      /maxWalletAmount/gi
    ],
    severity: 'medium',
    description: 'Maximum wallet size limits enforced',
    score: 5
  },

  antiBot: {
    patterns: [
      /isBot\s*\[/gi,
      /bots\s*\[/gi,
      /addBot\s*\(/gi,
      /antiBot/gi
    ],
    severity: 'medium',
    description: 'Anti-bot mechanisms present',
    score: 5
  },

  cooldown: {
    patterns: [
      /cooldown/gi,
      /buycooldown/gi,
      /sellcooldown/gi
    ],
    severity: 'medium',
    description: 'Cooldown periods enforced',
    score: 5
  },

  // RED FLAG KEYWORDS IN CODE/COMMENTS
  scamKeywordsInCode: {
    patterns: [
      /\/\/.*scam/gi,
      /\/\*.*scam.*\*\//gi,
      /\/\/.*honeypot/gi,
      /\/\*.*honeypot.*\*\//gi,
      /\/\/.*rug/gi,
      /\/\*.*rug.*\*\//gi,
      /\/\/.*exit.*scam/gi,
      /\/\*.*exit.*scam.*\*\//gi,
      /\/\/.*warning.*do.*not.*buy/gi,
      /\/\*.*warning.*do.*not.*buy.*\*\//gi
    ],
    severity: 'critical',
    description: 'Scam-related keywords found in source code comments',
    score: 30
  }
};

/**
 * Safe patterns that reduce risk
 */
const SAFE_PATTERNS = {
  renounceOwnership: {
    patterns: [
      /renounceOwnership\s*\(\s*\)\s*public/gi,
      /renounceOwnership\s*\(\s*\)\s*external/gi
    ],
    description: 'Ownership can be renounced',
    score: -10
  },

  timelockPresent: {
    patterns: [
      /timelock/gi,
      /TimelockController/gi,
      /delay\s*=\s*[0-9]+\s*days/gi
    ],
    description: 'Timelock mechanism present',
    score: -10
  },

  audited: {
    patterns: [
      /@audit/gi,
      /audited by/gi,
      /security audit/gi
    ],
    description: 'Contract mentions audit',
    score: -5
  },

  openZeppelin: {
    patterns: [
      /import.*@openzeppelin/gi,
      /OpenZeppelin/gi
    ],
    description: 'Uses OpenZeppelin contracts',
    score: -5
  }
};

/**
 * Analyze contract source code for patterns
 */
export function analyzeSourceCode(sourceCode, isProxy = false) {
  if (!sourceCode || sourceCode.length === 0) {
    return {
      analyzed: false,
      vulnerabilities: [],
      safePatterns: [],
      score: 0
    };
  }

  const vulnerabilities = [];
  const safePatterns = [];
  let score = 0;

  // Check for red flags
  for (const [key, pattern] of Object.entries(RED_FLAG_PATTERNS)) {
    let found = false;
    const evidence = [];

    for (const regex of pattern.patterns) {
      const matches = sourceCode.match(regex);
      if (matches) {
        found = true;
        evidence.push(...matches.slice(0, 3)); // Limit to 3 examples
      }
    }

    // For hiddenMint, also check if it has restricted modifiers
    if (key === 'hiddenMint' && found) {
      const hasRestrictedModifier = pattern.modifiers.some(modifier =>
        sourceCode.toLowerCase().includes(modifier.toLowerCase())
      );

      if (!hasRestrictedModifier) {
        // Mint function without restriction is less of a concern
        found = false;
        evidence.length = 0;
      }
    }

    // For delegatecall in proxy contracts, downgrade severity
    if (key === 'delegatecall' && found && isProxy) {
      vulnerabilities.push({
        type: key,
        severity: 'low',
        description: 'Proxy contract uses delegatecall (expected behavior)',
        evidence: evidence.join(', '),
        score: 2 // Much lower score for proxies
      });
      score += 2;
      found = false; // Skip the normal vulnerability addition below
    }

    if (found) {
      vulnerabilities.push({
        type: key,
        severity: pattern.severity,
        description: pattern.description,
        evidence: evidence.join(', '),
        score: pattern.score
      });

      score += pattern.score;
    }
  }

  // Check for safe patterns
  for (const [key, pattern] of Object.entries(SAFE_PATTERNS)) {
    let found = false;
    const evidence = [];

    for (const regex of pattern.patterns) {
      const matches = sourceCode.match(regex);
      if (matches) {
        found = true;
        evidence.push(...matches.slice(0, 2));
      }
    }

    if (found) {
      safePatterns.push({
        type: key,
        description: pattern.description,
        evidence: evidence.join(', '),
        score: pattern.score
      });

      score += pattern.score; // Safe patterns have negative scores
    }
  }

  return {
    analyzed: true,
    vulnerabilities,
    safePatterns,
    score
  };
}

/**
 * Extract function signatures from source code
 */
export function extractFunctions(sourceCode) {
  if (!sourceCode) return [];

  const functionPattern = /function\s+(\w+)\s*\([^)]*\)(\s+\w+)*\s*(?:returns\s*\([^)]*\))?/gi;
  const matches = sourceCode.matchAll(functionPattern);

  const functions = [];
  for (const match of matches) {
    functions.push({
      name: match[1],
      signature: match[0],
      modifiers: match[2] ? match[2].trim().split(/\s+/) : []
    });
  }

  return functions;
}

/**
 * Check for proxy pattern
 */
export function isProxyContract(sourceCode) {
  if (!sourceCode) return false;

  const proxyPatterns = [
    /upgradeTo/gi,
    /upgradeToAndCall/gi,
    /implementation\s*\(\)/gi,
    /_implementation/gi,
    /TransparentUpgradeableProxy/gi,
    /UUPSUpgradeable/gi
  ];

  return proxyPatterns.some(pattern => pattern.test(sourceCode));
}

/**
 * Estimate code complexity (simple heuristic)
 */
export function estimateComplexity(sourceCode) {
  if (!sourceCode) return 'low';

  const lines = sourceCode.split('\n').length;
  const functions = extractFunctions(sourceCode).length;

  if (lines > 1000 || functions > 50) return 'high';
  if (lines > 500 || functions > 25) return 'medium';
  return 'low';
}

export default {
  analyzeSourceCode,
  extractFunctions,
  isProxyContract,
  estimateComplexity
};
