/**
 * Behavioral Analyzer
 * Analyzes historical transaction patterns and contract behavior
 */

/**
 * Analyze contract behavior based on transaction history
 */
export async function analyzeBehavior(etherscanClient, contractAddress, contractInfo) {
  const analysis = {
    ageScore: 0,
    activityScore: 0,
    suspiciousActivity: [],
    score: 0,
    findings: []
  };

  try {
    // Analyze contract age
    const ageAnalysis = analyzeContractAge(contractInfo);
    analysis.ageScore = ageAnalysis.score;
    analysis.findings.push(...ageAnalysis.findings);

    // Analyze transaction activity
    const activityAnalysis = await analyzeActivity(etherscanClient, contractAddress);
    analysis.activityScore = activityAnalysis.score;
    analysis.findings.push(...activityAnalysis.findings);

    // Look for suspicious patterns
    const suspiciousPatterns = await detectSuspiciousPatterns(etherscanClient, contractAddress);
    analysis.suspiciousActivity = suspiciousPatterns.patterns;
    analysis.findings.push(...suspiciousPatterns.findings);

    // Calculate total score
    analysis.score = analysis.ageScore + analysis.activityScore + suspiciousPatterns.score;

  } catch (error) {
    console.error('Error analyzing behavior:', error.message);
    analysis.findings.push({
      type: 'analysis_error',
      severity: 'info',
      description: `Could not analyze behavior: ${error.message}`,
      score: 0
    });
  }

  return analysis;
}

/**
 * Analyze contract age
 */
function analyzeContractAge(contractInfo) {
  const findings = [];
  let score = 0;

  const ageInDays = contractInfo.ageInDays || 0;

  if (ageInDays < 1) {
    score += 10;
    findings.push({
      type: 'very_new_contract',
      severity: 'high',
      description: 'Contract deployed less than 24 hours ago - very high risk',
      evidence: `Age: ${ageInDays} days`,
      score: 10
    });
  } else if (ageInDays < 7) {
    score += 5;
    findings.push({
      type: 'new_contract',
      severity: 'medium',
      description: 'Contract deployed less than 7 days ago - untested',
      evidence: `Age: ${ageInDays} days`,
      score: 5
    });
  } else if (ageInDays < 30) {
    score += 3;
    findings.push({
      type: 'recent_contract',
      severity: 'medium',
      description: 'Contract deployed less than 30 days ago - limited history',
      evidence: `Age: ${ageInDays} days`,
      score: 3
    });
  } else if (ageInDays > 365) {
    score -= 5;
    findings.push({
      type: 'established_contract',
      severity: 'safe',
      description: 'Contract has been deployed for over a year - battle-tested',
      evidence: `Age: ${ageInDays} days`,
      score: -5
    });
  }

  return { score, findings };
}

/**
 * Analyze transaction activity
 */
async function analyzeActivity(etherscanClient, contractAddress) {
  const findings = [];
  let score = 0;

  try {
    const transactions = await etherscanClient.getTransactions(contractAddress, 0, 99999999, 1, 100);

    const txCount = transactions.length;

    if (txCount === 0) {
      score += 5;
      findings.push({
        type: 'no_activity',
        severity: 'medium',
        description: 'No transaction activity detected - suspicious',
        score: 5
      });
    } else if (txCount < 10) {
      score += 3;
      findings.push({
        type: 'low_activity',
        severity: 'medium',
        description: 'Very low transaction activity - not widely used',
        evidence: `${txCount} transactions`,
        score: 3
      });
    } else if (txCount > 1000) {
      score -= 5;
      findings.push({
        type: 'high_activity',
        severity: 'safe',
        description: 'High transaction activity - widely used contract',
        evidence: `${txCount}+ transactions`,
        score: -5
      });
    }

    return { score, findings };
  } catch (error) {
    console.error('Error analyzing activity:', error.message);
    return { score: 0, findings: [] };
  }
}

/**
 * Detect suspicious transaction patterns
 */
async function detectSuspiciousPatterns(etherscanClient, contractAddress) {
  const patterns = [];
  const findings = [];
  let score = 0;

  try {
    // Get recent transactions
    const transactions = await etherscanClient.getTransactions(contractAddress, 0, 99999999, 1, 100);

    if (transactions.length === 0) {
      return { patterns, findings, score };
    }

    // Check for tax/fee changes
    const taxChanges = transactions.filter(tx =>
      tx.functionName &&
      (tx.functionName.toLowerCase().includes('settax') ||
       tx.functionName.toLowerCase().includes('setfee') ||
       tx.functionName.toLowerCase().includes('updatefee'))
    );

    if (taxChanges.length > 0) {
      score += 5;
      patterns.push('tax_modifications');
      findings.push({
        type: 'tax_modifications',
        severity: 'medium',
        description: 'Owner has modified fees/taxes',
        evidence: `${taxChanges.length} fee modification(s) detected`,
        score: 5
      });
    }

    // Check for blacklist additions
    const blacklistAdditions = transactions.filter(tx =>
      tx.functionName &&
      (tx.functionName.toLowerCase().includes('blacklist') ||
       tx.functionName.toLowerCase().includes('block'))
    );

    if (blacklistAdditions.length > 0) {
      score += 5;
      patterns.push('blacklist_usage');
      findings.push({
        type: 'blacklist_usage',
        severity: 'medium',
        description: 'Addresses have been blacklisted',
        evidence: `${blacklistAdditions.length} blacklist transaction(s)`,
        score: 5
      });
    }

    // Check for pause events
    const pauseEvents = transactions.filter(tx =>
      tx.functionName &&
      (tx.functionName.toLowerCase().includes('pause') ||
       tx.functionName.toLowerCase().includes('unpause'))
    );

    if (pauseEvents.length > 0) {
      score += 3;
      patterns.push('pause_events');
      findings.push({
        type: 'pause_events',
        severity: 'medium',
        description: 'Contract has been paused/unpaused',
        evidence: `${pauseEvents.length} pause event(s)`,
        score: 3
      });
    }

    // Check for large transfers from contract
    const largeTransfers = transactions.filter(tx => {
      const value = BigInt(tx.value || 0);
      return value > BigInt('1000000000000000000'); // > 1 ETH
    });

    if (largeTransfers.length > 5) {
      score += 3;
      patterns.push('large_transfers');
      findings.push({
        type: 'large_transfers',
        severity: 'medium',
        description: 'Multiple large value transfers detected',
        evidence: `${largeTransfers.length} large transfer(s)`,
        score: 3
      });
    }

    // Check for ownership transfers
    const ownershipTransfers = transactions.filter(tx =>
      tx.functionName &&
      tx.functionName.toLowerCase().includes('transferownership')
    );

    if (ownershipTransfers.length > 1) {
      score += 5;
      patterns.push('multiple_ownership_transfers');
      findings.push({
        type: 'multiple_ownership_transfers',
        severity: 'high',
        description: 'Ownership has been transferred multiple times',
        evidence: `${ownershipTransfers.length} ownership transfer(s)`,
        score: 5
      });
    }

    // Check for contract upgrades (if proxy)
    const upgrades = transactions.filter(tx =>
      tx.functionName &&
      (tx.functionName.toLowerCase().includes('upgrade') ||
       tx.functionName.toLowerCase().includes('setimplementation'))
    );

    if (upgrades.length > 0) {
      score += 5;
      patterns.push('contract_upgrades');
      findings.push({
        type: 'contract_upgrades',
        severity: 'high',
        description: 'Contract logic has been upgraded',
        evidence: `${upgrades.length} upgrade(s) detected`,
        score: 5
      });
    }

  } catch (error) {
    console.error('Error detecting suspicious patterns:', error.message);
  }

  return { patterns, findings, score };
}

/**
 * Calculate behavioral score
 */
export function calculateBehavioralScore(behaviorAnalysis) {
  return behaviorAnalysis.score;
}

export default {
  analyzeBehavior,
  calculateBehavioralScore
};
