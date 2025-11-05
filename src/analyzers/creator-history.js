/**
 * Creator History Analyzer
 * Analyzes deployer wallet's history for past scams and patterns
 */

/**
 * Analyze creator wallet history
 */
export async function analyzeCreatorHistory(etherscanClient, rpcClient, creatorAddress) {
  if (!creatorAddress || creatorAddress === '0x0000000000000000000000000000000000000000') {
    return {
      analyzed: false,
      reason: 'No creator address available',
      score: 0,
      findings: []
    };
  }

  const analysis = {
    analyzed: true,
    creator_address: creatorAddress,
    total_contracts_deployed: 0,
    contracts: [],
    abandoned_contracts: 0,
    recent_deployments: 0,
    suspicious_pattern: false,
    score: 0,
    findings: []
  };

  try {
    console.log(`Analyzing creator history: ${creatorAddress}`);

    // Get all transactions from creator
    const transactions = await etherscanClient.getTransactions(creatorAddress, 0, 99999999, 1, 10000);

    // Filter for contract creation transactions
    // Contract creation txs have empty 'to' field
    const contractCreations = transactions.filter(tx =>
      !tx.to || tx.to === '' || tx.to === '0x' || tx.contractAddress
    );

    analysis.total_contracts_deployed = contractCreations.length;

    console.log(`Creator deployed ${contractCreations.length} contracts`);

    // Analyze each deployed contract (limit to last 20 for performance)
    const recentCreations = contractCreations.slice(0, 20);

    for (const tx of recentCreations) {
      const contractAddress = tx.contractAddress || tx.to;

      if (!contractAddress || contractAddress === '') continue;

      try {
        const contractAnalysis = await analyzeDeployedContract(
          etherscanClient,
          rpcClient,
          contractAddress,
          tx.timeStamp
        );

        analysis.contracts.push(contractAnalysis);

        // Count abandoned contracts
        if (contractAnalysis.abandoned) {
          analysis.abandoned_contracts++;
        }

        // Count recent deployments (last 30 days)
        const deploymentAge = Date.now() - (parseInt(tx.timeStamp) * 1000);
        if (deploymentAge < 30 * 24 * 60 * 60 * 1000) {
          analysis.recent_deployments++;
        }

      } catch (error) {
        console.error(`Error analyzing contract ${contractAddress}:`, error.message);
      }
    }

    // Detect suspicious patterns
    detectSuspiciousPatterns(analysis);

    // Calculate risk score
    calculateCreatorRiskScore(analysis);

    console.log(`Creator analysis complete: ${analysis.total_contracts_deployed} contracts, ${analysis.abandoned_contracts} abandoned`);

  } catch (error) {
    console.error('Error analyzing creator history:', error.message);
    analysis.analyzed = false;
    analysis.error = error.message;
  }

  return analysis;
}

/**
 * Analyze a single deployed contract
 */
async function analyzeDeployedContract(etherscanClient, rpcClient, contractAddress, deploymentTimestamp) {
  const analysis = {
    address: contractAddress,
    deployment_date: new Date(parseInt(deploymentTimestamp) * 1000),
    age_days: Math.floor((Date.now() - parseInt(deploymentTimestamp) * 1000) / (1000 * 60 * 60 * 24)),
    abandoned: false,
    has_code: false,
    transaction_count: 0
  };

  try {
    // Check if contract still has code
    const code = await rpcClient.getCode(contractAddress);
    analysis.has_code = code !== '0x';

    // Get recent transactions
    const recentTxs = await etherscanClient.getTransactions(contractAddress, 0, 99999999, 1, 10);
    analysis.transaction_count = recentTxs.length;

    // Check if abandoned
    // A contract is considered abandoned if:
    // 1. It's older than 7 days
    // 2. Has less than 10 transactions OR no transactions in last 30 days
    if (analysis.age_days > 7) {
      if (analysis.transaction_count < 10) {
        analysis.abandoned = true;
      } else {
        // Check for recent activity
        const lastTxTime = recentTxs.length > 0 ? parseInt(recentTxs[0].timeStamp) : 0;
        const daysSinceLastTx = Math.floor((Date.now() - lastTxTime * 1000) / (1000 * 60 * 60 * 24));

        if (daysSinceLastTx > 30) {
          analysis.abandoned = true;
        }
      }
    }

  } catch (error) {
    console.error(`Error analyzing deployed contract ${contractAddress}:`, error.message);
  }

  return analysis;
}

/**
 * Detect suspicious patterns in creator behavior
 */
function detectSuspiciousPatterns(analysis) {
  // Pattern 1: Serial deployer (10+ contracts)
  if (analysis.total_contracts_deployed >= 10) {
    analysis.suspicious_pattern = true;
    analysis.pattern_type = 'serial_deployer';
    analysis.pattern_description = 'Creator has deployed 10+ contracts';
  }

  // Pattern 2: Multiple abandoned contracts
  if (analysis.abandoned_contracts >= 3) {
    analysis.suspicious_pattern = true;
    analysis.pattern_type = 'multiple_abandoned';
    analysis.pattern_description = `${analysis.abandoned_contracts} abandoned contracts detected`;
  }

  // Pattern 3: Rapid deployment (5+ contracts in 30 days)
  if (analysis.recent_deployments >= 5) {
    analysis.suspicious_pattern = true;
    analysis.pattern_type = 'rapid_deployment';
    analysis.pattern_description = `${analysis.recent_deployments} contracts deployed in last 30 days`;
  }

  // Pattern 4: High abandonment rate
  const analyzedCount = analysis.contracts.length;
  if (analyzedCount > 0) {
    const abandonmentRate = analysis.abandoned_contracts / analyzedCount;

    if (abandonmentRate > 0.5 && analyzedCount >= 5) {
      analysis.suspicious_pattern = true;
      analysis.pattern_type = 'high_abandonment_rate';
      analysis.pattern_description = `${Math.round(abandonmentRate * 100)}% of contracts abandoned`;
    }
  }
}

/**
 * Calculate risk score from creator history
 */
function calculateCreatorRiskScore(analysis) {
  let score = 0;
  const findings = [];

  // Serial deployer (10+ contracts)
  if (analysis.total_contracts_deployed >= 10) {
    score += 15;
    findings.push({
      type: 'serial_deployer',
      severity: 'high',
      source: 'Creator History',
      description: `Creator has deployed ${analysis.total_contracts_deployed} contracts - serial deployer pattern`,
      evidence: `${analysis.total_contracts_deployed} contracts deployed`,
      score: 15
    });
  } else if (analysis.total_contracts_deployed >= 5) {
    score += 8;
    findings.push({
      type: 'multiple_deployments',
      severity: 'medium',
      source: 'Creator History',
      description: `Creator has deployed ${analysis.total_contracts_deployed} contracts`,
      evidence: `${analysis.total_contracts_deployed} contracts deployed`,
      score: 8
    });
  }

  // Multiple abandoned contracts
  if (analysis.abandoned_contracts >= 5) {
    score += 25;
    findings.push({
      type: 'multiple_abandoned_contracts',
      severity: 'critical',
      source: 'Creator History',
      description: `${analysis.abandoned_contracts} abandoned contracts - potential rug pull history`,
      evidence: `${analysis.abandoned_contracts} abandoned contracts detected`,
      score: 25
    });
  } else if (analysis.abandoned_contracts >= 3) {
    score += 20;
    findings.push({
      type: 'abandoned_contracts',
      severity: 'high',
      source: 'Creator History',
      description: `${analysis.abandoned_contracts} abandoned contracts detected`,
      evidence: `${analysis.abandoned_contracts} abandoned contracts`,
      score: 20
    });
  }

  // Rapid deployment pattern
  if (analysis.recent_deployments >= 5) {
    score += 12;
    findings.push({
      type: 'rapid_deployment',
      severity: 'high',
      source: 'Creator History',
      description: `${analysis.recent_deployments} contracts deployed in last 30 days - rapid deployment pattern`,
      evidence: `${analysis.recent_deployments} recent deployments`,
      score: 12
    });
  }

  // High abandonment rate
  const analyzedCount = analysis.contracts.length;
  if (analyzedCount >= 5) {
    const abandonmentRate = analysis.abandoned_contracts / analyzedCount;

    if (abandonmentRate > 0.7) {
      score += 20;
      findings.push({
        type: 'high_abandonment_rate',
        severity: 'high',
        source: 'Creator History',
        description: `${Math.round(abandonmentRate * 100)}% abandonment rate - high risk pattern`,
        evidence: `${analysis.abandoned_contracts}/${analyzedCount} contracts abandoned`,
        score: 20
      });
    } else if (abandonmentRate > 0.5) {
      score += 10;
      findings.push({
        type: 'moderate_abandonment_rate',
        severity: 'medium',
        source: 'Creator History',
        description: `${Math.round(abandonmentRate * 100)}% abandonment rate`,
        evidence: `${analysis.abandoned_contracts}/${analyzedCount} contracts abandoned`,
        score: 10
      });
    }
  }

  // First deployment (could be new dev, neutral to positive)
  if (analysis.total_contracts_deployed === 1) {
    findings.push({
      type: 'first_deployment',
      severity: 'info',
      source: 'Creator History',
      description: 'This is the creator\'s first contract deployment',
      evidence: '1 contract deployed',
      score: 0
    });
  }

  analysis.score = score;
  analysis.findings = findings;
}

/**
 * Calculate creator history score
 */
export function calculateCreatorHistoryScore(creatorAnalysis) {
  if (!creatorAnalysis || !creatorAnalysis.analyzed) {
    return 0;
  }

  return creatorAnalysis.score || 0;
}

export default {
  analyzeCreatorHistory,
  calculateCreatorHistoryScore
};
