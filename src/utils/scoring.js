/**
 * Risk Scoring Utility
 * Calculates final risk score from all analysis results
 */

import { isKnownSafeToken, isStablecoin } from './whitelist.js';

/**
 * Detect obvious scam indicators in token name/symbol
 */
function detectScamKeywords(name, symbol) {
  const scamKeywords = [
    'scam', 'beware', 'fake', 'phishing', 'warning', 'honeypot',
    'fraud', 'ponzi', 'rugpull', 'rug pull', 'exit scam', 'dont buy',
    "don't buy", 'stay away', 'avoid', 'stolen', 'hacked'
  ];

  const text = `${name || ''} ${symbol || ''}`.toLowerCase();

  for (const keyword of scamKeywords) {
    if (text.includes(keyword)) {
      return {
        isScam: true,
        keyword: keyword,
        evidence: `Token name/symbol contains "${keyword}"`
      };
    }
  }

  return { isScam: false };
}

/**
 * Detect suspicious patterns
 */
function detectSuspiciousPatterns(contractInfo, behaviorAnalysis) {
  const suspiciousPatterns = [];

  // Skip checks for known safe tokens
  if (contractInfo?.address && isKnownSafeToken(contractInfo.address)) {
    return suspiciousPatterns; // No suspicious patterns for whitelisted tokens
  }

  // Old contract with very low transaction count
  // Note: Some legitimate tokens were migrated to other chains (e.g., BNB to BSC)
  // so we need to be careful with this check
  if (contractInfo?.ageInDays > 365 && contractInfo?.transactionCount < 5000) {
    const avgTxPerDay = contractInfo.transactionCount / contractInfo.ageInDays;

    // Only flag if BOTH:
    // 1. Very low activity (< 1 tx/day)
    // 2. Not verified OR very young contract
    if (avgTxPerDay < 1 && (!contractInfo?.verified || contractInfo.ageInDays < 730)) {
      suspiciousPatterns.push({
        type: 'abandoned_or_suspicious',
        description: `Old contract (${contractInfo.ageInDays} days) with suspiciously low activity (${contractInfo.transactionCount} tx, ${avgTxPerDay.toFixed(1)} tx/day)`,
        score: 15
      });
    }
  }

  // Unverified contract older than 30 days
  if (!contractInfo?.verified && contractInfo?.ageInDays > 30) {
    suspiciousPatterns.push({
      type: 'unverified_old_contract',
      description: `Contract is ${contractInfo.ageInDays} days old but source code is not verified`,
      score: 20
    });
  }

  return suspiciousPatterns;
}

/**
 * Detect when external APIs can't find the token
 */
function detectAPINotFound(tokenSnifferResult, goplusResult, contractInfo) {
  const findings = [];

  // Check if contract appears to not exist or have no activity
  const hasNoCreationData = !contractInfo?.creator && !contractInfo?.creationTxHash;
  const hasNoActivity = contractInfo?.transactionCount === 0;
  const isUnverified = !contractInfo?.verified;

  // Contract doesn't exist or has no blockchain presence
  if (hasNoCreationData || hasNoActivity) {
    findings.push({
      type: 'contract_not_found',
      description: 'Contract does not exist on blockchain or has no activity - possible invalid address',
      score: 40
    });
    return findings; // Early return - this is a critical finding
  }

  // If token is old but not in any database, that's suspicious
  const isOld = contractInfo?.ageInDays > 30;

  if (tokenSnifferResult && !tokenSnifferResult.checked && isOld) {
    // Token Sniffer couldn't check - might be API error, not a red flag
  }

  if (goplusResult && !goplusResult.checked && isOld) {
    findings.push({
      type: 'not_in_security_databases',
      description: 'Token not found in GoPlus security database despite being 30+ days old',
      score: 10
    });
  }

  // If GoPlus checked but found zero data for an old token
  if (goplusResult?.checked && isOld) {
    const hasNoData = (
      goplusResult.is_honeypot === undefined &&
      goplusResult.buy_tax === undefined &&
      goplusResult.sell_tax === undefined
    );

    if (hasNoData) {
      findings.push({
        type: 'no_trading_data',
        description: 'No trading data found in security databases - possible inactive or abandoned token',
        score: 10
      });
    }
  }

  return findings;
}

/**
 * Calculate overall risk score
 *
 * NEW SCORING FORMULA (with external checks):
 * Base score = 50
 * + Internal checks (code, ownership, liquidity, behavior) × 0.4
 * + External checks (Token Sniffer, GoPlus, Creator History) × 0.6
 *
 * This weights professional external APIs more heavily than internal analysis.
 * Final score clamped to 0-100
 *
 * KNOWN SAFE TOKENS: Capped at 15 risk max
 * OBVIOUS SCAMS: Set to 95 CRITICAL
 */
export function calculateRiskScore(analyses) {
  const {
    codeAnalysis,
    ownershipAnalysis,
    liquidityAnalysis,
    behaviorAnalysis,
    contractInfo,
    // External checks
    tokenSnifferRisk,
    tokenSnifferResult,
    goplusRisk,
    goplusResult,
    creatorHistoryAnalysis,
    holderAnalysis,
    creatorHoldingAnalysis
  } = analyses;

  // ========== PRIORITY 0: OBVIOUS SCAM DETECTION ==========
  // Check for explicit scam indicators in name/symbol FIRST
  const scamDetection = detectScamKeywords(contractInfo?.name, contractInfo?.symbol);

  if (scamDetection.isScam) {
    console.log(`🚨 SCAM DETECTED: ${scamDetection.evidence}`);
    // Immediately return CRITICAL risk
    return 95;
  }

  let baseScore = 50;
  let internalAdjustments = 0;
  let externalAdjustments = 0;

  // ========== INTERNAL CHECKS ==========

  // Code analysis score
  if (codeAnalysis?.analyzed) {
    internalAdjustments += codeAnalysis.score;
  } else {
    // If contract is not verified, add risk
    if (!contractInfo?.verified) {
      internalAdjustments += 15;
    }
  }

  // Ownership score
  if (ownershipAnalysis) {
    internalAdjustments += ownershipAnalysis.score;
  }

  // Liquidity score
  if (liquidityAnalysis) {
    internalAdjustments += liquidityAnalysis.score;
  }

  // Behavioral score
  if (behaviorAnalysis) {
    internalAdjustments += behaviorAnalysis.score;
  }

  // ========== EXTERNAL CHECKS (Priority 1) ==========

  // Token Sniffer score
  if (tokenSnifferRisk && tokenSnifferRisk.score) {
    externalAdjustments += tokenSnifferRisk.score;
  }

  // GoPlus Security score
  if (goplusRisk && goplusRisk.score) {
    externalAdjustments += goplusRisk.score;
  }

  // Creator History score
  if (creatorHistoryAnalysis && creatorHistoryAnalysis.score) {
    externalAdjustments += creatorHistoryAnalysis.score;
  }

  // Holder Concentration score
  if (holderAnalysis && holderAnalysis.score) {
    externalAdjustments += holderAnalysis.score;
  }

  // Creator Holding score
  if (creatorHoldingAnalysis && creatorHoldingAnalysis.score) {
    externalAdjustments += creatorHoldingAnalysis.score;
  }

  // ========== SUSPICIOUS PATTERN DETECTION ==========

  // Detect suspicious patterns (abandoned contracts, unverified old contracts, etc.)
  const suspiciousPatterns = detectSuspiciousPatterns(contractInfo, behaviorAnalysis);
  for (const pattern of suspiciousPatterns) {
    console.log(`⚠️  Suspicious pattern detected: ${pattern.description}`);
    internalAdjustments += pattern.score;
  }

  // Detect when APIs can't find the token
  const apiNotFoundFindings = detectAPINotFound(tokenSnifferResult, goplusResult, contractInfo);
  for (const finding of apiNotFoundFindings) {
    console.log(`⚠️  API finding: ${finding.description}`);
    externalAdjustments += finding.score;
  }

  // ========== WEIGHTED CALCULATION ==========

  // Weight internal checks at 40%, external checks at 60%
  const weightedAdjustments = (internalAdjustments * 0.4) + (externalAdjustments * 0.6);

  // Calculate final score
  let finalScore = Math.max(0, Math.min(100, baseScore + weightedAdjustments));

  // ========== KNOWN SAFE TOKEN OVERRIDE ==========
  // If this is a known safe token, cap the risk score at 15
  if (contractInfo?.address && isKnownSafeToken(contractInfo.address)) {
    console.log(`Known safe token detected: ${contractInfo.address} - capping risk at 15`);
    finalScore = Math.min(finalScore, 15);
  }
  // If it's a stablecoin and verified, cap at 20
  else if (contractInfo?.verified && isStablecoin(contractInfo.symbol, contractInfo.name)) {
    console.log(`Stablecoin detected: ${contractInfo.symbol} - capping risk at 20`);
    finalScore = Math.min(finalScore, 20);
  }

  return Math.round(finalScore);
}

/**
 * Determine risk level from score
 */
export function getRiskLevel(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

/**
 * Calculate confidence level based on data availability
 */
export function calculateConfidence(analyses) {
  const {
    codeAnalysis,
    ownershipAnalysis,
    liquidityAnalysis,
    behaviorAnalysis,
    contractInfo,
    tokenSnifferResult,
    goplusResult,
    creatorHistoryAnalysis
  } = analyses;

  let confidence = 0.5; // Base confidence

  // Increase confidence if we have source code
  if (contractInfo?.verified && codeAnalysis?.analyzed) {
    confidence += 0.15;
  }

  // Increase confidence if we have ownership info
  if (ownershipAnalysis?.hasOwner !== undefined) {
    confidence += 0.05;
  }

  // Increase confidence if we have liquidity info
  if (liquidityAnalysis?.hasLiquidity !== undefined) {
    confidence += 0.05;
  }

  // Increase confidence if contract has some history
  if (contractInfo?.ageInDays && contractInfo.ageInDays > 7) {
    confidence += 0.05;
  }

  // ========== EXTERNAL CHECKS INCREASE CONFIDENCE ==========

  // Token Sniffer checked
  if (tokenSnifferResult?.checked) {
    confidence += 0.1;
  }

  // GoPlus checked
  if (goplusResult?.checked) {
    confidence += 0.15; // GoPlus is very reliable
  }

  // Creator history analyzed
  if (creatorHistoryAnalysis?.analyzed) {
    confidence += 0.1;
  }

  return Math.min(1.0, confidence);
}

/**
 * Compile all vulnerabilities from different analyses
 */
export function compileVulnerabilities(analyses) {
  const vulnerabilities = [];

  // ========== PRIORITY 0: CHECK FOR OBVIOUS SCAM ==========
  const scamDetection = detectScamKeywords(analyses.contractInfo?.name, analyses.contractInfo?.symbol);
  if (scamDetection.isScam) {
    vulnerabilities.push({
      type: 'explicit_scam_warning',
      severity: 'critical',
      description: `Contract explicitly marked as scam: "${scamDetection.keyword}" found in name/symbol`,
      evidence: scamDetection.evidence,
      source: 'Name/Symbol Analysis'
    });
  }

  // Add suspicious pattern findings
  const suspiciousPatterns = detectSuspiciousPatterns(analyses.contractInfo, analyses.behaviorAnalysis);
  for (const pattern of suspiciousPatterns) {
    vulnerabilities.push({
      type: pattern.type,
      severity: pattern.score >= 20 ? 'critical' : 'high',
      description: pattern.description,
      evidence: '',
      source: 'Pattern Analysis'
    });
  }

  // Add API not found findings
  const apiNotFoundFindings = detectAPINotFound(
    analyses.tokenSnifferResult,
    analyses.goplusResult,
    analyses.contractInfo
  );
  for (const finding of apiNotFoundFindings) {
    vulnerabilities.push({
      type: finding.type,
      severity: 'medium',
      description: finding.description,
      evidence: '',
      source: 'External API Analysis'
    });
  }

  // Add code analysis vulnerabilities
  if (analyses.codeAnalysis?.vulnerabilities) {
    vulnerabilities.push(...analyses.codeAnalysis.vulnerabilities);
  }

  // Add ownership findings as vulnerabilities
  if (analyses.ownershipAnalysis?.findings) {
    const ownershipVulns = analyses.ownershipAnalysis.findings
      .filter(f => f.severity === 'high' || f.severity === 'critical')
      .map(f => ({
        type: f.type,
        severity: f.severity,
        description: f.description,
        evidence: f.evidence || ''
      }));
    vulnerabilities.push(...ownershipVulns);
  }

  // Add liquidity findings as vulnerabilities
  if (analyses.liquidityAnalysis?.findings) {
    const liquidityVulns = analyses.liquidityAnalysis.findings
      .filter(f => f.severity === 'high' || f.severity === 'critical')
      .map(f => ({
        type: f.type,
        severity: f.severity,
        description: f.description,
        evidence: f.evidence || ''
      }));
    vulnerabilities.push(...liquidityVulns);
  }

  // Add behavioral findings as vulnerabilities
  if (analyses.behaviorAnalysis?.findings) {
    const behaviorVulns = analyses.behaviorAnalysis.findings
      .filter(f => f.severity === 'high' || f.severity === 'critical')
      .map(f => ({
        type: f.type,
        severity: f.severity,
        description: f.description,
        evidence: f.evidence || '',
        source: f.source || 'Internal'
      }));
    vulnerabilities.push(...behaviorVulns);
  }

  // ========== EXTERNAL CHECKS (Priority 1) ==========

  // Add Token Sniffer findings
  if (analyses.tokenSnifferRisk?.findings) {
    const snifferVulns = analyses.tokenSnifferRisk.findings
      .filter(f => f.severity === 'high' || f.severity === 'critical')
      .map(f => ({
        type: f.type,
        severity: f.severity,
        description: f.description,
        evidence: f.evidence || '',
        source: f.source || 'Token Sniffer'
      }));
    vulnerabilities.push(...snifferVulns);
  }

  // Add GoPlus findings
  if (analyses.goplusRisk?.findings) {
    const goplusVulns = analyses.goplusRisk.findings
      .filter(f => f.severity === 'high' || f.severity === 'critical')
      .map(f => ({
        type: f.type,
        severity: f.severity,
        description: f.description,
        evidence: f.evidence || '',
        source: f.source || 'GoPlus Security'
      }));
    vulnerabilities.push(...goplusVulns);
  }

  // Add Creator History findings
  if (analyses.creatorHistoryAnalysis?.findings) {
    const creatorVulns = analyses.creatorHistoryAnalysis.findings
      .filter(f => f.severity === 'high' || f.severity === 'critical')
      .map(f => ({
        type: f.type,
        severity: f.severity,
        description: f.description,
        evidence: f.evidence || '',
        source: f.source || 'Creator History'
      }));
    vulnerabilities.push(...creatorVulns);
  }

  // Add Holder Concentration findings
  if (analyses.holderAnalysis?.findings) {
    analyses.holderAnalysis.findings.forEach(finding => {
      if (analyses.holderAnalysis.score > 15) {
        vulnerabilities.push({
          type: 'holder_concentration',
          severity: 'high',
          description: finding,
          evidence: `Holder count: ${analyses.holderAnalysis.holderCount}`,
          source: 'Holder Analysis'
        });
      } else if (analyses.holderAnalysis.score > 5) {
        vulnerabilities.push({
          type: 'holder_concentration',
          severity: 'medium',
          description: finding,
          evidence: `Holder count: ${analyses.holderAnalysis.holderCount}`,
          source: 'Holder Analysis'
        });
      }
    });
  }

  // Add Creator Holding findings
  if (analyses.creatorHoldingAnalysis?.findings) {
    analyses.creatorHoldingAnalysis.findings.forEach(finding => {
      if (analyses.creatorHoldingAnalysis.score > 20) {
        vulnerabilities.push({
          type: 'creator_holding',
          severity: 'critical',
          description: finding,
          evidence: `Creator holds ${analyses.creatorHoldingAnalysis.creatorPercentage}% of supply`,
          source: 'Holder Analysis'
        });
      } else if (analyses.creatorHoldingAnalysis.score > 10) {
        vulnerabilities.push({
          type: 'creator_holding',
          severity: 'high',
          description: finding,
          evidence: `Creator holds ${analyses.creatorHoldingAnalysis.creatorPercentage}% of supply`,
          source: 'Holder Analysis'
        });
      }
    });
  }

  return vulnerabilities;
}

/**
 * Compile security checks results
 */
export function compileSecurityChecks(analyses) {
  const checks = {
    ownership_renounced: false,
    liquidity_locked: false,
    source_verified: false,
    proxy_contract: false,
    pausable: false,
    blacklist_function: false,
    mint_function: false,
    high_tax: false,
    max_tx_limit: false,
    self_destruct: false,
    honeypot_risk: false,
    centralized_ownership: false
  };

  // Source verification
  if (analyses.contractInfo?.verified) {
    checks.source_verified = true;
  }

  // Proxy contract
  if (analyses.contractInfo?.isProxy) {
    checks.proxy_contract = true;
  }

  // Ownership checks
  if (analyses.ownershipAnalysis) {
    checks.ownership_renounced = analyses.ownershipAnalysis.isRenounced || false;
    checks.centralized_ownership = analyses.ownershipAnalysis.isCentralized || false;
  }

  // Liquidity checks
  if (analyses.liquidityAnalysis) {
    checks.liquidity_locked = analyses.liquidityAnalysis.lpLocked || analyses.liquidityAnalysis.lpBurned || false;
  }

  // Code pattern checks
  if (analyses.codeAnalysis?.vulnerabilities) {
    const vulns = analyses.codeAnalysis.vulnerabilities;

    checks.pausable = vulns.some(v => v.type === 'pausable');
    checks.blacklist_function = vulns.some(v => v.type === 'honeypot');
    checks.mint_function = vulns.some(v => v.type === 'hiddenMint');
    checks.high_tax = vulns.some(v => v.type === 'highTax');
    checks.max_tx_limit = vulns.some(v => v.type === 'maxTransaction');
    checks.self_destruct = vulns.some(v => v.type === 'selfDestruct');
    checks.honeypot_risk = vulns.some(v => v.type === 'honeypot');
  }

  return checks;
}

export default {
  calculateRiskScore,
  getRiskLevel,
  calculateConfidence,
  compileVulnerabilities,
  compileSecurityChecks
};
