/**
 * Recommendations Generator
 * Provides actionable recommendations based on risk analysis
 */

/**
 * Generate recommendations based on risk score and analysis
 */
export function generateRecommendations(riskScore, riskLevel, analyses, vulnerabilities) {
  const recommendations = [];

  // Critical risk (80-100)
  if (riskLevel === 'critical') {
    recommendations.push('CRITICAL: DO NOT INTERACT - Multiple critical red flags detected');

    // Add specific critical issues
    const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
    for (const vuln of criticalVulns) {
      recommendations.push(`CRITICAL: ${vuln.description}`);
    }

    recommendations.push('RECOMMENDATION: Avoid this contract entirely until issues are resolved');
    return recommendations;
  }

  // High risk (60-79)
  if (riskLevel === 'high') {
    recommendations.push('WARNING: HIGH RISK - Proceed with extreme caution');

    const highVulns = vulnerabilities.filter(v => v.severity === 'high' || v.severity === 'critical');
    for (const vuln of highVulns.slice(0, 5)) {
      recommendations.push(`WARNING: ${vuln.description}`);
    }

    recommendations.push('RECOMMENDATION: Only interact with small amounts and be prepared to exit');
    return recommendations;
  }

  // Medium risk (40-59)
  if (riskLevel === 'medium') {
    recommendations.push('CAUTION: MEDIUM RISK - Some concerns identified');

    // Highlight main concerns
    if (!analyses.contractInfo?.verified) {
      recommendations.push('Contract source code is not verified - unable to audit');
    }

    if (analyses.ownershipAnalysis?.isCentralized) {
      recommendations.push('Single address controls contract - centralization risk');
    }

    if (!analyses.liquidityAnalysis?.lpLocked && !analyses.liquidityAnalysis?.lpBurned) {
      recommendations.push('Liquidity is not locked - potential rug pull risk');
    }

    if (analyses.contractInfo?.ageInDays && analyses.contractInfo.ageInDays < 30) {
      recommendations.push(`Contract is only ${analyses.contractInfo.ageInDays} days old - limited track record`);
    }

    recommendations.push('RECOMMENDATION: Do your own research and only invest what you can afford to lose');
    return recommendations;
  }

  // Low risk (0-39)
  recommendations.push('SAFE: Low risk detected - Contract appears legitimate');

  // Highlight safe patterns
  if (analyses.ownershipAnalysis?.isRenounced) {
    recommendations.push('Ownership has been renounced - immutable contract');
  }

  if (analyses.liquidityAnalysis?.lpBurned) {
    recommendations.push('Liquidity tokens burned - cannot be removed');
  } else if (analyses.liquidityAnalysis?.lpLocked) {
    recommendations.push('Liquidity tokens locked - reduced rug pull risk');
  }

  if (analyses.contractInfo?.verified) {
    recommendations.push('Source code is verified and can be audited');
  }

  if (analyses.contractInfo?.ageInDays && analyses.contractInfo.ageInDays > 365) {
    recommendations.push(`Contract has been active for ${analyses.contractInfo.ageInDays} days - battle-tested`);
  }

  // Still add some cautionary notes even for low risk
  if (riskScore > 20) {
    recommendations.push('RECOMMENDATION: Still perform your own research before investing large amounts');
  } else {
    recommendations.push('RECOMMENDATION: Contract appears safe, but always verify independently');
  }

  return recommendations;
}

/**
 * Generate specific action items based on what should be improved
 */
export function generateImprovements(analyses, securityChecks) {
  const improvements = [];

  // Not verified
  if (!securityChecks.source_verified) {
    improvements.push('Verify source code on block explorer');
  }

  // Centralized ownership
  if (securityChecks.centralized_ownership && !securityChecks.ownership_renounced) {
    improvements.push('Renounce ownership or transfer to multi-sig/timelock');
  }

  // Liquidity not locked
  if (!securityChecks.liquidity_locked && analyses.liquidityAnalysis?.hasLiquidity) {
    improvements.push('Lock liquidity tokens for at least 6 months');
  }

  // Pausable without timelock
  if (securityChecks.pausable && !analyses.ownershipAnalysis?.isTimelock) {
    improvements.push('Implement timelock for pause function or remove pause capability');
  }

  // Modifiable fees
  if (analyses.codeAnalysis?.vulnerabilities?.some(v => v.type === 'modifiableTax')) {
    improvements.push('Set maximum fee limits in contract or remove fee modification capability');
  }

  // New contract
  if (analyses.contractInfo?.ageInDays && analyses.contractInfo.ageInDays < 30) {
    improvements.push('Allow contract to mature and build transaction history');
  }

  return improvements;
}

/**
 * Get emoji based on risk level
 */
export function getRiskEmoji(riskLevel) {
  const emojis = {
    critical: '🚨',
    high: '⚠️',
    medium: '⚡',
    low: '✅'
  };
  return emojis[riskLevel] || '❓';
}

/**
 * Format recommendations with emojis
 */
export function formatRecommendations(recommendations, includeEmojis = false) {
  if (!includeEmojis) {
    return recommendations;
  }

  return recommendations.map(rec => {
    if (rec.includes('CRITICAL')) return `🚨 ${rec}`;
    if (rec.includes('WARNING')) return `⚠️ ${rec}`;
    if (rec.includes('CAUTION')) return `⚡ ${rec}`;
    if (rec.includes('SAFE')) return `✅ ${rec}`;
    if (rec.includes('RECOMMENDATION')) return `💡 ${rec}`;
    return rec;
  });
}

export default {
  generateRecommendations,
  generateImprovements,
  getRiskEmoji,
  formatRecommendations
};
