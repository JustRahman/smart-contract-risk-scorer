/**
 * Ownership Analyzer
 * Checks for centralization risks and ownership patterns
 */

import { allowsCentralizedOwnership, isKnownToken } from '../utils/whitelist.js';

/**
 * Analyze ownership centralization
 */
export async function analyzeOwnership(rpcClient, etherscanClient, contractAddress) {
  const checks = {
    hasOwner: false,
    ownerAddress: null,
    isRenounced: false,
    isMultiSig: false,
    isTimelock: false,
    isCentralized: true,
    score: 0,
    findings: []
  };

  try {
    // Get current owner
    const owner = await rpcClient.getOwner(contractAddress);

    if (!owner) {
      checks.findings.push({
        type: 'no_owner_function',
        severity: 'info',
        description: 'Contract does not have an owner() function',
        score: 0
      });
      checks.isCentralized = false;
      return checks;
    }

    checks.hasOwner = true;
    checks.ownerAddress = owner;

    // Check if ownership is renounced (zero address)
    const zeroAddress = '0x0000000000000000000000000000000000000000';
    if (owner.toLowerCase() === zeroAddress) {
      checks.isRenounced = true;
      checks.isCentralized = false;
      checks.score -= 10;
      checks.findings.push({
        type: 'ownership_renounced',
        severity: 'safe',
        description: 'Ownership has been renounced - no admin control',
        evidence: `Owner: ${owner}`,
        score: -10
      });
      return checks;
    }

    // Check if owner is a contract
    const isContract = await rpcClient.isContract(owner);

    if (isContract) {
      // Check if it's a multi-sig
      const isMultiSig = await rpcClient.isMultiSig(owner);
      if (isMultiSig) {
        checks.isMultiSig = true;
        checks.isCentralized = false;
        checks.score -= 5;
        checks.findings.push({
          type: 'multisig_owner',
          severity: 'safe',
          description: 'Owner is a multi-sig wallet - reduced centralization',
          evidence: `Owner: ${owner}`,
          score: -5
        });
      }

      // Check if it's a timelock
      const isTimelock = await rpcClient.isTimelock(owner);
      if (isTimelock) {
        checks.isTimelock = true;
        checks.isCentralized = false;
        checks.score -= 5;
        checks.findings.push({
          type: 'timelock_owner',
          severity: 'safe',
          description: 'Owner is a timelock contract - changes have delay',
          evidence: `Owner: ${owner}`,
          score: -5
        });
      }

      // If it's a contract but not multisig or timelock
      if (!isMultiSig && !isTimelock) {
        checks.findings.push({
          type: 'contract_owner',
          severity: 'info',
          description: 'Owner is a contract (not multi-sig or timelock)',
          evidence: `Owner: ${owner}`,
          score: 0
        });
      }
    } else {
      // Owner is an EOA (externally owned account) - centralized
      // Check if this is a known token that allows centralized ownership
      const knownToken = isKnownToken(contractAddress);
      const allowsCentralized = allowsCentralizedOwnership(contractAddress);

      if (allowsCentralized && knownToken) {
        // Known legitimate token with expected centralization
        checks.findings.push({
          type: 'centralized_ownership_expected',
          severity: 'low',
          description: `Centralized ownership (${knownToken.symbol} by ${knownToken.issuer}) - expected for this token type`,
          evidence: `Owner: ${owner}`,
          score: 2
        });
        checks.score += 2;
      } else {
        // Unknown token with centralized control
        checks.score += 10;
        checks.findings.push({
          type: 'centralized_ownership',
          severity: 'high',
          description: 'Single address controls contract - high centralization risk',
          evidence: `Owner: ${owner}`,
          score: 10
        });
      }
    }

    // Check ownership transfer history
    const ownershipHistory = await analyzeOwnershipHistory(etherscanClient, contractAddress);
    if (ownershipHistory.transferCount > 0) {
      checks.findings.push({
        type: 'ownership_transferred',
        severity: 'medium',
        description: `Ownership has been transferred ${ownershipHistory.transferCount} time(s)`,
        evidence: ownershipHistory.transfers.slice(0, 3).join(', '),
        score: 3
      });
      checks.score += 3;
    }

  } catch (error) {
    console.error('Error analyzing ownership:', error.message);
    checks.findings.push({
      type: 'analysis_error',
      severity: 'info',
      description: `Could not analyze ownership: ${error.message}`,
      score: 0
    });
  }

  return checks;
}

/**
 * Analyze ownership transfer history
 */
async function analyzeOwnershipHistory(etherscanClient, contractAddress) {
  try {
    // Get contract events - look for OwnershipTransferred events
    const transactions = await etherscanClient.getTransactions(contractAddress, 0, 99999999, 1, 1000);

    const ownershipTransfers = [];

    // Look for transactions that might be ownership transfers
    // OwnershipTransferred event signature: 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0
    const ownershipEventSig = '0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0';

    for (const tx of transactions) {
      // Check if this is an ownership transfer by looking at the input data or method name
      if (tx.functionName && tx.functionName.toLowerCase().includes('transferownership')) {
        ownershipTransfers.push(tx.hash);
      }
    }

    return {
      transferCount: ownershipTransfers.length,
      transfers: ownershipTransfers
    };
  } catch (error) {
    console.error('Error analyzing ownership history:', error.message);
    return {
      transferCount: 0,
      transfers: []
    };
  }
}

/**
 * Calculate ownership centralization score
 * Returns a score from 0-20:
 * - 0: Fully decentralized (renounced, multi-sig, timelock)
 * - 10: Moderately centralized (contract owner, some transfers)
 * - 20: Highly centralized (EOA owner, multiple transfers)
 */
export function calculateOwnershipScore(ownershipAnalysis) {
  return ownershipAnalysis.score;
}

export default {
  analyzeOwnership,
  calculateOwnershipScore
};
