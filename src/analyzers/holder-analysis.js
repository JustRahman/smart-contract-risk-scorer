import { ethers } from 'ethers';

/**
 * Holder Concentration Analyzer
 * Analyzes token holder distribution to detect whale manipulation risk
 * High concentration = Higher risk of price manipulation
 */

const ERC20_ABI = [
  'function balanceOf(address) view returns (uint256)',
  'function totalSupply() view returns (uint256)',
  'event Transfer(address indexed from, address indexed to, uint256 value)'
];

/**
 * Analyze holder concentration by checking top holders
 * Uses recent Transfer events to identify active holders
 */
export async function analyzeHolderConcentration(rpcClient, etherscanClient, contractAddress) {
  try {
    console.log('Analyzing holder concentration...');

    const contract = rpcClient.getContract(contractAddress, ERC20_ABI);

    // Get total supply
    let totalSupply;
    try {
      totalSupply = await contract.totalSupply();
    } catch (error) {
      console.log('Cannot get total supply, skipping holder analysis');
      return {
        analyzed: false,
        score: 0,
        findings: [],
        topHolders: []
      };
    }

    // Get recent transfer events to find holders (last 5000 blocks)
    let holders = new Map();

    try {
      // Get token transfers from Etherscan
      const transfers = await etherscanClient.getTokenTransfers(contractAddress, 0, 99999999, 1, 100);

      if (transfers && transfers.length > 0) {
        // Count unique holders from transfers
        transfers.forEach(tx => {
          if (tx.to && tx.to !== '0x0000000000000000000000000000000000000000') {
            holders.set(tx.to.toLowerCase(), true);
          }
        });
      }
    } catch (error) {
      console.log('Cannot fetch transfer events:', error.message);
    }

    const holderCount = holders.size;
    const findings = [];
    let score = 0;

    // Analyze holder distribution
    if (holderCount === 0) {
      findings.push('Unable to determine holder distribution');
      return {
        analyzed: false,
        score: 0,
        findings,
        holderCount: 0
      };
    }

    // Very few holders = HIGH RISK
    if (holderCount < 10) {
      score += 20;
      findings.push(`Very few holders detected (${holderCount}) - High concentration risk`);
    } else if (holderCount < 50) {
      score += 10;
      findings.push(`Limited holder base (${holderCount}) - Medium concentration risk`);
    } else if (holderCount < 100) {
      score += 5;
      findings.push(`Small holder base (${holderCount}) - Low concentration risk`);
    } else {
      findings.push(`Good holder distribution (${holderCount}+ holders)`);
    }

    return {
      analyzed: true,
      holderCount,
      score,
      findings
    };

  } catch (error) {
    console.error('Error in holder concentration analysis:', error.message);
    return {
      analyzed: false,
      score: 0,
      findings: ['Could not analyze holder concentration'],
      holderCount: 0
    };
  }
}

/**
 * Analyze if contract has large single-address concentration
 * by checking creator's balance
 */
export async function analyzeCreatorHolding(rpcClient, contractAddress, creatorAddress) {
  if (!creatorAddress) {
    return {
      analyzed: false,
      score: 0,
      findings: []
    };
  }

  try {
    const contract = rpcClient.getContract(contractAddress, ERC20_ABI);

    const [creatorBalance, totalSupply] = await Promise.all([
      contract.balanceOf(creatorAddress),
      contract.totalSupply()
    ]);

    if (totalSupply.toString() === '0') {
      return {
        analyzed: false,
        score: 0,
        findings: []
      };
    }

    const creatorPercentage = (Number(creatorBalance) / Number(totalSupply)) * 100;
    const findings = [];
    let score = 0;

    if (creatorPercentage > 50) {
      score += 25;
      findings.push(`Creator holds ${creatorPercentage.toFixed(1)}% of supply - CRITICAL concentration risk`);
    } else if (creatorPercentage > 20) {
      score += 15;
      findings.push(`Creator holds ${creatorPercentage.toFixed(1)}% of supply - High concentration risk`);
    } else if (creatorPercentage > 10) {
      score += 5;
      findings.push(`Creator holds ${creatorPercentage.toFixed(1)}% of supply - Moderate concentration`);
    } else if (creatorPercentage > 0.1) {
      findings.push(`Creator holds ${creatorPercentage.toFixed(1)}% of supply - Low concentration`);
    } else {
      findings.push('Creator has distributed tokens - Good sign');
    }

    return {
      analyzed: true,
      creatorPercentage: creatorPercentage.toFixed(2),
      score,
      findings
    };

  } catch (error) {
    console.log('Cannot analyze creator holding:', error.message);
    return {
      analyzed: false,
      score: 0,
      findings: []
    };
  }
}
