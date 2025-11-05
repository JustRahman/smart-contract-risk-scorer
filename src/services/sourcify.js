import fetch from 'node-fetch';

/**
 * Sourcify API Client
 * Decentralized source code verification alternative to Etherscan
 * FREE and open source
 */

const SOURCIFY_BASE_URL = 'https://sourcify.dev/server';

const CHAIN_ID_MAPPING = {
  ethereum: 1,
  polygon: 137,
  arbitrum: 42161,
  optimism: 10,
  base: 8453
};

class SourcifyClient {
  constructor() {
    this.baseUrl = SOURCIFY_BASE_URL;
  }

  /**
   * Check if contract is verified on Sourcify
   */
  async checkVerification(address, chain) {
    try {
      const chainId = CHAIN_ID_MAPPING[chain] || 1;
      const url = `${this.baseUrl}/check-by-addresses?addresses=${address}&chainIds=${chainId}`;

      console.log(`Checking Sourcify: ${url}`);

      const response = await fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        timeout: 5000
      });

      if (!response.ok) {
        console.log('Sourcify check failed:', response.status);
        return null;
      }

      const data = await response.json();

      // Sourcify returns array of results
      if (data && data.length > 0 && data[0].status) {
        return {
          verified: data[0].status === 'perfect' || data[0].status === 'partial',
          status: data[0].status,
          chainId: data[0].chainId
        };
      }

      return null;
    } catch (error) {
      console.log('Sourcify check error:', error.message);
      return null;
    }
  }

  /**
   * Get contract source code from Sourcify
   */
  async getSourceCode(address, chain) {
    try {
      const chainId = CHAIN_ID_MAPPING[chain] || 1;
      const url = `${this.baseUrl}/files/${chainId}/${address}`;

      const response = await fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        timeout: 10000
      });

      if (!response.ok) {
        return null;
      }

      const data = await response.json();

      // Extract main contract source
      let sourceCode = '';
      let contractName = 'Unknown';
      let abi = null;

      if (data && data.files) {
        // Find the main contract file
        const solFiles = Object.keys(data.files).filter(f => f.endsWith('.sol'));
        if (solFiles.length > 0) {
          sourceCode = data.files[solFiles[0]];
          contractName = solFiles[0].replace('.sol', '').split('/').pop();
        }

        // Try to get ABI
        const abiFile = Object.keys(data.files).find(f => f.endsWith('.json'));
        if (abiFile) {
          try {
            const abiData = JSON.parse(data.files[abiFile]);
            abi = abiData.abi || null;
          } catch (e) {
            // ABI parsing failed
          }
        }
      }

      return {
        sourceCode,
        contractName,
        abi,
        verified: true
      };
    } catch (error) {
      console.log('Sourcify source fetch error:', error.message);
      return null;
    }
  }

  /**
   * Get contract metadata from Sourcify
   */
  async getContractMetadata(address, chain) {
    try {
      const chainId = CHAIN_ID_MAPPING[chain] || 1;
      const url = `${this.baseUrl}/files/tree/any/${chainId}/${address}`;

      const response = await fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        timeout: 5000
      });

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.log('Sourcify metadata error:', error.message);
      return null;
    }
  }
}

/**
 * Create Sourcify client
 */
export function createSourcifyClient() {
  return new SourcifyClient();
}

export default SourcifyClient;
