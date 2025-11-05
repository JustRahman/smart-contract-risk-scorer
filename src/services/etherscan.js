import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config();

/**
 * Etherscan API Client
 * Supports Ethereum, Polygon, Arbitrum, Optimism, and Base
 * Using V2 API with chainid parameter
 */

const API_ENDPOINTS = {
  ethereum: 'https://api.etherscan.io/v2/api',
  polygon: 'https://api.polygonscan.com/v2/api',
  arbitrum: 'https://api.arbiscan.io/v2/api',
  optimism: 'https://api-optimistic.etherscan.io/v2/api',
  base: 'https://api.basescan.org/v2/api'
};

const API_KEYS = {
  ethereum: process.env.ETHERSCAN_API_KEY,
  polygon: process.env.POLYGONSCAN_API_KEY,
  arbitrum: process.env.ARBISCAN_API_KEY,
  optimism: process.env.OPTIMISM_API_KEY,
  base: process.env.BASESCAN_API_KEY
};

// Chain IDs for V2 API
const CHAIN_IDS = {
  ethereum: '1',
  polygon: '137',
  arbitrum: '42161',
  optimism: '10',
  base: '8453'
};

class EtherscanClient {
  constructor(chain = 'ethereum') {
    this.chain = chain;
    this.baseUrl = API_ENDPOINTS[chain];
    this.apiKey = API_KEYS[chain];
    this.chainId = CHAIN_IDS[chain];
  }

  /**
   * Make API request to Block Explorer V2 API
   */
  async makeRequest(params) {
    const url = new URL(this.baseUrl);
    const searchParams = new URLSearchParams({
      ...params,
      chainid: this.chainId,
      apikey: this.apiKey || ''
    });
    url.search = searchParams.toString();

    try {
      const response = await fetch(url.toString());
      const data = await response.json();

      // Handle various error conditions gracefully
      if (data.status === '0') {
        const message = data.message || data.result || 'Unknown error';

        // These are acceptable "errors" that we can work with
        const acceptableErrors = [
          'No transactions found',
          'No data found',
          'Contract source code not verified'
        ];

        if (!acceptableErrors.includes(message)) {
          throw new Error(message);
        }
      }

      return data;
    } catch (error) {
      console.error(`Etherscan API error for ${this.chain}:`, error.message);
      throw error;
    }
  }

  /**
   * Get contract source code
   */
  async getSourceCode(address) {
    const data = await this.makeRequest({
      module: 'contract',
      action: 'getsourcecode',
      address
    });

    if (!data.result || data.result.length === 0) {
      return null;
    }

    const contract = data.result[0];
    return {
      sourceCode: contract.SourceCode,
      abi: contract.ABI !== 'Contract source code not verified' ? contract.ABI : null,
      contractName: contract.ContractName,
      compilerVersion: contract.CompilerVersion,
      optimizationUsed: contract.OptimizationUsed,
      runs: contract.Runs,
      constructorArguments: contract.ConstructorArguments,
      evmVersion: contract.EVMVersion,
      library: contract.Library,
      licenseType: contract.LicenseType,
      proxy: contract.Proxy,
      implementation: contract.Implementation,
      swarmSource: contract.SwarmSource
    };
  }

  /**
   * Get contract creation transaction
   */
  async getContractCreation(address) {
    const data = await this.makeRequest({
      module: 'contract',
      action: 'getcontractcreation',
      contractaddresses: address
    });

    if (!data.result || data.result.length === 0) {
      return null;
    }

    return data.result[0];
  }

  /**
   * Get normal transactions for address
   */
  async getTransactions(address, startblock = 0, endblock = 99999999, page = 1, offset = 100) {
    const data = await this.makeRequest({
      module: 'account',
      action: 'txlist',
      address,
      startblock,
      endblock,
      page,
      offset,
      sort: 'desc'
    });

    return data.result || [];
  }

  /**
   * Get internal transactions
   */
  async getInternalTransactions(address, startblock = 0, endblock = 99999999, page = 1, offset = 100) {
    try {
      const data = await this.makeRequest({
        module: 'account',
        action: 'txlistinternal',
        address,
        startblock,
        endblock,
        page,
        offset,
        sort: 'desc'
      });

      return data.result || [];
    } catch (error) {
      // Some contracts may not have internal txs
      return [];
    }
  }

  /**
   * Get ERC20 token transfer events
   */
  async getTokenTransfers(address, startblock = 0, endblock = 99999999, page = 1, offset = 100) {
    try {
      const data = await this.makeRequest({
        module: 'account',
        action: 'tokentx',
        address,
        startblock,
        endblock,
        page,
        offset,
        sort: 'desc'
      });

      return data.result || [];
    } catch (error) {
      return [];
    }
  }

  /**
   * Get token supply
   */
  async getTokenSupply(address) {
    try {
      const data = await this.makeRequest({
        module: 'stats',
        action: 'tokensupply',
        contractaddress: address
      });

      return data.result || '0';
    } catch (error) {
      return '0';
    }
  }

  /**
   * Get account balance
   */
  async getBalance(address) {
    const data = await this.makeRequest({
      module: 'account',
      action: 'balance',
      address,
      tag: 'latest'
    });

    return data.result || '0';
  }

  /**
   * Get comprehensive contract info
   */
  async getContractInfo(address) {
    try {
      const [sourceData, creationData, transactions] = await Promise.all([
        this.getSourceCode(address),
        this.getContractCreation(address),
        this.getTransactions(address, 0, 99999999, 1, 1)
      ]);

      // Calculate contract age
      let ageInDays = 0;
      let creationDate = null;

      if (creationData) {
        const creationTx = await this.getTransactionByHash(creationData.txHash);
        if (creationTx && creationTx.blockNumber) {
          const block = await this.getBlockByNumber(creationTx.blockNumber);
          if (block && block.timestamp) {
            const creationTimestamp = parseInt(block.timestamp, 16);
            creationDate = new Date(creationTimestamp * 1000);
            const now = Date.now();
            ageInDays = Math.floor((now - creationTimestamp * 1000) / (1000 * 60 * 60 * 24));
          }
        }
      }

      return {
        address,
        chain: this.chain,
        sourceCode: sourceData?.sourceCode || null,
        abi: sourceData?.abi || null,
        contractName: sourceData?.contractName || 'Unknown',
        verified: sourceData && sourceData.sourceCode && sourceData.sourceCode.length > 0,
        isProxy: sourceData?.proxy === '1',
        implementation: sourceData?.implementation || null,
        creator: creationData?.contractCreator || null,
        creationTxHash: creationData?.txHash || null,
        creationDate,
        ageInDays,
        transactionCount: transactions.length > 0 ? parseInt(transactions[0].nonce) + 1 : 0
      };
    } catch (error) {
      console.error(`Error fetching contract info for ${address}:`, error.message);
      throw error;
    }
  }

  /**
   * Get transaction by hash
   */
  async getTransactionByHash(txhash) {
    const data = await this.makeRequest({
      module: 'proxy',
      action: 'eth_getTransactionByHash',
      txhash
    });

    return data.result;
  }

  /**
   * Get block by number
   */
  async getBlockByNumber(blockNumber) {
    const data = await this.makeRequest({
      module: 'proxy',
      action: 'eth_getBlockByNumber',
      tag: typeof blockNumber === 'number' ? '0x' + blockNumber.toString(16) : blockNumber,
      boolean: 'false'
    });

    return data.result;
  }
}

/**
 * Create Etherscan client for specific chain
 */
export function createEtherscanClient(chain) {
  return new EtherscanClient(chain);
}

export default EtherscanClient;
