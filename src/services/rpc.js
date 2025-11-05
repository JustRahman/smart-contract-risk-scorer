import { ethers } from 'ethers';
import dotenv from 'dotenv';

dotenv.config();

/**
 * RPC Service for blockchain queries
 * Uses ethers.js to interact with blockchain networks
 */

const RPC_URLS = {
  ethereum: process.env.ETHEREUM_RPC_URL || 'https://eth.llamarpc.com',
  polygon: process.env.POLYGON_RPC_URL || 'https://polygon-rpc.com',
  arbitrum: process.env.ARBITRUM_RPC_URL || 'https://arb1.arbitrum.io/rpc',
  optimism: process.env.OPTIMISM_RPC_URL || 'https://mainnet.optimism.io',
  base: process.env.BASE_RPC_URL || 'https://mainnet.base.org'
};

// Standard ERC20 ABI
const ERC20_ABI = [
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function totalSupply() view returns (uint256)',
  'function balanceOf(address) view returns (uint256)',
  'function owner() view returns (address)',
  'function getOwner() view returns (address)'
];

// Ownable contract ABI
const OWNABLE_ABI = [
  'function owner() view returns (address)',
  'function getOwner() view returns (address)'
];

class RPCClient {
  constructor(chain = 'ethereum') {
    this.chain = chain;
    this.provider = new ethers.JsonRpcProvider(RPC_URLS[chain]);
  }

  /**
   * Get contract instance
   */
  getContract(address, abi = ERC20_ABI) {
    return new ethers.Contract(address, abi, this.provider);
  }

  /**
   * Get ERC20 token info
   */
  async getTokenInfo(address) {
    try {
      const contract = this.getContract(address, ERC20_ABI);

      const [name, symbol, decimals, totalSupply] = await Promise.allSettled([
        contract.name(),
        contract.symbol(),
        contract.decimals(),
        contract.totalSupply()
      ]);

      return {
        name: name.status === 'fulfilled' ? name.value : 'Unknown',
        symbol: symbol.status === 'fulfilled' ? symbol.value : 'UNKNOWN',
        decimals: decimals.status === 'fulfilled' ? Number(decimals.value) : 18,
        totalSupply: totalSupply.status === 'fulfilled' ? totalSupply.value.toString() : '0'
      };
    } catch (error) {
      console.error(`Error getting token info for ${address}:`, error.message);
      return {
        name: 'Unknown',
        symbol: 'UNKNOWN',
        decimals: 18,
        totalSupply: '0'
      };
    }
  }

  /**
   * Get contract owner address
   */
  async getOwner(address) {
    try {
      const contract = this.getContract(address, OWNABLE_ABI);

      // Try both owner() and getOwner() methods
      try {
        const owner = await contract.owner();
        return owner;
      } catch {
        const owner = await contract.getOwner();
        return owner;
      }
    } catch (error) {
      console.error(`Error getting owner for ${address}:`, error.message);
      return null;
    }
  }

  /**
   * Check if ownership is renounced (owner is zero address)
   */
  async isOwnershipRenounced(address) {
    const owner = await this.getOwner(address);
    if (!owner) return false;

    const zeroAddress = '0x0000000000000000000000000000000000000000';
    return owner.toLowerCase() === zeroAddress;
  }

  /**
   * Get balance of an address
   */
  async getBalance(address) {
    try {
      const balance = await this.provider.getBalance(address);
      return balance.toString();
    } catch (error) {
      console.error(`Error getting balance for ${address}:`, error.message);
      return '0';
    }
  }

  /**
   * Get contract code
   */
  async getCode(address) {
    try {
      const code = await this.provider.getCode(address);
      return code;
    } catch (error) {
      console.error(`Error getting code for ${address}:`, error.message);
      return '0x';
    }
  }

  /**
   * Check if address is a contract
   */
  async isContract(address) {
    const code = await this.getCode(address);
    return code !== '0x';
  }

  /**
   * Get current block number
   */
  async getBlockNumber() {
    try {
      return await this.provider.getBlockNumber();
    } catch (error) {
      console.error(`Error getting block number:`, error.message);
      return 0;
    }
  }

  /**
   * Call a contract function
   */
  async callFunction(address, abi, functionName, params = []) {
    try {
      const contract = this.getContract(address, abi);
      return await contract[functionName](...params);
    } catch (error) {
      console.error(`Error calling ${functionName} on ${address}:`, error.message);
      throw error;
    }
  }

  /**
   * Check if address is a multi-sig wallet
   * Common multi-sig contracts: Gnosis Safe, Multi-sig Wallet
   */
  async isMultiSig(address) {
    try {
      const code = await this.getCode(address);

      // Check for common multi-sig patterns
      const multiSigPatterns = [
        'getOwners',
        'getThreshold',
        'confirmations',
        'required',
        'owners'
      ];

      // Convert code to lowercase for case-insensitive search
      const codeLower = code.toLowerCase();

      // Check if code contains multi-sig function signatures
      for (const pattern of multiSigPatterns) {
        const functionSig = ethers.id(pattern).slice(0, 10);
        if (codeLower.includes(functionSig.slice(2))) {
          return true;
        }
      }

      return false;
    } catch (error) {
      console.error(`Error checking if ${address} is multi-sig:`, error.message);
      return false;
    }
  }

  /**
   * Check if address is a timelock contract
   */
  async isTimelock(address) {
    try {
      const code = await this.getCode(address);

      // Check for timelock patterns
      const timelockPatterns = [
        'delay',
        'queueTransaction',
        'executeTransaction',
        'MINIMUM_DELAY',
        'GRACE_PERIOD'
      ];

      const codeLower = code.toLowerCase();

      for (const pattern of timelockPatterns) {
        const functionSig = ethers.id(pattern).slice(0, 10);
        if (codeLower.includes(functionSig.slice(2))) {
          return true;
        }
      }

      return false;
    } catch (error) {
      console.error(`Error checking if ${address} is timelock:`, error.message);
      return false;
    }
  }

  /**
   * Get Uniswap V2 pair info
   */
  async getUniswapV2PairInfo(pairAddress) {
    const pairAbi = [
      'function token0() view returns (address)',
      'function token1() view returns (address)',
      'function getReserves() view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)',
      'function totalSupply() view returns (uint256)'
    ];

    try {
      const contract = this.getContract(pairAddress, pairAbi);
      const [token0, token1, reserves, totalSupply] = await Promise.all([
        contract.token0(),
        contract.token1(),
        contract.getReserves(),
        contract.totalSupply()
      ]);

      return {
        token0,
        token1,
        reserve0: reserves.reserve0.toString(),
        reserve1: reserves.reserve1.toString(),
        totalSupply: totalSupply.toString()
      };
    } catch (error) {
      console.error(`Error getting Uniswap pair info for ${pairAddress}:`, error.message);
      return null;
    }
  }
}

/**
 * Create RPC client for specific chain
 */
export function createRPCClient(chain) {
  return new RPCClient(chain);
}

export default RPCClient;
