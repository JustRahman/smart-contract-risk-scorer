import { paymentMiddleware } from 'x402-hono';
import dotenv from 'dotenv';

dotenv.config();

/**
 * X402 Payment Middleware for Smart Contract Risk Scorer
 * Protects endpoints with micropayment requirements when ENABLE_PAYMENTS=true
 */

export function createPaymentMiddleware() {
  const paymentsEnabled = process.env.ENABLE_PAYMENTS === 'true';

  if (!paymentsEnabled) {
    // Return no-op middleware if payments are disabled
    return async (c, next) => await next();
  }

  // Payment configuration
  const payTo = process.env.PAY_TO_WALLET || '0x992920386E3D950BC260f99C81FDA12419eD4594';
  const network = process.env.PAYMENT_NETWORK || 'base';
  const price = process.env.PAYMENT_AMOUNT || '0.01';
  const facilitatorUrl = process.env.FACILITATOR_URL || 'https://facilitator.daydreams.systems';

  // USDC token address on Base network
  const usdcAddress = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

  // Convert price to smallest unit (USDC has 6 decimals)
  const priceInSmallestUnit = (parseFloat(price) * 1000000).toString();

  // Payment route configuration (network must be in each route!)
  const routes = {
    'POST /analyze': {
      price: priceInSmallestUnit,
      network,
      asset: usdcAddress,
      config: {
        description: 'Analyze a smart contract for security risks and rug pull indicators'
      }
    },
    'POST /analyze-batch': {
      price: priceInSmallestUnit,
      network,
      asset: usdcAddress,
      config: {
        description: 'Analyze multiple smart contracts at once (max 10)'
      }
    }
  };

  // Facilitator configuration
  const facilitator = {
    url: facilitatorUrl
  };

  console.log(`💳 X402 Payments ENABLED`);
  console.log(`   Price: $${price} USDC per scan`);
  console.log(`   Network: ${network}`);
  console.log(`   Wallet: ${payTo}`);
  console.log(`   Facilitator: ${facilitatorUrl}`);

  // Return x402-hono payment middleware
  // Signature: paymentMiddleware(payTo, routes, facilitator)
  return paymentMiddleware(payTo, routes, facilitator);
}
