import { serve } from '@hono/node-server';
import { app } from './agent.js';
import dotenv from 'dotenv';

dotenv.config();

const PORT = parseInt(process.env.PORT || '3000');

/**
 * Start the Smart Contract Risk Scorer server
 */

const paymentsEnabled = process.env.ENABLE_PAYMENTS === 'true';

console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         SMART CONTRACT RISK SCORER                            ║
║         AI Agent for DeFi Security Analysis                   ║
║                                                               ║
║         Version: 1.0.0 with X402 Payment System               ║
║         Mode: ${paymentsEnabled ? 'PAYMENTS ENABLED         ' : 'FREE TESTING (No Payment)'}║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
`);

console.log('Starting server...\n');

serve(
  {
    fetch: app.fetch,
    port: PORT,
    hostname: '0.0.0.0'
  },
  (info) => {
    console.log(`✅ Server running on http://localhost:${info.port}`);
    console.log(`\nEndpoints:`);
    console.log(`  - POST /analyze              (Analyze single contract)`);
    console.log(`  - POST /analyze-batch        (Analyze multiple contracts)`);
    console.log(`  - GET  /health               (Health check)`);
    console.log(`\nSupported Chains:`);
    console.log(`  - Ethereum, Polygon, Arbitrum, Optimism, Base`);
    console.log(`\nExample Request:`);
    console.log(`  curl -X POST http://localhost:${info.port}/analyze \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    if (paymentsEnabled) {
      console.log(`    -H "X-PAYMENT: <payment-header>" \\`);
    }
    console.log(`    -d '{"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum", "scan_depth": "quick"}'`);
    if (paymentsEnabled) {
      console.log(`\n💳 Payments: ENABLED - $${process.env.PAYMENT_AMOUNT || '0.01'} USDC on ${process.env.PAYMENT_NETWORK || 'base'}`);
      console.log(`💵 Payment wallet: ${process.env.PAY_TO_WALLET}`);
    } else {
      console.log(`\n✅ No payment required - FREE for testing`);
    }
    console.log('');
  }
);
