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
║         Version: 1.0.0 with agent-kit X402 Integration       ║
║         Mode: ${paymentsEnabled ? 'PAYMENTS ENABLED         ' : 'FREE TESTING (No Payment)'}║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
`);

console.log('Starting server...\n');

// Start the agent-kit server (agent-kit apps are Hono apps under the hood)
serve(
  {
    fetch: app.fetch,
    port: PORT,
    hostname: '0.0.0.0'
  },
  (info) => {
    console.log(`✅ Server running on http://localhost:${info.port}`);
    console.log(`\nEntrypoints:`);
    console.log(`  - analyze_contract           (Analyze single contract)`);
    console.log(`  - analyze_batch              (Analyze multiple contracts)`);
    console.log(`  - health                     (Health check)`);
    console.log(`\nSupported Chains:`);
    console.log(`  - Ethereum, Polygon, Arbitrum, Optimism, Base`);
    console.log(`\nAgent UI:`);
    console.log(`  - Open http://localhost:${info.port} in your browser for the agent interface`);
    console.log(`\nManifest:`);
    console.log(`  - http://localhost:${info.port}/manifest.json`);
    if (paymentsEnabled) {
      console.log(`\n💳 Payments: ENABLED - $${process.env.PAYMENT_AMOUNT || '0.01'} USDC on ${process.env.PAYMENT_NETWORK || 'base'}`);
      console.log(`💵 Payment wallet: ${process.env.PAY_TO_WALLET}`);
    } else {
      console.log(`\n✅ No payment required - FREE for testing`);
    }
    console.log('');
  }
);
