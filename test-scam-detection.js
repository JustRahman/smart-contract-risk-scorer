import { createSigner } from 'x402-fetch';
import { wrapFetchWithPayment } from 'x402-fetch';
import fetch from 'node-fetch';

const PRIVATE_KEY = "0x92f597b036614b50eefe4d029b9756xxx";
const NETWORK = "base";
const API_URL = "http://localhost:3000"; // Change to Railway URL for production

async function testContract(name, address, chain, fetchWithPayment) {
  console.log(`\n🔍 Testing: ${name}`);
  console.log('─'.repeat(60));
  console.log(`Address: ${address}`);
  console.log(`Chain: ${chain}\n`);
  
  try {
    const response = await fetchWithPayment(`${API_URL}/entrypoints/analyze_contract/invoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        input: {
          contract_address: address,
          chain: chain,
          scan_depth: "deep"
        }
      })
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      console.log(`❌ Status: ${response.status}`);
      console.log(`Error: ${errorText.substring(0, 200)}`);
      return;
    }
    
    const data = await response.json();
    const output = data.output;
    
    console.log(`✅ Status: ${response.status}`);
    console.log(`\n📊 RISK ASSESSMENT:`);
    console.log(`   Risk Score: ${output?.risk_score}/100`);
    console.log(`   Risk Level: ${output?.risk_level?.toUpperCase()}`);
    console.log(`   Confidence: ${(output?.confidence * 100).toFixed(1)}%`);
    
    // External checks
    console.log(`\n🔍 EXTERNAL CHECKS:`);
    const external = output?.external_checks;
    
    if (external?.token_sniffer?.checked) {
      const ts = external.token_sniffer;
      console.log(`   Token Sniffer:`);
      console.log(`     - Scam Score: ${ts.scam_score || 0}/100`);
      console.log(`     - Flagged: ${ts.flagged ? '🚨 YES' : '✅ No'}`);
    }
    
    if (external?.goplus) {
      const gp = external.goplus;
      console.log(`   GoPlus Security:`);
      console.log(`     - Honeypot: ${gp.is_honeypot === "1" ? '🚨 YES' : '✅ No'}`);
      console.log(`     - Cannot Sell: ${gp.cannot_sell_all === "1" ? '🚨 YES' : '✅ No'}`);
      console.log(`     - Hidden Owner: ${gp.hidden_owner === "1" ? '🚨 YES' : '✅ No'}`);
      console.log(`     - Selfdestruct: ${gp.selfdestruct === "1" ? '🚨 YES' : '✅ No'}`);
      console.log(`     - Buy Tax: ${gp.buy_tax || '0'}%`);
      console.log(`     - Sell Tax: ${gp.sell_tax || '0'}%`);
    }
    
    if (external?.creator_history?.analyzed) {
      const ch = external.creator_history;
      console.log(`   Creator History:`);
      console.log(`     - Total Contracts: ${ch.total_contracts || 0}`);
      console.log(`     - Abandoned: ${ch.abandoned_contracts || 0}`);
      console.log(`     - Confirmed Rugs: ${ch.confirmed_rugs || 0}`);
    }
    
    // Vulnerabilities
    const vulns = output?.vulnerabilities || [];
    if (vulns.length > 0) {
      console.log(`\n⚠️  VULNERABILITIES FOUND: ${vulns.length}`);
      
      const critical = vulns.filter(v => v.severity === 'critical');
      const high = vulns.filter(v => v.severity === 'high');
      
      if (critical.length > 0) {
        console.log(`   🚨 Critical (${critical.length}):`);
        critical.slice(0, 3).forEach(v => {
          console.log(`      - ${v.type}: ${v.description}`);
        });
      }
      
      if (high.length > 0) {
        console.log(`   ⚠️  High (${high.length}):`);
        high.slice(0, 3).forEach(v => {
          console.log(`      - ${v.type}: ${v.description}`);
        });
      }
    }
    
    // Recommendations
    const recs = output?.recommendations || [];
    if (recs.length > 0) {
      console.log(`\n💡 TOP RECOMMENDATIONS:`);
      recs.slice(0, 3).forEach((r, i) => {
        console.log(`   ${i + 1}. ${r}`);
      });
    }
    
    console.log('\n' + '─'.repeat(60));
    
  } catch (error) {
    console.error(`\n❌ ERROR: ${error.message}`);
    if (error.stack) console.error(error.stack);
  }
}

async function runAllTests() {
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║     SMART CONTRACT RISK SCANNER - COMPREHENSIVE TEST      ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');
  
  const signer = await createSigner(NETWORK, PRIVATE_KEY);
  const fetchWithPayment = wrapFetchWithPayment(fetch, signer, BigInt(150000));
  
  console.log('\n💰 Signer Address:', signer.account?.address || signer.address);
  console.log('🌐 Network:', NETWORK);
  console.log('🔗 API URL:', API_URL);
  
  // Test cases
  const tests = [
    {
      name: "USDC (Safe Contract)",
      address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      chain: "ethereum",
      expected: "LOW risk"
    },
    {
      name: "Squid Game Token (Known Rug Pull)",
      address: "0xfafb7581a65a1f554616bf780fc8a8acd2ab8c9b",
      chain: "ethereum",
      expected: "CRITICAL risk"
    },
    {
      name: "SpacePay Token (Suspected Scam)",
      address: "0x17fd3caa66502c6f1cbd5600d8448f3af8f2aba1",
      chain: "ethereum",
      expected: "HIGH/CRITICAL risk"
    }
  ];
  
  console.log(`\n📋 Running ${tests.length} test cases...\n`);
  console.log('═'.repeat(60));
  
  for (const test of tests) {
    await testContract(test.name, test.address, test.chain, fetchWithPayment);
    console.log('\n' + '═'.repeat(60));
    
    // Wait 2 seconds between tests to avoid rate limits
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  console.log('\n╔═══════════════════════════════════════════════════════════╗');
  console.log('║                  ALL TESTS COMPLETED!                     ║');
  console.log('╚═══════════════════════════════════════════════════════════╝\n');
  
  console.log('📊 SUMMARY:');
  console.log('   - Safe contracts should show LOW risk (0-25)');
  console.log('   - Scam contracts should show HIGH/CRITICAL risk (60-100)');
  console.log('   - External APIs should flag known scams');
  console.log('\n✅ Review results above to verify scanner accuracy!\n');
}

// Run tests
runAllTests().catch(error => {
  console.error('\n💥 Fatal error:', error);
  process.exit(1);
});