#!/bin/bash

# Smart Contract Risk Scorer - Test Script
# Tests various contracts to demonstrate the analyzer's capabilities

echo "========================================="
echo "Smart Contract Risk Scorer - Test Suite"
echo "========================================="
echo ""

# Check if server is running
echo "Checking if server is running..."
if ! curl -s http://localhost:3000/health > /dev/null 2>&1; then
    echo "❌ Server is not running!"
    echo "Please start the server first with: npm start"
    exit 1
fi

echo "✅ Server is running"
echo ""

# Function to analyze contract
analyze_contract() {
    local name=$1
    local address=$2
    local chain=${3:-ethereum}

    echo "----------------------------------------"
    echo "Testing: $name"
    echo "Address: $address"
    echo "Chain: $chain"
    echo "----------------------------------------"

    response=$(curl -s -X POST http://localhost:3000/analyze \
        -H "Content-Type: application/json" \
        -d "{\"contract_address\":\"$address\",\"chain\":\"$chain\",\"scan_depth\":\"quick\"}")

    # Extract key fields
    risk_score=$(echo $response | grep -o '"risk_score":[0-9]*' | grep -o '[0-9]*')
    risk_level=$(echo $response | grep -o '"risk_level":"[^"]*"' | cut -d'"' -f4)
    name_found=$(echo $response | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | head -1)

    if [ -n "$risk_score" ]; then
        echo "✅ Analysis complete:"
        echo "   Name: $name_found"
        echo "   Risk Score: $risk_score"
        echo "   Risk Level: $risk_level"
    else
        echo "❌ Analysis failed"
        echo "   Response: $response" | head -c 200
    fi

    echo ""
    sleep 2  # Rate limiting
}

# Test 1: USDC - Known safe stablecoin (should be LOW risk)
analyze_contract "USDC" "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" "ethereum"

# Test 2: USDT - Known safe but centralized (should be LOW risk)
analyze_contract "USDT" "0xdAC17F958D2ee523a2206206994597C13D831ec7" "ethereum"

# Test 3: DAI - Decentralized stablecoin (should be LOW risk)
analyze_contract "DAI" "0x6B175474E89094C44Da98b954EedeAC495271d0F" "ethereum"

# Test 4: WETH - Wrapped Ether (should be LOW risk)
analyze_contract "WETH" "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" "ethereum"

# Test 5: Uniswap Router (should be LOW risk)
analyze_contract "Uniswap V2 Router" "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D" "ethereum"

echo "========================================="
echo "Test Suite Complete!"
echo "========================================="
echo ""
echo "Summary:"
echo "- All major tokens should show LOW risk (0-39)"
echo "- Centralized tokens like USDT may show vulnerabilities but still LOW risk"
echo "- Cache should speed up repeated queries significantly"
echo ""
