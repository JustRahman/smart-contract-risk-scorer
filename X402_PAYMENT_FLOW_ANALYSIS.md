# X402 Payment Flow Analysis - Bridge Route Pinger

## Overview
This document explains how X402 payment verification works in the bridge-route-pinger project, from initial request to successful payment verification.

---

## 1. Payment Configuration (src/agent.js:6-23)

The agent is configured with payment settings when created:

```javascript
const { app, addEntrypoint } = createAgentApp(
  {
    name: "bridge-route-pinger",
    version: "1.0.0",
    description: "List viable bridge routes..."
  },
  {
    config: {
      payments: {
        facilitatorUrl: process.env.FACILITATOR_URL || "https://facilitator.daydreams.systems",
        payTo: process.env.PAY_TO_WALLET || "0x992920386E3D950BC260f99C81FDA12419eD4594",
        network: process.env.PAYMENT_NETWORK || "base",
        defaultPrice: process.env.PAYMENT_AMOUNT || "0.02"
      }
    },
    useConfigPayments: true  // ✅ CRITICAL FLAG - Enables payment middleware
  }
);
```

### Key Configuration Parameters:
- **facilitatorUrl**: The payment verification service URL (default: https://facilitator.daydreams.systems)
- **payTo**: Wallet address that receives payments
- **network**: Blockchain network for payments (base, ethereum, polygon, etc.)
- **defaultPrice**: Default price in USDC (0.02 = 2 cents)
- **useConfigPayments**: Boolean flag that **enables/disables the payment middleware**

---

## 2. Payment Middleware Flow

### How agent-kit Applies Payment Protection

When `useConfigPayments: true` is set, agent-kit automatically applies the `paymentMiddleware` from x402-hono to all entrypoints. This happens in `@lucid-dreams/agent-kit/dist/index.js:1041`.

The middleware is applied to each route like this:
```javascript
app.use(path, paymentMiddleware(payTo, routes, facilitator, paywall));
```

---

## 3. Complete Request Flow

### Step 1: Request Without X-PAYMENT Header

**Location**: `x402-hono/dist/esm/index.mjs:110-148`

When a request arrives **without** the `X-PAYMENT` header:

```javascript
const payment = c.req.header("X-PAYMENT");

if (!payment) {
  // Check if it's a web browser
  if (isWebBrowser) {
    // Return HTML paywall page with payment UI
    return c.html(html, 402);
  }

  // Return JSON with payment requirements
  return c.json({
    error: "X-PAYMENT header is required",
    accepts: paymentRequirements,
    x402Version: 1
  }, 402);
}
```

**Response**: HTTP 402 Payment Required with payment requirements in JSON or HTML paywall.

### Step 2: Request WITH X-PAYMENT Header

**Location**: `x402-hono/dist/esm/index.mjs:149-177`

When a request includes the `X-PAYMENT` header:

#### 2a. Decode Payment Header
```javascript
let decodedPayment;
try {
  decodedPayment = exact.evm.decodePayment(payment);
  decodedPayment.x402Version = x402Version;
} catch (error) {
  return c.json({
    error: "Invalid or malformed payment header",
    accepts: paymentRequirements,
    x402Version
  }, 402);
}
```

#### 2b. Match Payment Requirements
```javascript
const selectedPaymentRequirements = findMatchingPaymentRequirements(
  paymentRequirements,
  decodedPayment
);

if (!selectedPaymentRequirements) {
  return c.json({
    error: "Unable to find matching payment requirements",
    accepts: paymentRequirements,
    x402Version
  }, 402);
}
```

### Step 3: Verify Payment with Facilitator

**Location**: `x402-hono/dist/esm/index.mjs:177-188`

The middleware calls the facilitator's `/verify` endpoint:

```javascript
const verification = await verify(decodedPayment, selectedPaymentRequirements);

if (!verification.isValid) {
  return c.json({
    error: verification.invalidReason,
    accepts: paymentRequirements,
    payer: verification.payer,
    x402Version
  }, 402);
}
```

#### Facilitator Verification Request

**Location**: `x402/dist/esm/verify/index.mjs:10-31`

```javascript
async function verify(payload, paymentRequirements) {
  const url = facilitator?.url || "https://x402.org/facilitator";

  const res = await fetch(`${url}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      x402Version: payload.x402Version,
      paymentPayload: toJsonSafe(payload),
      paymentRequirements: toJsonSafe(paymentRequirements)
    })
  });

  if (res.status !== 200) {
    throw new Error(`Failed to verify payment: ${res.statusText}`);
  }

  return await res.json();
}
```

**Request to Facilitator**:
- **URL**: `https://facilitator.daydreams.systems/verify`
- **Method**: POST
- **Headers**: Content-Type: application/json
- **Body**:
  ```json
  {
    "x402Version": 1,
    "paymentPayload": { /* decoded payment data */ },
    "paymentRequirements": { /* expected payment details */ }
  }
  ```

**Valid Response** (payment accepted):
```json
{
  "isValid": true,
  "payer": "0x...",
  // other verification details
}
```

**Invalid Response** (payment rejected):
```json
{
  "isValid": false,
  "invalidReason": "Insufficient payment amount",
  "payer": "0x..."
}
```

### Step 4: Execute Handler (If Payment Valid)

**Location**: `x402-hono/dist/esm/index.mjs:189`

If verification succeeds, the middleware calls `await next()` which executes your handler:

```javascript
await next();  // Executes handler({ input }) in src/agent.js:43
```

**Your handler runs here** - this is where `getLifiRoutes()` is called and bridge routes are fetched.

### Step 5: Settle Payment

**Location**: `x402-hono/dist/esm/index.mjs:190-213`

After the handler completes successfully, the payment is settled:

```javascript
let res = c.res;

// Don't settle if handler returned an error
if (res.status >= 400) {
  return;
}

try {
  const settlement = await settle(decodedPayment, selectedPaymentRequirements);

  if (settlement.success) {
    const responseHeader = settleResponseHeader(settlement);
    res.headers.set("X-PAYMENT-RESPONSE", responseHeader);
  } else {
    throw new Error(settlement.errorReason);
  }
} catch (error) {
  res = c.json({
    error: "Failed to settle payment",
    accepts: paymentRequirements,
    x402Version
  }, 402);
}
```

#### Facilitator Settlement Request

**Location**: `x402/dist/esm/verify/index.mjs:32-54`

```javascript
async function settle(payload, paymentRequirements) {
  const url = facilitator?.url || "https://x402.org/facilitator";

  const res = await fetch(`${url}/settle`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      x402Version: payload.x402Version,
      paymentPayload: toJsonSafe(payload),
      paymentRequirements: toJsonSafe(paymentRequirements)
    })
  });

  if (res.status !== 200) {
    throw new Error(`Failed to settle payment: ${res.status} ${res.statusText}`);
  }

  return await res.json();
}
```

**Request to Facilitator**:
- **URL**: `https://facilitator.daydreams.systems/settle`
- **Method**: POST
- **Body**: Same structure as verify

**Success Response**:
```json
{
  "success": true,
  "transactionHash": "0x...",
  // settlement details
}
```

The middleware adds the settlement response to the HTTP response headers:
```
X-PAYMENT-RESPONSE: <settlement-data>
```

---

## 4. Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Client Request                                            │
│    POST /entrypoints/get_bridge_routes                      │
│    Headers: X-PAYMENT: <payment-data>                       │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Payment Middleware (x402-hono)                           │
│    - Check for X-PAYMENT header                             │
│    - If missing → Return 402 with payment requirements      │
│    - If present → Decode payment                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Facilitator Verification                                  │
│    POST https://facilitator.daydreams.systems/verify        │
│    Body: { x402Version, paymentPayload, paymentRequirements }│
└─────────────────────┬───────────────────────────────────────┘
                      │
        ┌─────────────┴──────────────┐
        │                            │
        ▼                            ▼
   ┌─────────┐                  ┌─────────┐
   │ INVALID │                  │  VALID  │
   │ Return  │                  │ Continue│
   │  402    │                  │         │
   └─────────┘                  └────┬────┘
                                     │
                                     ▼
                      ┌──────────────────────────────┐
                      │ 4. Execute Handler           │
                      │    handler({ input })        │
                      │    - getLifiRoutes()         │
                      │    - Return bridge data      │
                      └──────────┬───────────────────┘
                                 │
                                 ▼
                      ┌──────────────────────────────┐
                      │ 5. Settle Payment            │
                      │ POST facilitator/settle      │
                      │ Add X-PAYMENT-RESPONSE header│
                      └──────────┬───────────────────┘
                                 │
                                 ▼
                      ┌──────────────────────────────┐
                      │ 6. Return Response to Client │
                      │    Status: 200               │
                      │    Headers: X-PAYMENT-RESPONSE│
                      │    Body: { bridge routes }   │
                      └──────────────────────────────┘
```

---

## 5. Comparison with MEV Scanner

**MEV Scanner Not Found** in this repository. To verify if MEV scanner uses the same pattern:

### Check These Files:
```bash
# Look for MEV scanner in sibling directories
ls -la ../mev-scanner/src/agent.js
```

### What to Look For:
1. **Same payment configuration structure**:
   ```javascript
   config: {
     payments: {
       facilitatorUrl: "...",
       payTo: "...",
       network: "...",
       defaultPrice: "..."
     }
   }
   ```

2. **useConfigPayments flag**:
   ```javascript
   useConfigPayments: true  // Must be set to true
   ```

3. **Same agent-kit version**:
   Check `package.json` for `@lucid-dreams/agent-kit` version

### If MEV Scanner Doesn't Have Payments:
Add the same configuration:
```javascript
const { app, addEntrypoint } = createAgentApp(
  { name: "mev-scanner", ... },
  {
    config: {
      payments: {
        facilitatorUrl: process.env.FACILITATOR_URL || "https://facilitator.daydreams.systems",
        payTo: process.env.PAY_TO_WALLET || "0x992920386E3D950BC260f99C81FDA12419eD4594",
        network: process.env.PAYMENT_NETWORK || "base",
        defaultPrice: process.env.PAYMENT_AMOUNT || "0.01"
      }
    },
    useConfigPayments: true  // ✅ CRITICAL
  }
);
```

---

## 6. Key Takeaways

### How X402 Works:
1. **Middleware intercepts ALL requests** to protected endpoints
2. **No X-PAYMENT header** → Returns 402 with payment requirements
3. **With X-PAYMENT header** → Verifies with facilitator before executing handler
4. **Handler only runs** if payment is valid
5. **Payment is settled** after successful handler execution

### Critical Points:
- **useConfigPayments: true** is REQUIRED to enable payments
- **Facilitator verifies payments** - your agent doesn't handle blockchain directly
- **Handler is protected** - it only runs after payment verification
- **Payment settlement** happens AFTER handler completes successfully

### Security:
- Payment verification happens BEFORE your code runs
- Invalid payments never reach your handler
- Facilitator handles all blockchain interactions
- Your agent only receives verified, settled payments

---

## 7. Environment Variables

Required `.env` configuration:

```bash
# Payment Configuration
FACILITATOR_URL=https://facilitator.daydreams.systems
PAY_TO_WALLET=0x992920386E3D950BC260f99C81FDA12419eD4594
PAYMENT_NETWORK=base
PAYMENT_AMOUNT=0.02
```

---

## Conclusion

The bridge-route-pinger successfully implements X402 payments using:
- **agent-kit** for HTTP app creation and routing
- **x402-hono** for payment middleware
- **x402** for facilitator communication
- **useConfigPayments: true** flag to enable the flow

All bridge route requests require payment verification before execution, with the facilitator service handling blockchain verification and settlement transparently.
