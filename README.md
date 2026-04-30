# hive-aleo-arc

**Hive Privacy Receipt Layer** — commitment-style attestations for private agent-to-agent settlements.

[![Hive Brand Gold](https://img.shields.io/badge/Hive-Civilization-C08D23?style=flat&color=C08D23)](https://github.com/srotzin/hive-aleo-arc)
[![MCP 2024-11-05](https://img.shields.io/badge/MCP-2024--11--05-blue)](https://github.com/srotzin/hive-aleo-arc)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## What it does

`hive-aleo-arc` generates **commitment-style attestations** for settlement claims without revealing the underlying parties, amounts, or transaction data. Every attestation is:

- **Signed** with an ed25519 Spectral key (offline-verifiable against the published JWKS)
- **Commitment-bound** via SHA-256(value ∥ blinding_factor)
- **Nullifier-protected** — SHA-256(secret ∥ claim_hash) enables double-spend detection without revealing the claim

All four giants — Visa, Tether, Google A2A, LangChain — lack this surface. Visa cannot show a private settlement proof (KYC obligation). Tether refuses to. Google A2A is plaintext metadata. Hive can attest "agent A paid agent B settlement-X without revealing A, B, or X."

---

## Three Gates

| Gate | Status |
|---|---|
| **NEED** | Regulated agents (banking, healthcare, compliance) require private settlement attestations. Existing infrastructure exposes both parties and amounts. |
| **YIELD** | $0.05/attestation generated + $500/mo enterprise tier. Run-rate projection: ~$2,000/day at modest adoption (TEN_STEPS_AHEAD_20260429.md, Step 8). |
| **CLEAN-MONEY** | No derivatives, no energy futures, no GAS-PERP. Settlement to Monroe (Base mainnet USDC) only. x402 v2 standard. |

---

## v1 → v2 Upgrade Roadmap

| Version | Status | Description |
|---|---|---|
| **v1 (current)** | Live | SHA-256 commitment + ed25519 Spectral signature + nullifier. Offline-verifiable. No external chain dependency. |
| **v2 (roadmap)** | Planned | Anchor commitment proofs to Aleo / Arc zk chain via `aleo.network zkCloud`. Requires Aleo Reasoning Circle integration. Full zk-SNARK proof instead of commitment hash. |
| **v2.5** | Planned | Replace SHA-256 commitments with Pedersen commitments over Ristretto255 for homomorphic properties. |

v1 attestations remain valid under v2 — the nullifier set is append-only and the Spectral key is persistent.

---

## Tools

| Tool | Method | Endpoint | Price |
|---|---|---|---|
| `attest_private_payment` | POST | `/v1/private/attest` | $0.05 USDC (50000 atomic) |
| `verify_private_attestation` | POST | `/v1/private/verify` | Free |
| `subscribe_enterprise` | POST | `/v1/private/enterprise/subscribe` | $500/mo USDC (500000000 atomic) |
| `get_private_stats` | GET | `/v1/private/stats` | Free |

---

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | None | Service health, Monroe address, hive_take_pct |
| GET | `/.well-known/agent.json` | None | Agent card: Monroe, Spectral pubkey, capabilities |
| GET | `/.well-known/jwks.json` | None | ed25519 verification key in JWK format |
| POST | `/mcp` | None | JSON-RPC 2.0 (tools/list, tools/call) |
| POST | `/v1/private/attest` | x402 $0.05 | Generate commitment attestation |
| POST | `/v1/private/verify` | None | Verify attestation + nullifier check |
| GET | `/v1/private/jwks` | None | Alias for JWKS |
| POST | `/v1/private/enterprise/subscribe` | x402 $500 | Enterprise subscription |
| GET | `/v1/private/stats` | None | Aggregated counts, no PII |

---

## Pricing

| Tier | Price | Details |
|---|---|---|
| Pay-per-attest | $0.05 USDC | 50000 atomic USDC on Base mainnet |
| Verify | Free | Drives adoption |
| Enterprise | $500/mo USDC | Unlimited verifies, priority SLA (<200ms p99), audit export |

Settlement to Monroe: `0x15184bf50b3d3f52b60434f8942b7d52f2eb436e` (Base 8453, USDC)

---

## Privacy Primitives

### Commitment (v1)

```
commitment = SHA-256(value ∥ blinding_factor)
```

The blinding factor is generated server-side and returned only in the attestation response. v2 upgrade: Pedersen commitment over Ristretto255.

### Nullifier

```
nullifier = SHA-256(secret ∥ claim_hash)
```

The secret is ephemeral per attestation. The nullifier is stored in `data/nullifiers.json` (append-only). Presenting the same nullifier twice signals a double-spend attempt without revealing the underlying claim.

### Signature

ed25519 over the canonical JSON of the signed payload fields. Verify against the published JWKS:

```
GET /.well-known/jwks.json
```

---

## Connect

### MCP client (Claude Desktop, Cursor, etc.)

```json
{
  "mcpServers": {
    "hive-aleo-arc": {
      "url": "https://hive-aleo-arc.onrender.com/mcp",
      "transport": "streamable-http"
    }
  }
}
```

### Direct REST

```bash
# Get service info
curl https://hive-aleo-arc.onrender.com/health

# Generate attestation (requires x402 payment header)
curl -X POST https://hive-aleo-arc.onrender.com/v1/private/attest \
  -H 'Content-Type: application/json' \
  -H 'X-Payment: <x402-payment-token>' \
  -d '{
    "claim_hash": "<sha256-of-your-claim>",
    "nonce": "<unique-nonce>",
    "currency": "USDC"
  }'

# Verify attestation (free)
curl -X POST https://hive-aleo-arc.onrender.com/v1/private/verify \
  -H 'Content-Type: application/json' \
  -d '{"attestation": <attestation-object>}'

# View aggregated stats
curl https://hive-aleo-arc.onrender.com/v1/private/stats
```

---

## x402 Payment

Attestation generation requires an [x402 v2](https://x402.org) payment:

- **Amount:** 50000 atomic USDC ($0.05)
- **Network:** base-mainnet (chain 8453)
- **Asset:** `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` (USDC on Base)
- **Recipient:** `0x15184bf50b3d3f52b60434f8942b7d52f2eb436e` (Monroe)

Without a valid payment header, `/v1/private/attest` returns HTTP 402 with a standard x402 challenge object.

---

## Verification Keys

Published at `/.well-known/jwks.json` — OKP / Ed25519, kid `hive-aleo-arc-spectral-v1`.

To verify offline:

```js
import * as ed from '@noble/ed25519';

const pubkeyB64 = "<from /.well-known/agent.json spectral.public_key>";
const pubkeyBytes = Buffer.from(pubkeyB64, 'base64');

// Reconstruct signedPayload (attestation object minus nullifier, spectral_signature,
// spectral_public_key, verification_url, jwks_uri)
const msg = Buffer.from(JSON.stringify(signedPayload));
const sig = Buffer.from(attestation.spectral_signature, 'hex');

const valid = await ed.verifyAsync(sig, msg, pubkeyBytes);
```

---

## Council Provenance

Ad-hoc launch. NEED + YIELD + CLEAN-MONEY gates passed. No derivatives, no energy futures, no GAS-PERP. Step 8 of [TEN_STEPS_AHEAD_20260429](https://github.com/srotzin/hivemorph) — "biggest bang for the buck."

---

## License

MIT — see [LICENSE](LICENSE)

---

*Hive Civilization — neutral plumbing under the agentic economy. Brand gold: #C08D23.*


---

## Hive Civilization

Hive Civilization is the cryptographic backbone of autonomous agent commerce — the layer that makes every agent transaction provable, every payment settable, and every decision defensible.

This repository is part of the **PROVABLE · SETTABLE · DEFENSIBLE** pillar.

- thehiveryiq.com
- hiveagentiq.com
- agent-card: https://hivetrust.onrender.com/.well-known/agent-card.json
