# hive-aleo-arc v1.0.0

Privacy receipt layer for private agent-to-agent settlements.

## Tools (4)

| Tool | Price | Description |
|---|---|---|
| `attest_private_payment` | $0.05 USDC | SHA-256 commitment + ed25519 Spectral sig + nullifier |
| `verify_private_attestation` | Free | Sig check + nullifier double-spend detection |
| `subscribe_enterprise` | $500/mo USDC | Unlimited verifies + priority SLA |
| `get_private_stats` | Free | Aggregated counts, no PII |

## Backend

`https://hive-aleo-arc.onrender.com` (Render Starter)

## Privacy Primitives

- commitment = SHA-256(value ∥ blinding_factor) — offline-verifiable
- nullifier = SHA-256(secret ∥ claim_hash) — double-spend detection without revealing claim
- ed25519 Spectral signature over attestation payload
- JWKS published at `/.well-known/jwks.json`

## v2 Roadmap

- Anchor commitments to Aleo Reasoning Circle / Arc zk chain
- Replace SHA-256 commitments with Pedersen commitments over Ristretto255

## Settlement

Monroe: `0x15184bf50b3d3f52b60434f8942b7d52f2eb436e` (Base 8453, USDC)

Hive take: 15%. $0.05 per attestation. $500/mo enterprise.

## Council

Ad-hoc — NEED + YIELD + CLEAN-MONEY passed. Step 8 of TEN_STEPS_AHEAD_20260429. Steve Rotzin: "biggest bang for the buck."

---

*Hive Civilization — Brand gold #C08D23*
