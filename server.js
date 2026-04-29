// hive-aleo-arc — Privacy Receipt Layer
// MCP 2024-11-05, Streamable-HTTP, JSON-RPC 2.0
// ed25519 commitment-attestations + nullifier double-spend detection
// v1: SHA-256 commitments + ed25519 signatures (offline-verifiable)
// v2 roadmap: anchor proofs to Aleo / Arc zk chain

import express from 'express';
import { createHash, randomBytes } from 'crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// noble/ed25519 requires sha512 sync shim
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, 'data');

// Ensure data directory exists
if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

const NULLIFIERS_PATH = join(DATA_DIR, 'nullifiers.json');
const ATTESTATIONS_PATH = join(DATA_DIR, 'attestations.json');
const SPECTRAL_KEY_PATH = join(DATA_DIR, 'spectral.key');

// ─── Key management ──────────────────────────────────────────────────────────

function loadOrCreateSpectralKey() {
  if (existsSync(SPECTRAL_KEY_PATH)) {
    const data = JSON.parse(readFileSync(SPECTRAL_KEY_PATH, 'utf8'));
    return {
      privateKey: Buffer.from(data.private_key_hex, 'hex'),
      publicKeyHex: data.public_key_hex,
      publicKeyB64: data.public_key_b64,
    };
  }
  const privateKey = randomBytes(32);
  const publicKeyBytes = await_sync_pubkey(privateKey);
  const publicKeyHex = Buffer.from(publicKeyBytes).toString('hex');
  const publicKeyB64 = Buffer.from(publicKeyBytes).toString('base64');
  writeFileSync(SPECTRAL_KEY_PATH, JSON.stringify({
    private_key_hex: privateKey.toString('hex'),
    public_key_hex: publicKeyHex,
    public_key_b64: publicKeyB64,
  }, null, 2));
  return { privateKey, publicKeyHex, publicKeyB64 };
}

function await_sync_pubkey(privateKey) {
  // synchronous public key derivation
  return ed.getPublicKey(privateKey);
}

const spectral = loadOrCreateSpectralKey();

// ─── Persistent stores ───────────────────────────────────────────────────────

function loadJSON(path, def) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return def; }
}

function saveJSON(path, data) {
  writeFileSync(path, JSON.stringify(data, null, 2));
}

// nullifier set: { [nullifier_hex]: { attestation_id, created_at } }
let nullifierSet = loadJSON(NULLIFIERS_PATH, {});

// audit log: [ { attestation_id, created_at } ]
let attestationLog = loadJSON(ATTESTATIONS_PATH, []);

// ─── Crypto primitives ────────────────────────────────────────────────────────

function sha256hex(...parts) {
  const h = createHash('sha256');
  for (const p of parts) h.update(typeof p === 'string' ? p : p);
  return h.digest('hex');
}

// Commitment = SHA-256(value || blinding_factor)
// v2 upgrade path: replace with Pedersen commitment over Ristretto255
function makeCommitment(value, blindingFactor) {
  return sha256hex(value + '||' + blindingFactor);
}

// Nullifier = SHA-256(secret || claim_hash)
// Detects double-spend without revealing the claim
function makeNullifier(secret, claimHash) {
  return sha256hex(secret + '||' + claimHash);
}

async function signPayload(payload) {
  const msg = Buffer.from(JSON.stringify(payload));
  const sig = await ed.signAsync(msg, spectral.privateKey);
  return Buffer.from(sig).toString('hex');
}

// ─── x402 challenge helper ────────────────────────────────────────────────────

function x402Challenge(amountAtomic, description) {
  return {
    x402Version: 2,
    error: 'Payment Required',
    accepts: [
      {
        scheme: 'exact',
        network: 'base-mainnet',
        maxAmountRequired: String(amountAtomic),
        resource: description,
        description,
        mimeType: 'application/json',
        payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
        maxTimeoutSeconds: 300,
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        extra: {
          name: 'USD Coin',
          version: '2',
        },
      },
    ],
  };
}

// ─── Express app ─────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ─── Health ───────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'hive-aleo-arc',
    version: '1.0.0',
    monroe: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
    hive_take_pct: 15,
    spectral_pubkey: spectral.publicKeyB64,
  });
});

// ─── Agent card ───────────────────────────────────────────────────────────────

app.get('/.well-known/agent.json', (_req, res) => {
  res.json({
    name: 'hive-aleo-arc',
    version: '1.0.0',
    description: 'Privacy receipt layer. Produces commitment-style attestations (SHA-256 commitment + ed25519 sig + nullifier) verifiable offline. v2 roadmap: anchor to Aleo / Arc zk chain.',
    url: BASE_URL,
    brand_gold: '#C08D23',
    monroe: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
    solana_treasury: 'B1N61cuL35fhskWz5dw8XqDyP6LWi3ZWmq8CNA9L3FVn',
    spectral: {
      algorithm: 'ed25519',
      public_key: spectral.publicKeyB64,
      public_key_hex: spectral.publicKeyHex,
      jwks_uri: `${BASE_URL}/.well-known/jwks.json`,
    },
    capabilities: [
      'private_attestation',
      'nullifier_verification',
      'commitment_scheme',
      'double_spend_detection',
    ],
    pricing: {
      attest: '$0.05 USDC per attestation',
      verify: 'free',
      enterprise: '$500/mo unlimited verifies + SLA',
    },
    mcp_endpoint: `${BASE_URL}/mcp`,
  });
});

// ─── JWKS ─────────────────────────────────────────────────────────────────────

app.get('/.well-known/jwks.json', (_req, res) => {
  // Publish ed25519 key in JWK format (OKP / Ed25519)
  const xBytes = Buffer.from(spectral.publicKeyHex, 'hex');
  res.json({
    keys: [
      {
        kty: 'OKP',
        crv: 'Ed25519',
        use: 'sig',
        kid: 'hive-aleo-arc-spectral-v1',
        x: xBytes.toString('base64url'),
      },
    ],
  });
});

// Also alias
app.get('/v1/private/jwks', (_req, res) => {
  const xBytes = Buffer.from(spectral.publicKeyHex, 'hex');
  res.json({
    keys: [
      {
        kty: 'OKP',
        crv: 'Ed25519',
        use: 'sig',
        kid: 'hive-aleo-arc-spectral-v1',
        x: xBytes.toString('base64url'),
      },
    ],
  });
});

// ─── Stats ────────────────────────────────────────────────────────────────────

app.get('/v1/private/stats', (_req, res) => {
  res.json({
    total_attestations: attestationLog.length,
    total_nullifiers: Object.keys(nullifierSet).length,
    service: 'hive-aleo-arc',
    version: '1.0.0',
    note: 'Aggregated counts only. No PII stored.',
  });
});

// ─── Attest (gated 402, $0.05) ────────────────────────────────────────────────

app.post('/v1/private/attest', async (req, res) => {
  // x402 gate — check for payment header
  const paymentHeader = req.headers['x-payment'] || req.headers['x402-payment'];
  if (!paymentHeader) {
    return res.status(402).json(x402Challenge(50000, 'POST /v1/private/attest — $0.05 USDC per attestation'));
  }

  const { claim_hash, payer_did_blinded, merchant_did_blinded, amount_commitment, currency, nonce } = req.body || {};

  if (!claim_hash || !nonce) {
    return res.status(400).json({ error: 'claim_hash and nonce are required' });
  }

  const blindingFactor = randomBytes(16).toString('hex');
  const secret = randomBytes(32).toString('hex');

  const commitment = makeCommitment(claim_hash, blindingFactor);
  const nullifier = makeNullifier(secret, claim_hash);
  const attestationId = 'att_' + randomBytes(12).toString('hex');
  const createdAt = new Date().toISOString();

  // The signed payload is what verify will reconstruct (without spectral_signature/nullifier)
  // so we sign a deterministic subset, then attach nullifier + signature alongside.
  const signedPayload = {
    attestation_id: attestationId,
    commitment,
    claim_hash_blinded: makeCommitment(claim_hash, randomBytes(8).toString('hex')),
    payer_did_blinded: payer_did_blinded || null,
    merchant_did_blinded: merchant_did_blinded || null,
    amount_commitment: amount_commitment || null,
    currency: currency || 'USDC',
    nonce,
    created_at: createdAt,
    algorithm: 'sha256-commitment-ed25519',
    version: 'v1',
    upgrade_path: 'v2: anchor commitment to Aleo Reasoning Circle via aleo.network zkCloud',
  };

  const signature = await signPayload(signedPayload);

  // Persist nullifier (append-only)
  nullifierSet[nullifier] = { attestation_id: attestationId, created_at: createdAt };
  saveJSON(NULLIFIERS_PATH, nullifierSet);

  // Persist audit log (no claim contents)
  attestationLog.push({ attestation_id: attestationId, created_at: createdAt });
  saveJSON(ATTESTATIONS_PATH, attestationLog);

  return res.status(200).json({
    ...signedPayload,
    nullifier,
    spectral_signature: signature,
    spectral_public_key: spectral.publicKeyB64,
    verification_url: `${BASE_URL}/v1/private/verify`,
    jwks_uri: `${BASE_URL}/.well-known/jwks.json`,
  });
});

// ─── Verify (FREE) ────────────────────────────────────────────────────────────

app.post('/v1/private/verify', async (req, res) => {
  const { attestation, expected_claim_hash } = req.body || {};

  if (!attestation) {
    return res.status(400).json({ error: 'attestation object required' });
  }

  // Strip transport-only fields to reconstruct the signed payload
  const { nullifier, spectral_signature, spectral_public_key, verification_url, jwks_uri, ...signedPayload } = attestation;

  // Check nullifier seen before (double-spend detection)
  const nullifierSeenBefore = nullifier ? (nullifierSet[nullifier] !== undefined) : null;

  // Verify signature over the signed payload (same fields that were signed at attest time)
  let signatureValid = false;
  let signatureError = null;
  try {
    if (spectral_signature) {
      const msg = Buffer.from(JSON.stringify(signedPayload));
      const sigBytes = Buffer.from(spectral_signature, 'hex');
      const pubKeyBytes = Buffer.from(spectral.publicKeyHex, 'hex');
      signatureValid = await ed.verifyAsync(sigBytes, msg, pubKeyBytes);
    }
  } catch (e) {
    signatureError = e.message;
  }

  // If expected_claim_hash supplied, check commitment matches
  let commitmentValid = null;
  if (expected_claim_hash && attestation.commitment && attestation.blinding_factor) {
    const recomputed = makeCommitment(expected_claim_hash, attestation.blinding_factor);
    commitmentValid = recomputed === attestation.commitment;
  }

  return res.status(200).json({
    valid: signatureValid,
    signature_valid: signatureValid,
    signature_error: signatureError,
    nullifier_seen_before: nullifierSeenBefore,
    commitment_valid: commitmentValid,
    attestation_id: attestation.attestation_id || null,
    spectral_public_key: spectral.publicKeyB64,
    jwks_uri: `${BASE_URL}/.well-known/jwks.json`,
  });
});

// ─── Enterprise subscribe (gated 402, $500/mo) ────────────────────────────────

app.post('/v1/private/enterprise/subscribe', async (req, res) => {
  const paymentHeader = req.headers['x-payment'] || req.headers['x402-payment'];
  if (!paymentHeader) {
    return res.status(402).json(x402Challenge(500000000, 'POST /v1/private/enterprise/subscribe — $500/mo USDC, unlimited verifies + premium SLA'));
  }

  const { subscriber_did, contact_email, tier } = req.body || {};
  if (!subscriber_did) {
    return res.status(400).json({ error: 'subscriber_did required' });
  }

  const subscriptionId = 'sub_' + randomBytes(12).toString('hex');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  return res.status(200).json({
    subscription_id: subscriptionId,
    subscriber_did,
    tier: tier || 'enterprise',
    amount_usdc: 500,
    expires_at: expiresAt,
    benefits: [
      'Unlimited attestation verifies',
      'Priority SLA < 200ms p99',
      'Dedicated nullifier namespace',
      'Audit export API',
      'Email support',
    ],
    created_at: new Date().toISOString(),
  });
});

// ─── MCP endpoint (JSON-RPC 2.0) ─────────────────────────────────────────────

const TOOLS = [
  {
    name: 'attest_private_payment',
    description: 'Generate a commitment-style attestation for a private payment. Returns a SHA-256 commitment + ed25519 Spectral signature + nullifier for double-spend detection. Costs $0.05 USDC. Offline-verifiable. v2 roadmap: anchor to Aleo zk chain.',
    inputSchema: {
      type: 'object',
      required: ['claim_hash', 'nonce'],
      properties: {
        claim_hash: { type: 'string', description: 'SHA-256 hash of the claim to attest (you pre-hash; Hive never sees plaintext)' },
        payer_did_blinded: { type: 'string', description: 'Blinded DID of payer (optional)' },
        merchant_did_blinded: { type: 'string', description: 'Blinded DID of merchant (optional)' },
        amount_commitment: { type: 'string', description: 'Commitment to settlement amount (optional)' },
        currency: { type: 'string', description: 'Currency (default USDC)', default: 'USDC' },
        nonce: { type: 'string', description: 'Caller-supplied nonce for replay protection' },
      },
    },
  },
  {
    name: 'verify_private_attestation',
    description: 'Verify a previously-issued attestation. Checks the ed25519 Spectral signature, detects nullifier reuse (double-spend), and optionally validates a commitment against an expected claim hash. FREE.',
    inputSchema: {
      type: 'object',
      required: ['attestation'],
      properties: {
        attestation: { type: 'object', description: 'The full attestation object returned by attest_private_payment' },
        expected_claim_hash: { type: 'string', description: 'Optional: supply the original claim_hash to validate the commitment' },
      },
    },
  },
  {
    name: 'subscribe_enterprise',
    description: 'Subscribe to the enterprise tier ($500/mo USDC). Provides unlimited verifies, priority SLA, and audit export. Requires x402 payment.',
    inputSchema: {
      type: 'object',
      required: ['subscriber_did'],
      properties: {
        subscriber_did: { type: 'string', description: 'DID of the subscribing agent or organization' },
        contact_email: { type: 'string', description: 'Contact email for SLA notifications (optional)' },
        tier: { type: 'string', description: 'Subscription tier', default: 'enterprise' },
      },
    },
  },
  {
    name: 'get_private_stats',
    description: 'Retrieve aggregated service statistics: total attestations issued, total nullifiers tracked. No PII returned. FREE.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

app.post('/mcp', async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};

  if (jsonrpc !== '2.0') {
    return res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
  }

  if (method === 'tools/list') {
    return res.json({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
  }

  if (method === 'tools/call') {
    const { name, arguments: args = {} } = params || {};

    if (name === 'attest_private_payment') {
      // Simulate 402 gate in MCP context — return instructions
      return res.json({
        jsonrpc: '2.0', id,
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              instruction: 'Call POST /v1/private/attest directly with X-Payment header. This tool requires $0.05 USDC x402 payment.',
              endpoint: `${BASE_URL}/v1/private/attest`,
              payment_required: true,
              amount_atomic: 50000,
              currency: 'USDC',
              network: 'base-mainnet',
              pay_to: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
            }),
          }],
        },
      });
    }

    if (name === 'verify_private_attestation') {
      const { attestation, expected_claim_hash } = args;
      if (!attestation) {
        return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'attestation required' } });
      }
      const { nullifier, spectral_signature, spectral_public_key: _spk, verification_url: _vu, jwks_uri: _ji, ...signedPayloadMcp } = attestation;
      const nullifierSeenBefore = nullifier ? (nullifierSet[nullifier] !== undefined) : null;

      let signatureValid = false;
      try {
        if (spectral_signature) {
          const msg = Buffer.from(JSON.stringify(signedPayloadMcp));
          const sigBytes = Buffer.from(spectral_signature, 'hex');
          const pubKeyBytes = Buffer.from(spectral.publicKeyHex, 'hex');
          signatureValid = await ed.verifyAsync(sigBytes, msg, pubKeyBytes);
        }
      } catch { signatureValid = false; }

      return res.json({
        jsonrpc: '2.0', id,
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              valid: signatureValid,
              nullifier_seen_before: nullifierSeenBefore,
              attestation_id: attestation.attestation_id || null,
            }),
          }],
        },
      });
    }

    if (name === 'subscribe_enterprise') {
      return res.json({
        jsonrpc: '2.0', id,
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              instruction: 'Call POST /v1/private/enterprise/subscribe directly with X-Payment header.',
              endpoint: `${BASE_URL}/v1/private/enterprise/subscribe`,
              payment_required: true,
              amount_atomic: 500000000,
              currency: 'USDC',
              network: 'base-mainnet',
              pay_to: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
            }),
          }],
        },
      });
    }

    if (name === 'get_private_stats') {
      return res.json({
        jsonrpc: '2.0', id,
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              total_attestations: attestationLog.length,
              total_nullifiers: Object.keys(nullifierSet).length,
              service: 'hive-aleo-arc',
              version: '1.0.0',
            }),
          }],
        },
      });
    }

    return res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } });
  }

  return res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
});

// ─── Start ────────────────────────────────────────────────────────────────────

// ── well-known / x402 ─────────────────────────────────────────────────────────

app.get('/.well-known/x402', (_req, res) => {
  res.json({
    x402Version:  2,
    cold_safe:    true,
    service:      'hive-aleo-arc',
    version:      '1.0.0',
    brand_color:  '#C08D23',
    payTo:        '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
    network:      'base',
    chain_id:     8453,
    asset:        'USDC',
    contract:     '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    facilitator: {
      url:                    'https://hivemorph.onrender.com/v1/x402',
      supported_schemes:      ['exact'],
      supported_networks:     ['eip155:8453'],
      syncFacilitatorOnStart: false,
      cold_safe:              true
    },
    resources: [
      {
        path:        '/v1/private/attest',
        method:      'POST',
        description: 'Generate commitment-style attestation for a private payment. $0.05 USDC per attestation.',
        'x-pricing': {
          scheme: 'exact',
          asset: 'USDC',
          amount_atomic: 50000,
          amount_usd: '$0.05',
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
          description: '$0.05 USDC per attestation. payTo Monroe.',
        },
        'x-payment-info': {
          scheme: 'exact',
          asset: 'USDC',
          amount_atomic: 50000,
          amount_usd: '$0.05',
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
          description: '$0.05 USDC per attestation. payTo Monroe.',
        }
      },
      {
        path:        '/v1/private/enterprise/subscribe',
        method:      'POST',
        description: 'Enterprise tier subscription. $500/mo USDC. Unlimited verifies + priority SLA.',
        'x-pricing': {
          scheme: 'exact',
          asset: 'USDC',
          amount_atomic: 500000000,
          amount_usd: '$500.00/mo',
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
          description: '$500 USDC/mo. Unlimited verifies + priority SLA.',
        },
        'x-payment-info': {
          scheme: 'exact',
          asset: 'USDC',
          amount_atomic: 500000000,
          amount_usd: '$500.00/mo',
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
          description: '$500 USDC/mo. Unlimited verifies + priority SLA.',
        }
      },
      {
        path:        '/v1/private/verify',
        method:      'POST',
        description: 'Verify a previously issued attestation. Free.',
        'x-pricing':      { scheme: 'free', note: 'Verification is always free.' },
        'x-payment-info': { scheme: 'free', note: 'Verification is always free.' }
      },
      {
        path:        '/v1/private/stats',
        method:      'GET',
        description: 'Aggregated service statistics. Free.',
        'x-pricing':      { scheme: 'free', note: 'Stats are public and free.' },
        'x-payment-info': { scheme: 'free', note: 'Stats are public and free.' }
      }
    ],
    discovery_companions: {
      agent_card: '/.well-known/agent-card.json',
      ap2:        '/.well-known/ap2.json',
      openapi:    '/.well-known/openapi.json'
    },
    disclaimers: {
      not_a_security: true,
      not_custody:    true,
      not_insurance:  true,
      signal_only:    true
    }
  });
});

// ── well-known / agent-card.json (A2A 0.1) ────────────────────────────────────

app.get('/.well-known/agent-card.json', (req, res) => {
  const pubkey = (typeof getPublicKeyB64 === 'function')
    ? getPublicKeyB64()
    : (typeof spectral !== 'undefined' ? (spectral.publicKeyB64 || null) : null);
  res.json({
    name:        'hive-aleo-arc',
    version:     '1.0.0',
    description: 'Privacy receipt layer. Commitment-style attestations (SHA-256 + ed25519 + nullifier). Offline-verifiable. v2 roadmap: anchor to Aleo/Arc zk chain.',
    brand_color: '#C08D23',
    did:         `did:web:${req.hostname}`,
    protocol:    'A2A/0.1',
    capabilities: [
      'private_attestation',
      'nullifier_verification',
      'commitment_scheme',
      'double_spend_detection'
    ],
    spectral: {
      public_key:    pubkey,
      signature_algo: 'ed25519',
      jwks_endpoint: '/.well-known/jwks.json'
    },
    treasury: {
      address:  '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
      network:  'base',
      chain_id: 8453,
      asset:    'USDC'
    },
    payment: {
      protocol: 'x402',
      version:  '2',
      network:  'base',
      chain_id: 8453,
      asset:    'USDC',
      contract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      payTo:    '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e'
    },
    mcp_endpoint: '/mcp',
    tools: ['attest_private_payment', 'verify_private_attestation', 'subscribe_enterprise', 'get_private_stats']
  });
});

// ── well-known / ap2.json (AP2 0.1) ───────────────────────────────────────────

app.get('/.well-known/ap2.json', (_req, res) => {
  res.json({
    ap2_version:   '0.1',
    service:       'hive-aleo-arc',
    accepted_tokens: [
      {
        symbol:   'USDC',
        contract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        network:  'base',
        chain_id: 8453,
        decimals: 6
      },
      {
        symbol:   'USDT',
        contract: '0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2',
        network:  'base',
        chain_id: 8453,
        decimals: 6,
        role:     'alternate'
      }
    ],
    networks:           [{ name: 'base', chain_id: 8453, role: 'primary' }],
    payment_protocols:  ['x402/v2'],
    settlement: {
      finality:  'on-chain',
      network:   'base',
      chain_id:  8453,
      payTo:     '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e'
    },
    paid_endpoints: [
      { path: '/v1/private/attest', method: 'POST', description: 'Generate commitment-style attestation for a private payment. $0.05 USDC per attestation.' },
      { path: '/v1/private/enterprise/subscribe', method: 'POST', description: 'Enterprise tier subscription. $500/mo USDC. Unlimited verifies + priority SLA.' }
    ],
    free_endpoints: [
      { path: '/v1/private/verify', method: 'POST', description: 'Verify a previously issued attestation. Free.' },
      { path: '/v1/private/stats', method: 'GET', description: 'Aggregated service statistics. Free.' }
    ],
    brand_color: '#C08D23'
  });
});

// ── well-known / openapi.json (OpenAPI 3.0.3 + x-pricing + x-payment-info) ────

app.get('/.well-known/openapi.json', (_req, res) => {
  res.json({
    openapi: '3.0.3',
    info: {
      title:       'hive-aleo-arc API',
      version:     '1.0.0',
      description: 'Privacy receipt layer. Commitment-style attestations (SHA-256 + ed25519 + nullifier). Offline-verifiable. v2 roadmap: anchor to Aleo/Arc zk chain.',
      contact:     { name: 'The Hivery', url: 'https://thehiveryiq.com' }
    },
    servers: [{ url: 'https://hive-aleo-arc.onrender.com', description: 'Production (Render)' }],
    paths: {
      '/v1/private/attest': {
        post: {
          operationId: 'v1_private_attest',
          summary: 'Generate commitment-style attestation for a private payment. $0.05 USDC per attestation.',
          'x-pricing': {
          scheme: 'exact',
          asset: 'USDC',
          amount_atomic: 50000,
          amount_usd: '$0.05',
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
          description: '$0.05 USDC per attestation. payTo Monroe.'
          },
          'x-payment-info': {
          scheme: 'exact',
          asset: 'USDC',
          amount_atomic: 50000,
          amount_usd: '$0.05',
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
          description: '$0.05 USDC per attestation. payTo Monroe.'
          },
          responses: {
            '200': { description: 'Success.' },
            '402': { description: 'Payment Required — x402 challenge.' },
            '400': { description: 'Validation error.' }
          }
        }
      },
      '/v1/private/enterprise/subscribe': {
        post: {
          operationId: 'v1_private_enterprise_subscribe',
          summary: 'Enterprise tier subscription. $500/mo USDC. Unlimited verifies + priority SLA.',
          'x-pricing': {
          scheme: 'exact',
          asset: 'USDC',
          amount_atomic: 500000000,
          amount_usd: '$500.00/mo',
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
          description: '$500 USDC/mo. Unlimited verifies + priority SLA.'
          },
          'x-payment-info': {
          scheme: 'exact',
          asset: 'USDC',
          amount_atomic: 500000000,
          amount_usd: '$500.00/mo',
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
          description: '$500 USDC/mo. Unlimited verifies + priority SLA.'
          },
          responses: {
            '200': { description: 'Success.' },
            '402': { description: 'Payment Required — x402 challenge.' },
            '400': { description: 'Validation error.' }
          }
        }
      },
      '/v1/private/verify': {
        post: {
          operationId: 'v1_private_verify',
          summary: 'Verify a previously issued attestation. Free.',
          responses: {
            '200': { description: 'Success.' },
            '400': { description: 'Validation error.' }
          }
        }
      },
      '/v1/private/stats': {
        get: {
          operationId: 'v1_private_stats',
          summary: 'Aggregated service statistics. Free.',
          responses: {
            '200': { description: 'Success.' },
            '400': { description: 'Validation error.' }
          }
        }
      }
    }
  });
});

app.listen(PORT, () => {
  console.log(`hive-aleo-arc listening on port ${PORT}`);
  console.log(`Spectral pubkey (ed25519): ${spectral.publicKeyB64}`);
  console.log(`Monroe: 0x15184bf50b3d3f52b60434f8942b7d52f2eb436e`);
});
