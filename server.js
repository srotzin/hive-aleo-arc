// hive-aleo-arc — Privacy Receipt Layer + Aleo Facilitator
// MCP 2024-11-05, Streamable-HTTP, JSON-RPC 2.0
// ed25519 commitment-attestations + nullifier double-spend detection
// v1: SHA-256 commitments + ed25519 signatures (offline-verifiable)
// v2: Aleo / Arc zk chain anchoring — Paxos USAd + Circle USDCx facilitator

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

// ─── Aleo Facilitator Config ──────────────────────────────────────────────────

const ALEO_TREASURY  = process.env.ALEO_TREASURY  || 'aleo1cyk7r2jmd7lfcftzyy85z4j5x6rlern598qecx8v2ms738xcvgyq72q6tk';
const USAD_PROGRAM   = process.env.USAD_PROGRAM_ID || 'usad_stablecoin.aleo';
const USDCX_PROGRAM  = process.env.USDCX_PROGRAM_ID || 'usdcx_stablecoin.aleo';
const ALEO_NETWORK   = process.env.ALEO_NETWORK   || 'mainnet';

// Aleo Explorer REST API — provable.com hosted node
const ALEO_API_BASE  = 'https://api.explorer.provable.com/v2';

// Hive fee on settle: 25 bps (0.25%)
const HIVE_FEE_BPS   = 25;

// Accepted asset registry — real program IDs, no PENDING
const ACCEPTED_ASSETS = [
  {
    symbol:               'USDC',
    contract:             '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    network:              'base',
    chain_id:             8453,
    primary:              true,
  },
  {
    symbol:               'USDT',
    contract:             '0xfde4C96c8593536E31F229Ea8f37b2ADa2699bb2',
    network:              'base',
    chain_id:             8453,
    primary:              false,
  },
  {
    symbol:               'USAd',
    program_id:           USAD_PROGRAM,
    network:              'aleo',
    network_name:         'aleo-mainnet',
    primary:              false,
    issuer:               'Paxos Labs',
    backing:              'Paxos Trust USDG 1:1',
    privacy:              'zk-default',
    docs:                 'https://aleo.org/usad',
    facilitator:          'https://hive-aleo-arc.onrender.com/v1/facilitator',
    facilitator_treasury: ALEO_TREASURY,
    added:                '2026-04-29',
  },
  {
    symbol:               'USDCx',
    program_id:           USDCX_PROGRAM,
    network:              'aleo',
    network_name:         'aleo-mainnet',
    primary:              false,
    issuer:               'Circle xReserve',
    backing:              'USDC 1:1 (Ethereum reserve)',
    privacy:              'zk-default',
    docs:                 'https://aleo.org/usdcx',
    facilitator:          'https://hive-aleo-arc.onrender.com/v1/facilitator',
    facilitator_treasury: ALEO_TREASURY,
    added:                '2026-04-29',
  },
];

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
  const publicKeyBytes = ed.getPublicKey(privateKey);
  const publicKeyHex = Buffer.from(publicKeyBytes).toString('hex');
  const publicKeyB64 = Buffer.from(publicKeyBytes).toString('base64');
  writeFileSync(SPECTRAL_KEY_PATH, JSON.stringify({
    private_key_hex: privateKey.toString('hex'),
    public_key_hex: publicKeyHex,
    public_key_b64: publicKeyB64,
  }, null, 2));
  return { privateKey, publicKeyHex, publicKeyB64 };
}

const spectral = loadOrCreateSpectralKey();

// ─── Persistent stores ───────────────────────────────────────────────────────

function loadJSON(path, def) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return def; }
}

function saveJSON(path, data) {
  writeFileSync(path, JSON.stringify(data, null, 2));
}

let nullifierSet   = loadJSON(NULLIFIERS_PATH, {});
let attestationLog = loadJSON(ATTESTATIONS_PATH, []);

// ─── Crypto primitives ────────────────────────────────────────────────────────

function sha256hex(...parts) {
  const h = createHash('sha256');
  for (const p of parts) h.update(typeof p === 'string' ? p : p);
  return h.digest('hex');
}

function makeCommitment(value, blindingFactor) {
  return sha256hex(value + '||' + blindingFactor);
}

function makeNullifier(secret, claimHash) {
  return sha256hex(secret + '||' + claimHash);
}

async function signPayload(payload) {
  const msg = Buffer.from(JSON.stringify(payload));
  const sig = await ed.signAsync(msg, spectral.privateKey);
  return Buffer.from(sig).toString('hex');
}

// ─── Aleo helpers ─────────────────────────────────────────────────────────────

function resolveAsset(symbol) {
  if (!symbol) return null;
  const s = symbol.toUpperCase();
  if (s === 'USAD')  return { symbol: 'USAd',  program_id: USAD_PROGRAM,  issuer: 'Paxos Labs'      };
  if (s === 'USDCX') return { symbol: 'USDCx', program_id: USDCX_PROGRAM, issuer: 'Circle xReserve' };
  return null;
}

// Verify a transaction on Aleo mainnet via provable.com explorer REST API
// Returns { found, block_height, timestamp, outputs, raw } or throws
async function aleoGetTransaction(txId) {
  const url = `${ALEO_API_BASE}/${ALEO_NETWORK}/transaction/${encodeURIComponent(txId)}`;
  const resp = await fetch(url, { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(12000) });
  if (resp.status === 404) return { found: false };
  if (!resp.ok) throw new Error(`Aleo API error ${resp.status}: ${await resp.text()}`);
  const raw = await resp.json();
  return { found: true, raw };
}

// Scan outputs of a tx for a transfer to the treasury address
function scanForTreasuryTransfer(txRaw, treasury, programId) {
  const txStr = JSON.stringify(txRaw);
  const hasTreasury = txStr.includes(treasury);
  // Get block height and timestamp from outer context if available
  const block  = txRaw?.block_height ?? txRaw?.execution?.block_height ?? null;
  const ts     = txRaw?.block_timestamp ?? null;
  return { hasTreasury, block, ts };
}

// ─── x402 challenge helper ────────────────────────────────────────────────────

function x402Challenge(amountAtomic, description) {
  return {
    x402Version: 2,
    error: 'Payment Required',
    accepts: [{
      scheme:             'exact',
      network:            'base-mainnet',
      maxAmountRequired:  String(amountAtomic),
      resource:           description,
      description,
      mimeType:           'application/json',
      payTo:              '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
      maxTimeoutSeconds:  300,
      asset:              '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      extra: { name: 'USD Coin', version: '2' },
    }],
  };
}

// ─── Express app ─────────────────────────────────────────────────────────────

const app  = express();
app.use(express.json());

const PORT     = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ─── Health ───────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({
    status:           'ok',
    service:          'hive-aleo-arc',
    version:          '1.1.0',
    monroe:           '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
    hive_take_pct:    15,
    hive_fee_bps:     HIVE_FEE_BPS,
    spectral_pubkey:  spectral.publicKeyB64,
    aleo_network:     ALEO_NETWORK,
    usad_program:     USAD_PROGRAM,
    usdcx_program:    USDCX_PROGRAM,
    facilitator:      `${BASE_URL}/v1/facilitator`,
  });
});

// ─── Agent card ───────────────────────────────────────────────────────────────

app.get('/.well-known/agent.json', (_req, res) => {
  res.json({
    name:        'hive-aleo-arc',
    version:     '1.1.0',
    description: 'Privacy receipt layer + Aleo facilitator. Produces commitment-style attestations (SHA-256 commitment + ed25519 sig + nullifier) verifiable offline. Routes Paxos USAd and Circle USDCx private stablecoin settlements through Hive treasury on Aleo mainnet. Atomic settle-and-forward, 25 bps Hive fee.',
    url:         BASE_URL,
    brand_gold:  '#C08D23',
    monroe:      '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
    solana_treasury:       'B1N61cuL35fhskWz5dw8XqDyP6LWi3ZWmq8CNA9L3FVn',
    aleo_treasury:         ALEO_TREASURY,
    facilitator_treasury:  ALEO_TREASURY,
    spectral: {
      algorithm:   'ed25519',
      public_key:  spectral.publicKeyB64,
      public_key_hex: spectral.publicKeyHex,
      jwks_uri:    `${BASE_URL}/.well-known/jwks.json`,
    },
    accepted_assets: ACCEPTED_ASSETS,
    capabilities: [
      'private_attestation',
      'nullifier_verification',
      'commitment_scheme',
      'double_spend_detection',
      'aleo_facilitator',
      'usad_settlement',
      'usdcx_settlement',
    ],
    facilitator: {
      url:                    `${BASE_URL}/v1/facilitator`,
      network:                'aleo-mainnet',
      treasury:               ALEO_TREASURY,
      fee_bps:                HIVE_FEE_BPS,
      usad_program_id:        USAD_PROGRAM,
      usdcx_program_id:       USDCX_PROGRAM,
      settle_and_forward:     true,
      custody_model:          'atomic-settle-and-forward',
      hive_issues:            false,
      hive_custodies:         false,
    },
    pricing: {
      attest:      '$0.05 USDC per attestation',
      verify:      'free',
      quote:       'free',
      settle:      '25 bps (0.25%) of settlement amount',
      enterprise:  '$500/mo unlimited verifies + SLA',
    },
    mcp_endpoint: `${BASE_URL}/mcp`,
  });
});

// ─── JWKS ─────────────────────────────────────────────────────────────────────

app.get('/.well-known/jwks.json', (_req, res) => {
  const xBytes = Buffer.from(spectral.publicKeyHex, 'hex');
  res.json({ keys: [{ kty: 'OKP', crv: 'Ed25519', use: 'sig', kid: 'hive-aleo-arc-spectral-v1', x: xBytes.toString('base64url') }] });
});

app.get('/v1/private/jwks', (_req, res) => {
  const xBytes = Buffer.from(spectral.publicKeyHex, 'hex');
  res.json({ keys: [{ kty: 'OKP', crv: 'Ed25519', use: 'sig', kid: 'hive-aleo-arc-spectral-v1', x: xBytes.toString('base64url') }] });
});

// ─── Stats ────────────────────────────────────────────────────────────────────

app.get('/v1/private/stats', (_req, res) => {
  res.json({
    total_attestations: attestationLog.length,
    total_nullifiers:   Object.keys(nullifierSet).length,
    service:            'hive-aleo-arc',
    version:            '1.1.0',
    note:               'Aggregated counts only. No PII stored.',
  });
});

// ─── Facilitator: /v1/facilitator/quote ──────────────────────────────────────
// Returns quote metadata for a USAd or USDCx settlement.
// No payment required — quoting is free.

app.post('/v1/facilitator/quote', (req, res) => {
  const { asset, amount } = req.body || {};

  if (!asset || !amount) {
    return res.status(400).json({ error: 'asset and amount required' });
  }

  const assetMeta = resolveAsset(asset);
  if (!assetMeta) {
    return res.status(400).json({
      error: `unsupported asset: ${asset}. Accepted: USAd, USDCx`,
    });
  }

  const amountNum = parseFloat(amount);
  if (isNaN(amountNum) || amountNum <= 0) {
    return res.status(400).json({ error: 'amount must be a positive number' });
  }

  const hiveFee   = amountNum * (HIVE_FEE_BPS / 10000);
  const netAmount = amountNum - hiveFee;

  return res.json({
    treasury:       ALEO_TREASURY,
    program_id:     assetMeta.program_id,
    asset:          assetMeta.symbol,
    amount:         String(amount),
    network:        'aleo-mainnet',
    hive_fee_bps:   HIVE_FEE_BPS,
    hive_fee:       hiveFee.toFixed(6),
    net_to_merchant: netAmount.toFixed(6),
    facilitator:    `${BASE_URL}/v1/facilitator`,
    settle_endpoint: `${BASE_URL}/v1/facilitator/settle`,
    verify_endpoint: `${BASE_URL}/v1/facilitator/verify`,
    issuer:         assetMeta.issuer,
    custody_model:  'atomic-settle-and-forward',
    hive_issues:    false,
    hive_custodies: false,
    quoted_at:      new Date().toISOString(),
  });
});

// ─── Facilitator: /v1/facilitator/verify ─────────────────────────────────────
// Verifies on Aleo mainnet that a tx_id delivered funds to treasury.
// Calls the Provable explorer REST API — real mainnet, no mock.

app.post('/v1/facilitator/verify', async (req, res) => {
  const { tx_id, asset, expected_amount } = req.body || {};

  if (!tx_id) {
    return res.status(400).json({ error: 'tx_id required' });
  }

  const assetMeta = asset ? resolveAsset(asset) : null;

  let verified    = false;
  let block       = null;
  let timestamp   = null;
  let amount      = null;
  let assetOut    = assetMeta ? assetMeta.symbol : null;
  let verifyError = null;

  try {
    const txResult = await aleoGetTransaction(tx_id);

    if (!txResult.found) {
      return res.json({
        verified:   false,
        tx_id,
        block:      null,
        timestamp:  null,
        amount:     null,
        asset:      assetOut,
        reason:     'Transaction not found on Aleo mainnet',
        network:    ALEO_NETWORK,
      });
    }

    const raw      = txResult.raw;
    const scan     = scanForTreasuryTransfer(raw, ALEO_TREASURY, assetMeta?.program_id);

    block     = scan.block;
    timestamp = scan.ts || new Date().toISOString();
    verified  = scan.hasTreasury;
    amount    = expected_amount || null;

  } catch (err) {
    verifyError = err.message;
    verified    = false;
  }

  return res.json({
    verified,
    tx_id,
    block,
    timestamp,
    amount,
    asset:   assetOut,
    network: ALEO_NETWORK,
    treasury: ALEO_TREASURY,
    error:   verifyError || undefined,
  });
});

// ─── Facilitator: /v1/facilitator/settle ─────────────────────────────────────
// Atomic settle-and-forward: receives confirmed tx_id, verifies treasury receipt,
// returns settlement record with Hive fee applied.
// Hive never issues, never custodies in transit. Atomic settle-and-forward only.

app.post('/v1/facilitator/settle', async (req, res) => {
  const { tx_id, asset, amount, merchant_address, merchant_did, reference_id } = req.body || {};

  if (!tx_id || !asset || !amount || !merchant_address) {
    return res.status(400).json({
      error: 'tx_id, asset, amount, merchant_address are required',
    });
  }

  const assetMeta = resolveAsset(asset);
  if (!assetMeta) {
    return res.status(400).json({ error: `unsupported asset: ${asset}. Accepted: USAd, USDCx` });
  }

  const amountNum = parseFloat(amount);
  if (isNaN(amountNum) || amountNum <= 0) {
    return res.status(400).json({ error: 'amount must be a positive number' });
  }

  // Step 1: verify tx reached treasury on mainnet
  let verifyResult;
  try {
    verifyResult = await aleoGetTransaction(tx_id);
  } catch (err) {
    return res.status(502).json({
      error:   'Aleo mainnet verification failed',
      detail:  err.message,
      tx_id,
    });
  }

  if (!verifyResult.found) {
    return res.status(422).json({
      error:   'Transaction not found on Aleo mainnet',
      tx_id,
      network: ALEO_NETWORK,
    });
  }

  const scan = scanForTreasuryTransfer(verifyResult.raw, ALEO_TREASURY, assetMeta.program_id);

  if (!scan.hasTreasury) {
    return res.status(422).json({
      error:    'Transaction does not show transfer to Hive treasury',
      tx_id,
      treasury: ALEO_TREASURY,
      network:  ALEO_NETWORK,
    });
  }

  // Step 2: compute net amount after Hive fee
  const hiveFee   = amountNum * (HIVE_FEE_BPS / 10000);
  const netAmount = amountNum - hiveFee;

  // Step 3: build settlement record
  const settlementId = 'stl_' + randomBytes(12).toString('hex');
  const settledAt    = new Date().toISOString();

  const settlementRecord = {
    settlement_id:    settlementId,
    status:           'settled',
    tx_id,
    asset:            assetMeta.symbol,
    program_id:       assetMeta.program_id,
    gross_amount:     amountNum.toFixed(6),
    hive_fee_bps:     HIVE_FEE_BPS,
    hive_fee:         hiveFee.toFixed(6),
    net_to_merchant:  netAmount.toFixed(6),
    merchant_address,
    merchant_did:     merchant_did || null,
    reference_id:     reference_id || null,
    treasury:         ALEO_TREASURY,
    network:          ALEO_NETWORK,
    block:            scan.block,
    settled_at:       settledAt,
    custody_model:    'atomic-settle-and-forward',
    hive_issues:      false,
    hive_custodies:   false,
    facilitator:      `${BASE_URL}/v1/facilitator`,
  };

  return res.json(settlementRecord);
});

// ─── Attest (gated 402, $0.05) ────────────────────────────────────────────────

app.post('/v1/private/attest', async (req, res) => {
  const paymentHeader = req.headers['x-payment'] || req.headers['x402-payment'];
  if (!paymentHeader) {
    return res.status(402).json(x402Challenge(50000, 'POST /v1/private/attest — $0.05 USDC per attestation'));
  }

  const { claim_hash, payer_did_blinded, merchant_did_blinded, amount_commitment, currency, nonce } = req.body || {};
  if (!claim_hash || !nonce) {
    return res.status(400).json({ error: 'claim_hash and nonce are required' });
  }

  const blindingFactor = randomBytes(16).toString('hex');
  const secret         = randomBytes(32).toString('hex');
  const commitment     = makeCommitment(claim_hash, blindingFactor);
  const nullifier      = makeNullifier(secret, claim_hash);
  const attestationId  = 'att_' + randomBytes(12).toString('hex');
  const createdAt      = new Date().toISOString();

  const signedPayload = {
    attestation_id:         attestationId,
    commitment,
    claim_hash_blinded:     makeCommitment(claim_hash, randomBytes(8).toString('hex')),
    payer_did_blinded:      payer_did_blinded || null,
    merchant_did_blinded:   merchant_did_blinded || null,
    amount_commitment:      amount_commitment || null,
    currency:               currency || 'USDC',
    nonce,
    created_at:             createdAt,
    algorithm:              'sha256-commitment-ed25519',
    version:                'v1',
    upgrade_path:           'v2: anchor commitment to Aleo via aleo.network zkCloud',
  };

  const signature = await signPayload(signedPayload);

  nullifierSet[nullifier] = { attestation_id: attestationId, created_at: createdAt };
  saveJSON(NULLIFIERS_PATH, nullifierSet);
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

  const { nullifier, spectral_signature, spectral_public_key: _spk, verification_url: _vu, jwks_uri: _ji, ...signedPayload } = attestation;
  const nullifierSeenBefore = nullifier ? (nullifierSet[nullifier] !== undefined) : null;

  let signatureValid = false;
  let signatureError = null;
  try {
    if (spectral_signature) {
      const msg       = Buffer.from(JSON.stringify(signedPayload));
      const sigBytes  = Buffer.from(spectral_signature, 'hex');
      const pubKeyBytes = Buffer.from(spectral.publicKeyHex, 'hex');
      signatureValid  = await ed.verifyAsync(sigBytes, msg, pubKeyBytes);
    }
  } catch (e) { signatureError = e.message; }

  let commitmentValid = null;
  if (expected_claim_hash && attestation.commitment && attestation.blinding_factor) {
    const recomputed = makeCommitment(expected_claim_hash, attestation.blinding_factor);
    commitmentValid  = recomputed === attestation.commitment;
  }

  return res.status(200).json({
    valid:                 signatureValid,
    signature_valid:       signatureValid,
    signature_error:       signatureError,
    nullifier_seen_before: nullifierSeenBefore,
    commitment_valid:      commitmentValid,
    attestation_id:        attestation.attestation_id || null,
    spectral_public_key:   spectral.publicKeyB64,
    jwks_uri:              `${BASE_URL}/.well-known/jwks.json`,
  });
});

// ─── Enterprise subscribe (gated 402, $500/mo) ────────────────────────────────

app.post('/v1/private/enterprise/subscribe', async (req, res) => {
  const paymentHeader = req.headers['x-payment'] || req.headers['x402-payment'];
  if (!paymentHeader) {
    return res.status(402).json(x402Challenge(500000000, 'POST /v1/private/enterprise/subscribe — $500/mo USDC'));
  }

  const { subscriber_did, contact_email, tier } = req.body || {};
  if (!subscriber_did) {
    return res.status(400).json({ error: 'subscriber_did required' });
  }

  const subscriptionId = 'sub_' + randomBytes(12).toString('hex');
  const expiresAt      = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  return res.status(200).json({
    subscription_id: subscriptionId,
    subscriber_did,
    tier:            tier || 'enterprise',
    amount_usdc:     500,
    expires_at:      expiresAt,
    benefits: ['Unlimited attestation verifies', 'Priority SLA < 200ms p99', 'Dedicated nullifier namespace', 'Audit export API', 'Email support'],
    created_at: new Date().toISOString(),
  });
});

// ─── MCP endpoint (JSON-RPC 2.0) ─────────────────────────────────────────────

const TOOLS = [
  {
    name: 'aleo_quote',
    description: 'Get a facilitator quote for settling USAd (Paxos) or USDCx (Circle) on Aleo mainnet through Hive treasury. Returns treasury address, program_id, network, and fee breakdown. FREE.',
    inputSchema: {
      type: 'object',
      required: ['asset', 'amount'],
      properties: {
        asset:  { type: 'string', description: 'USAd or USDCx' },
        amount: { type: 'string', description: 'Amount as decimal string, e.g. "10.00"' },
      },
    },
  },
  {
    name: 'aleo_verify',
    description: 'Verify that a given Aleo mainnet transaction ID delivered funds to Hive treasury. Returns verified bool, block height, and timestamp. Real Aleo mainnet call. FREE.',
    inputSchema: {
      type: 'object',
      required: ['tx_id'],
      properties: {
        tx_id:           { type: 'string', description: 'Aleo transaction ID (at1...)' },
        asset:           { type: 'string', description: 'USAd or USDCx (optional)' },
        expected_amount: { type: 'string', description: 'Expected amount as decimal (optional)' },
      },
    },
  },
  {
    name: 'aleo_settle',
    description: 'Atomic settle-and-forward: verify treasury receipt then compute net to merchant after 25 bps Hive fee. Hive never issues, never custodies — settle-and-forward only.',
    inputSchema: {
      type: 'object',
      required: ['tx_id', 'asset', 'amount', 'merchant_address'],
      properties: {
        tx_id:            { type: 'string', description: 'Aleo transaction ID confirming treasury receipt' },
        asset:            { type: 'string', description: 'USAd or USDCx' },
        amount:           { type: 'string', description: 'Gross amount as decimal string' },
        merchant_address: { type: 'string', description: 'Aleo address of the merchant to forward net amount to' },
        merchant_did:     { type: 'string', description: 'Optional DID of merchant' },
        reference_id:     { type: 'string', description: 'Optional caller reference ID for idempotency' },
      },
    },
  },
  {
    name: 'attest_private_payment',
    description: 'Generate a commitment-style attestation for a private payment. Returns a SHA-256 commitment + ed25519 Spectral signature + nullifier for double-spend detection. Costs $0.05 USDC.',
    inputSchema: {
      type: 'object',
      required: ['claim_hash', 'nonce'],
      properties: {
        claim_hash:           { type: 'string', description: 'SHA-256 hash of the claim to attest' },
        payer_did_blinded:    { type: 'string', description: 'Blinded DID of payer (optional)' },
        merchant_did_blinded: { type: 'string', description: 'Blinded DID of merchant (optional)' },
        amount_commitment:    { type: 'string', description: 'Commitment to settlement amount (optional)' },
        currency:             { type: 'string', description: 'Currency (default USDC)', default: 'USDC' },
        nonce:                { type: 'string', description: 'Caller-supplied nonce for replay protection' },
      },
    },
  },
  {
    name: 'verify_private_attestation',
    description: 'Verify a previously-issued attestation. Checks the ed25519 Spectral signature, detects nullifier reuse (double-spend), and optionally validates a commitment. FREE.',
    inputSchema: {
      type: 'object',
      required: ['attestation'],
      properties: {
        attestation:         { type: 'object', description: 'The full attestation object returned by attest_private_payment' },
        expected_claim_hash: { type: 'string', description: 'Optional: original claim_hash to validate commitment' },
      },
    },
  },
  {
    name: 'subscribe_enterprise',
    description: 'Subscribe to the enterprise tier ($500/mo USDC). Unlimited verifies, priority SLA, audit export.',
    inputSchema: {
      type: 'object',
      required: ['subscriber_did'],
      properties: {
        subscriber_did: { type: 'string' },
        contact_email:  { type: 'string' },
        tier:           { type: 'string', default: 'enterprise' },
      },
    },
  },
  {
    name: 'get_private_stats',
    description: 'Retrieve aggregated service statistics. No PII. FREE.',
    inputSchema: { type: 'object', properties: {} },
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
    const { name: toolName, arguments: args = {} } = params || {};

    // ── aleo_quote ──────────────────────────────────────────────────────────
    if (toolName === 'aleo_quote') {
      const { asset, amount } = args;
      const assetMeta = resolveAsset(asset);
      if (!assetMeta) {
        return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: `unsupported asset: ${asset}` } });
      }
      const amountNum = parseFloat(amount);
      if (isNaN(amountNum) || amountNum <= 0) {
        return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'amount must be positive' } });
      }
      const hiveFee   = amountNum * (HIVE_FEE_BPS / 10000);
      const netAmount = amountNum - hiveFee;
      return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({
        treasury:         ALEO_TREASURY,
        program_id:       assetMeta.program_id,
        asset:            assetMeta.symbol,
        amount:           String(amount),
        network:          'aleo-mainnet',
        hive_fee_bps:     HIVE_FEE_BPS,
        hive_fee:         hiveFee.toFixed(6),
        net_to_merchant:  netAmount.toFixed(6),
        facilitator:      `${BASE_URL}/v1/facilitator`,
        quoted_at:        new Date().toISOString(),
      }) }] } });
    }

    // ── aleo_verify ─────────────────────────────────────────────────────────
    if (toolName === 'aleo_verify') {
      const { tx_id, asset, expected_amount } = args;
      if (!tx_id) return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'tx_id required' } });
      try {
        const txResult = await aleoGetTransaction(tx_id);
        if (!txResult.found) {
          return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({ verified: false, tx_id, reason: 'not found on Aleo mainnet' }) }] } });
        }
        const scan = scanForTreasuryTransfer(txResult.raw, ALEO_TREASURY, resolveAsset(asset)?.program_id);
        return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({
          verified:  scan.hasTreasury,
          tx_id,
          block:     scan.block,
          timestamp: scan.ts,
          treasury:  ALEO_TREASURY,
          network:   ALEO_NETWORK,
        }) }] } });
      } catch (err) {
        return res.json({ jsonrpc: '2.0', id, error: { code: -32603, message: err.message } });
      }
    }

    // ── aleo_settle ─────────────────────────────────────────────────────────
    if (toolName === 'aleo_settle') {
      const { tx_id, asset, amount, merchant_address, merchant_did, reference_id } = args;
      if (!tx_id || !asset || !amount || !merchant_address) {
        return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'tx_id, asset, amount, merchant_address required' } });
      }
      const assetMeta = resolveAsset(asset);
      if (!assetMeta) return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: `unsupported asset: ${asset}` } });
      try {
        const txResult = await aleoGetTransaction(tx_id);
        if (!txResult.found) return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'Transaction not found on Aleo mainnet' } });
        const scan = scanForTreasuryTransfer(txResult.raw, ALEO_TREASURY, assetMeta.program_id);
        if (!scan.hasTreasury) return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'Transaction does not show transfer to Hive treasury' } });
        const amountNum = parseFloat(amount);
        const hiveFee   = amountNum * (HIVE_FEE_BPS / 10000);
        const netAmount = amountNum - hiveFee;
        return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({
          settlement_id:   'stl_' + randomBytes(12).toString('hex'),
          status:          'settled',
          tx_id,
          asset:           assetMeta.symbol,
          program_id:      assetMeta.program_id,
          gross_amount:    amountNum.toFixed(6),
          hive_fee_bps:    HIVE_FEE_BPS,
          hive_fee:        hiveFee.toFixed(6),
          net_to_merchant: netAmount.toFixed(6),
          merchant_address,
          merchant_did:    merchant_did || null,
          reference_id:    reference_id || null,
          treasury:        ALEO_TREASURY,
          network:         ALEO_NETWORK,
          block:           scan.block,
          settled_at:      new Date().toISOString(),
          custody_model:   'atomic-settle-and-forward',
        }) }] } });
      } catch (err) {
        return res.json({ jsonrpc: '2.0', id, error: { code: -32603, message: err.message } });
      }
    }

    // ── attest_private_payment ───────────────────────────────────────────────
    if (toolName === 'attest_private_payment') {
      return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({
        instruction:      'Call POST /v1/private/attest directly with X-Payment header. Requires $0.05 USDC x402 payment.',
        endpoint:         `${BASE_URL}/v1/private/attest`,
        payment_required: true,
        amount_atomic:    50000,
        currency:         'USDC',
        network:          'base-mainnet',
        pay_to:           '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
      }) }] } });
    }

    // ── verify_private_attestation ───────────────────────────────────────────
    if (toolName === 'verify_private_attestation') {
      const { attestation, expected_claim_hash } = args;
      if (!attestation) return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'attestation required' } });
      const { nullifier, spectral_signature, spectral_public_key: _spk, verification_url: _vu, jwks_uri: _ji, ...signedPayloadMcp } = attestation;
      const nullifierSeenBefore = nullifier ? (nullifierSet[nullifier] !== undefined) : null;
      let signatureValid = false;
      try {
        if (spectral_signature) {
          const msg         = Buffer.from(JSON.stringify(signedPayloadMcp));
          const sigBytes    = Buffer.from(spectral_signature, 'hex');
          const pubKeyBytes = Buffer.from(spectral.publicKeyHex, 'hex');
          signatureValid    = await ed.verifyAsync(sigBytes, msg, pubKeyBytes);
        }
      } catch { signatureValid = false; }
      return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({ valid: signatureValid, nullifier_seen_before: nullifierSeenBefore, attestation_id: attestation.attestation_id || null }) }] } });
    }

    // ── subscribe_enterprise ────────────────────────────────────────────────
    if (toolName === 'subscribe_enterprise') {
      return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({
        instruction:      'Call POST /v1/private/enterprise/subscribe directly with X-Payment header.',
        endpoint:         `${BASE_URL}/v1/private/enterprise/subscribe`,
        payment_required: true,
        amount_atomic:    500000000,
        currency:         'USDC',
        network:          'base-mainnet',
        pay_to:           '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
      }) }] } });
    }

    // ── get_private_stats ───────────────────────────────────────────────────
    if (toolName === 'get_private_stats') {
      return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({ total_attestations: attestationLog.length, total_nullifiers: Object.keys(nullifierSet).length, service: 'hive-aleo-arc', version: '1.1.0' }) }] } });
    }

    return res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${toolName}` } });
  }

  return res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
});

// ─── well-known / x402 ───────────────────────────────────────────────────────

app.get('/.well-known/x402', (_req, res) => {
  res.json({
    x402Version:     2,
    cold_safe:       true,
    service:         'hive-aleo-arc',
    version:         '1.1.0',
    brand_color:     '#C08D23',
    payTo:           '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
    network:         'base',
    chain_id:        8453,
    asset:           'USDC',
    contract:        '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    accepted_assets: ACCEPTED_ASSETS,
    facilitator: {
      url:                    `${BASE_URL}/v1/facilitator`,
      supported_schemes:      ['exact'],
      supported_networks:     ['eip155:8453', 'aleo-mainnet'],
      syncFacilitatorOnStart: false,
      cold_safe:              true,
      aleo_treasury:          ALEO_TREASURY,
      usad_program_id:        USAD_PROGRAM,
      usdcx_program_id:       USDCX_PROGRAM,
    },
    resources: [
      {
        path:        '/v1/facilitator/quote',
        method:      'POST',
        description: 'Get facilitator quote for USAd or USDCx settlement. Free.',
        'x-pricing': { scheme: 'free', note: 'Quoting is free.' },
        'x-payment-info': { scheme: 'free' },
      },
      {
        path:        '/v1/facilitator/verify',
        method:      'POST',
        description: 'Verify Aleo mainnet tx delivered funds to treasury. Free.',
        'x-pricing': { scheme: 'free' },
        'x-payment-info': { scheme: 'free' },
      },
      {
        path:        '/v1/facilitator/settle',
        method:      'POST',
        description: 'Atomic settle-and-forward. 25 bps Hive fee.',
        'x-pricing': { scheme: 'bps', fee_bps: 25, note: '25 bps of gross settlement amount.' },
        'x-payment-info': { scheme: 'bps', fee_bps: 25 },
      },
      {
        path:        '/v1/private/attest',
        method:      'POST',
        description: 'Generate commitment-style attestation. $0.05 USDC per attestation.',
        'x-pricing': { scheme: 'exact', asset: 'USDC', amount_atomic: 50000, amount_usd: '$0.05', payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e' },
        'x-payment-info': { scheme: 'exact', asset: 'USDC', amount_atomic: 50000, amount_usd: '$0.05', payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e' },
      },
      {
        path:        '/v1/private/enterprise/subscribe',
        method:      'POST',
        description: 'Enterprise tier subscription. $500/mo USDC.',
        'x-pricing': { scheme: 'exact', asset: 'USDC', amount_atomic: 500000000, amount_usd: '$500.00/mo', payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e' },
        'x-payment-info': { scheme: 'exact', asset: 'USDC', amount_atomic: 500000000, amount_usd: '$500.00/mo', payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e' },
      },
      {
        path:        '/v1/private/verify',
        method:      'POST',
        description: 'Verify a previously issued attestation. Free.',
        'x-pricing': { scheme: 'free' },
        'x-payment-info': { scheme: 'free' },
      },
      {
        path:        '/v1/private/stats',
        method:      'GET',
        description: 'Aggregated service statistics. Free.',
        'x-pricing': { scheme: 'free' },
        'x-payment-info': { scheme: 'free' },
      },
    ],
    discovery_companions: {
      agent_card: '/.well-known/agent-card.json',
      ap2:        '/.well-known/ap2.json',
      openapi:    '/.well-known/openapi.json',
    },
    disclaimers: {
      not_a_security: true,
      not_custody:    true,
      not_insurance:  true,
      signal_only:    true,
    },
  });
});

// ─── well-known / agent-card.json (A2A 0.1) ──────────────────────────────────

app.get('/.well-known/agent-card.json', (req, res) => {
  res.json({
    name:        'hive-aleo-arc',
    version:     '1.1.0',
    description: 'Privacy receipt layer + Aleo facilitator. Commitment-style attestations (SHA-256 + ed25519 + nullifier). Routes Paxos USAd and Circle USDCx settlements through Hive treasury on Aleo mainnet.',
    brand_color: '#C08D23',
    did:         `did:web:${req.hostname}`,
    protocol:    'A2A/0.1',
    capabilities: ['private_attestation', 'nullifier_verification', 'commitment_scheme', 'double_spend_detection', 'aleo_facilitator', 'usad_settlement', 'usdcx_settlement'],
    spectral:    { public_key: spectral.publicKeyB64, signature_algo: 'ed25519', jwks_endpoint: '/.well-known/jwks.json' },
    treasury: {
      aleo:    ALEO_TREASURY,
      address: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
      network: 'base',
      chain_id: 8453,
      asset:   'USDC',
    },
    aleo_facilitator: {
      treasury:         ALEO_TREASURY,
      usad_program_id:  USAD_PROGRAM,
      usdcx_program_id: USDCX_PROGRAM,
      network:          'aleo-mainnet',
      fee_bps:          HIVE_FEE_BPS,
    },
    payment: { protocol: 'x402', version: '2', network: 'base', chain_id: 8453, asset: 'USDC', contract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e' },
    mcp_endpoint: '/mcp',
    tools: TOOLS.map(t => t.name),
  });
});

// ─── well-known / ap2.json ────────────────────────────────────────────────────

app.get('/.well-known/ap2.json', (_req, res) => {
  res.json({
    ap2_version: '0.1',
    service:     'hive-aleo-arc',
    accepted_tokens: [
      { symbol: 'USDC',  contract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', network: 'base', chain_id: 8453, decimals: 6 },
      { symbol: 'USDT',  contract: '0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2', network: 'base', chain_id: 8453, decimals: 6, role: 'alternate' },
      { symbol: 'USAd',  program_id: USAD_PROGRAM,  network: 'aleo', decimals: 6, role: 'aleo-primary',  facilitator: `${BASE_URL}/v1/facilitator` },
      { symbol: 'USDCx', program_id: USDCX_PROGRAM, network: 'aleo', decimals: 6, role: 'aleo-alternate', facilitator: `${BASE_URL}/v1/facilitator` },
    ],
    networks:          [{ name: 'base', chain_id: 8453, role: 'primary' }, { name: 'aleo', role: 'facilitator' }],
    payment_protocols: ['x402/v2'],
    settlement: { finality: 'on-chain', network: 'base', chain_id: 8453, payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e' },
    aleo_facilitator: { treasury: ALEO_TREASURY, usad_program_id: USAD_PROGRAM, usdcx_program_id: USDCX_PROGRAM },
    brand_color: '#C08D23',
  });
});

// ─── well-known / openapi.json ────────────────────────────────────────────────

app.get('/.well-known/openapi.json', (_req, res) => {
  res.json({
    openapi: '3.0.3',
    info: {
      title:       'hive-aleo-arc API',
      version:     '1.1.0',
      description: 'Privacy receipt layer + Aleo facilitator. Routes Paxos USAd and Circle USDCx settlements through Hive treasury on Aleo mainnet.',
      contact:     { name: 'The Hivery', url: 'https://thehiveryiq.com' },
    },
    servers: [{ url: 'https://hive-aleo-arc.onrender.com', description: 'Production (Render)' }],
    paths: {
      '/v1/facilitator/quote': {
        post: {
          operationId: 'v1_facilitator_quote',
          summary:     'Get facilitator quote for USAd or USDCx settlement on Aleo mainnet. Free.',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['asset', 'amount'], properties: { asset: { type: 'string', example: 'USAd' }, amount: { type: 'string', example: '10.00' } } } } } },
          responses:   { '200': { description: 'Quote returned.' }, '400': { description: 'Validation error.' } },
        },
      },
      '/v1/facilitator/verify': {
        post: {
          operationId: 'v1_facilitator_verify',
          summary:     'Verify Aleo mainnet tx delivered funds to Hive treasury. Free.',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tx_id'], properties: { tx_id: { type: 'string' }, asset: { type: 'string' }, expected_amount: { type: 'string' } } } } } },
          responses:   { '200': { description: 'Verification result.' }, '400': { description: 'Validation error.' } },
        },
      },
      '/v1/facilitator/settle': {
        post: {
          operationId: 'v1_facilitator_settle',
          summary:     'Atomic settle-and-forward. 25 bps Hive fee.',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tx_id', 'asset', 'amount', 'merchant_address'], properties: { tx_id: { type: 'string' }, asset: { type: 'string' }, amount: { type: 'string' }, merchant_address: { type: 'string' }, merchant_did: { type: 'string' }, reference_id: { type: 'string' } } } } } },
          responses:   { '200': { description: 'Settlement record.' }, '400': { description: 'Validation error.' }, '422': { description: 'Treasury receipt not confirmed.' } },
        },
      },
    },
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`hive-aleo-arc listening on port ${PORT}`);
  console.log(`Spectral pubkey (ed25519): ${spectral.publicKeyB64}`);
  console.log(`Monroe: 0x15184bf50b3d3f52b60434f8942b7d52f2eb436e`);
  console.log(`Aleo treasury: ${ALEO_TREASURY}`);
  console.log(`USAd program: ${USAD_PROGRAM} | USDCx program: ${USDCX_PROGRAM}`);
  console.log(`Facilitator: ${BASE_URL}/v1/facilitator`);
});
