# quanta-wasm

[![npm](https://img.shields.io/npm/v/quanta-wasm)](https://www.npmjs.com/package/quanta-wasm)
[![crates.io](https://img.shields.io/crates/v/quanta-wasm)](https://crates.io/crates/quanta-wasm)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

WebAssembly bindings for QuantaChain post-quantum cryptography — compiled from Rust using `wasm-pack`.

Provides Falcon-512 key generation, signing, and verification directly in the browser or Node.js at near-native speed. No server round-trips for cryptographic operations.

---

## When to Use This Package

| Use case | Package |
|----------|---------|
| Build wallets, explorers, or integrations | Use **`quanta-sdk`** (bundles this internally) |
| Need raw Falcon-512 WASM operations | Use **`quanta-wasm`** directly |

Most developers should install `quanta-sdk` instead.

---

## Installation

```bash
npm install quanta-wasm
```

Or with Cargo (Rust):

```toml
[dependencies]
quanta-wasm = "0.1"
```

---

## Browser Usage

```typescript
import init, {
  generate_keypair,
  sign_message,
  verify_signature,
  generate_mnemonic,
  keypair_from_mnemonic
} from 'quanta-wasm';

// Must call init() before any other function in browser environments
await init();

// Generate a Falcon-512 keypair
const keypair = generate_keypair();
console.log('Public key length:', keypair.public_key.length);   // 897 bytes
console.log('Address:', keypair.address);                        // "0x..."

// Sign a message
const message = new TextEncoder().encode("hello quanta");
const signature = sign_message(keypair.secret_key, message);

// Verify
const valid = verify_signature(keypair.public_key, message, signature);
console.log('Valid:', valid);   // true
```

---

## Node.js Usage

In Node.js environments, initialization is automatic:

```typescript
const { generate_keypair, generate_mnemonic } = require('quanta-wasm');

// No await needed in Node.js
const keypair = generate_keypair();
console.log('Address:', keypair.address);

const mnemonic = generate_mnemonic();
console.log('Mnemonic:', mnemonic);   // 24 BIP39 words
```

---

## API Reference

### `generate_keypair() → Keypair`

Generates a fresh Falcon-512 keypair.

```typescript
const keypair = generate_keypair();
// keypair.public_key  — Uint8Array (897 bytes)
// keypair.secret_key  — Uint8Array (~1,281 bytes) — never share or send
// keypair.address     — string "0x" + hex(SHA3-256(pubkey)[0:20])
```

---

### `generate_mnemonic() → string`

Generates a cryptographically secure 24-word BIP39 mnemonic.

```typescript
const mnemonic = generate_mnemonic();
// "word1 word2 word3 ... word24"
```

---

### `keypair_from_mnemonic(mnemonic: string) → Keypair`

Derives a deterministic Falcon-512 keypair from a 24-word BIP39 mnemonic.

```typescript
const keypair = keypair_from_mnemonic("word1 word2 ... word24");
// Same mnemonic always produces the same keypair and address
```

---

### `sign_message(secret_key: Uint8Array, message: Uint8Array) → Uint8Array`

Signs a message with a Falcon-512 secret key. Returns the signed-message blob (33–698 bytes).

```typescript
const signature = sign_message(keypair.secret_key, messageBytes);
```

In the Quanta protocol, the message is always the canonical signing hash:
```
SHA3-256("QUANTA_TX_V1:" || signing_bytes)
```

The `quanta-sdk` handles this automatically — use `TransactionBuilder.sign()` instead of calling this directly for transactions.

---

### `verify_signature(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array) → boolean`

Verifies a Falcon-512 signature.

```typescript
const valid = verify_signature(pubkey, message, signature);
```

Returns `false` (does not throw) for any invalid input.

---

## Cryptographic Details

- **Algorithm**: Falcon-512 (NTRU lattice-based, NIST Level 1)
- **Public key**: exactly 897 bytes (consensus-enforced in the Quanta protocol)
- **Secret key**: ~1,281 bytes
- **Signature**: variable 33–698 bytes
- **Security**: 128-bit classical, 64-bit post-quantum (Grover's)
- **No known quantum attack**: Falcon relies on NTRU lattice problems — not affected by Shor's algorithm

### Build Flags

The Rust source is compiled with:
- `target-feature=+strict-float` — enforces IEEE 754 compliance for consensus determinism across x86_64 and ARM64
- `opt-level = "z"` — minimize WASM binary size
- `codegen-units = 1` — reproducible builds

---

## Ecosystem

| Package | Description |
|---------|-------------|
| [`quanta-sdk`](https://www.npmjs.com/package/quanta-sdk) | Full JS/TS SDK — wallets, transactions, node client |
| [`quanta-wasm`](https://www.npmjs.com/package/quanta-wasm) | This package — raw Falcon-512 WASM bindings |
| [Quanta Node](https://github.com/quantachain/quanta) | Rust node source — runs the blockchain |

---

## License

Apache-2.0 — see [LICENSE](LICENSE)
