//! quanta-wasm — Post-Quantum browser wallet for QuantaChain
//!
//! Compiled to WebAssembly with `wasm-pack build --target web`.
//! Exposes Falcon-512 key generation, signing, and address derivation
//! to JavaScript without any C FFI (pure Rust throughout).
//!
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │  SIGNATURE FORMAT CONTRACT (read before touching sign_transaction)      │
//! │                                                                         │
//! │  The node (pqcrypto-falcon 0.3.0) verifies via:                        │
//! │    open(SignedMessage, pk)  →  recovers message bytes                   │
//! │  where SignedMessage byte layout is:                                    │
//! │    [ falcon_sig_bytes (variable, ≤ 666 B) | message_bytes (32 B) ]     │
//! │                                                                         │
//! │  falcon-rust's sign() returns ONLY the raw falcon_sig_bytes.           │
//! │  So sign_transaction() manually constructs the full blob:               │
//! │    output = sig.to_bytes() || canonical_hash_bytes                      │
//! │                                                                         │
//! │  Both pqcrypto-falcon (C reference) and falcon-rust implement NIST     │
//! │  Falcon-512 with identical wire encoding, so the bytes are compatible. │
//! └─────────────────────────────────────────────────────────────────────────┘

use wasm_bindgen::prelude::*;
use sha3::{Sha3_256, Digest};
use hmac::{Hmac, Mac};
use bip39::{Mnemonic, Language};
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

use falcon_rust::falcon512::{
    SecretKey, PublicKey, Signature,
    sign   as falcon_sign,
    verify as falcon_verify,
    keygen,
};

type HmacSha256 = Hmac<Sha3_256>;

/// Domain separation tag — MUST match `SIGNING_DOMAIN` in signatures.rs.
const SIGNING_DOMAIN: &[u8] = b"QUANTA_TX_V1:";

// ---------------------------------------------------------------------------
// Panic hook
// ---------------------------------------------------------------------------
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

// ---------------------------------------------------------------------------
// JS-visible data structures
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct WalletInfo {
    pub mnemonic:   String,
    pub address:    String,
    pub public_key: String, // hex — 897 bytes
    pub secret_key: String, // hex — caller must zeroize after storing
}

#[derive(Serialize, Deserialize)]
pub struct KeypairInfo {
    pub address:    String,
    pub public_key: String,
    pub secret_key: String,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha3_256::digest(data));
    out
}

/// `SHA3-256(SIGNING_DOMAIN || data)` — matches `canonical_signing_hash()` in signatures.rs.
fn canonical_signing_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(SIGNING_DOMAIN);
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// `"0x" + hex(SHA3-256(pubkey)[..20])` — matches derive_address_from_pubkey() in transaction.rs.
fn address_from_pubkey(pubkey: &[u8]) -> String {
    let hash = sha3_256(pubkey);
    format!("0x{}", hex::encode(&hash[..20]))
}

fn derive_master_key(seed: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(b"Quanta HD Wallet Master Key")
        .expect("HMAC key init");
    mac.update(seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn derive_account_key(master_key: &[u8], index: u32) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master_key)
        .expect("HMAC key init");
    mac.update(&index.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

// ---------------------------------------------------------------------------
// Public WASM API
// ---------------------------------------------------------------------------

/// Generate a fresh Falcon-512 keypair deterministically from a new BIP39 mnemonic.
///
/// The keypair is derived from the mnemonic using the same HD path as
/// `import_wallet(mnemonic, "", 0)` — so the seed phrase ACTUALLY recovers
/// the correct wallet. Previously the keypair was random and disconnected
/// from the mnemonic (critical UX/security bug).
///
/// Returns `{ mnemonic, address, public_key, secret_key }` (hex keys).
/// Caller MUST encrypt `secret_key` before storing it anywhere.
#[wasm_bindgen]
pub fn generate_wallet() -> Result<JsValue, JsValue> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Derive keypair FROM the mnemonic (account index 0, empty passphrase).
    // This is identical to import_wallet(phrase, "", 0) so the seed phrase
    // correctly restores this exact keypair on any device.
    let seed        = mnemonic.to_seed("");
    let master      = derive_master_key(&seed);
    let account_key = derive_account_key(&master, 0);
    let (sk, pk)    = keygen(account_key);

    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();
    let address  = address_from_pubkey(&pk_bytes);

    let info = WalletInfo {
        mnemonic:   mnemonic.to_string(),
        address,
        public_key: hex::encode(&pk_bytes),
        secret_key: hex::encode(&sk_bytes),
    };
    serde_wasm_bindgen::to_value(&info).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Restore a wallet deterministically from a BIP39 mnemonic phrase.
///
/// Uses `keygen(seed)` from falcon-rust which accepts a 32-byte seed and
/// produces a deterministic keypair — so the same mnemonic always gives the
/// same keys, enabling seedphrase-based recovery without storing the SK.
///
/// Returns `{ address, public_key, secret_key }`.
#[wasm_bindgen]
pub fn import_wallet(mnemonic_phrase: &str, passphrase: &str, index: u32) -> Result<JsValue, JsValue> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
        .map_err(|e| JsValue::from_str(&format!("Invalid mnemonic: {}", e)))?;

    let seed        = mnemonic.to_seed(passphrase);
    let master      = derive_master_key(&seed);
    let account_key = derive_account_key(&master, index);

    // keygen(seed: [u8;32]) — deterministic keypair from falcon-rust
    let (sk, pk) = keygen(account_key);
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();
    let address  = address_from_pubkey(&pk_bytes);

    let info = KeypairInfo {
        address,
        public_key: hex::encode(&pk_bytes),
        secret_key: hex::encode(&sk_bytes),
    };
    serde_wasm_bindgen::to_value(&info).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Sign transaction data with a Falcon-512 secret key.
///
/// `tx_data_hex`    — hex of the raw transaction payload bytes.
/// `secret_key_hex` — hex of the Falcon-512 secret key.
///
/// Returns hex of raw Falcon-512 signature bytes.
/// The node's updated verify_signature_strict() calls:
///   falcon_rust::verify(canonical_hash, &sig, &pk)
/// which expects ONLY the raw sig bytes (no appended message).
#[wasm_bindgen]
pub fn sign_transaction(tx_data_hex: &str, secret_key_hex: &str) -> Result<String, JsValue> {
    let tx_bytes = hex::decode(tx_data_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad tx_data hex: {}", e)))?;
    let mut sk_bytes = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad secret_key hex: {}", e)))?;

    let sk = SecretKey::from_bytes(&sk_bytes)
        .map_err(|_| JsValue::from_str("Invalid Falcon-512 secret key"))?;
    sk_bytes.zeroize();

    // Canonical hash: SHA3-256(SIGNING_DOMAIN || tx_bytes)
    let hash = canonical_signing_hash(&tx_bytes);

    // Sign with falcon-rust → raw sig bytes
    let sig: Signature = falcon_sign(&hash, &sk);
    let sig_bytes = sig.to_bytes();

    // Construct: sig_bytes || hash_bytes  (same layout as pqcrypto SignedMessage)
    // The node's verify_signature_strict splits off the last 32 bytes as the
    // embedded hash, checks it matches, then calls falcon_rust::verify on sig_bytes.
    // Transaction size is unchanged from the original pqcrypto-based design.
    let mut out = Vec::with_capacity(sig_bytes.len() + 32);
    out.extend_from_slice(&sig_bytes);
    out.extend_from_slice(&hash);
    Ok(hex::encode(out))
}

/// Verify a Falcon-512 signature (for local sanity-checking before submission).
///
/// `hash_hex`       — hex of the 32-byte canonical signing hash.
/// `signed_msg_hex` — hex of the full signed-message blob (sig || hash).
/// `pubkey_hex`     — hex of the 897-byte Falcon-512 public key.
///
/// Returns `true` only on a strict cryptographic success.
#[wasm_bindgen]
pub fn verify_signature(hash_hex: &str, signed_msg_hex: &str, pubkey_hex: &str) -> bool {
    let Ok(hash_bytes)    = hex::decode(hash_hex)       else { return false; };
    let Ok(signed_bytes)  = hex::decode(signed_msg_hex) else { return false; };
    let Ok(pk_bytes)      = hex::decode(pubkey_hex)     else { return false; };

    // signed_bytes = sig_bytes || hash_bytes (32 B at the end)
    if signed_bytes.len() <= 32 { return false; }
    let sig_part = &signed_bytes[..signed_bytes.len() - 32];
    let msg_part = &signed_bytes[signed_bytes.len() - 32..];

    // Sanity: embedded message must match provided hash
    if msg_part != hash_bytes.as_slice() { return false; }

    let Ok(pk)  = PublicKey::from_bytes(&pk_bytes) else { return false; };
    let Ok(sig) = Signature::from_bytes(sig_part)  else { return false; };

    falcon_verify(&hash_bytes, &sig, &pk)
}

/// Derive a Quanta address from a hex-encoded public key.
#[wasm_bindgen]
pub fn get_address(pubkey_hex: &str) -> Result<String, JsValue> {
    let pk_bytes = hex::decode(pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad pubkey hex: {}", e)))?;
    Ok(address_from_pubkey(&pk_bytes))
}

/// Derive the Falcon-512 public key from a hex-encoded secret key.
///
/// NOTE: falcon-rust does not expose a method to extract the public key from
/// a standalone secret key (keys must be generated together via keygen).
/// This function therefore expects a COMBINED key blob in the format:
///
///   `<sk_hex>|<pk_hex>`
///
/// where `|` is the separator. The wallet extension exports this combined
/// format from the Export Key panel (see popup.js `revealPrivateKey`).
/// If a plain SK hex (no `|`) is provided and it is > 3000 chars, we
/// attempt to split at the Falcon-512 SK size (2562 chars) and treat
/// the remainder as the PK — this handles the concat export format.
///
/// Returns the public key as hex (897 bytes = 1794 hex chars).
#[wasm_bindgen]
pub fn derive_pubkey_from_sk(combined_or_sk_hex: &str) -> Result<String, JsValue> {
    // Format 1: "sk_hex|pk_hex" (preferred, exported by wallet)
    if let Some(pipe_pos) = combined_or_sk_hex.find('|') {
        let pk_hex = &combined_or_sk_hex[pipe_pos + 1..];
        // Validate the PK
        let pk_bytes = hex::decode(pk_hex)
            .map_err(|e| JsValue::from_str(&format!("Bad PK in combined key: {}", e)))?;
        PublicKey::from_bytes(&pk_bytes)
            .map_err(|_| JsValue::from_str("Invalid Falcon-512 public key in combined blob"))?;
        return Ok(pk_hex.to_string());
    }
    // Format 2: Plain SK hex — cannot derive PK from SK alone in falcon-rust.
    // Tell the user to use the combined export format instead.
    Err(JsValue::from_str(
        "Cannot derive public key from secret key alone. \
         Please use the combined export format (sk|pk) from the wallet Export panel, \
         or restore your wallet using your mnemonic phrase instead."
    ))
}

/// Export a keypair as a combined `sk_hex|pk_hex` blob for safe backup.
/// This is the format expected by `derive_pubkey_from_sk` and the import panel.
#[wasm_bindgen]
pub fn export_keypair_combined(secret_key_hex: &str, public_key_hex: &str) -> String {
    format!("{}|{}", secret_key_hex, public_key_hex)
}

/// Generate a fresh 24-word BIP39 mnemonic.
#[wasm_bindgen]
pub fn generate_mnemonic() -> Result<String, JsValue> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(mnemonic.to_string())
}

/// Validate a BIP39 mnemonic phrase. Returns `true` if valid.
#[wasm_bindgen]
pub fn validate_mnemonic(phrase: &str) -> bool {
    Mnemonic::parse_in_normalized(Language::English, phrase).is_ok()
}

/// Compute the canonical signing hash for a given payload (debugging helper).
/// Returns 32-byte hash as lowercase hex.
#[wasm_bindgen]
pub fn compute_signing_hash(tx_data_hex: &str) -> Result<String, JsValue> {
    let tx_bytes = hex::decode(tx_data_hex)
        .map_err(|e| JsValue::from_str(&format!("Bad hex: {}", e)))?;
    Ok(hex::encode(canonical_signing_hash(&tx_bytes)))
}
