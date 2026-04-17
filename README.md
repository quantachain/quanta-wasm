# quanta-wasm

WASM bindings for QuantaChain PQC wallet operations.

This module provides high-performance, native-speed post-quantum cryptographic operations directly in the browser or Node.js via WebAssembly, compiled from Rust.

## Built for QuantaChain
As part of the Quanta ecosystem, `quanta-wasm` powers the fundamental cryptographic necessities of the protocol, compiled directly into WASM for cross-environment compatibility.

## Features

- **Falcon-512 Signatures**: Generate NIST Level 1 lattice signatures natively.
- **Fast and Lightweight**: Compiled with aggressive optimizations for reduced size, bringing Rust's extreme optimizations directly to frontend and server applications.
- **BIP39 Support**: Built-in 24-word seed phrase mnemonic support.

## Ecosystem

Instead of using this WASM core library directly, most developers should use the **`quanta-sdk`**:
[View `quanta-sdk` on NPM](https://www.npmjs.com/package/quanta-sdk)

## License
Apache-2.0
