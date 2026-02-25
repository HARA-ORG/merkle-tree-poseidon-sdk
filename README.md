# Merkle Tree Poseidon SDK

A TypeScript SDK for generating Merkle Tree proofs and selective disclosure inputs compatible with Poseidon-based Circom circuits.

This SDK is the companion to the official [HARA-ORG/circom-zk](https://github.com/HARA-ORG/circom-zk) repository, which contains the Circom circuit implementations and verification keys.

## Features

- **Poseidon Hashing**: Uses `circomlibjs` for Snark-friendly hashing on the BN254 curve.
- **Merkle Tree Proofs**: Generates inclusion proofs for a fixed-depth (8) Merkle Tree.
- **Selective Disclosure**: Supports generating proof inputs for:
  - **Numeric/Date Claims**: Proves that a value is greater than or equal to a threshold (e.g., age verification).
  - **String Claims**: Proves equality to a known value without revealing the value itself (using Poseidon hashes).
- **Identity Binding**: Binds credentials to a public commitment (e.g., a wallet address).

## Project Structure

```text
src/
├── core/           # Low-level primitives (Poseidon, Merkle, Encoding)
├── sdk/            # Main SDK interface
└── index.ts        # Library entry point
tests/
└── sdk.test.ts     # Logic simulation (mirrors Circom constraints)
```

## Installation

```bash
npm install
```

## Scripts

### Run Logic Simulation

Verifies the SDK's logic against a TypeScript implementation of the `SelectiveDisclosure.circom` constraints.

```bash
npm test
```

### Build SDK

Compiles TypeScript into the `dist/` directory.

```bash
npm run build
```

## Usage Example

```typescript
import { ZkIdentitySDK } from "merkle-tree-poseidon-sdk";

// 1. Define fields
const fields = [{ label: "credit_score", type: "number", value: 750 }];

// 2. Initialize SDK and build tree with a salt
const sdk = new ZkIdentitySDK(fields);
const salt = BigInt(123456);
await sdk.build(salt);

// 3. Generate input for SelectiveDisclosure circuit
const proofInput = await sdk.generateProofInput({
  label: "credit_score",
  identitySecret: BigInt("0x..."),
  publicCommitment: BigInt("0x..."),
  threshold: 700n,
});
```

## License

MIT
