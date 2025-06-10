# STWO Verifier (no-std)

A no-std compatible verifier implementation for [STWO](https://github.com/starkware-libs/stwo), a next-generation CSTARK prover and verifier written in Rust.

## Overview

This project provides a no-std compatible verifier for STWO proofs, allowing verification in constrained environments where the standard library is not available. It's based on STWO commit [a194fad](https://github.com/starkware-libs/stwo/commit/a194fad).

## Features

- No-std compatible implementation
- Support for Circle STARK verification
- Minimal dependencies
- Compatible with stable Rust for compilation
- Test suite

## Requirements

- Rust stable toolchain for compilation
- Rust nightly-2025-01-02 for running tests

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
stwo-verifier-no-std = { git = "https://github.com/trad-vex/stwo-verifier-no-std"}
```

## Usage

Here's a complete example of how to use the verifier with a Fibonacci sequence proof:

```rust
use stwo_verifier_no_std::{
    channel::Blake2sChannel,
    constraint_framework::{FrameworkComponent, FrameworkEval, TraceLocationAllocator},
    fields::qm31::SecureField,
    pcs::{CommitmentSchemeVerifier, PcsConfig},
    vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
    verify, StarkProof,
};

// 1. Define your constraint evaluator
#[derive(Clone)]
struct FibonacciEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for FibonacciEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut a = eval.next_trace_mask();
        let mut b = eval.next_trace_mask();
        for _ in 2..100 { // Example with 100 steps
            let c = eval.next_trace_mask();
            eval.add_constraint(c.clone() - (a.square() + b.square()));
            a = b;
            b = c;
        }
        eval
    }
}

// 2. Verify a proof
fn verify_proof(proof_json: &str) -> Result<(), Error> {
    // Parse the proof
    let proof: StarkProof<Blake2sMerkleHasher> = serde_json::from_str(proof_json)?;
    
    // Setup verification
    let config = PcsConfig::default();
    let verifier_channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    
    // Create the component for verification
    let component = FrameworkComponent::new(
        &mut TraceLocationAllocator::default(),
        FibonacciEval { log_n_rows: 6 }, // Example with 2^6 rows
        SecureField::zero(),
    );
    
    // Commit to the proof
    let sizes = component.trace_log_degree_bounds();
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    
    // Verify the proof
    verify(&[&component], verifier_channel, commitment_scheme, proof)
}
```

## Development

### Building

The project can be built using stable Rust:

```bash
cargo build
```

### Testing

Tests require the nightly-2025-01-02 toolchain:

```bash
rustup override set nightly-2025-01-02
cargo test
```

## Project Structure

- `src/` - Main source code
  - `air/` - AIR (Algebraic Intermediate Representation) implementation
  - `backend/` - Backend implementations
  - `channel/` - Channel implementation
  - `constraint_framework/` - Constraint framework
  - `fields/` - Field implementations
  - `fri/` - FRI (Fast Reed-Solomon Interactive) implementation
  - `lookups/` - Lookup implementations
  - `pcs/` - Polynomial commitment scheme
  - `poly/` - Polynomial implementations
  - `vcs/` - Vector commitment scheme

## License

This project is licensed under the Apache 2.0 license.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 