use serde::{Deserialize, Serialize};
use crate::types::fri::FriConfig; // Use the FriConfig from this crate's types
use crate::channel::Channel; // Assuming Channel trait is accessible

// Copied and adapted from stwo/crates/prover/src/core/pcs/mod.rs
// Ensure fields and derives are suitable for no-std verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcsConfig {
    pub pow_bits: u32,
    pub fri_config: FriConfig,
}

impl PcsConfig {
    // We might not need all methods from the prover, only what's needed for verification.
    // security_bits might be useful for sanity checks.
    pub const fn security_bits(&self) -> u32 {
        self.pow_bits + self.fri_config.security_bits() // Assumes FriConfig has security_bits
    }

    // mix_into might be needed if the config is part of the channel transcript
    pub fn mix_into(&self, channel: &mut impl Channel) {
        let Self {
            pow_bits,
            fri_config,
        } = self;
        channel.mix_u64(*pow_bits as u64);
        fri_config.mix_into(channel); // Assumes FriConfig has mix_into
    }
}

// Default might not be strictly necessary for verifier, but can be useful
// Ensure the FriConfig::new call matches the definition in this crate
impl Default for PcsConfig {
    fn default() -> Self {
        Self {
            pow_bits: 5, // Default value from prover
            fri_config: FriConfig::new(0, 1, 3), // Use prover's default FriConfig values
        }
    }
}

// TODO: Define CommitmentSchemeProof here if needed, adapting from prover
// pub struct CommitmentSchemeProof<H: MerkleHasher> { ... } 