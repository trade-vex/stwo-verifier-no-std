use serde::{Deserialize, Serialize};
use crate::fri::FriConfig;
use crate::channel::Channel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcsConfig {
    pub pow_bits: u32,
    pub fri_config: FriConfig,
}

impl PcsConfig {
    pub fn new(pow_bits: u32, fri_config: FriConfig) -> Self {
        Self { pow_bits, fri_config }
    }

    pub const fn security_bits(&self) -> u32 {
        self.pow_bits + self.fri_config.security_bits()
    }

    pub fn mix_into(&self, channel: &mut impl Channel) {
        let Self {
            pow_bits,
            fri_config,
        } = self;
        channel.mix_u64(*pow_bits as u64);
        fri_config.mix_into(channel);
    }
}

// Add a default if needed, matching prover's
impl Default for PcsConfig {
    fn default() -> Self {
        Self {
            pow_bits: 5,
            fri_config: FriConfig::new(0, 1, 3), // Ensure FriConfig::new exists/matches
        }
    }
}

// TODO: Define CommitmentSchemeProof here if needed, adapting from prover
// pub struct CommitmentSchemeProof<H: MerkleHasher> { ... } 