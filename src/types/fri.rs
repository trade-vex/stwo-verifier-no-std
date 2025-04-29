use alloc::vec::Vec;
use core::fmt::Debug;
use crate::fields::qm31::SecureField;
use crate::channel::MerkleHasher;
use crate::types::commitment::MerkleDecommitment;
use serde::{Deserialize, Serialize};
use crate::channel::Channel;

#[derive(Clone)]
pub struct FriProof<H: MerkleHasher> where H::Hash: Clone {
    pub first_layer: FriLayerProof<H>,
    pub inner_layers: Vec<FriLayerProof<H>>,
    pub last_layer_poly: Vec<SecureField>,
}

#[derive(Clone)]
pub struct FriLayerProof<H: MerkleHasher> where H::Hash: Clone {
    pub fri_witness: Vec<SecureField>,
    pub decommitment: MerkleDecommitment<H>,
    pub commitment: H::Hash,
}

/// Bound on the degree of a circle polynomial.
/// The degree is defined as the maximal sum of x and y degrees for each monomial.
/// The circle polynomial has a maximum of (2*points - 1) coefficients
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FriCirclePolyDegreeBound {
    log_degree_bound: usize,
}

impl FriCirclePolyDegreeBound {
    pub fn new(log_degree_bound: usize) -> Self {
        Self { log_degree_bound }
    }
}

/// A configuration for a FRI proof.
/// Defines the parameters for the FRI protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriConfig {
    pub log_blowup_factor: usize,
    pub log_last_layer_degree_bound: usize,
    pub n_queries: usize,
}

impl FriConfig {
    pub fn new(log_blowup_factor: usize, log_last_layer_degree_bound: usize, n_queries: usize) -> Self {
        Self {
            log_blowup_factor,
            log_last_layer_degree_bound,
            n_queries,
        }
    }

    pub const fn security_bits(&self) -> u32 {
        (self.log_blowup_factor * self.n_queries) as u32
    }

    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_blowup_factor as u64);
        channel.mix_u64(self.n_queries as u64);
        channel.mix_u64(self.log_last_layer_degree_bound as u64);
    }
} 