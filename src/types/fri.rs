use alloc::vec::Vec;
use core::fmt::Debug;
use crate::fields::qm31::SecureField;
use crate::channel::MerkleHasher;
use crate::types::commitment::MerkleDecommitment;

#[derive(Clone, Debug)]
pub struct FriProof<H: MerkleHasher> {
    pub first_layer: FriLayerProof<H>,
    pub inner_layers: Vec<FriLayerProof<H>>,
    pub last_layer_poly: Vec<SecureField>,
}

#[derive(Clone, Debug)]
pub struct FriLayerProof<H: MerkleHasher> {
    pub fri_witness: Vec<SecureField>,
    pub decommitment: MerkleDecommitment<H>,
    pub commitment: H,
}

#[derive(Clone, Debug)]
pub struct FriConfig {
    pub log_blowup_factor: usize,
    pub last_layer_degree_bound: usize,
} 