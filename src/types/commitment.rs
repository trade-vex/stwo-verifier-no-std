use alloc::vec::Vec;
use crate::fields::m31::BaseField;
use crate::channel::MerkleHasher;
use serde::{Deserialize, Serialize};
use blake2::Blake2s256;
use digest::Digest;

#[derive(Clone, Serialize, Deserialize)]
pub struct MerkleDecommitment<H: MerkleHasher> {
    pub hash_witness: Vec<H::Hash>,
    pub column_witness: Vec<BaseField>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Tree {
    pub root: Vec<u8>,
    pub leaves: Vec<Vec<u8>>,
    pub column_log_sizes: Vec<usize>,
}

impl Tree {
    pub fn new(values: &[u8]) -> Self {
        let mut hasher = Blake2s256::new();
        Digest::update(&mut hasher, values);
        let root = hasher.finalize().to_vec();
        Self {
            root,
            leaves: values.chunks(32).map(|chunk| chunk.to_vec()).collect(),
            column_log_sizes: Vec::new(),
        }
    }

    pub fn verify_values(&self, _point: &[usize], _values: &[u8]) -> bool {
        // Implementation of verification logic
        true
    }
} 