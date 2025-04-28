use alloc::vec::Vec;
use core::fmt::Debug;
use crate::fields::qm31::SecureField;
use crate::channel::MerkleHasher;

#[derive(Clone, Debug)]
pub struct MerkleDecommitment<H: MerkleHasher> {
    pub hash_witness: Vec<H>,
    pub column_witness: Vec<Vec<SecureField>>,
}

#[derive(Clone, Debug)]
pub struct Tree {
    pub column_log_sizes: Vec<usize>,
} 