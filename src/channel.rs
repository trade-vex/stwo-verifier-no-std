use crate::fields::qm31::SecureField;
use crate::fields::m31::BaseField;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::cmp::Eq;
// Merkle Channel
pub trait MerkleChannel: Default {
    type C: Channel;
    type H: MerkleHasher;
    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasher>::Hash);
}

// Channel
pub trait Channel: Default + Clone + Debug {
    const BYTES_PER_HASH: usize;

    fn trailing_zeros(&self) -> u32;

    // Mix functions.
    fn mix_felts(&mut self, felts: &[SecureField]);
    fn mix_u64(&mut self, value: u64);

    // Draw functions.
    fn draw_felt(&mut self) -> BaseField;
    fn draw_secure_felt(&mut self) -> SecureField;

    // Prover might need these, keep for now?
    // fn draw_felts(&mut self, n_felts: usize) -> Vec<SecureField>;
    // fn draw_random_bytes(&mut self) -> Vec<u8>;
}

// Corrected MerkleHasher trait definition
pub trait MerkleHasher: Debug + Default + Clone {
    type Hash: Clone + Debug + Eq;
    // Use correct signature from prover
    fn hash_node(
        children_hashes: Option<(Self::Hash, Self::Hash)>,
        column_values: &[BaseField],
    ) -> Self::Hash;
}