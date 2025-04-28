use crate::fields::qm31::SecureField;
use crate::fields::m31::BaseField;
use core::fmt::Debug;
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
}

pub trait MerkleHasher {
    type Hash;
    fn hash(&self, data: &[u8]) -> Self::Hash;
}