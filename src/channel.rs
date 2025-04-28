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
    /// Generates a uniform random vector of SecureField elements.
    // fn draw_felts(&mut self, n_felts: usize) -> Vec<SecureField>;
    /// Returns a vector of random bytes of length `BYTES_PER_HASH`.
    // fn draw_random_bytes(&mut self) -> Vec<u8>;
}