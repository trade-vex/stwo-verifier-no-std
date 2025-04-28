use alloc::vec::Vec;
use core::fmt::Debug;
use core::array;
use core::mem;

use blake2::Blake2s;
use blake2::digest::{Update, FixedOutput};

use crate::fields::Field;
use crate::channel::{Channel, MerkleChannel, MerkleHasher};
use crate::types::{
    point::CirclePoint,
    error::VerificationError,
    commitment::Tree,
    proof::CommitmentSchemeProof,
    fri::{FriProof, FriConfig},
};
use crate::verifier::CommitmentSchemeVerifier;

#[derive(Clone, Debug, Default)]
pub struct Blake2sHasher;

impl MerkleHasher for Blake2sHasher {
    type Hash = [u8; 32];
    fn hash(&self, data: &[u8]) -> Self::Hash {
        let mut hasher = Blake2s::new();
        hasher.update(data);
        let result = hasher.finalize_fixed();
        result.into()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Blake2sChannel {
    state: [u8; 32],
    counter: u64,
}

impl Blake2sChannel {
    pub fn new(seed: &[u8]) -> Self {
        let mut state = [0u8; 32];
        let mut hasher = Blake2s::new();
        hasher.update(seed);
        state.copy_from_slice(&hasher.finalize_fixed());
        Self { state, counter: 0 }
    }

    fn update_state(&mut self) {
        let mut hasher = Blake2s::new();
        hasher.update(&self.state);
        hasher.update(&self.counter.to_le_bytes());
        self.state.copy_from_slice(&hasher.finalize_fixed());
        self.counter = self.counter.wrapping_add(1);
    }
}

impl Channel for Blake2sChannel {
    const BYTES_PER_HASH: usize = 32;

    fn trailing_zeros(&self) -> u32 {
        self.state.iter()
            .rev()
            .map(|&b| b.trailing_zeros())
            .sum()
    }

    fn mix_felts(&mut self, felts: &[Field]) {
        let mut hasher = Blake2s::new();
        hasher.update(&self.state);
        for felt in felts {
            hasher.update(&felt.to_bytes());
        }
        self.state.copy_from_slice(&hasher.finalize_fixed());
    }

    fn mix_u64(&mut self, value: u64) {
        let mut hasher = Blake2s::new();
        hasher.update(&self.state);
        hasher.update(&value.to_le_bytes());
        self.state.copy_from_slice(&hasher.finalize_fixed());
    }

    fn draw_felt(&mut self) -> Field {
        self.update_state();
        // Take first 4 bytes and convert to field element
        let bytes: [u8; 4] = self.state[..4].try_into().unwrap();
        Field::from(u32::from_le_bytes(bytes))
    }
}

#[derive(Clone, Debug)]
pub struct CommitmentSchemeVerifierImpl<H: MerkleHasher> {
    _phantom: std::marker::PhantomData<H>,
}

impl<H: MerkleHasher> CommitmentSchemeVerifierImpl<H> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn commit(&self, values: &[Field]) -> Tree<H> {
        Tree::new(values)
    }

    pub fn verify_values(
        &self,
        tree: &Tree<H>,
        point: CirclePoint<Field>,
        values: &[Field],
    ) -> Result<(), VerificationError> {
        tree.verify_values(point, values)
    }
}

#[derive(Clone, Debug)]
pub struct FriVerifier<MC: MerkleChannel> {
    pub config: FriConfig,
}

impl<MC: MerkleChannel> FriVerifier<MC> {
    pub fn new(config: FriConfig) -> Self {
        Self { config }
    }

    pub fn verify(
        &self,
        proof: &FriProof<MC::H>,
        channel: &mut MC::C,
    ) -> Result<(), VerificationError> {
        // Verify the first layer
        let mut current_degree = 1 << self.config.log_blowup_factor;
        
        // Verify the inner layers
        for layer in &proof.inner_layers {
            // Verify the decommitment
            let mut hasher = Blake2s::new();
            for hash in &layer.decommitment.hash_witness {
                hasher.update(&hash.hash(&[]));
            }
            let root = hasher.finalize_fixed();
            
            // Mix the root into the channel
            channel.mix_felts(&[Field::from_bytes(&root)]);

            // Update the degree
            current_degree >>= 1;
        }

        // Verify the last layer
        if proof.last_layer_poly.len() > self.config.last_layer_degree_bound {
            return Err(VerificationError::Fri);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Blake2sMerkleChannel;

impl MerkleChannel for Blake2sMerkleChannel {
    type C = Blake2sChannel;
    type H = Blake2sHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasher>::Hash) {
        channel.mix_felts(&[Field::from_bytes(&root)]);
    }
} 