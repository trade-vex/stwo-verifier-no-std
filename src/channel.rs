use crate::backend::{compress, Blake2sMerkleHasher};
use crate::fields::m31::N_BYTES_FELT;
use crate::SECURE_EXTENSION_DEGREE;
use crate::backend::Blake2sHasher;
use crate::fields::IntoSlice;
use crate::backend::Blake2sHash;
use crate::fields::qm31::SecureField;
use crate::fields::m31::{BaseField, P};
use core::cmp::Eq;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default)]
pub struct ChannelTime {
    pub n_challenges: usize,
    pub n_sent: usize,
    pub n_received: usize,
}

impl ChannelTime {
    pub fn inc_sent(&mut self) {
        self.n_sent += 1;
    }

    pub fn inc_received(&mut self) {
        self.n_received += 1;
    }

    const fn inc_challenges(&mut self) {
        self.n_challenges += 1;
        self.n_sent = 0;
    }
}

// Channel
pub trait Channel: Default + Clone {
    const BYTES_PER_HASH: usize;

    fn trailing_zeros(&self) -> u32;

    // Mix functions.
    fn mix_felts(&mut self, felts: &[SecureField]);
    fn mix_u64(&mut self, value: u64);

    // Draw functions.
    fn draw_felt(&mut self) -> SecureField;
    fn draw_random_bytes(&mut self) -> Vec<u8>;

    // Prover might need these, keep for now?
    // fn draw_felts(&mut self, n_felts: usize) -> Vec<SecureField>;
    
}

pub trait MerkleChannel: Default {
    type C: Channel;
    type H: MerkleHasher;
    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasher>::Hash);
}

// Corrected MerkleHasher trait definition
pub trait MerkleHasher: Default + Clone {
    type Hash: Clone 
        + AsRef<[u8]>
        + Eq 
        + Serialize 
        + for<'de> Deserialize<'de>;
    // Use correct signature from prover
    fn hash_node(
        children_hashes: Option<(Self::Hash, Self::Hash)>,
        column_values: &[BaseField],
    ) -> Self::Hash;
}

pub const BLAKE_BYTES_PER_HASH: usize = 32;
pub const FELTS_PER_HASH: usize = 8;
/// A channel that can be used to draw random elements from a [Blake2sHash] digest.
#[derive(Default, Clone)]
pub struct Blake2sChannel {
    digest: Blake2sHash,
    pub channel_time: ChannelTime,
}

impl Blake2sChannel {
    pub const fn digest(&self) -> Blake2sHash {
        self.digest
    }
    pub const fn update_digest(&mut self, new_digest: Blake2sHash) {
        self.digest = new_digest;
        self.channel_time.inc_challenges();
    }
    /// Generates a uniform random vector of BaseField elements.
    fn draw_base_felts(&mut self) -> [BaseField; FELTS_PER_HASH] {
        // Repeats hashing with an increasing counter until getting a good result.
        // Retry probability for each round is ~ 2^(-28).
        loop {
            let u32s: [u32; FELTS_PER_HASH] = self
                .draw_random_bytes()
                .chunks_exact(N_BYTES_FELT) // 4 bytes per u32.
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // Retry if not all the u32 are in the range [0, 2P).
            if u32s.iter().all(|x| *x < 2 * P) {
                return u32s
                    .into_iter()
                    .map(|x| BaseField::reduce(x as u64))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
            }
        }
    }

    // Constructor using initial state
    pub fn new(initial_digest: Blake2sHash) -> Self {
        Self { 
            digest: initial_digest, 
            channel_time: ChannelTime::default() // Initialize time
        }
    }
}

impl Channel for Blake2sChannel {
    const BYTES_PER_HASH: usize = BLAKE_BYTES_PER_HASH;

    fn trailing_zeros(&self) -> u32 {
        // Use self.digest and apply slice
        let hash_bytes: [u8; 32] = self.digest.into(); // Assuming Blake2sHash implements Into<[u8; 32]>
        // Take first 16 bytes (LSB)
        let bytes_for_u128: [u8; 16] = hash_bytes[0..16].try_into().expect("Slice len != 16");
        u128::from_le_bytes(bytes_for_u128).trailing_zeros()
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let mut hasher = Blake2sHasher::new();
        hasher.update(self.digest.as_ref());
        hasher.update(IntoSlice::<u8>::into_slice(felts));

        self.update_digest(hasher.finalize());
    }

    fn mix_u64(&mut self, nonce: u64) {
        let digest: [u32; 8] = unsafe { core::mem::transmute(self.digest) };
        let mut msg = [0; 16];
        msg[0] = nonce as u32;
        msg[1] = (nonce >> 32) as u32;
        // rewrite without using std::array
        let res = compress(core::array::from_fn(|i| digest[i]), msg, 0, 0, 0, 0);

        // TODO(shahars) Channel should always finalize hash.
        self.update_digest(unsafe { core::mem::transmute::<[u32; 8], Blake2sHash>(res) });
    }

    fn draw_felt(&mut self) -> SecureField {
        let felts: [BaseField; FELTS_PER_HASH] = self.draw_base_felts();
        SecureField::from_m31_array(felts[..SECURE_EXTENSION_DEGREE].try_into().unwrap())
    }

    fn draw_random_bytes(&mut self) -> Vec<u8> {
        self.channel_time.inc_received();
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&self.digest.0);
        hash_input.extend_from_slice(&(self.channel_time.n_received as u64).to_le_bytes());
        self.digest = Blake2sHasher::hash(&hash_input);
        self.digest.0.to_vec()
    }
}

#[derive(Default)]
pub struct Blake2sMerkleChannel;

impl MerkleChannel for Blake2sMerkleChannel {
    type C = Blake2sChannel;
    type H = Blake2sMerkleHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasher>::Hash) {
        channel.update_digest(Blake2sHasher::concat_and_hash(
            &channel.digest(),
            &root,
        ));
    }
}