#![no_std]

extern crate alloc;

pub mod backend;
pub mod channel;
pub mod circle;
pub mod fields;
pub mod serde_utils;
pub mod types;
pub mod utils;
pub mod verifier;
pub mod vcs;
pub mod quotients;
pub mod fri_utils;
pub mod fft_utils;
pub mod constraints;

// Define globally used constants
pub const SECURE_EXTENSION_DEGREE: usize = 4;

// Keep only necessary re-exports if any, or none for now
// pub use types::point::CirclePoint;
// pub use types::poly::{LinePoly, Coset};
// pub use types::fri::FriConfig;
// pub use types::pcs::PcsConfig;
// pub use types::commitment::{/* MerkleTree, */ MerkleDecommitment};
// pub use types::proof::{StarkProof, CommitmentSchemeProof};
// pub use types::error::VerificationError;
// pub use channel::{Channel, MerkleChannel, Blake2sChannel, MerkleHasher};
// pub use backend::{FriVerifier, Blake2sMerkleHasher};
// pub use fields::m31::BaseField;
// pub use fields::qm31::SecureField;