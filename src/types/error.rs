use core::fmt::{self, Debug, Display};
use alloc::string::String;

#[derive(Clone, Debug)]
pub enum VerificationError {
    InvalidStructure(String),
    MerkleProof,
    ProofOfWork,
    OodsNotMatching,
    FriCommitment,
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::InvalidStructure(msg) => write!(f, "Invalid proof structure: {}", msg),
            VerificationError::MerkleProof => write!(f, "Merkle proof verification failed"),
            VerificationError::ProofOfWork => write!(f, "Proof of work verification failed"),
            VerificationError::OodsNotMatching => write!(f, "Out-of-domain sampling mismatch"),
            VerificationError::FriCommitment => write!(f, "FRI commitment verification failed"),
        }
    }
}

// If needed for interop with std errors (e.g. via thiserror features later), 
// you might need a feature gate.
// #[cfg(feature = "std")]
// impl std::error::Error for VerificationError {} 