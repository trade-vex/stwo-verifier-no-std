use core::fmt::{self, Debug, Display};
use alloc::string::String;

#[derive(Clone, Debug)]
pub enum VerificationError {
    InvalidStructure(String),
    MerkleProof,
    ProofOfWork,
    OodsNotMatching,
    FriQueriesNotSampled,
    FriInsufficientWitness,
    FriInvalidNumLayers,
    FriFirstLayerEvaluationsInvalid,
    FriFirstLayerCommitmentInvalid(String),
    FriInnerLayerCommitmentInvalid { layer_index: usize, error_msg: String },
    FriInnerLayerEvaluationsInvalid { layer_index: usize },
    FriLastLayerDegreeInvalid,
    FriLastLayerEvaluationsInvalid,
    MerkleVerificationFailed(usize, String),
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::InvalidStructure(msg) => write!(f, "Invalid proof structure: {}", msg),
            VerificationError::MerkleProof => write!(f, "Merkle proof verification failed (Generic)"),
            VerificationError::ProofOfWork => write!(f, "Proof of work verification failed"),
            VerificationError::OodsNotMatching => write!(f, "Out-of-domain sampling mismatch"),
            VerificationError::FriQueriesNotSampled => write!(f, "FRI queries were not sampled before decommitment"),
            VerificationError::FriInsufficientWitness => write!(f, "FRI proof witness insufficient"),
            VerificationError::FriInvalidNumLayers => write!(f, "FRI proof contains an invalid number of layers"),
            VerificationError::FriFirstLayerEvaluationsInvalid => write!(f, "FRI first layer evaluations invalid"),
            VerificationError::FriFirstLayerCommitmentInvalid(err) => write!(f, "FRI first layer commitment invalid: {}", err),
            VerificationError::FriInnerLayerCommitmentInvalid { layer_index, error_msg } => write!(f, "FRI inner layer {} commitment invalid: {}", layer_index, error_msg),
            VerificationError::FriInnerLayerEvaluationsInvalid { layer_index } => write!(f, "FRI inner layer {} evaluations invalid", layer_index),
            VerificationError::FriLastLayerDegreeInvalid => write!(f, "FRI last layer degree invalid"),
            VerificationError::FriLastLayerEvaluationsInvalid => write!(f, "FRI last layer evaluations invalid"),
            VerificationError::MerkleVerificationFailed(layer, msg) => write!(f, "Merkle verification failed (Layer/Context {}): {}", layer, msg),
        }
    }
}

// If needed for interop with std errors (e.g. via thiserror features later), 
// you might need a feature gate.
// #[cfg(feature = "std")]
// impl std::error::Error for VerificationError {} 