use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum VerificationError {
    #[error("Proof has invalid structure: {0}.")]
    InvalidStructure(String),
    #[error("Merkle verification failed.")]
    Merkle,
    #[error("The composition polynomial OODS value does not match the trace OODS values (DEEP-ALI failure).")]
    OodsNotMatching,
    #[error("FRI verification failed.")]
    Fri,
    #[error("Proof of work verification failed.")]
    ProofOfWork,
} 