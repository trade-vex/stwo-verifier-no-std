#![no_std]

use core::ops::{Deref, DerefMut};

use alloc::{string::String, vec};
use alloc::{string::ToString, vec::Vec};
use array_init::try_array_init;
use serde::{Deserialize, Serialize};
use thiserror_no_std::Error;

use crate::{
    air::{Component, Components},
    channel::{Channel, MerkleChannel},
    circle::CirclePoint,
    constraint_framework::PREPROCESSED_TRACE_IDX,
    fields::{qm31::SecureField, secure_column::SECURE_EXTENSION_DEGREE},
    fri::FriVerificationError,
    pcs::{CommitmentSchemeProof, CommitmentSchemeVerifier},
    vcs::{ops::MerkleHasher, verifier::MerkleVerificationError},
};

extern crate alloc;

pub mod air;
pub mod backend;
pub mod channel;
pub mod circle;
pub mod constraint_framework;
pub mod constraints;
pub mod fft;
pub mod fields;
pub mod fri;
pub mod lookups;
pub mod pcs;
pub mod poly;
pub mod proof_of_work;
pub mod queries;
pub mod utils;
pub mod vcs;

/// A vector in which each element relates (by index) to a column in the trace.
pub type ColumnVec<T> = Vec<T>;

/// A vector of [ColumnVec]s. Each [ColumnVec] relates (by index) to a component in the air.
#[derive(Debug, Clone)]
pub struct ComponentVec<T>(pub Vec<ColumnVec<T>>);

impl<T> ComponentVec<T> {
    pub fn flatten(self) -> ColumnVec<T> {
        self.0.into_iter().flatten().collect()
    }
}

impl<T> ComponentVec<ColumnVec<T>> {
    pub fn flatten_cols(self) -> Vec<T> {
        self.0.into_iter().flatten().flatten().collect()
    }
}

impl<T> Default for ComponentVec<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> Deref for ComponentVec<T> {
    type Target = Vec<ColumnVec<T>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for ComponentVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[macro_export]
macro_rules! parallel_iter {
    ($i: expr) => {{
        #[cfg(not(feature = "parallel"))]
        let iter = $i.into_iter();

        #[cfg(feature = "parallel")]
        let iter = $i.into_par_iter();

        iter
    }};
}

pub fn verify<MC: MerkleChannel>(
    components: &[&dyn Component],
    channel: &mut MC::C,
    commitment_scheme: &mut CommitmentSchemeVerifier<MC>,
    proof: StarkProof<MC::H>,
) -> Result<(), VerificationError> {
    let n_preprocessed_columns = commitment_scheme.trees[PREPROCESSED_TRACE_IDX]
        .column_log_sizes
        .len();
    kprintln!("pre-processed columns: {}", n_preprocessed_columns);
    let components = Components {
        components: components.to_vec(),
        n_preprocessed_columns,
    };
    let random_coeff = channel.draw_felt();
    kprintln!("random coefficient: {}", random_coeff);
    kprintln!(
        "composition log degree bound: {}",
        components.composition_log_degree_bound()
    );
    kprintln!("last commitment: {}", proof.commitments.last().unwrap());

    // Read composition polynomial commitment.
    commitment_scheme.commit(
        *proof.commitments.last().unwrap(),
        &[components.composition_log_degree_bound(); SECURE_EXTENSION_DEGREE],
        channel,
    );

    // Draw OODS point.
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);
    kprintln!("oods point: {:?}", oods_point);
    // Get mask sample points relative to oods point.
    let mut sample_points = components.mask_points(oods_point);
    // kprintln!("mask points: {:?}", sample_points);
    // Add the composition polynomial mask points.
    sample_points.push(vec![vec![oods_point]; SECURE_EXTENSION_DEGREE]);

    let composition_oods_eval = proof.extract_composition_oods_eval().map_err(|_| {
        VerificationError::InvalidStructure("Unexpected sampled_values structure".to_string())
    })?;
    kprintln!("composition OODS eval: {}", composition_oods_eval);
    if composition_oods_eval
        != components.eval_composition_polynomial_at_point(
            oods_point,
            &proof.sampled_values,
            random_coeff,
        )
    {
        return Err(VerificationError::OodsNotMatching);
    }
    kprintln!("Verified oods eval matches composition polynomial evaluation.");
    commitment_scheme.verify_values(sample_points, proof.0, channel)
}

/// Error when the sampled values have an invalid structure.
#[derive(Clone, Copy, Debug)]
pub struct InvalidOodsSampleStructure;

#[derive(Clone, Copy, Debug, Error)]
pub enum ProvingError {
    #[error("Constraints not satisfied.")]
    ConstraintsNotSatisfied,
}

#[derive(Clone, Debug, Error)]
pub enum VerificationError {
    #[error("Proof has invalid structure: {0}.")]
    InvalidStructure(String),
    #[error(transparent)]
    Merkle(#[from] MerkleVerificationError),
    #[error(
        "The composition polynomial OODS value does not match the trace OODS values
    (DEEP-ALI failure)."
    )]
    OodsNotMatching,
    #[error(transparent)]
    Fri(#[from] FriVerificationError),
    #[error("Proof of work verification failed.")]
    ProofOfWork,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkProof<H: MerkleHasher>(pub CommitmentSchemeProof<H>);

impl<H: MerkleHasher> StarkProof<H> {
    /// Extracts the composition trace Out-Of-Domain-Sample evaluation from the mask.
    fn extract_composition_oods_eval(&self) -> Result<SecureField, InvalidOodsSampleStructure> {
        // TODO(andrew): `[.., composition_mask, _quotients_mask]` when add quotients commitment.
        let [.., composition_mask] = &**self.sampled_values else {
            return Err(InvalidOodsSampleStructure);
        };

        let mut composition_cols = composition_mask.iter();

        let coordinate_evals = try_array_init(|_| {
            let col = &**composition_cols.next().ok_or(InvalidOodsSampleStructure)?;
            let [eval] = col.try_into().map_err(|_| InvalidOodsSampleStructure)?;
            Ok(eval)
        })?;

        // Too many columns.
        if composition_cols.next().is_some() {
            return Err(InvalidOodsSampleStructure);
        }

        Ok(SecureField::from_partial_evals(coordinate_evals))
    }
}

impl<H: MerkleHasher> Deref for StarkProof<H> {
    type Target = CommitmentSchemeProof<H>;

    fn deref(&self) -> &CommitmentSchemeProof<H> {
        &self.0
    }
}

use core::fmt::{self, Write};

#[cfg(feature = "std")]
extern crate std;

struct DummyWriter;

impl Write for DummyWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        #[cfg(feature = "std")]
        {
            use std::io::{self, Write as _};
            let _ = io::stdout().write_all(s.as_bytes());
            let _ = io::stdout().flush();
        }

        // In real no_std builds, do nothing or forward to serial.
        Ok(())
    }
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ({
        let _ = core::fmt::write(&mut DummyWriter, format_args!($($arg)*));
    });
}

#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($fmt:expr) => ($crate::kprint!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::kprint!(concat!($fmt, "\n"), $($arg)*));
}
