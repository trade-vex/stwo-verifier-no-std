use alloc::vec::Vec;
use alloc::string::String;
use thiserror::Error;
use core::array;

use crate::fields::qm31::SecureField;
use crate::fields::m31::BaseField;
use crate::channel::{Channel, MerkleChannel, MerkleHasher};
use crate::types::{
    component::Component,
    point::CirclePoint,
    proof::{StarkProof, InvalidOodsSampleStructure},
    error::VerificationError,
    commitment::{MerkleDecommitment, Tree},
    fri::{FriProof, FriConfig},
};

pub const PREPROCESSED_TRACE_IDX: usize = 0;
pub const SECURE_EXTENSION_DEGREE: usize = 4;

#[derive(Clone, Debug)]
pub struct CommitmentSchemeVerifier<MC: MerkleChannel> {
    pub trees: Vec<Tree>,
}

impl<MC: MerkleChannel> CommitmentSchemeVerifier<MC> {
    pub fn new(trees: Vec<Tree>) -> Self {
        Self { trees }
    }

    pub fn commit(
        &mut self,
        commitment: MC::H,
        log_degree_bounds: &[usize],
        channel: &mut MC::C,
    ) {
        // Implementation would verify the commitment matches the expected structure
        // This is a placeholder for the actual implementation
    }

    pub fn verify_values(
        &mut self,
        sample_points: Vec<Vec<Vec<CirclePoint<SecureField>>>>,
        proof: crate::types::proof::CommitmentSchemeProof<MC::H>,
        channel: &mut MC::C,
    ) -> Result<(), VerificationError> {
        // Implementation would verify the sampled values match the commitments
        // This is a placeholder for the actual implementation
        Ok(())
    }
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

    let components = crate::types::component::Components {
        components: components.to_vec(),
        n_preprocessed_columns,
    };
    let random_coeff = channel.draw_felt();

    // Read composition polynomial commitment.
    commitment_scheme.commit(
        *proof.0.commitments.last().unwrap(),
        &[components.composition_log_degree_bound(); SECURE_EXTENSION_DEGREE],
        channel,
    );

    // Draw OODS point.
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    // Get mask sample points relative to oods point.
    let mut sample_points = components.mask_points(oods_point);
    // Add the composition polynomial mask points.
    sample_points.push(vec![vec![oods_point]; SECURE_EXTENSION_DEGREE]);

    let composition_oods_eval = proof.extract_composition_oods_eval().map_err(|_| {
        VerificationError::InvalidStructure("Unexpected sampled_values structure".to_string())
    })?;

    if composition_oods_eval
        != components.eval_composition_polynomial_at_point(
            oods_point,
            &proof.0.sampled_values,
            random_coeff,
        )
    {
        return Err(VerificationError::OodsNotMatching);
    }

    commitment_scheme.verify_values(sample_points, proof.0, channel)
}