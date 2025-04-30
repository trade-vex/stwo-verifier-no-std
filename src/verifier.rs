use alloc::vec::Vec;
use alloc::string::{String, ToString};
use alloc::format;
use thiserror::Error;
use core::array;
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};
use itertools::Itertools;

use crate::fields::qm31::SecureField;
use crate::fields::m31::BaseField;
use crate::channel::{Channel, MerkleChannel, MerkleHasher};
use crate::types::{
    component::Component,
    point::CirclePoint,
    proof::{StarkProof, InvalidOodsSampleStructure, CommitmentSchemeProof},
    error::VerificationError,
    commitment::{MerkleDecommitment, Tree},
    fri::{FriProof, FriConfig, FriCirclePolyDegreeBound},
    pcs::PcsConfig,
};
use crate::backend::FriVerifier;
use crate::vcs::MerkleVerifier;

pub const PREPROCESSED_TRACE_IDX: usize = 0;
pub const SECURE_EXTENSION_DEGREE: usize = 4;

#[derive(Clone)]
pub struct CommitmentSchemeVerifier<MC> 
where 
    MC: MerkleChannel,
    MC::H: MerkleHasher,
    <MC::H as MerkleHasher>::Hash: Clone + AsRef<[u8]> + Eq
{
    pub committed_trees: Vec<MerkleVerifier<MC::H>>,
    pub config: PcsConfig,
    _phantom: PhantomData<MC>,
}

impl<MC: MerkleChannel> CommitmentSchemeVerifier<MC>
where <MC::H as MerkleHasher>::Hash: Clone + AsRef<[u8]> + Eq
{
    pub fn new(config: PcsConfig) -> Self {
        Self {
            committed_trees: Vec::new(),
            config,
            _phantom: PhantomData,
        }
    }

    pub fn commit(
        &mut self,
        commitment: <MC::H as MerkleHasher>::Hash,
        log_degree_bounds: &[usize],
        channel: &mut MC::C 
    )
    where 
        <MC::H as MerkleHasher>::Hash: AsRef<[u8]> + Clone + Eq
    {
        MC::mix_root(channel, commitment.clone());

        let extended_log_sizes = log_degree_bounds
            .iter()
            .map(|&log_size| log_size.saturating_add(self.config.fri_config.log_blowup_factor as usize))
            .collect::<Vec<_>>();

        let verifier = MerkleVerifier::new(commitment, extended_log_sizes);
        self.committed_trees.push(verifier);
    }

    pub fn verify_values(&self, points: Vec<Vec<Vec<CirclePoint<SecureField>>>>, proof: CommitmentSchemeProof<MC::H>, channel: &mut MC::C) -> Result<(), VerificationError>
    where <MC::H as MerkleHasher>::Hash: Clone + AsRef<[u8]> + Eq
    {
        let flattened_sampled_values: Vec<SecureField> = proof.sampled_values
            .iter()
            .flat_map(|tree_samples| tree_samples.iter())
            .flat_map(|col_samples| col_samples.iter())
            .cloned()
            .collect();
        channel.mix_felts(&flattened_sampled_values);

        let random_coeff = channel.draw_secure_felt();

        let mut fri_bounds = self.committed_trees
            .iter()
            .flat_map(|verifier| verifier.column_log_sizes.iter().copied())
            .collect::<Vec<_>>();
        
        fri_bounds.sort_unstable();
        fri_bounds.reverse();
        
        let fri_bounds = fri_bounds
            .into_iter()
            .dedup()
            .map(|log_size| {
                let log_degree = log_size.saturating_sub(self.config.fri_config.log_blowup_factor as usize);
                FriCirclePolyDegreeBound::new(log_degree)
            })
            .collect::<Vec<_>>();

        let mut fri_verifier = FriVerifier::<MC>::commit(channel, self.config.fri_config.clone(), proof.fri_proof, &fri_bounds)?;
        
        channel.mix_u64(proof.proof_of_work);
        if channel.trailing_zeros() < self.config.pow_bits {
            return Err(VerificationError::ProofOfWork);
        }
        
        let query_positions = fri_verifier.sample_query_positions(channel);
        
        // Check total decommitment count against expected total columns across all trees
        let total_columns = self.committed_trees.iter().map(|t| t.column_log_sizes.len()).sum::<usize>();
        if total_columns != proof.decommitments.len() {
            return Err(VerificationError::InvalidStructure(format!(
                "Total column count mismatch: expected {}, got {} decommitments",
                total_columns, proof.decommitments.len()
            )));
        }
        // Check tree count for queried_values
        if self.committed_trees.len() != proof.queried_values.len() {
             return Err(VerificationError::InvalidStructure(format!(
                "Proof tree count mismatch for queried_values: expected {}, got {}",
                self.committed_trees.len(), proof.queried_values.len()
             )));
        }

        let mut decommitment_idx = 0; // Index for the flat decommitments Vec
        let n_queries = self.config.fri_config.n_queries; // Get number of queries

        for (tree_idx, verifier) in self.committed_trees.iter().enumerate() {
            let claimed_values_for_tree = &proof.queried_values[tree_idx];

            // Check column count for this specific tree in queried_values
            if verifier.column_log_sizes.len() != claimed_values_for_tree.len() / n_queries {
                 return Err(VerificationError::InvalidStructure(format!(
                    "Tree {} column count mismatch based on n_queries: verifier expects {}, queried_values implies {}",
                    tree_idx, verifier.column_log_sizes.len(), claimed_values_for_tree.len() / n_queries
                 )));
            }
            // Also check if total length is divisible by n_queries
            if claimed_values_for_tree.len() % n_queries != 0 {
                return Err(VerificationError::InvalidStructure(format!(
                    "Tree {} queried_values length ({}) not divisible by n_queries ({})",
                    tree_idx, claimed_values_for_tree.len(), n_queries
                )));
            }

            // Iterate through columns for this tree
            for col_idx in 0..verifier.column_log_sizes.len() {
                // Get the specific decommitment for this tree/column from the flat list
                let decommitment_for_column = &proof.decommitments[decommitment_idx];
                
                // Calculate slice indices
                let start_idx = col_idx * n_queries;
                let end_idx = start_idx + n_queries;
                let claimed_values_slice = &claimed_values_for_tree[start_idx..end_idx];
                
                // Verify this column using the slice
                verifier.verify(&query_positions, claimed_values_slice, decommitment_for_column.clone())
                    .map_err(|_e| VerificationError::MerkleProof)?; // Use simpler error
                
                decommitment_idx += 1; // Move to the next decommitment in the flat list
            }
        }
        
        let _ = (points, random_coeff);

        Ok(())
    }
}

pub fn verify<MC: MerkleChannel>(
    components: &[&dyn Component],
    channel: &mut MC::C,
    commitment_scheme: &mut CommitmentSchemeVerifier<MC>,
    proof: StarkProof<MC::H>,
) -> Result<(), VerificationError>
where 
    <MC::H as MerkleHasher>::Hash: Clone + core::fmt::Debug + AsRef<[u8]> + Eq
{
    let n_preprocessed_columns = commitment_scheme.committed_trees.get(PREPROCESSED_TRACE_IDX).map_or(0, |verifier| verifier.column_log_sizes.len());

    let components = crate::types::component::Components {
        components: components.to_vec(),
        n_preprocessed_columns,
    };
    let random_coeff = channel.draw_secure_felt();

    let composition_commitment = proof.0.commitments.last()
        .ok_or_else(|| VerificationError::InvalidStructure("Missing composition commitment".to_string()))?
        .clone();

    commitment_scheme.commit(
        composition_commitment,
        &[components.composition_log_degree_bound(); SECURE_EXTENSION_DEGREE],
        channel,
    );

    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    let mut sample_points = components.mask_points(oods_point.clone());
    let inner_vec: Vec<_> = core::iter::repeat(oods_point.clone()).take(SECURE_EXTENSION_DEGREE).collect();
    sample_points.push(Vec::from([inner_vec]));

    let composition_oods_eval = proof.extract_composition_oods_eval().map_err(|_| {
        VerificationError::InvalidStructure(String::from("Unexpected sampled_values structure"))
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
