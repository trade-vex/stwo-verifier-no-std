use alloc::vec;
use alloc::vec::Vec;
use alloc::string::{String, ToString};
use alloc::format;
use itertools::Itertools;
use core::iter::zip;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use num_traits::Zero;

use crate::fields::qm31::SecureField;
use crate::channel::{Channel, MerkleChannel, MerkleHasher};
use crate::SECURE_EXTENSION_DEGREE;
use crate::types::{
    component::Component,
    point::CirclePoint,
    proof::{StarkProof, CommitmentSchemeProof},
    error::VerificationError,
    fri::FriCirclePolyDegreeBound,
    pcs::PcsConfig,
    proof::PointSample,
    component::Components,
};
use crate::backend::FriVerifier;
use crate::vcs::MerkleVerifier;
use crate::quotients::fri_answers;

pub const PREPROCESSED_TRACE_IDX: usize = 0;

#[derive(Clone)]
pub struct CommitmentSchemeVerifier<MC> 
where 
    MC: MerkleChannel,
    MC::H: MerkleHasher,
    <MC::H as MerkleHasher>::Hash: Clone + AsRef<[u8]> + Eq + core::fmt::Debug
{
    pub committed_trees: Vec<MerkleVerifier<MC::H>>,
    pub config: PcsConfig,
}

impl<MC: MerkleChannel> CommitmentSchemeVerifier<MC>
where <MC::H as MerkleHasher>::Hash: Clone + AsRef<[u8]> + Eq + core::fmt::Debug
{
    pub fn new(config: PcsConfig) -> Self {
        Self {
            committed_trees: Vec::new(),
            config,
        }
    }

    pub fn commit(
        &mut self,
        commitment: <MC::H as MerkleHasher>::Hash,
        log_degree_bounds: &[u32],
        channel: &mut MC::C 
    )
    where 
        <MC::H as MerkleHasher>::Hash: AsRef<[u8]> + Clone + Eq + core::fmt::Debug
    {
        MC::mix_root(channel, commitment.clone());

        let extended_log_sizes = log_degree_bounds
            .iter()
            .map(|&log_size| log_size.saturating_add(self.config.fri_config.log_blowup_factor))
            .collect::<Vec<_>>();

        let verifier = MerkleVerifier::new(commitment, extended_log_sizes);
        self.committed_trees.push(verifier);
    }

    pub fn verify_values(&self, points: Vec<Vec<Vec<CirclePoint<SecureField>>>>, proof: CommitmentSchemeProof<MC::H>, channel: &mut MC::C) -> Result<(), VerificationError>
    where <MC::H as MerkleHasher>::Hash: Clone + AsRef<[u8]> + Eq + core::fmt::Debug
    {
        let flattened_sampled_values: Vec<SecureField> = proof.sampled_values
            .iter()
            .flat_map(|tree_samples| tree_samples.iter())
            .flat_map(|col_samples| col_samples.iter())
            .cloned()
            .collect();
        channel.mix_felts(&flattened_sampled_values);

        let random_coeff = channel.draw_felt();

        let mut fri_bounds_u32 = self.committed_trees
            .iter()
            .flat_map(|verifier| verifier.column_log_sizes.iter().copied())
            .collect::<Vec<_>>();
        
        fri_bounds_u32.sort_unstable();
        fri_bounds_u32.reverse();
        
        let fri_bounds_for_all_polys = fri_bounds_u32
            .into_iter()
            .dedup()
            .map(|log_size| {
                let log_degree = log_size.saturating_sub(self.config.fri_config.log_blowup_factor);
                FriCirclePolyDegreeBound::new(log_degree)
            })
            .collect::<Vec<_>>();

        let effective_fri_input_log_degree = fri_bounds_for_all_polys
            .iter()
            .map(|b| b.log_degree_bound)
            .max()
            .unwrap_or(0);
        
        let fri_verifier_bounds = [FriCirclePolyDegreeBound::new(effective_fri_input_log_degree)];

        let mut fri_verifier = FriVerifier::<MC>::commit(channel, self.config.fri_config.clone(), proof.fri_proof, &fri_verifier_bounds)?;
        
        channel.mix_u64(proof.proof_of_work);
        if channel.trailing_zeros() < self.config.pow_bits {
            return Err(VerificationError::ProofOfWork);
        }
        
        let unique_column_log_sizes: BTreeSet<u32> = self.committed_trees
            .iter()
            .flat_map(|tree| tree.column_log_sizes.iter().copied())
            .collect();

        let query_positions_per_log_size = fri_verifier.sample_query_positions(channel, unique_column_log_sizes);
        
        if self.committed_trees.len() != proof.decommitments.len() || self.committed_trees.len() != proof.queried_values.len() {
            return Err(VerificationError::InvalidStructure(format!(
                "Proof structure mismatch: {} trees, {} decommitments, {} queried_values sets",
                self.committed_trees.len(), proof.decommitments.len(), proof.queried_values.len()
            )));
        }

        zip(&self.committed_trees, &proof.decommitments)
            .zip(&proof.queried_values)
            .try_for_each(|((tree, decommitment), queried_values_for_tree)| {
                tree.verify(&query_positions_per_log_size, queried_values_for_tree, decommitment.clone())
            })?;

        if points.len() != proof.sampled_values.len() {
            return Err(VerificationError::InvalidStructure("Mismatch between points and sampled_values tree count".to_string()));
        }
        let samples_res: Result<Vec<Vec<Vec<PointSample>>>, VerificationError> = zip(points, &proof.sampled_values)
            .map(|(tree_points, tree_values)| {
                if tree_points.len() != tree_values.len() {
                    return Err(VerificationError::InvalidStructure(format!(
                        "Mismatch between points and sampled_values column count in tree. Expected {}, got {}",
                        tree_points.len(),
                        tree_values.len()
                    )));
                }
                zip(tree_points, tree_values)
                    .map(|(col_points, col_values)| {
                        if col_points.len() != col_values.len() {
                            return Err(VerificationError::InvalidStructure(format!(
                                "Mismatch between points and sampled_values sample count in column. Expected {}, got {}",
                                col_points.len(),
                                col_values.len()
                            )));
                        }
                         zip(col_points, col_values)
                            .map(|(point, value)| PointSample { point: point.clone(), value: *value })
                            .collect::<Vec<_>>()
                            .into_iter()
                            .map(Ok)
                            .collect::<Result<Vec<_>, VerificationError>>()
                    })
                    .collect::<Result<Vec<_>, VerificationError>>()
            })
            .collect();
        
        let samples = samples_res?;

        let n_columns_per_log_size_for_fri: Vec<BTreeMap<u32, usize>> = self.committed_trees
            .iter()
            .map(|tree| tree.n_columns_per_log_size.clone())
            .collect();

        let column_log_sizes_for_fri: Vec<Vec<u32>> = self.committed_trees
            .iter()
            .map(|tree| tree.column_log_sizes.clone())
            .collect();

        let fri_answers_result = fri_answers(
            column_log_sizes_for_fri, 
            samples, 
            random_coeff, 
            &query_positions_per_log_size,
            proof.queried_values.clone(),
            n_columns_per_log_size_for_fri
        )?;

        // Assuming fri_answers_result is Vec<Vec<SecureField>> where inner Vec has 1 element.
        let fri_evaluations_for_decommit: Vec<SecureField> = fri_answers_result
            .into_iter()
            .map(|mut v| v.remove(0)) // Take the first (and only) element from inner Vec
            .collect();

        fri_verifier.decommit(fri_evaluations_for_decommit)?;

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
    <MC::H as MerkleHasher>::Hash: Clone + AsRef<[u8]> + Eq + core::fmt::Debug
{
    if commitment_scheme.committed_trees.len() <= PREPROCESSED_TRACE_IDX {
        return Err(VerificationError::InvalidStructure(format!(
            "Not enough committed trees ({}) to access preprocessed trace at index {}",
            commitment_scheme.committed_trees.len(),
            PREPROCESSED_TRACE_IDX
        )));
    }
    let n_preprocessed_columns = commitment_scheme.committed_trees[PREPROCESSED_TRACE_IDX]
        .column_log_sizes
        .len();
    
    let components_struct = Components {
        components: components.to_vec(),
        n_preprocessed_columns,
    };
    
    let random_coeff = channel.draw_felt();

    let composition_log_degree_bound_u32 = components_struct.max_constraint_log_degree_bound();
    let log_bounds_for_commit = [composition_log_degree_bound_u32; SECURE_EXTENSION_DEGREE];
    
    commitment_scheme.commit(
        proof.0.commitments.last().ok_or_else(|| VerificationError::InvalidStructure("Missing composition commitment".to_string()))?.clone(),
        &log_bounds_for_commit,
        channel,
    );

    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    let mut sample_points = components_struct.mask_points(oods_point.clone()); 
    sample_points.push(vec![vec![oods_point.clone()]; SECURE_EXTENSION_DEGREE]);

    let composition_oods_eval = proof.extract_composition_oods_eval().map_err(|_| {
        VerificationError::InvalidStructure(String::from("Unexpected sampled_values structure"))
    })?;

    let sampled_values = &proof.0.sampled_values;

    let actual_composition_eval = components_struct.eval_composition_polynomial_at_point(
            oods_point, 
            sampled_values, 
            random_coeff,
        );

    if composition_oods_eval != actual_composition_eval {
        return Err(VerificationError::OodsNotMatching);
    }

    commitment_scheme.verify_values(sample_points, proof.0, channel)
}

// Added from stwo/core/air/accumulation.rs
/// Accumulates N evaluations of u_i(P0) at a single point.
/// Computes f(P0), the combined polynomial at that point.
/// For n accumulated evaluations, the i'th evaluation is multiplied by alpha^(N-1-i).
#[derive(Debug, Clone)]
pub struct PointEvaluationAccumulator {
    random_coeff: SecureField,
    accumulation: SecureField,
}

impl PointEvaluationAccumulator {
    /// Creates a new accumulator.
    pub fn new(random_coeff: SecureField) -> Self {
        Self {
            random_coeff,
            accumulation: SecureField::zero(), // Initialize with zero
        }
    }

    /// Accumulates u_i(P0), a polynomial evaluation at a P0 in reverse order.
    pub fn accumulate(&mut self, evaluation: SecureField) {
        self.accumulation = self.accumulation * self.random_coeff + evaluation;
    }

    pub fn finalize(self) -> SecureField {
        self.accumulation
    }
}
