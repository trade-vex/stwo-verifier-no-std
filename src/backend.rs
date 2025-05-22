use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use core::marker::PhantomData;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::ToString;

use blake2::{Blake2s256, Digest};

use crate::fields::m31::M31;
use crate::fields::qm31::SecureField;
use crate::channel::{Channel, MerkleHasher};
use crate::types::{
    point::CirclePoint,
    error::VerificationError,
    commitment::Tree,
    fri::{FriProof, FriConfig, FriCirclePolyDegreeBound, Queries, FriLayerProof, SparseEvaluation},
    poly::LinePoly,
};
use crate::circle::CircleDomain;

use crate::channel::MerkleChannel;

use crate::fields::m31::BaseField;

use bytemuck::{Pod, Zeroable};

use crate::circle::CanonicCoset;
use crate::fri_utils::{compute_decommitment_positions_and_rebuild_evals, CIRCLE_TO_LINE_FOLD_STEP, FOLD_STEP};

use alloc::vec;
use crate::types::poly::{LineDomain, Coset};

use core::iter::zip;
use crate::utils::bit_reverse_index;

use crate::types::point::CirclePointIndex;

pub trait Hash:
    Copy
    + Default
    + Eq
    + Send
    + Sync
    + 'static
    + Serialize
    + for<'de> Deserialize<'de>
{
}

// Wrapper for the blake2s hash type.
#[repr(C, align(32))]
#[derive(Clone, Copy, PartialEq, Default, Eq, Pod, Zeroable, Deserialize, Serialize, Debug)]
pub struct Blake2sHash(pub [u8; 32]);

impl From<Blake2sHash> for Vec<u8> {
    fn from(value: Blake2sHash) -> Self {
        Vec::from(value.0)
    }
}

impl From<Vec<u8>> for Blake2sHash {
    fn from(value: Vec<u8>) -> Self {
        Self(
            value
                .try_into()
                .expect("Failed converting Vec<u8> to Blake2Hash type"),
        )
    }
}

impl From<&[u8]> for Blake2sHash {
    fn from(value: &[u8]) -> Self {
        Self(
            value
                .try_into()
                .expect("Failed converting &[u8] to Blake2sHash Type!"),
        )
    }
}

impl AsRef<[u8]> for Blake2sHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Blake2sHash> for [u8; 32] {
    fn from(val: Blake2sHash) -> Self {
        val.0
    }
}

impl Hash for Blake2sHash {}

// Wrapper for the blake2s Hashing functionalities.
#[derive(Clone, Default, Debug)]
pub struct Blake2sHasher {
    state: Blake2s256,
}

impl Blake2sHasher {
    pub fn new() -> Self {
        Self {
            state: Blake2s256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        blake2::Digest::update(&mut self.state, data);
    }

    pub fn finalize(self) -> Blake2sHash {
        Blake2sHash(self.state.finalize().into())
    }

    pub fn concat_and_hash(v1: &Blake2sHash, v2: &Blake2sHash) -> Blake2sHash {
        let mut hasher = Self::new();
        hasher.update(v1.as_ref());
        hasher.update(v2.as_ref());
        hasher.finalize()
    }

    pub fn hash(data: &[u8]) -> Blake2sHash {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Default, Deserialize, Serialize, Debug)]
pub struct Blake2sMerkleHasher;
impl MerkleHasher for Blake2sMerkleHasher {
    type Hash = Blake2sHash;

    fn hash_node(
        children_hashes: Option<(Self::Hash, Self::Hash)>,
        column_values: &[BaseField],
    ) -> Self::Hash {
        let mut hasher = Blake2s256::new();

        if let Some((left_child, right_child)) = children_hashes {
            hasher.update(left_child);
            hasher.update(right_child);
        }

        for value in column_values {
            hasher.update(value.0.to_le_bytes());
        }

        Blake2sHash(hasher.finalize().into())
    }
}

#[derive(Clone)]
pub struct FriVerifier<MC: MerkleChannel> {
    pub config: FriConfig,
    _layer_commitments: Vec<<MC::H as MerkleHasher>::Hash>,
    folding_alphas: Vec<SecureField>,
    first_layer_proof: Option<FriLayerProof<MC::H>>,
    inner_layers_proof: Vec<FriLayerProof<MC::H>>,
    last_layer_poly: Option<LinePoly>,
    queries: Option<Queries>,
    column_commitment_domains: Vec<CircleDomain>,
    column_bounds: Vec<FriCirclePolyDegreeBound>,
    _phantom: PhantomData<MC>,
}

impl<MC: MerkleChannel> FriVerifier<MC> 
where 
    MC::H: MerkleHasher,
    <MC::H as MerkleHasher>::Hash: Clone + AsRef<[u8]> + Eq + core::fmt::Debug,
    MC::C: Channel,
{
    pub fn commit(
        channel: &mut MC::C, 
        config: FriConfig, 
        proof: FriProof<MC::H>,
        bounds: &[FriCirclePolyDegreeBound]
    ) -> Result<Self, VerificationError> 
    {
        // Ensure bounds are sorted descending? Prover code asserts this.
        if bounds.windows(2).any(|w| w[0] < w[1]) {
            // Prover panics, maybe return error?
             return Err(VerificationError::InvalidStructure("FRI bounds must be sorted descending".to_string()));
        }
        if bounds.is_empty() {
             return Err(VerificationError::InvalidStructure("FRI bounds cannot be empty".to_string()));
        }

        // Calculate and store domains from bounds
        let column_commitment_domains = bounds
            .iter()
            .map(|bound| {
                // Assumes FriCirclePolyDegreeBound has pub log_degree_bound: u32
                let commitment_domain_log_size = bound.log_degree_bound + config.log_blowup_factor as u32;
                // Assumes CanonicCoset::new(log_size).circle_domain() exists
                CanonicCoset::new(commitment_domain_log_size).circle_domain()
            })
            .collect();

        let mut layer_commitments = Vec::new();
        let mut folding_alphas = Vec::new();

        // Mix and store first layer commitment
        MC::mix_root(channel, proof.first_layer.commitment.clone());
        layer_commitments.push(proof.first_layer.commitment.clone());
        folding_alphas.push(channel.draw_felt());

        // Mix and store inner layer commitments
        for layer_proof in &proof.inner_layers {
            MC::mix_root(channel, layer_proof.commitment.clone());
            layer_commitments.push(layer_proof.commitment.clone());
            folding_alphas.push(channel.draw_felt());
        }

        // Mix last layer polynomial coefficients
        channel.mix_felts(&proof.last_layer_poly.coeffs);

        // TODO: Validate proof structure against config (num layers, last layer degree)
        // Prover does this implicitly via fold().ok_or() and degree check.

        Ok(Self {
            config,
            _layer_commitments: layer_commitments,
            folding_alphas,
            first_layer_proof: Some(proof.first_layer),
            inner_layers_proof: proof.inner_layers,
            last_layer_poly: Some(proof.last_layer_poly),
            queries: None,
            column_commitment_domains,
            column_bounds: bounds.to_vec(),
            _phantom: PhantomData,
        })
    }

    pub fn decommit(
        mut self,
        fri_input_evaluations: Vec<SecureField>
    ) -> Result<(), VerificationError> 
    where 
        <MC::H as MerkleHasher>::Hash: AsRef<[u8]> + Clone + Eq + core::fmt::Debug
    {
        let queries = self.queries.take().ok_or(VerificationError::FriQueriesNotSampled)?;
        
        self.decommit_on_queries(&queries, fri_input_evaluations)
    }

    /// Verifies all FRI layers based on the stored proof and calculated answers.
    /// Calls the layer-specific decommit methods in sequence.
    fn decommit_on_queries(
        self, // Take ownership to consume proof parts
        queries: &Queries, // Initial queries from sample_query_positions
        fri_input_evaluations: Vec<SecureField>
    ) -> Result<(), VerificationError> {
        // Decommit first layer, get SparseEvaluations needed for inner layers
        let first_layer_evals_for_folding = self.decommit_first_layer(queries, &fri_input_evaluations)?;

        // Decommit inner layers, passing first layer evals and initial queries.
        // This returns the final queries and evals needed for the last layer check.
        // Note: `decommit_inner_layers` takes ownership of `layer_queries` (which starts as a clone of initial queries)
        let (last_layer_queries, last_layer_evals) = 
            self.decommit_inner_layers(queries.clone(), first_layer_evals_for_folding)?;

        // Decommit last layer using the final queries and evals
        // This takes ownership of `self` because it consumes `last_layer_poly`.
        self.decommit_last_layer(last_layer_queries, last_layer_evals)
    }

    /// Verifies the first FRI layer decommitment.
    /// Corresponds to prover's `FriFirstLayerVerifier::verify`.
    fn decommit_first_layer(
        &self,
        queries: &Queries, 
        fri_input_evaluations_at_queries: &[SecureField]
    ) -> Result<Vec<SparseEvaluation>, VerificationError> // Return Vec instead of ColumnVec
    {
        let first_layer_proof = self.first_layer_proof.as_ref()
            .ok_or_else(|| VerificationError::InvalidStructure("Missing first layer proof".to_string()))?;

        if fri_input_evaluations_at_queries.is_empty() {
            return Err(VerificationError::InvalidStructure("Answers cannot be empty for decommit_first_layer".to_string()));
        }

        // compute_decommitment_positions_and_rebuild_evals gives us the actual values at query points
        // and the witness values, combined into sparse_evaluation. It also gives the positions
        // of these combined values in the domain.
        let (decommitment_positions, sparse_evaluation) = 
            compute_decommitment_positions_and_rebuild_evals(
                queries, // These are queries into the *original* domain, fold_steps are applied inside
                fri_input_evaluations_at_queries, 
                first_layer_proof.fri_witness.iter().copied(),
                CIRCLE_TO_LINE_FOLD_STEP as u32, 
            )?;

        // Perform Merkle Verification for the first layer commitment
        let layer_commitment = first_layer_proof.commitment.clone();
        let layer_decommitment = first_layer_proof.decommitment.clone();
        
        // The domain for this FRI layer. Since column_commitment_domains is Vec of len 1 for FRI on a single poly.
        let layer_log_domain_size = self.column_commitment_domains[0].log_size();

        // The MerkleVerifier expects values as Vec<BaseField>.
        // sparse_evaluation.subset_evals is Vec<Vec<SecureField>> (values for each query bundle).
        // These are the unique values needed for Merkle paths, corresponding to decommitment_positions.
        let unique_leaf_values_as_secure_field: Vec<SecureField> = sparse_evaluation.subset_evals.iter().flatten().cloned().collect();
        
        // Convert to a flat Vec<BaseField> for MerkleVerifier.
        let queried_values_for_merkle_verify: Vec<BaseField> = unique_leaf_values_as_secure_field
            .iter()
            .flat_map(|sf| sf.to_m31_array())
            .collect();
        
        let query_positions_for_merkle_verify = BTreeMap::from([(layer_log_domain_size, decommitment_positions)]);

        let merkle_verifier = crate::vcs::MerkleVerifier::new(
            layer_commitment, 
            vec![layer_log_domain_size; crate::SECURE_EXTENSION_DEGREE]
        );

        merkle_verifier.verify(&query_positions_for_merkle_verify, &queried_values_for_merkle_verify, layer_decommitment)?;

        Ok(vec![sparse_evaluation]) 
    }

    /// Verifies the inner FRI layers.
    /// Takes folded queries and SparseEvaluations from the first layer.
    /// Returns the queries and evaluations for the last layer.
    fn decommit_inner_layers(
        &self,
        mut layer_queries: Queries, 
        first_layer_evals: Vec<SparseEvaluation>, 
    ) -> Result<(Queries, Vec<SecureField>), VerificationError> {
        let mut current_line_bound = self.column_bounds[0].fold_to_line(); // column_bounds is Vec of len 1
        
        // The domain for the first *line-folded* layer before any more folding.
        let mut current_layer_domain = LineDomain::new(Coset::half_odds(
            current_line_bound.log_degree_bound + self.config.log_blowup_factor as u32
        ));
        
        let mut layer_query_evals: Vec<SecureField> = Vec::new(); 
        // Initialize layer_query_evals from first_layer_evals after necessary folding (if any based on prover logic)
        // Prover's decommit_inner_layers folds first_layer_sparse_evals using first_layer.folding_alpha
        // Our current structure passes SparseEvaluation and expects decommit_inner_layers to use it.
        // The first_layer_evals[0] (if it exists) is the SparseEvaluation from the first layer.
        if let Some(first_eval_sparse) = first_layer_evals.get(0) { 
            // This folding should ideally use the alpha from the first layer.
            // self.folding_alphas[0] is the alpha for folding layer 0 to layer 1.
            // The `fold_line` here needs to be on the output of `compute_decommitment_positions_and_rebuild_evals` from the *first layer*.
            // The `first_layer_evals` *is* this output (a Vec containing one SparseEvaluation).
            layer_query_evals = first_eval_sparse.clone().fold_line(self.folding_alphas[0], current_layer_domain);
        }
        
        for (layer_index, layer_proof) in self.inner_layers_proof.iter().enumerate() {
            let current_folding_alpha = self.folding_alphas[layer_index + 1]; // Alpha for folding current layer to next

            let next_layer_queries = layer_queries.fold(FOLD_STEP as u32);

            current_line_bound = current_line_bound.fold(FOLD_STEP as u32)
                .ok_or_else(|| VerificationError::InvalidStructure("Degree bound too small for folding".to_string()))?;

            // Domain for the current layer being verified (before it's folded to next_layer_queries domain)
            // current_layer_domain is the domain where layer_query_evals are defined.
            // This domain should be used for Merkle verification of the current layer_proof.
            let this_layer_domain_for_merkle_verify = current_layer_domain;

            // Compute positions and sparse evals for *this* layer, using layer_query_evals (evals on this_layer_domain_for_merkle_verify)
            let (decommitment_positions, sparse_evaluation_for_layer) = compute_decommitment_positions_and_rebuild_evals(
                &layer_queries, // Queries are on this_layer_domain_for_merkle_verify
                &layer_query_evals,  
                layer_proof.fri_witness.iter().copied(),
                FOLD_STEP as u32 
            )?;

            // MERKLE VERIFICATION FOR CURRENT INNER LAYER
            let inner_layer_commitment = layer_proof.commitment.clone();
            let inner_layer_decommitment = layer_proof.decommitment.clone();
            let inner_layer_log_domain_size = this_layer_domain_for_merkle_verify.log_size();

            let unique_leaf_values_as_secure_field: Vec<SecureField> = sparse_evaluation_for_layer.subset_evals.iter().flatten().cloned().collect();
            // Convert to a flat Vec<BaseField> for MerkleVerifier.
            let queried_values_for_merkle_verify: Vec<BaseField> = unique_leaf_values_as_secure_field
                .iter()
                .flat_map(|sf| sf.to_m31_array())
                .collect();
            
            let query_positions_for_merkle_verify = BTreeMap::from([(inner_layer_log_domain_size, decommitment_positions)]);

            let merkle_verifier = crate::vcs::MerkleVerifier::new(
                inner_layer_commitment, 
                vec![inner_layer_log_domain_size; crate::SECURE_EXTENSION_DEGREE]
            );
            merkle_verifier.verify(&query_positions_for_merkle_verify, &queried_values_for_merkle_verify, inner_layer_decommitment)?;
            // END MERKLE VERIFICATION

            // Fold the verified evaluations for the next layer
            layer_query_evals = sparse_evaluation_for_layer.fold_line(current_folding_alpha, this_layer_domain_for_merkle_verify);
            layer_queries = next_layer_queries; 
            current_layer_domain = current_layer_domain.double(); // Domain for the *next* layer (after folding)
        }
        
        Ok((layer_queries, layer_query_evals))
    }

    /// Verifies the last FRI layer polynomial.
    fn decommit_last_layer(
        self,
        queries: Queries, 
        final_folded_evals: Vec<SecureField>
    ) -> Result<(), VerificationError> {
        let last_layer_poly = self.last_layer_poly.ok_or_else(|| 
            VerificationError::InvalidStructure("Missing last layer polynomial in proof".to_string()))?;
            
        let last_layer_log_domain_size = 
            (self.config.log_last_layer_degree_bound + self.config.log_blowup_factor) as usize;
            
        // Use correct Coset constructor with CirclePointIndex
        let domain = LineDomain::new(Coset::new(CirclePointIndex::zero(), last_layer_log_domain_size as u32));

        if queries.log_domain_size != domain.log_size() {
            return Err(VerificationError::InvalidStructure("Query domain size mismatch for last layer".to_string()));
        }
        
        if queries.len() != final_folded_evals.len() {
             return Err(VerificationError::InvalidStructure("Number of queries does not match number of evals for last layer".to_string()));
        }

        // TODO: Add check if last_layer_poly.coeffs.len() > (1 << self.config.log_last_layer_degree_bound)
        // Prover checks this during commit. Maybe add it there?

        for (&query_index, query_eval) in zip(&queries.positions, final_folded_evals) {
            let point = domain.at(bit_reverse_index(query_index, domain.log_size() as u32)); 
            let expected_eval = last_layer_poly.eval_at_point(point.into());

            if query_eval != expected_eval {
                return Err(VerificationError::FriLastLayerEvaluationsInvalid); // Use specific error
            }
        }

        Ok(())
    }

    /// Samples query positions using the channel.
    pub fn sample_query_positions(
        &mut self, 
        channel: &mut MC::C, 
        column_log_sizes: BTreeSet<u32>
    ) -> BTreeMap<u32, Vec<usize>> {
        let max_log_size = *column_log_sizes.iter().max().unwrap_or(&0);
        let queries = Queries::generate(channel, max_log_size, self.config.n_queries);
        self.queries = Some(queries.clone());
        get_query_positions_by_log_size(&queries, &column_log_sizes)
    }
}

fn get_query_positions_by_log_size(
    queries: &crate::types::fri::Queries,
    column_log_sizes: &BTreeSet<u32>,
) -> BTreeMap<u32, Vec<usize>> {
    let mut positions = BTreeMap::new();
    for log_size_ref in column_log_sizes {
        let log_size = *log_size_ref;
        let n_folds = queries.log_domain_size.saturating_sub(log_size);
        let folded_queries = queries.fold(n_folds);
        positions.insert(log_size, folded_queries.positions);
    }
    positions
}

pub const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

pub const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[inline(always)]
const fn add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

#[inline(always)]
const fn xor(a: u32, b: u32) -> u32 {
    a ^ b
}

#[inline(always)]
const fn rot16(x: u32) -> u32 {
    x.rotate_right(16)
}

#[inline(always)]
const fn rot12(x: u32) -> u32 {
    x.rotate_right(12)
}

#[inline(always)]
const fn rot8(x: u32) -> u32 {
    x.rotate_right(8)
}

#[inline(always)]
const fn rot7(x: u32) -> u32 {
    x.rotate_right(7)
}

#[inline(always)]
const fn round(v: &mut [u32; 16], m: [u32; 16], r: usize) {
    v[0] = add(v[0], m[SIGMA[r][0] as usize]);
    v[1] = add(v[1], m[SIGMA[r][2] as usize]);
    v[2] = add(v[2], m[SIGMA[r][4] as usize]);
    v[3] = add(v[3], m[SIGMA[r][6] as usize]);
    v[0] = add(v[0], v[4]);
    v[1] = add(v[1], v[5]);
    v[2] = add(v[2], v[6]);
    v[3] = add(v[3], v[7]);
    v[12] = xor(v[12], v[0]);
    v[13] = xor(v[13], v[1]);
    v[14] = xor(v[14], v[2]);
    v[15] = xor(v[15], v[3]);
    v[12] = rot16(v[12]);
    v[13] = rot16(v[13]);
    v[14] = rot16(v[14]);
    v[15] = rot16(v[15]);
    v[8] = add(v[8], v[12]);
    v[9] = add(v[9], v[13]);
    v[10] = add(v[10], v[14]);
    v[11] = add(v[11], v[15]);
    v[4] = xor(v[4], v[8]);
    v[5] = xor(v[5], v[9]);
    v[6] = xor(v[6], v[10]);
    v[7] = xor(v[7], v[11]);
    v[4] = rot12(v[4]);
    v[5] = rot12(v[5]);
    v[6] = rot12(v[6]);
    v[7] = rot12(v[7]);
    v[0] = add(v[0], m[SIGMA[r][1] as usize]);
    v[1] = add(v[1], m[SIGMA[r][3] as usize]);
    v[2] = add(v[2], m[SIGMA[r][5] as usize]);
    v[3] = add(v[3], m[SIGMA[r][7] as usize]);
    v[0] = add(v[0], v[4]);
    v[1] = add(v[1], v[5]);
    v[2] = add(v[2], v[6]);
    v[3] = add(v[3], v[7]);
    v[12] = xor(v[12], v[0]);
    v[13] = xor(v[13], v[1]);
    v[14] = xor(v[14], v[2]);
    v[15] = xor(v[15], v[3]);
    v[12] = rot8(v[12]);
    v[13] = rot8(v[13]);
    v[14] = rot8(v[14]);
    v[15] = rot8(v[15]);
    v[8] = add(v[8], v[12]);
    v[9] = add(v[9], v[13]);
    v[10] = add(v[10], v[14]);
    v[11] = add(v[11], v[15]);
    v[4] = xor(v[4], v[8]);
    v[5] = xor(v[5], v[9]);
    v[6] = xor(v[6], v[10]);
    v[7] = xor(v[7], v[11]);
    v[4] = rot7(v[4]);
    v[5] = rot7(v[5]);
    v[6] = rot7(v[6]);
    v[7] = rot7(v[7]);

    v[0] = add(v[0], m[SIGMA[r][8] as usize]);
    v[1] = add(v[1], m[SIGMA[r][10] as usize]);
    v[2] = add(v[2], m[SIGMA[r][12] as usize]);
    v[3] = add(v[3], m[SIGMA[r][14] as usize]);
    v[0] = add(v[0], v[5]);
    v[1] = add(v[1], v[6]);
    v[2] = add(v[2], v[7]);
    v[3] = add(v[3], v[4]);
    v[15] = xor(v[15], v[0]);
    v[12] = xor(v[12], v[1]);
    v[13] = xor(v[13], v[2]);
    v[14] = xor(v[14], v[3]);
    v[15] = rot16(v[15]);
    v[12] = rot16(v[12]);
    v[13] = rot16(v[13]);
    v[14] = rot16(v[14]);
    v[10] = add(v[10], v[15]);
    v[11] = add(v[11], v[12]);
    v[8] = add(v[8], v[13]);
    v[9] = add(v[9], v[14]);
    v[5] = xor(v[5], v[10]);
    v[6] = xor(v[6], v[11]);
    v[7] = xor(v[7], v[8]);
    v[4] = xor(v[4], v[9]);
    v[5] = rot12(v[5]);
    v[6] = rot12(v[6]);
    v[7] = rot12(v[7]);
    v[4] = rot12(v[4]);
    v[0] = add(v[0], m[SIGMA[r][9] as usize]);
    v[1] = add(v[1], m[SIGMA[r][11] as usize]);
    v[2] = add(v[2], m[SIGMA[r][13] as usize]);
    v[3] = add(v[3], m[SIGMA[r][15] as usize]);
    v[0] = add(v[0], v[5]);
    v[1] = add(v[1], v[6]);
    v[2] = add(v[2], v[7]);
    v[3] = add(v[3], v[4]);
    v[15] = xor(v[15], v[0]);
    v[12] = xor(v[12], v[1]);
    v[13] = xor(v[13], v[2]);
    v[14] = xor(v[14], v[3]);
    v[15] = rot8(v[15]);
    v[12] = rot8(v[12]);
    v[13] = rot8(v[13]);
    v[14] = rot8(v[14]);
    v[10] = add(v[10], v[15]);
    v[11] = add(v[11], v[12]);
    v[8] = add(v[8], v[13]);
    v[9] = add(v[9], v[14]);
    v[5] = xor(v[5], v[10]);
    v[6] = xor(v[6], v[11]);
    v[7] = xor(v[7], v[8]);
    v[4] = xor(v[4], v[9]);
    v[5] = rot7(v[5]);
    v[6] = rot7(v[6]);
    v[7] = rot7(v[7]);
    v[4] = rot7(v[4]);
}

/// Performs a Blake2s compression.
pub const fn compress(
    h_vecs: [u32; 8],
    msg_vecs: [u32; 16],
    count_low: u32,
    count_high: u32,
    lastblock: u32,
    lastnode: u32,
) -> [u32; 8] {
    let mut v = [
        h_vecs[0],
        h_vecs[1],
        h_vecs[2],
        h_vecs[3],
        h_vecs[4],
        h_vecs[5],
        h_vecs[6],
        h_vecs[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        xor(IV[4], count_low),
        xor(IV[5], count_high),
        xor(IV[6], lastblock),
        xor(IV[7], lastnode),
    ];

    round(&mut v, msg_vecs, 0);
    round(&mut v, msg_vecs, 1);
    round(&mut v, msg_vecs, 2);
    round(&mut v, msg_vecs, 3);
    round(&mut v, msg_vecs, 4);
    round(&mut v, msg_vecs, 5);
    round(&mut v, msg_vecs, 6);
    round(&mut v, msg_vecs, 7);
    round(&mut v, msg_vecs, 8);
    round(&mut v, msg_vecs, 9);

    [
        xor(xor(h_vecs[0], v[0]), v[8]),
        xor(xor(h_vecs[1], v[1]), v[9]),
        xor(xor(h_vecs[2], v[2]), v[10]),
        xor(xor(h_vecs[3], v[3]), v[11]),
        xor(xor(h_vecs[4], v[4]), v[12]),
        xor(xor(h_vecs[5], v[5]), v[13]),
        xor(xor(h_vecs[6], v[6]), v[14]),
        xor(xor(h_vecs[7], v[7]), v[15]),
    ]
}
