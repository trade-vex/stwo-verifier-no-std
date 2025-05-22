use alloc::vec::Vec;
use crate::fields::qm31::SecureField;
use crate::types::error::VerificationError;
use crate::types::fri::{Queries, SparseEvaluation};
use crate::utils::bit_reverse_index; // Assuming this exists or needs porting
use alloc::string::ToString;
use crate::types::poly::{LineEvaluation, SecureEvaluation};
use core::iter::zip; // Add zip import
use crate::fft_utils::ibutterfly;
use crate::fields::FieldExpOps; // Add import back

// Define public constants for folding steps
pub const FOLD_STEP: usize = 1;
pub const CIRCLE_TO_LINE_FOLD_STEP: usize = 1;


/// Reconstructs the evaluations needed for Merkle verification and folding for a single FRI layer.
/// From `stwo/core/fri.rs`.
/// Takes query positions, the evaluations provided for those positions, and an iterator over
/// witness evaluations for the positions *not* queried.
/// Returns the full list of positions for the Merkle proof and the reconstructed evaluations.
pub fn compute_decommitment_positions_and_rebuild_evals(
    queries: &Queries,
    query_evals: &[SecureField],
    mut witness_evals: impl Iterator<Item = SecureField>,
    fold_step: u32, // Changed from usize
) -> Result<(Vec<usize>, SparseEvaluation), VerificationError> { // Return our error type
    let mut query_evals_iter = query_evals.iter().copied();

    let mut decommitment_positions = Vec::new();
    let mut subset_evals = Vec::new();
    let mut subset_domain_initial_indexes = Vec::new();

    let fold_step_size = 1 << fold_step;

    // Group queries by the subset they reside in.
    let mut current_subset_start = 0;
    let mut subset_queries_group: Vec<usize> = Vec::new();

    for &query_pos in &queries.positions {
        let subset_start_for_query = (query_pos >> fold_step) << fold_step;
        
        if subset_queries_group.is_empty() || subset_start_for_query == current_subset_start {
            // Continue current group
            subset_queries_group.push(query_pos);
            current_subset_start = subset_start_for_query;
        } else {
            // Process completed group
            process_subset(
                current_subset_start,
                &subset_queries_group,
                fold_step_size,
                &mut query_evals_iter,
                &mut witness_evals,
                &mut decommitment_positions,
                &mut subset_evals,
                &mut subset_domain_initial_indexes,
                queries.log_domain_size,
            )?;
            
            // Start new group
            subset_queries_group.clear();
            subset_queries_group.push(query_pos);
            current_subset_start = subset_start_for_query;
        }
    }

    // Process the last group if it exists
    if !subset_queries_group.is_empty() {
        process_subset(
            current_subset_start,
            &subset_queries_group,
            fold_step_size,
            &mut query_evals_iter,
            &mut witness_evals,
            &mut decommitment_positions,
            &mut subset_evals,
            &mut subset_domain_initial_indexes,
            queries.log_domain_size,
        )?;
    }
    
    // Check if all query_evals were consumed (might miss cases if queries is empty)
    if query_evals_iter.next().is_some() && !queries.positions.is_empty() {
        // This indicates an inconsistency between the number of queries and provided evals
        return Err(VerificationError::InvalidStructure("Extra query evaluations provided".to_string()));
    }

    let sparse_evaluation = SparseEvaluation::new(subset_evals, subset_domain_initial_indexes);

    Ok((decommitment_positions, sparse_evaluation))
}

// Helper function to process one subset of queries
fn process_subset(
    subset_start: usize,
    subset_queries: &[usize],
    fold_step_size: usize,
    query_evals_iter: &mut core::iter::Copied<core::slice::Iter<SecureField>>,
    witness_evals: &mut impl Iterator<Item = SecureField>,
    decommitment_positions: &mut Vec<usize>,
    subset_evals: &mut Vec<Vec<SecureField>>,
    subset_domain_initial_indexes: &mut Vec<usize>,
    log_domain_size: u32,
) -> Result<(), VerificationError> {
    
    let subset_decommitment_positions = subset_start..subset_start + fold_step_size;
    decommitment_positions.extend(subset_decommitment_positions.clone());

    let mut current_subset_queries_iter = subset_queries.iter().copied().peekable();
    let mut current_subset_evals = Vec::with_capacity(fold_step_size);

    for position in subset_decommitment_positions {
        match current_subset_queries_iter.next_if_eq(&position) {
            Some(_) => {
                // Position was queried, use the provided eval
                let eval = query_evals_iter.next().ok_or_else(|| 
                    VerificationError::InvalidStructure("Missing query evaluation".to_string()))?;
                current_subset_evals.push(eval);
            }
            None => {
                // Position was not queried, use witness eval
                let eval = witness_evals.next().ok_or(VerificationError::FriInsufficientWitness)?;
                current_subset_evals.push(eval);
            }
        }
    }
    subset_evals.push(current_subset_evals);
    subset_domain_initial_indexes.push(bit_reverse_index(subset_start, log_domain_size));
    Ok(())
}

// Standalone folding functions (stubs)

/// Folds a line evaluation.
/// Based on `stwo/core/fri.rs::fold_line`.
pub fn fold_line(
    eval: &LineEvaluation, 
    alpha: SecureField
) -> LineEvaluation {
    let n = eval.values.len();
    assert!(n >= 2, "Evaluation too small for folding");
    assert!(n.is_power_of_two(), "Evaluation size must be power of two");

    let domain = eval.domain;
    let log_size = domain.log_size();
    let folded_len = n / 2;
    
    let mut folded_values = Vec::with_capacity(folded_len);

    // Use chunks_exact instead of unstable array_chunks
    for (i, chunk) in eval.values.chunks_exact(2).enumerate() {
        let f_x = chunk[0];
        let f_neg_x = chunk[1];
        
        // Get the domain point x corresponding to the *start* of the pair
        // Prover uses `i << FOLD_STEP`, which is `i * 2` for FOLD_STEP=1.
        let domain_index = bit_reverse_index(i * 2, log_size as u32);
        let x = domain.at(domain_index); // Needs LineDomain::at() 
        
        let mut f0 = f_x;
        let mut f1 = f_neg_x;
        
        // Apply inverse butterfly
        let x_inv = x.inverse(); // Needs BaseField::inverse()
        ibutterfly(&mut f0, &mut f1, x_inv.into()); // Needs ibutterfly, BaseField::into<SecureField>
        
        // Combine
        folded_values.push(f0 + alpha * f1);
    }
    
    // Create new evaluation on the doubled domain (halved size)
    LineEvaluation::new(domain.double(), folded_values) // Needs LineDomain::double()
}

/// Folds a circle evaluation into a line evaluation buffer.
/// Based on `stwo/core/fri.rs::fold_circle_into_line`.
pub fn fold_circle_into_line(
    dst: &mut LineEvaluation,
    src: &SecureEvaluation,
    alpha: SecureField,
) {
    let n_src = src.values.len();
    let n_dst = dst.values.len();
    let fold_step = CIRCLE_TO_LINE_FOLD_STEP; // Usually 1
    let expected_dst_len = n_src >> fold_step;
    
    assert_eq!(expected_dst_len, n_dst, "Destination length mismatch");
    assert!(n_src >= 2, "Source evaluation too small for folding");
    assert!(n_src.is_power_of_two(), "Source evaluation size must be power of two");

    let domain = src.domain;
    let log_size = domain.log_size();
    let alpha_sq = alpha.square();

    // Use chunks_exact instead of unstable array_chunks
    // Chunk size depends on fold_step (2^fold_step)
    let chunk_size = 1 << fold_step;
    
    for (i, chunk) in src.values.chunks_exact(chunk_size).enumerate() {
        let f_p = chunk[0]; // Assuming fold_step = 1, chunk has [f(p), f(-p)]
        let f_neg_p = chunk[1]; 
        
        // Get the domain point p corresponding to the *start* of the pair
        let domain_index = bit_reverse_index(i << fold_step, log_size as u32);
        let p = domain.at(domain_index); // Needs CircleDomain::at()
        
        let mut f0_px = f_p;
        let mut f1_px = f_neg_p;
        
        // Apply inverse butterfly
        let p_y_inv = p.y.inverse(); // Access .y field directly
        ibutterfly(&mut f0_px, &mut f1_px, p_y_inv.into());
        
        // Combine
        let f_prime = alpha * f1_px + f0_px;
        
        // Accumulate into destination buffer
        dst.values[i] = dst.values[i] * alpha_sq + f_prime;
    }
}

/// Accumulates folded column evaluations into the current layer's evaluations.
/// From `stwo/core/fri.rs`.
pub fn accumulate_line(
    layer_query_evals: &mut [SecureField],
    column_query_evals: &[SecureField],
    folding_alpha: SecureField,
) {
    // Prover used zip_eq, using zip and assuming lengths match (or panic)
    let folding_alpha_squared = folding_alpha.square();
    for (curr_layer_eval, folded_column_eval) in zip(layer_query_evals, column_query_evals) {
        *curr_layer_eval *= folding_alpha_squared;
        *curr_layer_eval += *folded_column_eval;
    }
} 