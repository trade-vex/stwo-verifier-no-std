use alloc::vec::Vec;
 // Added for vec! macro
use alloc::format; // Added for format! macro
use alloc::string::ToString; // Added for to_string()
use alloc::collections::BTreeMap;
use core::cmp::Reverse; // Added import
 // Added import
use num_traits::{One, Zero}; // Add Zero import
use itertools::{izip, Itertools, zip_eq}; // Added zip_eq

use crate::fields::qm31::SecureField;
use crate::types::point::CirclePoint;
use crate::types::proof::PointSample;
use crate::fields::m31::BaseField;
use crate::types::error::VerificationError;
use crate::fields::ComplexConjugate;
use crate::fields::FieldExpOps;
use crate::circle::CanonicCoset; // Added import
use crate::utils::bit_reverse_index; // Added import
use crate::fields::cm31::CM31; // Added import
use crate::fields::m31::M31; // Added import

/// A batch of column samplings at a specific out-of-domain point.
#[derive(Debug, Clone)] // Added derive
pub struct ColumnSampleBatch {
    /// The point at which the columns are sampled.
    pub point: CirclePoint<SecureField>,
    /// The sampled column indices and their values at the point.
    pub columns_and_values: Vec<(usize, SecureField)>,
}

impl ColumnSampleBatch {
    /// Groups column samples by sampled point.
    /// Input `samples` is Vec<Vec<PointSample>> (representing columns -> samples for that column)
    pub fn new_vec(samples: &[Vec<PointSample>]) -> Vec<Self> {
        // Group samples by point, maintaining insertion order approximately.
        // Use BTreeMap for deterministic ordering based on point, though original might rely on hash stability.
        let mut grouped_samples: BTreeMap<CirclePoint<SecureField>, Vec<(usize, SecureField)>> = BTreeMap::new();
        
        for (column_index, column_samples) in samples.iter().enumerate() {
            for sample in column_samples {
                 grouped_samples
                    .entry(sample.point.clone()) // Added clone
                    .or_insert_with(Vec::new)
                    .push((column_index, sample.value));
            }
        }

        grouped_samples
            .into_iter()
            .map(|(point, columns_and_values)| ColumnSampleBatch {
                point,
                columns_and_values,
            })
            .collect()
    }
}


/// Holds the precomputed constant values used in each quotient evaluation.
#[derive(Debug, Clone)] // Added derive
pub struct QuotientConstants {
    /// The line coefficients for each quotient numerator term. For more details see
    /// `column_line_coeffs`.
    pub line_coeffs: Vec<Vec<(SecureField, SecureField, SecureField)>>,
    /// The random coefficients used to linearly combine the batched quotients. For more details see
    /// `batch_random_coeffs`.
    pub batch_random_coeffs: Vec<SecureField>,
}

// Placeholder for the core logic
// fn accumulate_row_quotients(...) // Removing old placeholder

pub fn accumulate_row_quotients(
    sample_batches: &[ColumnSampleBatch],
    queried_values_at_row: &[BaseField],
    quotient_constants: &QuotientConstants,
    domain_point: CirclePoint<BaseField>,
) -> SecureField {
    let denominator_inverses = denominator_inverses(sample_batches, domain_point);
    let mut row_accumulator = SecureField::zero();
    for (sample_batch, line_coeffs, batch_coeff, denominator_inverse) in izip!(
        sample_batches,
        &quotient_constants.line_coeffs,
        &quotient_constants.batch_random_coeffs,
        denominator_inverses
    ) {
        let mut numerator = SecureField::zero();
        for ((column_index, _), (a, b, c)) in zip_eq(&sample_batch.columns_and_values, line_coeffs)
        {
            if *column_index >= queried_values_at_row.len() {
                panic!(
                    "Column index {} out of bounds for queried_values_at_row (len {})",
                    *column_index, queried_values_at_row.len()
                );
            }
            let value = queried_values_at_row[*column_index] * *c;
            let linear_term = *a * domain_point.y + *b;
            numerator += SecureField::from(value) - linear_term;
        }
        // Use the specific mul_cm31 method
        row_accumulator = row_accumulator * *batch_coeff + numerator.mul_cm31(denominator_inverse);
    }
    row_accumulator
}

// Ported denominator_inverses function
fn denominator_inverses(
    sample_batches: &[ColumnSampleBatch],
    domain_point: CirclePoint<M31>, // Keep M31
) -> Vec<CM31> { // Keep CM31 return type
    let mut denominators = Vec::with_capacity(sample_batches.len());

    for sample_batch in sample_batches {
        // Extract Pr, Pi from SecureField (assuming QM31 structure: (CM31, CM31))
        // Need to access the underlying M31 components of QM31
        // Assuming SecureField = QM31(cm31_0, cm31_1) and CM31 = M31 + i * M31
        // sample_batch.point.x = qm31_x = cm31_x0 + u * cm31_x1
        // sample_batch.point.y = qm31_y = cm31_y0 + u * cm31_y1
        // cm31_x0 = m31_x00 + i*m31_x01, cm31_x1 = m31_x10 + i*m31_x11
        
        // Prover code uses: prx = sample_batch.point.x.0; -> real part of QM31 (which is CM31)
        //                   pix = sample_batch.point.x.1; -> imag part of QM31 (which is CM31)
        // Requires QM31 to be tuple struct QM31(CM31, CM31)
        // Check definition of SecureField/QM31 in src/fields/...
        
        // Assuming SecureField = QM31 and QM31 has fields .0 and .1 of type CM31
        // Assuming CM31 has fields .0 and .1 of type M31
        let prx = sample_batch.point.x.0; // CM31
        let pry = sample_batch.point.y.0; // CM31
        let pix = sample_batch.point.x.1; // CM31
        let piy = sample_batch.point.y.1; // CM31

        // The formula uses M31 components: (prx - domain_point.x) * piy - (pry - domain_point.y) * pix
        // This requires CM31 * CM31 multiplication resulting in CM31. Check CM31 ops.
        // (prx.0 - domain_point.x) needs M31 - M31
        // (pry.0 - domain_point.y) needs M31 - M31
        // Need multiplication like: (M31 * M31) - (M31 * M31)
        // Let's assume CM31 implements Mul and Sub and the formula holds.
        let domain_point_x_cm31 = CM31::from(domain_point.x);
        let domain_point_y_cm31 = CM31::from(domain_point.y);

        let denominator: CM31 = (prx - domain_point_x_cm31) * piy - (pry - domain_point_y_cm31) * pix;
        denominators.push(denominator);
    }

    // Assuming CM31 implements FieldExpOps trait for batch_inverse
    FieldExpOps::batch_inverse(&denominators)
}

pub fn fri_answers(
    column_log_sizes: Vec<Vec<u32>>,
    samples: Vec<Vec<Vec<PointSample>>>,
    random_coeff: SecureField,
    query_positions_per_log_size: &BTreeMap<u32, Vec<usize>>,
    queried_values: Vec<Vec<BaseField>>,
    n_columns_per_log_size: Vec<BTreeMap<u32, usize>>,
) -> Result<Vec<Vec<SecureField>>, VerificationError> {

    let flat_log_sizes: Vec<u32> = column_log_sizes.iter().flatten().cloned().collect();
    let flat_samples: Vec<&Vec<PointSample>> = samples.iter().flat_map(|tree| tree.iter()).collect();
    let mut queried_values_iters: Vec<_> = queried_values.into_iter().map(|v| v.into_iter()).collect();
    let n_cols_ref: Vec<&BTreeMap<u32, usize>> = n_columns_per_log_size.iter().collect();

    let mut indices_by_log_size: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (index, log_size) in flat_log_sizes.iter().enumerate() {
        indices_by_log_size.entry(*log_size).or_default().push(index);
    }

    let sorted_log_sizes = indices_by_log_size.keys().cloned().sorted_by_key(|&k| Reverse(k)).collect::<Vec<_>>();
    let mut results_by_log_size: BTreeMap<u32, Vec<SecureField>> = BTreeMap::new();

    // Compute answers per log_size
    for log_size_u32 in sorted_log_sizes {
        let indices: &[usize] = &indices_by_log_size[&log_size_u32];
        let current_samples: Vec<&Vec<PointSample>> = indices.iter().map(|&i| flat_samples[i]).collect();

        let mut n_columns_for_group: Vec<usize> = Vec::with_capacity(indices.len());
        let mut col_idx_counter = 0;
        let mut tree_idx = 0;
        let mut cols_in_tree = column_log_sizes.get(0).map_or(0, |t| t.len());
        for &original_index in indices {
             while tree_idx < column_log_sizes.len() && original_index >= col_idx_counter + cols_in_tree {
                 col_idx_counter += cols_in_tree;
                 tree_idx += 1;
                 cols_in_tree = column_log_sizes.get(tree_idx).map_or(0, |t| t.len());
             }
             if tree_idx >= n_cols_ref.len() { return Err(VerificationError::InvalidStructure("Mismatch (tree_idx)".to_string())); }
             let n_cols = n_cols_ref[tree_idx].get(&log_size_u32).copied().unwrap_or(0);
             n_columns_for_group.push(n_cols);
        }

        if let Some(query_positions) = query_positions_per_log_size.get(&log_size_u32) {
             let answers = fri_answers_for_log_size(
                 log_size_u32,
                 &current_samples,
                 indices,
                 random_coeff,
                 query_positions,
                 &mut queried_values_iters,
                 &n_columns_for_group,
             )?;
             results_by_log_size.insert(log_size_u32, answers);
        } else {
             results_by_log_size.insert(log_size_u32, Vec::new());
        }
    }

    let mut final_flat_result: Vec<Vec<SecureField>> = Vec::with_capacity(flat_log_sizes.len());
    for log_size_u32_ref in &flat_log_sizes {
         let answers_for_this_log_size = results_by_log_size.get(log_size_u32_ref)
                                        .cloned()
                                        .unwrap_or_default();
         final_flat_result.push(answers_for_this_log_size);
    }

    for mut iter in queried_values_iters.into_iter() {
         if iter.next().is_some() {
             return Err(VerificationError::InvalidStructure("Not all queried values were consumed".to_string()));
         }
    }

    Ok(final_flat_result)
}

fn fri_answers_for_log_size(
    log_size: u32,
    samples: &[&Vec<PointSample>],
    column_indices: &[usize],
    random_coeff: SecureField,
    query_positions: &[usize],
    queried_values_iters: &mut Vec<impl Iterator<Item = BaseField>>,
    n_columns_for_group: &[usize],
) -> Result<Vec<SecureField>, VerificationError> {
    let sample_batches = ColumnSampleBatch::new_vec(samples.iter().map(|v| (**v).clone()).collect::<Vec<_>>().as_slice());
    let quotient_constants = quotient_constants(&sample_batches, random_coeff);
    let commitment_domain = CanonicCoset::new(log_size).circle_domain();
    let mut quotient_evals_at_queries = Vec::with_capacity(query_positions.len());

    for &query_position in query_positions {
        let domain_point = commitment_domain.at(bit_reverse_index(query_position, log_size));
        let mut queried_values_at_row: Vec<BaseField> = Vec::new();
        let mut consumed_count = 0;

        for (group_idx, &original_col_idx) in column_indices.iter().enumerate() {
             if n_columns_for_group[group_idx] > 0 {
                if let Some(value) = queried_values_iters[original_col_idx].next() {
                    queried_values_at_row.push(value);
                    consumed_count += 1;
                } else { return Err(VerificationError::InvalidStructure(format!("Insufficient values L{} C{} Q{}", log_size, original_col_idx, query_position))); }
             }
        }
        let expected_consumed: usize = n_columns_for_group.iter().filter(|&&n| n > 0).count();
        if consumed_count != expected_consumed { return Err(VerificationError::InvalidStructure(format!("Consumed mismatch L{} Q{}", log_size, query_position))); }

        quotient_evals_at_queries.push(accumulate_row_quotients(
            &sample_batches,
            &queried_values_at_row,
            &quotient_constants,
            domain_point,
        ));
    }
    Ok(quotient_evals_at_queries)
}

/// Evaluates the coefficients of a line between a point and its complex conjugate.
/// From `stwo/core/constraints.rs`.
pub fn complex_conjugate_line_coeffs(
    sample: &PointSample,
    alpha: SecureField,
) -> (SecureField, SecureField, SecureField) {
    assert_ne!(
        sample.point.x, // Use .x field
        sample.point.x.complex_conjugate(), // Use .x field
        "Cannot evaluate a line with a single point ({:?}).",
        sample.point
    );
    let a = sample.value.complex_conjugate() - sample.value;
    let c = sample.point.y.complex_conjugate() - sample.point.y; // Use .y field
    let b = sample.value * c - a * sample.point.y; // Use .y field
    (alpha * a, alpha * b, alpha * c)
}

/// Precomputes the complex conjugate line coefficients for each column in each sample batch.
/// From `stwo/core/backend/cpu/quotients.rs`.
pub fn column_line_coeffs(
    sample_batches: &[ColumnSampleBatch],
    random_coeff: SecureField,
) -> Vec<Vec<(SecureField, SecureField, SecureField)>> {
    sample_batches
        .iter()
        .map(|sample_batch| {
            let mut alpha = SecureField::one();
            sample_batch
                .columns_and_values
                .iter()
                .map(|(_, sampled_value)| { 
                    alpha *= random_coeff;
                    let sample = PointSample {
                        point: sample_batch.point.clone(), // Added clone 
                        value: *sampled_value,
                    };
                    complex_conjugate_line_coeffs(&sample, alpha)
                })
                .collect()
        })
        .collect()
}

/// Precomputes the random coefficients used to linearly combine the batched quotients.
/// From `stwo/core/backend/cpu/quotients.rs`.
pub fn batch_random_coeffs(
    sample_batches: &[ColumnSampleBatch],
    random_coeff: SecureField,
) -> Vec<SecureField> {
    sample_batches
        .iter()
        .map(|sb| random_coeff.pow(sb.columns_and_values.len() as u128))
        .collect()
}

/// Computes and bundles the constants needed for quotient calculation.
/// From `stwo/core/backend/cpu/quotients.rs`.
pub fn quotient_constants(
    sample_batches: &[ColumnSampleBatch],
    random_coeff: SecureField,
) -> QuotientConstants { 
    QuotientConstants {
        line_coeffs: column_line_coeffs(sample_batches, random_coeff),
        batch_random_coeffs: batch_random_coeffs(sample_batches, random_coeff),
    }
}

// Removed TODOs related to removed functions 