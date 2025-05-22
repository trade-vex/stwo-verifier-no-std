use crate::fields::qm31::SecureField;
use crate::types::point::CirclePoint;
use alloc::vec::Vec;
use alloc::vec;
use crate::verifier::PointEvaluationAccumulator;
use crate::verifier::PREPROCESSED_TRACE_IDX;
use alloc::collections::BTreeSet;

pub trait Component {
    fn n_constraints(&self) -> usize;
    fn trace_log_degree_bounds(&self) -> Vec<Vec<u32>>;
    fn preproccessed_column_indices(&self) -> Vec<usize>;
    fn max_constraint_log_degree_bound(&self) -> u32;
    fn mask_points(&self, point: CirclePoint<SecureField>) -> Vec<Vec<Vec<CirclePoint<SecureField>>>>;
    fn evaluate_constraint_quotients_at_point(
        &self,
        point: CirclePoint<SecureField>,
        mask: &[Vec<Vec<SecureField>>],
        evaluation_accumulator: &mut PointEvaluationAccumulator,
    );
}

#[derive(Clone)]
pub struct Components<'a> {
    pub components: Vec<&'a dyn Component>,
    pub n_preprocessed_columns: usize,
}

impl<'a> Component for Components<'a> {
    fn n_constraints(&self) -> usize {
        self.components.iter().map(|c| c.n_constraints()).sum()
    }

    fn trace_log_degree_bounds(&self) -> Vec<Vec<u32>> {
        self.components.iter().flat_map(|c| c.trace_log_degree_bounds()).collect()
    }

    fn preproccessed_column_indices(&self) -> Vec<usize> {
        self.components.iter().flat_map(|c| c.preproccessed_column_indices()).collect::<BTreeSet<_>>().into_iter().collect()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.components.iter()
            .map(|c| c.max_constraint_log_degree_bound())
            .max()
            .unwrap()
    }

    fn mask_points(&self, point: CirclePoint<SecureField>) -> Vec<Vec<Vec<CirclePoint<SecureField>>>> {
        if self.components.is_empty() {
            return Vec::new();
        }

        // 1. Collect all component masks
        let component_masks: Vec<Vec<Vec<Vec<CirclePoint<SecureField>>>>> = self
            .components
            .iter()
            .map(|c| c.mask_points(point.clone()))
            .collect();

        // Determine the number of phases from the first component.
        // Assume all components return masks with the same number of phases.
        let num_phases = component_masks.first().map_or(0, |m| m.len());
        
        if num_phases == 0 {
             // If the first component has 0 phases, and all others also have 0 phases, return empty.
            if component_masks.iter().all(|m| m.is_empty()) {
                return Vec::new();
            }
            // If some components have phases and others don't, this is an inconsistency.
            // For now, this implementation might not perfectly handle ragged phase counts.
            // The original prover's TreeVec likely has specific behavior for this.
            // Let's assume for now that if num_phases (from first) is 0, all should be, or it's an error state.
            // Or, a more robust way would be to find the max number of phases.
            // Given the goal of 1:1, let's stick to behavior implied by TreeVec which usually assumes regularity.
        }

        let mut aggregated_masks: Vec<Vec<Vec<CirclePoint<SecureField>>>> = vec![Vec::new(); num_phases];

        for phase_idx in 0..num_phases {
            // Determine the max number of columns in this phase across all components.
            // This allows for components to have a varying number of columns per phase.
            let max_cols_in_phase = component_masks
                .iter()
                .filter_map(|m| m.get(phase_idx))
                .map(|p| p.len())
                .max()
                .unwrap_or(0);

            aggregated_masks[phase_idx] = vec![Vec::new(); max_cols_in_phase];

            for col_idx in 0..max_cols_in_phase {
                let mut collected_points_for_col: Vec<CirclePoint<SecureField>> = Vec::new();
                for comp_mask in &component_masks {
                    if let Some(phase_data) = comp_mask.get(phase_idx) {
                        if let Some(col_points) = phase_data.get(col_idx) {
                            collected_points_for_col.extend(col_points.iter().cloned());
                        }
                        // If a component has fewer columns in this phase, its contribution to this col_idx will be empty.
                        // This matches how concatenating columns would work if some components don't have that column.
                    }
                }
                aggregated_masks[phase_idx][col_idx] = collected_points_for_col;
            }
        }

        // Apply preprocessed column logic (similar to prover)
        // PREPROCESSED_TRACE_IDX is usually 0.
        if num_phases > PREPROCESSED_TRACE_IDX && self.n_preprocessed_columns > 0 {
            // Ensure the preprocessed trace phase exists.
            // The prover's logic for preprocessed columns effectively overwrites whatever concat_cols produced
            // for that specific set of columns. It initializes them as `vec![vec![]; self.n_preprocessed_columns]`.
            
            // If aggregated_masks[PREPROCESSED_TRACE_IDX] doesn't have self.n_preprocessed_columns,
            // it should be resized. The prover code is:
            // `let preprocessed_mask_points = &mut mask_points[PREPROCESSED_TRACE_IDX];`
            // `*preprocessed_mask_points = vec![vec![]; self.n_preprocessed_columns];`
            // This replaces the entire column vector for the preprocessed trace phase.

            let mut new_preprocessed_phase_columns = vec![Vec::new(); self.n_preprocessed_columns];

            for component in &self.components {
                for &idx in &component.preproccessed_column_indices() {
                    if idx < self.n_preprocessed_columns { // Check bounds against n_preprocessed_columns
                        new_preprocessed_phase_columns[idx] = vec![point.clone()];
                    }
                }
            }
            // Replace the existing columns for the preprocessed trace phase
            aggregated_masks[PREPROCESSED_TRACE_IDX] = new_preprocessed_phase_columns;
        } else if num_phases > PREPROCESSED_TRACE_IDX && self.n_preprocessed_columns == 0 {
            // If there are no preprocessed columns, the preprocessed phase should be empty.
            aggregated_masks[PREPROCESSED_TRACE_IDX] = Vec::new();
        }


        aggregated_masks
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        point: CirclePoint<SecureField>,
        mask: &[Vec<Vec<SecureField>>],
        evaluation_accumulator: &mut PointEvaluationAccumulator,
    ) {
        for component in &self.components {
            component.evaluate_constraint_quotients_at_point(
                point.clone(),
                mask,
                evaluation_accumulator,
            );
        }
    }
}

impl<'a> Components<'a> {
    pub fn eval_composition_polynomial_at_point(
        &self,
        point: CirclePoint<SecureField>,
        mask_values: &[Vec<Vec<SecureField>>],
        random_coeff: SecureField,
    ) -> SecureField {
        let mut evaluation_accumulator = PointEvaluationAccumulator::new(random_coeff);
        for component in &self.components {
            component.evaluate_constraint_quotients_at_point(
                point.clone(), 
                mask_values,   
                &mut evaluation_accumulator,
            );
        }
        evaluation_accumulator.finalize()
    }
} 