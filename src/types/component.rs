use crate::fields::qm31::SecureField;
use crate::fields::m31::BaseField;
use crate::types::point::CirclePoint;
use num_traits::Zero;
use alloc::vec::Vec;

pub trait Component {
    fn composition_log_degree_bound(&self) -> usize;
    fn mask_points(&self, point: CirclePoint<SecureField>) -> Vec<Vec<Vec<CirclePoint<SecureField>>>>;
    fn eval_composition_polynomial_at_point(
        &self,
        point: CirclePoint<SecureField>,
        sampled_values: &[Vec<Vec<SecureField>>],
        random_coeff: SecureField,
    ) -> SecureField;
}

#[derive(Clone)]
pub struct Components<'a> {
    pub components: Vec<&'a dyn Component>,
    pub n_preprocessed_columns: usize,
}

impl<'a> Component for Components<'a> {
    fn composition_log_degree_bound(&self) -> usize {
        self.components.iter()
            .map(|c| c.composition_log_degree_bound())
            .max()
            .unwrap_or(0)
    }

    fn mask_points(&self, point: CirclePoint<SecureField>) -> Vec<Vec<Vec<CirclePoint<SecureField>>>> {
        let mut points = Vec::new();
        for component in &self.components {
            points.extend(component.mask_points(point.clone()));
        }
        points
    }

    fn eval_composition_polynomial_at_point(
        &self,
        point: CirclePoint<SecureField>,
        sampled_values: &[Vec<Vec<SecureField>>],
        random_coeff: SecureField,
    ) -> SecureField {
        let mut result = SecureField::zero();
        for component in &self.components {
            result = result + component.eval_composition_polynomial_at_point(
                point.clone(),
                sampled_values,
                random_coeff,
            );
        }
        result
    }
} 