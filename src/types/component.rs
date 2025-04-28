use crate::fields::qm31::SecureField;
use crate::fields::m31::BaseField;
use crate::types::point::CirclePoint;

pub trait Component {
    fn composition_log_degree_bound(&self) -> usize;
    fn mask_points(&self, point: CirclePoint<SecureField>) -> Vec<Vec<Vec<CirclePoint<SecureField>>>>;
    fn eval_composition_polynomial_at_point(
        &self,
        point: CirclePoint<SecureField>,
        sampled_values: &[Vec<Vec<SecureField>>],
        random_coeff: BaseField,
    ) -> SecureField;
}

#[derive(Clone, Debug)]
pub struct Components<'a> {
    pub components: Vec<&'a dyn Component>,
    pub n_preprocessed_columns: usize,
} 