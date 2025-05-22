use crate::types::point::CirclePoint; // Removed CirclePointIndex
use crate::types::poly::Coset; // Adjusted import
use crate::fields::qm31::SecureField; // Adjusted import

/// Evaluates a vanishing polynomial of the coset at a point.
/// Ported from stwo/crates/prover/src/core/constraints.rs
/// Specialised to SecureField as F, removing generics.
pub fn coset_vanishing(coset: Coset, mut p: CirclePoint<SecureField>) -> SecureField
{
    // Doubling a point `log_order - 1` times and taking the x coordinate is
    // essentially evaluating a polynomial in x of degree `2^(log_order - 1)`. If
    // the entire `2^log_order` points of the coset are roots (i.e. yield 0), then
    // this is a vanishing polynomial of these points.

    // Rotating the coset -coset.initial + step / 2 yields a canonic coset:
    // `step/2 + <step>.`
    // Doubling this coset log_order - 1 times yields the coset +-G_4.
    // The polynomial x vanishes on these points.
    // ```text
    //   X
    // .   .
    //   X
    // ```
    
    // Need `Coset` fields to be public or have getters
    let initial_point_ef = coset.initial.into_ef();
    // Need CirclePointIndex::half() and to_point()
    let half_step_point_ef = coset.step_size.half().to_point().into_ef();
    
    // CirclePoint ops should now work as all points are CirclePoint<SecureField>
    p = p - initial_point_ef + half_step_point_ef; 
    let mut x = p.x;

    // Need CirclePoint::double_x(x) defined for SecureField
    // Need coset.log_size to be public or have getter
    for _ in 1..coset.log_size {
        x = CirclePoint::double_x(x);
    }
    x
}

// TODO: Add point_excluder, pair_vanishing, point_vanishing if needed later 