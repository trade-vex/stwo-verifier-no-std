use serde::{Deserialize, Serialize};
use std::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign,
};

use super::cm31::CM31;
use super::m31::M31;
use crate::impl_field;
use crate::impl_extension_field;
use super::{FieldExpOps, ComplexConjugate};
use super::secure_column::SECURE_EXTENSION_DEGREE;

pub const P4: u128 = 21267647892944572736998860269687930881; // (2 ** 31 - 1) ** 4
pub const R: CM31 = CM31::from_u32_unchecked(2, 1);

/// Extension field of CM31.
/// Equivalent to CM31\[x\] over (x^2 - 2 - i) as the irreducible polynomial.
/// Represented as ((a, b), (c, d)) of (a + bi) + (c + di)u.
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct QM31(pub CM31, pub CM31);
pub type SecureField = QM31;

impl_field!(QM31, P4);
impl_extension_field!(QM31, CM31);

impl QM31 {
    pub const fn from_u32_unchecked(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self(
            CM31::from_u32_unchecked(a, b),
            CM31::from_u32_unchecked(c, d),
        )
    }

    pub const fn from_m31(a: M31, b: M31, c: M31, d: M31) -> Self {
        Self(CM31::from_m31(a, b), CM31::from_m31(c, d))
    }

    pub const fn from_m31_array(array: [M31; SECURE_EXTENSION_DEGREE]) -> Self {
        Self::from_m31(array[0], array[1], array[2], array[3])
    }

    pub const fn to_m31_array(self) -> [M31; SECURE_EXTENSION_DEGREE] {
        [self.0 .0, self.0 .1, self.1 .0, self.1 .1]
    }

    /// Returns the combined value, given the values of its composing base field polynomials at that
    /// point.
    pub fn from_partial_evals(evals: [Self; SECURE_EXTENSION_DEGREE]) -> Self {
        let mut res = evals[0];
        res += evals[1] * Self::from_u32_unchecked(0, 1, 0, 0);
        res += evals[2] * Self::from_u32_unchecked(0, 0, 1, 0);
        res += evals[3] * Self::from_u32_unchecked(0, 0, 0, 1);
        res
    }

    // Note: Adding this as a Mul impl drives rust insane, and it tries to infer Qm31*Qm31 as
    // QM31*CM31.
    pub fn mul_cm31(self, rhs: CM31) -> Self {
        Self(self.0 * rhs, self.1 * rhs)
    }
}

impl Mul for QM31 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        // (a + bu) * (c + du) = (ac + rbd) + (ad + bc)u.
        Self(
            self.0 * rhs.0 + R * self.1 * rhs.1,
            self.0 * rhs.1 + self.1 * rhs.0,
        )
    }
}

impl From<usize> for QM31 {
    fn from(value: usize) -> Self {
        M31::from(value).into()
    }
}

impl From<u32> for QM31 {
    fn from(value: u32) -> Self {
        M31::from(value).into()
    }
}

impl From<i32> for QM31 {
    fn from(value: i32) -> Self {
        M31::from(value).into()
    }
}

impl TryInto<M31> for QM31 {
    type Error = ();

    fn try_into(self) -> Result<M31, Self::Error> {
        if self.1 != CM31::zero() {
            return Err(());
        }
        self.0.try_into()
    }
}

impl FieldExpOps for QM31 {
    fn inverse(&self) -> Self {
        assert!(!self.is_zero(), "0 has no inverse");
        // (a + bu)^-1 = (a - bu) / (a^2 - (2+i)b^2).
        let b2 = self.1.square();
        let ib2 = CM31(-b2.1, b2.0);
        let denom = self.0.square() - (b2 + b2 + ib2);
        let denom_inverse = denom.inverse();
        Self(self.0 * denom_inverse, -self.1 * denom_inverse)
    }
}