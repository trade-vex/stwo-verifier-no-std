use serde::{Deserialize, Serialize};
use std::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign,
};

use crate::{impl_field, impl_extension_field};
use crate::fields::m31::M31;
use crate::fields::{FieldExpOps, ComplexConjugate};

/// Complex extension field of M31.
/// Equivalent to M31\[x\] over (x^2 + 1) as the irreducible polynomial.
/// Represented as (a, b) of a + bi.
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CM31(pub M31, pub M31);

impl_field!(CM31, P2);
impl_extension_field!(CM31, M31);

impl CM31 {
    pub const fn from_u32_unchecked(a: u32, b: u32) -> CM31 {
        Self(M31::from_u32_unchecked(a), M31::from_u32_unchecked(b))
    }

    pub const fn from_m31(a: M31, b: M31) -> CM31 {
        Self(a, b)
    }
}

impl Mul for CM31 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        // (a + bi) * (c + di) = (ac - bd) + (ad + bc)i.
        Self(
            self.0 * rhs.0 - self.1 * rhs.1,
            self.0 * rhs.1 + self.1 * rhs.0,
        )
    }
}

impl TryInto<M31> for CM31 {
    type Error = ();

    fn try_into(self) -> Result<M31, Self::Error> {
        if self.1 != M31::zero() {
            return Err(());
        }
        Ok(self.0)
    }
}

impl FieldExpOps for CM31 {
    fn inverse(&self) -> Self {
        assert!(!self.is_zero(), "0 has no inverse");
        // 1 / (a + bi) = (a - bi) / (a^2 + b^2).
        Self(self.0, -self.1) * (self.0.square() + self.1.square()).inverse()
    }
}