use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign};
use core::marker::PhantomData;
use bytemuck::{Pod, Zeroable};
use num_traits::{Num, Zero, One, NumAssign, NumAssignOps, NumOps};
use serde::{Deserialize, Serialize};
use alloc::vec::Vec;

pub mod cm31;
pub mod m31;
pub mod qm31;
pub mod secure_column;
pub mod backend;

pub trait FieldExpOps: Mul<Output = Self> + MulAssign + Sized + One + Clone {
    fn square(&self) -> Self {
        self.clone() * self.clone()
    }

    fn pow(&self, exp: u32) -> Self {
        let mut res = Self::one();
        let mut base = self.clone();
        let mut exp = exp;
        while exp > 0 {
            if exp & 1 == 1 {
                res *= base.clone();
            }
            base = base.square();
            exp >>= 1;
        }
        res
    }

    fn inverse(&self) -> Self;

    fn batch_inverse(column: &[Self]) -> Vec<Self> {
        batch_inverse(column)
    }
}

/// Assumes dst is initialized and of the same length as column.
fn batch_inverse_classic<T: FieldExpOps>(column: &[T], dst: &mut [T]) {
    let n = column.len();
    debug_assert!(dst.len() >= n);

    if let Some(first) = column.first() {
        dst[0] = first.clone();
    } else {
        return;
    }

    // First pass.
    for i in 1..n {
        dst[i] = dst[i - 1].clone() * column[i].clone();
    }

    // Inverse cumulative product.
    let mut curr_inverse = dst[n - 1].inverse();

    // Second pass.
    for i in (1..n).rev() {
        dst[i] = dst[i - 1].clone() * curr_inverse.clone();
        curr_inverse *= column[i].clone();
    }
    dst[0] = curr_inverse;
}

/// Inverts a batch of elements using Montgomery's trick.
pub fn batch_inverse_in_place<F: FieldExpOps>(column: &[F], dst: &mut [F]) {
    // Placeholder implementation
    if column.len() != dst.len() { /* handle error or panic */ }
    for (d, c) in dst.iter_mut().zip(column.iter()) {
        *d = c.inverse(); // Basic, non-batched inverse
    }
    // Original logic relied on WIDTH, chunking, std::array::from_fn etc.
}

/// Return empty Vec - TODO: Implement correctly
pub fn batch_inverse<F: FieldExpOps>(_column: &[F]) -> Vec<F> {
    Vec::new()
}

/// Return () - TODO: Implement correctly
pub fn batch_inverse_parallel<T: FieldExpOps + Pod>(
    _column: &[T],
    _dst: &mut [T],
    _chunk_size: usize,
) {
    // Placeholder
}

/// Return empty Vec - TODO: Implement correctly
pub fn batch_inverse_reordered_parallel<T: FieldExpOps + Pod>(
    _column: &[T],
    _chunk_size: usize,
) -> Vec<T> {
    Vec::new()
}

pub trait Field:
    NumAssign
    + Neg<Output = Self>
    + ComplexConjugate
    + Copy
    + Default
    + PartialOrd
    + Ord
    + Send
    + Sync
    + Sized
    + FieldExpOps
    + Product
    + for<'a> Product<&'a Self>
    + Sum
    + for<'a> Sum<&'a Self>
{
    fn double(&self) -> Self {
        *self + *self
    }
}

/// # Safety
///
/// Do not use unless you are aware of the endianess in the platform you are compiling for, and the
/// Field element's representation in memory.
// TODO(Ohad): Do not compile on non-le targets.
pub unsafe trait IntoSlice<T: Sized>: Sized {
    fn into_slice(sl: &[Self]) -> &[T] {
        unsafe {
            core::slice::from_raw_parts(
                sl.as_ptr() as *const T,
                core::mem::size_of_val(sl) / core::mem::size_of::<T>(),
            )
        }
    }
}

unsafe impl<F: Field> IntoSlice<u8> for F {}

pub trait ComplexConjugate {
    /// # Example
    ///
    /// ```
    /// use stwo_prover::core::fields::m31::P;
    /// use stwo_prover::core::fields::qm31::QM31;
    /// use stwo_prover::core::fields::ComplexConjugate;
    ///
    /// let x = QM31::from_u32_unchecked(1, 2, 3, 4);
    /// assert_eq!(
    ///     x.complex_conjugate(),
    ///     QM31::from_u32_unchecked(1, 2, P - 3, P - 4)
    /// );
    /// ```
    fn complex_conjugate(&self) -> Self;
}

pub trait ExtensionOf<F: Field>: Field + From<F> + NumOps<F> + NumAssignOps<F> {
    const EXTENSION_DEGREE: usize;
}

impl<F: Field> ExtensionOf<F> for F {
    const EXTENSION_DEGREE: usize = 1;
}

#[macro_export]
macro_rules! impl_field {
    ($field_name: ty, $field_size: ident) => {
        use core::iter::{Product, Sum};

        use num_traits::{Num, Zero, One};
        use $crate::fields::Field;

        impl Num for $field_name {
            type FromStrRadixErr = ();

            fn from_str_radix(_str: &str, _radix: u32) -> Result<Self, Self::FromStrRadixErr> {
                Err(())
            }
        }

        impl Field for $field_name {}

        impl AddAssign for $field_name {
            fn add_assign(&mut self, rhs: Self) {
                *self = *self + rhs;
            }
        }

        impl SubAssign for $field_name {
            fn sub_assign(&mut self, rhs: Self) {
                *self = *self - rhs;
            }
        }

        impl MulAssign for $field_name {
            fn mul_assign(&mut self, rhs: Self) {
                *self = *self * rhs;
            }
        }

        impl Div for $field_name {
            type Output = Self;

            #[allow(clippy::suspicious_arithmetic_impl)]
            fn div(self, rhs: Self) -> Self::Output {
                self * rhs.inverse()
            }
        }

        impl DivAssign for $field_name {
            fn div_assign(&mut self, rhs: Self) {
                *self = *self / rhs;
            }
        }

        impl Rem for $field_name {
            type Output = Self;

            fn rem(self, _rhs: Self) -> Self::Output {
                unimplemented!("Rem is not implemented for {}", stringify!($field_name));
            }
        }

        impl RemAssign for $field_name {
            fn rem_assign(&mut self, _rhs: Self) {
                unimplemented!(
                    "RemAssign is not implemented for {}",
                    stringify!($field_name)
                );
            }
        }

        impl Product for $field_name {
            fn product<I>(mut iter: I) -> Self
            where
                I: Iterator<Item = Self>,
            {
                let first = iter.next().unwrap_or_else(Self::one);
                iter.fold(first, |a, b| a * b)
            }
        }

        impl<'a> Product<&'a Self> for $field_name {
            fn product<I>(iter: I) -> Self
            where
                I: Iterator<Item = &'a Self>,
            {
                iter.map(|&v| v).product()
            }
        }

        impl Sum for $field_name {
            fn sum<I>(mut iter: I) -> Self
            where
                I: Iterator<Item = Self>,
            {
                let first = iter.next().unwrap_or_else(Self::zero);
                iter.fold(first, |a, b| a + b)
            }
        }

        impl<'a> Sum<&'a Self> for $field_name {
            fn sum<I>(iter: I) -> Self
            where
                I: Iterator<Item = &'a Self>,
            {
                iter.map(|&v| v).sum()
            }
        }
    };
}

/// Used to extend a field (with characteristic M31) by 2.
#[macro_export]
macro_rules! impl_extension_field {
    ($field_name: ident, $extended_field_name: ty) => {
        use $crate::fields::ExtensionOf;

        impl ExtensionOf<M31> for $field_name {
            const EXTENSION_DEGREE: usize =
                <$extended_field_name as ExtensionOf<M31>>::EXTENSION_DEGREE * 2;
        }

        impl Add for $field_name {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                Self(self.0 + rhs.0, self.1 + rhs.1)
            }
        }

        impl Neg for $field_name {
            type Output = Self;

            fn neg(self) -> Self::Output {
                Self(-self.0, -self.1)
            }
        }

        impl Sub for $field_name {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self::Output {
                Self(self.0 - rhs.0, self.1 - rhs.1)
            }
        }

        impl One for $field_name {
            fn one() -> Self {
                Self(
                    <$extended_field_name>::one(),
                    <$extended_field_name>::zero(),
                )
            }
        }

        impl Zero for $field_name {
            fn zero() -> Self {
                Self(
                    <$extended_field_name>::zero(),
                    <$extended_field_name>::zero(),
                )
            }

            fn is_zero(&self) -> bool {
                *self == Self::zero()
            }
        }

        impl Add<M31> for $field_name {
            type Output = Self;

            fn add(self, rhs: M31) -> Self::Output {
                Self(self.0 + rhs, self.1)
            }
        }

        impl Add<$field_name> for M31 {
            type Output = $field_name;

            fn add(self, rhs: $field_name) -> Self::Output {
                rhs + self
            }
        }

        impl Sub<M31> for $field_name {
            type Output = Self;

            fn sub(self, rhs: M31) -> Self::Output {
                Self(self.0 - rhs, self.1)
            }
        }

        impl Sub<$field_name> for M31 {
            type Output = $field_name;

            fn sub(self, rhs: $field_name) -> Self::Output {
                -rhs + self
            }
        }

        impl Mul<M31> for $field_name {
            type Output = Self;

            fn mul(self, rhs: M31) -> Self::Output {
                Self(self.0 * rhs, self.1 * rhs)
            }
        }

        impl Mul<$field_name> for M31 {
            type Output = $field_name;

            fn mul(self, rhs: $field_name) -> Self::Output {
                rhs * self
            }
        }

        impl Div<M31> for $field_name {
            type Output = Self;

            fn div(self, rhs: M31) -> Self::Output {
                Self(self.0 / rhs, self.1 / rhs)
            }
        }

        impl Div<$field_name> for M31 {
            type Output = $field_name;

            #[allow(clippy::suspicious_arithmetic_impl)]
            fn div(self, rhs: $field_name) -> Self::Output {
                rhs.inverse() * self
            }
        }

        impl ComplexConjugate for $field_name {
            fn complex_conjugate(&self) -> Self {
                Self(self.0, -self.1)
            }
        }

        impl From<M31> for $field_name {
            fn from(x: M31) -> Self {
                Self(x.into(), <$extended_field_name>::zero())
            }
        }

        impl AddAssign<M31> for $field_name {
            fn add_assign(&mut self, rhs: M31) {
                *self = *self + rhs;
            }
        }

        impl SubAssign<M31> for $field_name {
            fn sub_assign(&mut self, rhs: M31) {
                *self = *self - rhs;
            }
        }

        impl MulAssign<M31> for $field_name {
            fn mul_assign(&mut self, rhs: M31) {
                *self = *self * rhs;
            }
        }

        impl DivAssign<M31> for $field_name {
            fn div_assign(&mut self, rhs: M31) {
                *self = *self / rhs;
            }
        }

        // Implement dummy Rem<M31> to satisfy NumOps<M31>
        impl Rem<M31> for $field_name {
            type Output = Self;
            fn rem(self, _rhs: M31) -> Self::Output {
                // Remainder with base field element is ill-defined
                Self::zero()
            }
        }

        // Implement dummy RemAssign<M31> to satisfy NumAssignOps<M31>
        impl RemAssign<M31> for $field_name {
            fn rem_assign(&mut self, _rhs: M31) {
                // Remainder with base field element is ill-defined
                *self = Self::zero();
            }
        }
    };
}

pub unsafe fn u32_slice_to_felt_slice<T: Pod>(sl: &[u32]) -> &[T] {
    unsafe {
        core::slice::from_raw_parts(
            sl.as_ptr() as *const T,
            core::mem::size_of_val(sl) / core::mem::size_of::<T>(),
        )
    }
}