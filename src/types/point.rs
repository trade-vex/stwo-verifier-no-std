use crate::fields::m31::BaseField;
use crate::fields::qm31::SecureField;
use crate::channel::Channel;
use core::fmt::Debug;
use crate::fields::{FieldExpOps, Field};
use num_traits::{Zero, One};
use core::ops::{Add, Neg, Sub};

/// Represents a point on the complex circle group defined over a field F.
/// Uses struct { x, y } representation like the prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CirclePoint<F: Field> {
    pub x: F,
    pub y: F,
}

// Add basic constructor and methods needed
impl<F: Field> CirclePoint<F> {
    pub fn new(x: F, y: F) -> Self {
        Self { x, y }
    }

    pub fn zero() -> Self {
        Self { x: F::one(), y: F::zero() }
    }

    /// Computes the double of a point using complex number multiplication:
    /// (x + iy)^2 = (x^2 - y^2) + i(2xy).
    pub fn double(&self) -> Self {
        let xx = self.x.square();
        let yy = self.y.square();
        let xy = self.x * self.y;
        Self { x: xx - yy, y: xy + xy }
    }

    /// Computes `2x^2 - 1`.
    pub fn double_x(x: F) -> F {
        // 2x^2 - 1
        x.square().double() - F::one()
    }

    /// Repeatedly doubles the point `n` times.
    pub fn repeated_double(&self, n: u32) -> Self {
        let mut res = *self;
        let mut i = 0;
        while i < n {
            res = res.double();
            i += 1;
        }
        res
    }

    /// Converts a point to its representation in the extension field.
    /// Assumes F is BaseField and the target is SecureField.
    /// TODO: Consider trait bounds if needed more generally.
    pub fn into_ef(&self) -> CirclePoint<SecureField> 
    where 
        F: Into<SecureField> // Ensure the base field can be converted
    {
        CirclePoint {
            x: self.x.into(),
            y: self.y.into(),
        }
    }
}

// Add impl block specifically for SecureField
impl CirclePoint<SecureField> {
    // Ported from stwo/crates/prover/src/core/circle.rs
    pub fn get_random_point<C: Channel>(channel: &mut C) -> Self {
        let t = channel.draw_felt();
        let t_square = t.square();

        // Assuming SecureField implements Add, Neg, Mul, One, FieldExpOps (for inverse), Field (for double)
        let one_plus_tsquared = t_square + SecureField::one();
        let one_plus_tsquared_inv = one_plus_tsquared.inverse();

        let x = (SecureField::one() - t_square) * one_plus_tsquared_inv;
        // Assuming Field trait provides double()
        let y = t.double() * one_plus_tsquared_inv;

        Self { x, y }
    }

    // TODO: Port get_point(index) if needed
}

// This is incompatible now, needs rethinking.
// How to get x,y from channel draw?
// impl<T> CirclePoint<T> {
//     pub fn get_random_point<C: Channel>(channel: &mut C) -> Self
//     where
//         T: From<SecureField> + Field, 
//     {
//         Self { x: T::zero(), y: T::zero() } 
//     }
// }

// This y() method is no longer needed as .y access is direct
// impl<T: FieldExpOps + Copy + Field> CirclePoint<T> { 
//     pub fn y(&self) -> T {
//         self.y
//     }
// }

// TODO: Implement point arithmetic (Add, Neg, Mul<Scalar>)
// TODO: Implement complex_conjugate if needed
// TODO: Implement get_random_point 

// --- Point Arithmetic Stubs ---

impl<F: Field> Add for CirclePoint<F> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        // Complex number addition: (x1 + iy1) + (x2 + iy2) = (x1 + x2) + i(y1 + y2)
        Self { x: self.x + rhs.x, y: self.y + rhs.y }
    }
}

impl<F: Field> Neg for CirclePoint<F> 
where F: Neg<Output=F> + Copy 
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        // Negation on twisted Edwards curve: (x, y) -> (-x, y)
        Self { x: -self.x, y: self.y } // Corrected negation
    }
}

// Explicitly implement Sub using Add and Neg
impl<F: Field> Sub for CirclePoint<F>
where
    Self: Add<Self, Output = Self> + Neg<Output = Self>,
    F: Copy + Neg<Output = F>, // Ensure field requirements are met
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs) // Standard definition: a - b = a + (-b)
    }
}

// Multiplication by scalar (usize for coset iteration)
// Specify only bounds directly used by double-and-add: Add, Zero, One
// Add itself requires the other field ops.
// Removing problematic Mul<usize> implementation for now
/*
impl<F: Field + Zero + One + Add<Output=Self> + Copy>
    Mul<usize> for CirclePoint<F> 
where Self: Add<Output=Self>
{
    type Output = Self;
    fn mul(self, rhs: usize) -> Self::Output {
        let mut res = Self { x: F::zero(), y: F::one() }; 
        let mut temp = self;
        let mut n = rhs;
        if n == 0 { return res; }
        while n > 0 {
            if n & 1 == 1 {
                res = res + temp;
            }
            temp = temp + temp;
            n >>= 1;
        }
        res
    }
}
*/

// --- End Point Arithmetic Stubs --- 

// Definition from stwo/core/circle.rs
/// Integer i that represent the circle point i * CIRCLE_GEN. Treated as an
/// additive ring modulo `1 << M31_CIRCLE_LOG_ORDER`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct CirclePointIndex(pub usize);

// Need the constants and generator point
// Prover defined these in circle.rs
const M31_CIRCLE_LOG_ORDER: u32 = 31;
const M31_CIRCLE_GEN_X: BaseField = BaseField::from_u32_unchecked(2);
const M31_CIRCLE_GEN_Y: BaseField = BaseField::from_u32_unchecked(1268011823);
const M31_CIRCLE_GEN: CirclePoint<BaseField> = CirclePoint { x: M31_CIRCLE_GEN_X, y: M31_CIRCLE_GEN_Y };

impl CirclePointIndex {
    pub const fn zero() -> Self {
        Self(0)
    }

    pub const fn generator() -> Self {
        Self(1)
    }

    pub const fn reduce(self) -> Self {
        Self(self.0 & ((1 << M31_CIRCLE_LOG_ORDER) - 1))
    }

    pub fn subgroup_gen(log_size: u32) -> Self { // Changed from usize to u32
        assert!(log_size <= M31_CIRCLE_LOG_ORDER); // Both are u32
        // Operations on u32, result cast to usize for Self(usize)
        Self((1 << (M31_CIRCLE_LOG_ORDER - log_size)) as usize)
    }

    // Convert index to actual point using double-and-add
    pub fn to_point(self) -> CirclePoint<BaseField> {
        let mut res = CirclePoint::<BaseField> { x: BaseField::zero(), y: BaseField::one() }; // Identity
        let mut generator = M31_CIRCLE_GEN; // The generator point G
        let mut n = self.0; // The index to multiply by

        if n == 0 {
            return res; // 0 * G = Identity
        }

        while n > 0 {
            if n & 1 == 1 {
                res = res + generator; // Add G^(2^k) 
            }
            generator = generator + generator; // Double G -> G^(2^(k+1))
            n >>= 1;
        }
        res
    }
    
    // Add arithmetic ops if needed later (Add, Sub, Mul<usize>, Neg)
    // Add half() method if needed by Coset

    // Added from prover code
    pub fn add(self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0)).reduce()
    }

    pub fn sub(self, rhs: Self) -> Self {
        Self(self.0.wrapping_sub(rhs.0)).reduce()
    }
    
    pub fn neg(self) -> Self {
         Self(0).sub(self)
    }
    
    // Needs FieldLike multiplication (not just usize)
    // For now, implement Mul<usize> as requested by Coset::at
    pub fn mul(self, rhs: usize) -> Self { // Mul<usize>
         // Prover uses FieldLike trait here. 
         // Treating usize as a field element isn't quite right, but needed for now.
         // Need to handle potential overflow and reduction.
         let res = (self.0 as u128) * (rhs as u128);
         // Reduce assuming M31_CIRCLE_LOG_ORDER is max
         Self((res % (1u128 << M31_CIRCLE_LOG_ORDER)) as usize)
    }

    // Added from prover code
    pub fn half(self) -> Self {
        // Assumes index is even, which should hold for step_size of non-odds cosets.
        // TODO: Add assertion or error handling if needed.
        assert!(self.0 & 1 == 0, "CirclePointIndex::half called on odd index");
        Self(self.0 >> 1)
    }
} 