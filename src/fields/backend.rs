use alloc::vec::Vec;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use core::hash::Hash;
use core::cmp::{Eq, Ord, PartialEq, PartialOrd};
use core::marker::PhantomData;

use crate::fields::m31::M31;
use crate::fields::qm31::QM31;

/// Trait for column operations
pub trait ColumnOps<F: Zero + Clone + Copy>: Clone {
    fn zeros(len: usize) -> Self;
    unsafe fn uninitialized(len: usize) -> Self;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn at(&self, index: usize) -> F;
    fn set(&mut self, index: usize, value: F);
    fn to_cpu(&self) -> Col<CpuBackend<F>, F>;
}

/// A column of field elements
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Col<B: ColumnOps<F>, F: Zero + Clone + Copy> {
    backend: B,
    _phantom: core::marker::PhantomData<(B, F)>,
}

impl<B: ColumnOps<F>, F: Zero + Clone + Copy> Col<B, F> {
    pub fn zeros(len: usize) -> Self {
        Self {
            backend: B::zeros(len),
            _phantom: core::marker::PhantomData,
        }
    }

    pub unsafe fn uninitialized(len: usize) -> Self {
        Self {
            backend: B::uninitialized(len),
            _phantom: core::marker::PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.backend.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backend.is_empty()
    }

    pub fn at(&self, index: usize) -> F {
        self.backend.at(index)
    }

    pub fn set(&mut self, index: usize, value: F) {
        self.backend.set(index, value);
    }

    pub fn to_cpu(&self) -> Col<CpuBackend<F>, F> {
        self.backend.to_cpu()
    }
}

impl<B: ColumnOps<F>, F: Zero + Clone + Copy + Serialize> Serialize for Col<B, F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut values = Vec::with_capacity(self.len());
        for i in 0..self.len() {
            values.push(self.at(i));
        }
        values.serialize(serializer)
    }
}

impl<'de, B: ColumnOps<F>, F: Zero + Clone + Copy + Deserialize<'de>> Deserialize<'de> for Col<B, F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct VecVisitor<F>(core::marker::PhantomData<F>);
        impl<'de, F: Deserialize<'de>> serde::de::Visitor<'de> for VecVisitor<F> {
            type Value = Vec<F>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a sequence of field values")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(value) = seq.next_element()? {
                    vec.push(value);
                }
                Ok(vec)
            }
        }

        let values = deserializer.deserialize_seq(VecVisitor(core::marker::PhantomData))?;
        let mut col = unsafe { Self::uninitialized(values.len()) };
        for (i, value) in values.into_iter().enumerate() {
            col.set(i, value);
        }
        Ok(col)
    }
}

/// CPU backend implementation
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CpuBackend<F: Zero + Clone + Copy> {
    values: Vec<F>,
}

impl<F: Zero + Clone + Copy> ColumnOps<F> for CpuBackend<F> {
    fn zeros(len: usize) -> Self {
        let mut values = Vec::with_capacity(len);
        values.resize(len, F::zero());
        Self { values }
    }

    unsafe fn uninitialized(len: usize) -> Self {
        let mut values = Vec::with_capacity(len);
        values.set_len(len);
        Self { values }
    }

    fn len(&self) -> usize {
        self.values.len()
    }

    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn at(&self, index: usize) -> F {
        self.values[index]
    }

    fn set(&mut self, index: usize, value: F) {
        self.values[index] = value;
    }

    fn to_cpu(&self) -> Col<CpuBackend<F>, F> {
        Col {
            backend: self.clone(),
            _phantom: core::marker::PhantomData,
        }
    }
}

// Implement Serialize and Deserialize for specific field types
impl Serialize for CpuBackend<M31> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.values.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CpuBackend<M31> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct VecVisitor;
        impl<'de> serde::de::Visitor<'de> for VecVisitor {
            type Value = Vec<M31>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a sequence of M31 values")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(value) = seq.next_element()? {
                    vec.push(value);
                }
                Ok(vec)
            }
        }

        let values = deserializer.deserialize_seq(VecVisitor)?;
        Ok(Self { values })
    }
}

impl Serialize for CpuBackend<QM31> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.values.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CpuBackend<QM31> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct VecVisitor;
        impl<'de> serde::de::Visitor<'de> for VecVisitor {
            type Value = Vec<QM31>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a sequence of QM31 values")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(value) = seq.next_element()? {
                    vec.push(value);
                }
                Ok(vec)
            }
        }

        let values = deserializer.deserialize_seq(VecVisitor)?;
        Ok(Self { values })
    }
} 