use core::array;
use core::iter::zip;
use serde::{Deserialize, Serialize};
use alloc::vec::Vec;

use super::m31::M31;
use super::qm31::SecureField;
use super::ExtensionOf;
use super::backend::{Col, ColumnOps, CpuBackend};
use num_traits::Zero;


pub const SECURE_EXTENSION_DEGREE: usize =
    <SecureField as ExtensionOf<M31>>::EXTENSION_DEGREE;

/// A column major array of `SECURE_EXTENSION_DEGREE` base field columns, that represents a column
/// of secure field element coordinates.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct SecureColumnByCoords<B: ColumnOps<M31>> {
    pub columns: [Col<B, M31>; SECURE_EXTENSION_DEGREE],
}

impl SecureColumnByCoords<CpuBackend<M31>> {
    // TODO(first): Remove.
    pub fn to_vec(&self) -> Vec<SecureField> {
        (0..self.len()).map(|i| self.at(i)).collect()
    }
}

impl<B: ColumnOps<M31>> SecureColumnByCoords<B> {
    pub fn at(&self, index: usize) -> SecureField {
        SecureField::from_m31_array(core::array::from_fn(|i| self.columns[i].at(index)))
    }

    pub fn zeros(len: usize) -> Self {
        Self {
            columns: core::array::from_fn(|_| Col::<B, M31>::zeros(len)),
        }
    }

    /// # Safety
    pub unsafe fn uninitialized(len: usize) -> Self {
        Self {
            columns: core::array::from_fn(|_| Col::<B, M31>::uninitialized(len)),
        }
    }

    pub fn len(&self) -> usize {
        self.columns[0].len()
    }

    pub fn is_empty(&self) -> bool {
        self.columns[0].is_empty()
    }

    pub fn to_cpu(&self) -> SecureColumnByCoords<CpuBackend<M31>> {
        SecureColumnByCoords {
            columns: self.columns.clone().map(|c| c.to_cpu()),
        }
    }

    pub fn set(&mut self, index: usize, value: SecureField) {
        let values = value.to_m31_array();
        for i in 0..SECURE_EXTENSION_DEGREE {
            self.columns[i].set(index, values[i]);
        }
    }
}

pub struct SecureColumnByCoordsIter<'a> {
    column: &'a SecureColumnByCoords<CpuBackend<M31>>,
    index: usize,
}

impl Iterator for SecureColumnByCoordsIter<'_> {
    type Item = SecureField;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.column.len() {
            let value = self.column.at(self.index);
            self.index += 1;
            Some(value)
        } else {
            None
        }
    }
}

impl<'a> IntoIterator for &'a SecureColumnByCoords<CpuBackend<M31>> {
    type Item = SecureField;
    type IntoIter = SecureColumnByCoordsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SecureColumnByCoordsIter {
            column: self,
            index: 0,
        }
    }
}

impl FromIterator<M31> for SecureColumnByCoords<CpuBackend<M31>> {
    fn from_iter<I: IntoIterator<Item = M31>>(iter: I) -> Self {
        let values = iter.into_iter();
        let (lower_bound, _) = values.size_hint();
        let mut vecs: [Vec<M31>; SECURE_EXTENSION_DEGREE] = array::from_fn(|_| Vec::with_capacity(lower_bound));

        for value in values {
            let coords = [value, M31::zero(), M31::zero(), M31::zero()];
            zip(&mut vecs, coords).for_each(|(col, coord)| col.push(coord));
        }

        let columns = array::from_fn(|i| unsafe {
            let mut col = Col::<CpuBackend<M31>, M31>::uninitialized(vecs[i].len());
            for (j, val) in vecs[i].iter().enumerate() {
                col.set(j, *val);
            }
            col
        });

        SecureColumnByCoords { columns }
    }
}

impl From<SecureColumnByCoords<CpuBackend<M31>>> for Vec<SecureField> {
    fn from(column: SecureColumnByCoords<CpuBackend<M31>>) -> Self {
        column.into_iter().collect()
    }
}
