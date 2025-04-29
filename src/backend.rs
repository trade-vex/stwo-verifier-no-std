use alloc::vec::Vec;
use core::array;
use core::mem;
use serde::{Deserialize, Serialize};
use core::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign,
};
use num_traits::Zero;
use core::marker::PhantomData;
use alloc::collections::BTreeMap;

use blake2::{Blake2s256, Digest};

use crate::m31::M31;
use crate::qm31::QM31;
use crate::fields::qm31::SecureField;
use crate::channel::{Channel, MerkleChannel, MerkleHasher};
use crate::types::{
    point::CirclePoint,
    error::VerificationError,
    commitment::Tree,
    proof::CommitmentSchemeProof,
    fri::{FriProof, FriConfig, FriCirclePolyDegreeBound},
};

use crate::impl_field;
use super::{FieldExpOps, ComplexConjugate};

use crate::fields::backend::ColumnOps;
use crate::fields::m31::BaseField;

#[derive(Clone, Default, Debug)]
pub struct Blake2sHasher;

impl MerkleHasher for Blake2sHasher {
    type Hash = [u8; 32];
    fn hash_node(
        children_hashes: Option<(Self::Hash, Self::Hash)>,
        column_values: &[BaseField],
    ) -> Self::Hash {
        let mut hasher = Blake2s256::new();

        if let Some((left_child, right_child)) = children_hashes {
            hasher.update(left_child);
            hasher.update(right_child);
        }

        for value in column_values {
            hasher.update(value.0.to_le_bytes());
        }
        let result = hasher.finalize();
        result.into()
    }
}

#[derive(Clone, Default, Debug)]
pub struct Blake2sChannel {
    state: [u8; 32],
    counter: u64,
}

impl Blake2sChannel {
    pub fn new(seed: &[u8]) -> Self {
        let mut state = [0u8; 32];
        let mut hasher = Blake2s256::new();
        hasher.update(seed);
        state.copy_from_slice(&hasher.finalize());
        Self { state, counter: 0 }
    }

    fn update_state(&mut self) {
        let mut hasher = Blake2s256::new();
        hasher.update(&self.state);
        hasher.update(&self.counter.to_le_bytes());
        self.state.copy_from_slice(&hasher.finalize());
        self.counter = self.counter.wrapping_add(1);
    }
}

impl Channel for Blake2sChannel {
    const BYTES_PER_HASH: usize = 32;

    fn trailing_zeros(&self) -> u32 {
        self.state.iter()
            .rev()
            .map(|&b| b.trailing_zeros())
            .sum()
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let mut hasher = Blake2s256::new();
        hasher.update(&self.state);
        for felt in felts {
             let m31_components = felt.to_m31_array();
             for component in m31_components {
                 hasher.update(&component.to_bytes());
             }
        }
        self.state.copy_from_slice(&hasher.finalize());
    }

    fn mix_u64(&mut self, value: u64) {
        let mut hasher = Blake2s256::new();
        hasher.update(&self.state);
        hasher.update(&value.to_le_bytes());
        self.state.copy_from_slice(&hasher.finalize());
    }

    fn draw_felt(&mut self) -> M31 {
        self.update_state();
        let bytes: [u8; 4] = self.state[..4].try_into().unwrap();
        M31::from(u32::from_le_bytes(bytes))
    }

    fn draw_secure_felt(&mut self) -> SecureField {
        SecureField::from_m31_array([
            self.draw_felt(), 
            self.draw_felt(), 
            self.draw_felt(), 
            self.draw_felt()
        ])
    }
}

#[derive(Clone, Debug)]
pub struct CommitmentSchemeVerifierImpl {
    _phantom: PhantomData<Blake2sHasher>,
}

impl CommitmentSchemeVerifierImpl {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    pub fn commit(&self, values: &[M31]) -> Tree {
         let value_bytes: Vec<u8> = values.iter().flat_map(|m| m.to_bytes()).collect();
         Tree::new(&value_bytes)
    }

    pub fn verify_values(
        &self,
        tree: &Tree,
        point: CirclePoint<M31>,
        values: &[M31],
    ) -> Result<(), VerificationError> {
        let _ = (tree, point, values);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FriVerifier<MC: MerkleChannel> {
    pub config: FriConfig,
    pub layer_commitments: Vec<<MC::H as MerkleHasher>::Hash>,
    _phantom: PhantomData<MC>,
}

impl<MC: MerkleChannel> FriVerifier<MC> 
where <MC::H as MerkleHasher>::Hash: Clone + core::fmt::Debug + AsRef<[u8]>
{
    pub fn commit(
        channel: &mut MC::C, 
        config: FriConfig, 
        proof: FriProof<MC::H>, 
        bounds: &[FriCirclePolyDegreeBound]
    ) -> Result<Self, VerificationError> 
    where <MC::H as MerkleHasher>::Hash: Clone + core::fmt::Debug + AsRef<[u8]>
    {
        let mut layer_commitments = Vec::new();

        for layer_proof in &proof.inner_layers {
            let commitment = layer_proof.commitment.clone();
            MC::mix_root(channel, commitment.clone());
            layer_commitments.push(commitment);
        }

        Ok(Self {
            config,
            layer_commitments,
            _phantom: PhantomData,
        })
    }

    pub fn new(config: FriConfig) -> Self {
        Self { config, layer_commitments: Vec::new(), _phantom: PhantomData }
    }

    pub fn verify(
        &self,
        proof: &FriProof<MC::H>,
        channel: &mut MC::C,
    ) -> Result<(), VerificationError> 
    where 
        <MC::H as MerkleHasher>::Hash: AsRef<[u8]> + Clone
    {
        let _ = proof;
        let _ = channel;
        Ok(())
    }

    pub fn sample_query_positions(&mut self, channel: &mut MC::C) -> BTreeMap<usize, Vec<usize>> {
        let _ = channel;
        BTreeMap::new()
    }
}

#[derive(Clone, Default, Debug)]
pub struct Blake2sMerkleChannel;

impl MerkleChannel for Blake2sMerkleChannel {
    type C = Blake2sChannel;
    type H = Blake2sHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasher>::Hash) {
         let mut hasher = Blake2s256::new();
         hasher.update(&channel.state);
         hasher.update(&root);
         channel.state.copy_from_slice(&hasher.finalize());
    }
} 