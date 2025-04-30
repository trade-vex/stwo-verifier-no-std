use alloc::vec::Vec;
use crate::fields::qm31::SecureField;
use crate::channel::MerkleHasher;
use crate::types::commitment::MerkleDecommitment;
use crate::fri::FriProof;
use crate::fri::FriConfig;
use crate::fields::m31::BaseField;
use crate::types::pcs::PcsConfig;

use num_traits::Zero;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct StarkProof<H: MerkleHasher>(pub CommitmentSchemeProof<H>);

#[derive(Clone, Copy)]
pub struct InvalidOodsSampleStructure;

impl<H: MerkleHasher> StarkProof<H> {
    pub fn extract_composition_oods_eval(&self) -> Result<SecureField, InvalidOodsSampleStructure> {
        let sampled_values_slice: &[Vec<Vec<SecureField>>] = self.0.sampled_values.as_slice();

        let composition_mask: &Vec<Vec<SecureField>> = sampled_values_slice.last().ok_or(InvalidOodsSampleStructure)?;

        let mut composition_cols = composition_mask.iter();

        let mut coordinate_evals = [SecureField::zero(); 4];
        for i in 0..4 {
            let col_vec: &Vec<SecureField> = composition_cols.next().ok_or(InvalidOodsSampleStructure)?;
            if col_vec.len() != 1 {
                return Err(InvalidOodsSampleStructure);
            }
            let eval = col_vec[0];
            coordinate_evals[i] = eval;
        }

        if composition_cols.next().is_some() {
            return Err(InvalidOodsSampleStructure);
        }

        Ok(SecureField::from_partial_evals(coordinate_evals))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CommitmentSchemeProof<H: MerkleHasher> {
    pub config: PcsConfig,
    pub commitments: Vec<H::Hash>,
    pub sampled_values: Vec<Vec<Vec<SecureField>>>,
    pub decommitments: Vec<MerkleDecommitment<H>>,
    pub queried_values: Vec<Vec<BaseField>>,
    pub proof_of_work: u64,
    pub fri_proof: FriProof<H>,
}