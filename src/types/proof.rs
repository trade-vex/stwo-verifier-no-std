use alloc::vec::Vec;
use crate::fields::qm31::SecureField;
use crate::channel::MerkleHasher;
use crate::types::commitment::MerkleDecommitment;
use crate::fri::FriProof;
use crate::fri::FriConfig;

use std::array;

#[derive(Clone, Debug)]
pub struct StarkProof<H: MerkleHasher>(pub CommitmentSchemeProof<H>);

impl<H: MerkleHasher> StarkProof<H> {
    pub fn extract_composition_oods_eval(&self) -> Result<SecureField, InvalidOodsSampleStructure> {
        let [.., composition_mask] = &**self.0.sampled_values else {
            return Err(InvalidOodsSampleStructure);
        };

        let mut composition_cols = composition_mask.iter();

        let mut coordinate_evals = [SecureField::zero(); 4];
        for i in 0..4 {
            let col = &**composition_cols.next().ok_or(InvalidOodsSampleStructure)?;
            let [eval] = col.try_into().map_err(|_| InvalidOodsSampleStructure)?;
            coordinate_evals[i] = eval;
        }

        // Too many columns.
        if composition_cols.next().is_some() {
            return Err(InvalidOodsSampleStructure);
        }

        Ok(SecureField::from_partial_evals(coordinate_evals))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InvalidOodsSampleStructure;

#[derive(Clone, Debug)]
pub struct CommitmentSchemeProof<H: MerkleHasher> {
    pub commitments: Vec<H>,
    pub sampled_values: Vec<Vec<Vec<SecureField>>>,
    pub decommitments: Vec<MerkleDecommitment<H>>,
    pub queried_values: Vec<Vec<Vec<SecureField>>>,
    pub proof_of_work: u64,
    pub fri_proof: FriProof<H>,
    pub config: FriConfig,
} 