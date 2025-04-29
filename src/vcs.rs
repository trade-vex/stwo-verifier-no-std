use alloc::vec::Vec;
use core::fmt::Debug;
use crate::channel::MerkleHasher;
use crate::types::commitment::MerkleDecommitment; // Assuming this exists
use crate::types::error::VerificationError; // Assuming this exists
use alloc::collections::BTreeMap; // Use alloc::collections
use crate::fields::m31::BaseField; // Import BaseField
use core::iter::{Peekable, Copied, Flatten, Chain};
use core::option; // For Option::into_iter

// Placeholder MerkleVerifier based on prover structure
// Needs adaptation for no-std and actual verification logic
#[derive(Clone, Debug)]
pub struct MerkleVerifier<H: MerkleHasher> where H::Hash: Clone + Debug + AsRef<[u8]> {
    pub commitment: H::Hash,
    pub column_log_sizes: Vec<usize>, // Log size of columns within this tree
    pub n_columns_per_log_size: BTreeMap<usize, usize>,
}

impl<H: MerkleHasher> MerkleVerifier<H> where H::Hash: Clone + Debug + AsRef<[u8]> + Eq {
    pub fn new(commitment: H::Hash, column_log_sizes: Vec<usize>) -> Self {
        let mut n_columns_per_log_size = BTreeMap::new();
        for log_size in &column_log_sizes {
            *n_columns_per_log_size.entry(*log_size).or_insert(0) += 1;
        }
        Self { commitment, column_log_sizes, n_columns_per_log_size }
    }

    // TODO: Implement actual Merkle verification logic here
    pub fn verify(
        &self,
        queries_per_log_size: &BTreeMap<usize, Vec<usize>>, // Key is usize
        queried_values: &[BaseField],
        decommitment: MerkleDecommitment<H>
    ) -> Result<(), VerificationError> {
        // Explicitly bring trait into scope for associated function call
        use crate::channel::MerkleHasher;

        let Some(max_log_size) = self.column_log_sizes.iter().max().copied() else {
            if self.commitment == H::hash_node(None, &[]) { // Handle empty commit
                return Ok(());
            } else {
                return Err(VerificationError::MerkleProof); // Or specific error
            }
        };

        let mut queried_values_iter = queried_values.iter().copied();
        let mut hash_witness = decommitment.hash_witness.into_iter();
        let mut column_witness = decommitment.column_witness.into_iter();

        // Store computed hashes for the current layer being processed.
        // Map from node index to computed hash.
        let mut current_layer_hashes: BTreeMap<usize, H::Hash> = BTreeMap::new();

        for layer_log_size in (0..=max_log_size).rev() {
            let n_columns_in_layer = self.n_columns_per_log_size.get(&layer_log_size).copied().unwrap_or(0);
            let mut next_layer_hashes: BTreeMap<usize, H::Hash> = BTreeMap::new();

            let prev_layer_node_indices = current_layer_hashes.keys().copied().collect::<Vec<_>>();

            let mut prev_layer_queries = prev_layer_node_indices.into_iter().peekable();
            let mut layer_column_queries = option_flatten_peekable(queries_per_log_size.get(&layer_log_size));

            while let Some(node_index) = next_decommitment_node(&mut prev_layer_queries, &mut layer_column_queries) {

                let children_hashes = if layer_log_size == max_log_size {
                    // Leaf layer
                    None
                } else {
                    // Read children hashes: either computed from previous layer or from witness
                    let left_child_index = node_index * 2;
                    let right_child_index = node_index * 2 + 1;

                    let left_hash = current_layer_hashes.remove(&left_child_index)
                        .or_else(|| hash_witness.next())
                        .ok_or(VerificationError::MerkleProof)?; // Witness too short

                    let right_hash = current_layer_hashes.remove(&right_child_index)
                        .or_else(|| hash_witness.next())
                        .ok_or(VerificationError::MerkleProof)?; // Witness too short

                    Some((left_hash, right_hash))
                };

                // Read column values: either from queried_values or column_witness
                let mut node_column_values = Vec::with_capacity(n_columns_in_layer);
                if layer_column_queries.peek() == Some(&node_index) {
                    layer_column_queries.next(); // Consume query index
                    for _ in 0..n_columns_in_layer {
                        node_column_values.push(queried_values_iter.next().ok_or(VerificationError::MerkleProof)?); // Queried values too short
                    }
                } else {
                    for _ in 0..n_columns_in_layer {
                        node_column_values.push(column_witness.next().ok_or(VerificationError::MerkleProof)?); // Witness too short
                    }
                }

                let computed_hash = H::hash_node(children_hashes, &node_column_values);
                next_layer_hashes.insert(node_index, computed_hash);
            }
            current_layer_hashes = next_layer_hashes;
        }

        // Final checks
        if !hash_witness.next().is_none() || !column_witness.next().is_none() {
            return Err(VerificationError::MerkleProof); // Witness too long
        }
        if !queried_values_iter.next().is_none() {
             return Err(VerificationError::MerkleProof); // Queried values too long
        }
        if current_layer_hashes.len() != 1 || current_layer_hashes.get(&0) != Some(&self.commitment) {
            return Err(VerificationError::MerkleProof); // Root mismatch or invalid structure
        }

        Ok(())
    }
}

// Copied from stwo/crates/prover/src/core/vcs/utils.rs

/// Fetches the next node that needs to be decommited in the current Merkle layer.
pub fn next_decommitment_node(
    prev_queries: &mut Peekable<impl Iterator<Item = usize>>,
    layer_queries: &mut Peekable<impl Iterator<Item = usize>>,
) -> Option<usize> {
    // Use core::cmp::min if needed, or chain/min works
    prev_queries
        .peek()
        .map(|q| *q / 2)
        .into_iter()
        .chain(layer_queries.peek().copied())
        .min()
}

type FlattenedOptionIter<'a> = Flatten<<Option<&'a Vec<usize>> as IntoIterator>::IntoIter>;
type CopiedFlattenedOptionIter<'a> = Copied<FlattenedOptionIter<'a>>;

pub fn option_flatten_peekable(
    a: Option<&Vec<usize>>,
) -> Peekable<CopiedFlattenedOptionIter<'_>>
{
    // Use core::iter::Flatten and core::option::Option::into_iter
    a.into_iter().flatten().copied().peekable()
} 