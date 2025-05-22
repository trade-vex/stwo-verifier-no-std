use alloc::vec::Vec;
use core::fmt::Debug;
use crate::channel::MerkleHasher;
use crate::types::commitment::MerkleDecommitment;
use crate::types::error::VerificationError;
use alloc::collections::BTreeMap;
use crate::fields::m31::BaseField;
use core::iter::{Peekable, Copied, Flatten};
 // For Option::into_iter
use alloc::string::ToString; // Added ToString

// Placeholder MerkleVerifier based on prover structure
// Needs adaptation for no-std and actual verification logic
#[derive(Clone, Debug)]
pub struct MerkleVerifier<H: MerkleHasher> where H::Hash: Clone + Debug + AsRef<[u8]> {
    pub commitment: H::Hash,
    pub column_log_sizes: Vec<u32>, // Changed from Vec<usize>
    pub n_columns_per_log_size: BTreeMap<u32, usize>, // Key changed from usize to u32
}

impl<H: MerkleHasher> MerkleVerifier<H> where H::Hash: Clone + Debug + AsRef<[u8]> + Eq {
    pub fn new(commitment: H::Hash, column_log_sizes: Vec<u32>) -> Self {
        let mut n_columns_per_log_size = BTreeMap::new();
        for log_size in &column_log_sizes {
            *n_columns_per_log_size.entry(*log_size).or_insert(0) += 1;
        }
        Self { commitment, column_log_sizes, n_columns_per_log_size }
    }

    // TODO: Implement actual Merkle verification logic here
    pub fn verify(
        &self,
        queries_per_log_size: &BTreeMap<u32, Vec<usize>>, // Key changed from usize to u32
        queried_values: &[BaseField],
        decommitment: MerkleDecommitment<H> // Changed to generic
    ) -> Result<(), VerificationError> {
        let Some(max_log_size) = self.column_log_sizes.iter().max().copied() else {
            // Check against empty hash if tree is empty
            let empty_hash = H::hash_node(None, &[]);
            // Check if commitment matches empty hash AND inputs are empty
            if self.commitment == empty_hash && 
               queried_values.is_empty() && 
               decommitment.hash_witness.is_empty() && 
               decommitment.column_witness.is_empty() 
            {
                return Ok(());
            } else {
                return Err(VerificationError::InvalidStructure("Empty tree mismatch".to_string()));
            }
        };

        let mut queried_values_iter = queried_values.iter().copied().peekable(); // Add peekable
        let mut hash_witness = decommitment.hash_witness.into_iter();
        let mut column_witness = decommitment.column_witness.into_iter().peekable(); // Add peekable

        let mut current_layer_hashes: BTreeMap<usize, H::Hash> = BTreeMap::new();

        for layer_log_size_u32 in (0..=max_log_size).rev() { // iterator is u32
            let layer_log_size = layer_log_size_u32; // Use u32 directly
            let n_columns_in_layer = self.n_columns_per_log_size.get(&layer_log_size).copied().unwrap_or(0);
            let mut next_layer_hashes: BTreeMap<usize, H::Hash> = BTreeMap::new();

            let prev_layer_node_indices = current_layer_hashes.keys().copied().collect::<Vec<_>>();

            let mut prev_layer_queries = prev_layer_node_indices.into_iter().peekable();
            // queries_per_log_size now has u32 keys
            let mut layer_column_queries = option_flatten_peekable(queries_per_log_size.get(&layer_log_size));

            while let Some(node_index) = next_decommitment_node(&mut prev_layer_queries, &mut layer_column_queries) {

                let children_hashes: Option<(H::Hash, H::Hash)> = if layer_log_size == max_log_size { // comparison with u32
                    None // Leaf node
                } else {
                    let left_child_index = node_index * 2;
                    let right_child_index = node_index * 2 + 1;

                    // Use specific error for missing witness
                    let left_hash = current_layer_hashes.remove(&left_child_index)
                        .or_else(|| hash_witness.next())
                        .ok_or(VerificationError::FriInsufficientWitness)?;

                    let right_hash = current_layer_hashes.remove(&right_child_index)
                        .or_else(|| hash_witness.next())
                        .ok_or(VerificationError::FriInsufficientWitness)?;

                    Some((left_hash, right_hash))
                };

                let mut node_column_values = Vec::with_capacity(n_columns_in_layer);
                if layer_column_queries.peek() == Some(&node_index) {
                    layer_column_queries.next(); // Consume query index
                    // Take values from queried_values iterator
                    for _ in 0..n_columns_in_layer {
                        node_column_values.push(queried_values_iter.next()
                            .ok_or(VerificationError::InvalidStructure("Too few queried values".to_string()))?);
                    }
                    // Add prover's check: Ensure correct number taken for this node
                    if node_column_values.len() != n_columns_in_layer {
                        // This case should be caught by the .next().ok_or above
                        // but keep for safety/clarity?
                         return Err(VerificationError::InvalidStructure("Queried values count mismatch for node".to_string()));
                    }
                } else {
                    // Take values from column_witness iterator
                    for _ in 0..n_columns_in_layer {
                        node_column_values.push(column_witness.next()
                            .ok_or(VerificationError::FriInsufficientWitness)?); // Use specific error
                    }
                     // Add prover's check: Ensure correct number taken for this node
                    if node_column_values.len() != n_columns_in_layer {
                         // This case should be caught by the .next().ok_or above
                         return Err(VerificationError::FriInsufficientWitness);
                    }
                }

                let computed_hash = H::hash_node(children_hashes, &node_column_values);
                next_layer_hashes.insert(node_index, computed_hash);
            }
            current_layer_hashes = next_layer_hashes;
        }

        // Final checks - use specific errors
        if hash_witness.next().is_some() {
            return Err(VerificationError::InvalidStructure("Hash witness too long".to_string()));
        }
        if column_witness.next().is_some() {
             return Err(VerificationError::InvalidStructure("Column witness too long".to_string()));
        }
        if queried_values_iter.next().is_some() {
             return Err(VerificationError::InvalidStructure("Queried values too long".to_string()));
        }
        if current_layer_hashes.len() != 1 || current_layer_hashes.get(&0) != Some(&self.commitment) {
             // Use specific error from error.rs? No direct match, use structure error.
            return Err(VerificationError::InvalidStructure("Root mismatch or final hash layer invalid".to_string()));
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