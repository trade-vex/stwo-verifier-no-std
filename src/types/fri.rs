use crate::fields::qm31::SecureField;
use crate::types::{
    commitment::MerkleDecommitment,
    poly::{LineDomain, LineEvaluation, Coset, LinePoly},
};
use crate::channel::{MerkleHasher as Hasher, Channel};
use crate::fri_utils::{FOLD_STEP, CIRCLE_TO_LINE_FOLD_STEP};
use alloc::vec::Vec;
use core::iter::zip;
use itertools::Itertools;
use num_traits::Zero;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct Queries {
    pub log_domain_size: u32,
    pub positions: Vec<usize>,
}

impl Queries {
    pub fn generate(channel: &mut impl Channel, log_domain_size: u32, n_queries: usize) -> Self {
        let domain_size = 1 << log_domain_size;
        let mut positions = Vec::with_capacity(n_queries);
        let mut i = 0;
        while positions.len() < n_queries {
            let random_bytes = channel.draw_random_bytes();
            let random_val = if random_bytes.len() >= 8 {
                usize::from_le_bytes(random_bytes[0..8].try_into().unwrap())
            } else {
                let mut padded = [0u8; 8];
                padded[0..random_bytes.len()].copy_from_slice(&random_bytes);
                usize::from_le_bytes(padded)
            };
            let pos = random_val % domain_size;
            if !positions.contains(&pos) {
                positions.push(pos);
            }
            i += 1;
            if i > n_queries * 100 { // Safeguard
                panic!("Failed to generate unique queries after {} tries.", i);
            }
        }
        positions.sort_unstable();
        Self { log_domain_size, positions }
    }

    pub fn fold(&self, n_folds: u32) -> Self {
        assert!(n_folds <= self.log_domain_size);
        let folded_log_domain_size = self.log_domain_size - n_folds;
        let folded_positions = self.positions
            .iter()
            .map(|q| q >> n_folds)
            .dedup()
            .collect();
        Self { log_domain_size: folded_log_domain_size, positions: folded_positions }
    }

    pub fn len(&self) -> usize {
        self.positions.len()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FriProof<H: Hasher> {
    pub first_layer: FriLayerProof<H>,
    pub inner_layers: Vec<FriLayerProof<H>>,
    pub last_layer_poly: LinePoly,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FriLayerProof<H: Hasher> {
    pub fri_witness: Vec<SecureField>,
    pub decommitment: MerkleDecommitment<H>,
    pub commitment: H::Hash,
}

/// Bound on the degree of a circle polynomial.
/// The degree is defined as the maximal sum of x and y degrees for each monomial.
/// The circle polynomial has a maximum of (2*points - 1) coefficients
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FriCirclePolyDegreeBound {
    pub log_degree_bound: u32,
}

impl FriCirclePolyDegreeBound {
    pub fn new(log_degree_bound: u32) -> Self {
        Self { log_degree_bound }
    }

    /// Maps a circle polynomial's degree bound to the degree bound of the univariate (line)
    /// polynomial it gets folded into.
    pub fn fold_to_line(&self) -> LinePolyDegreeBound {
        LinePolyDegreeBound {
            log_degree_bound: self.log_degree_bound.saturating_sub(CIRCLE_TO_LINE_FOLD_STEP as u32),
        }
    }
}

/// A configuration for a FRI proof.
/// Defines the parameters for the FRI protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriConfig {
    pub log_blowup_factor: u32,
    pub log_last_layer_degree_bound: u32,
    pub n_queries: usize,
}

impl FriConfig {
    pub fn new(log_blowup_factor: u32, log_last_layer_degree_bound: u32, n_queries: usize) -> Self {
        Self {
            log_blowup_factor,
            log_last_layer_degree_bound,
            n_queries,
        }
    }

    pub const fn security_bits(&self) -> u32 {
        self.log_blowup_factor * self.n_queries as u32
    }

    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_blowup_factor as u64);
        channel.mix_u64(self.n_queries as u64);
        channel.mix_u64(self.log_last_layer_degree_bound as u64);
    }
}

/// Foldable subsets of evaluations on a FRI layer.
/// From `stwo/core/fri.rs`.
#[derive(Clone, Debug)]
pub struct SparseEvaluation {
    // Represents evaluations needed by the verifier, grouped by folding subsets.
    // e.g., for fold_step=1, each inner Vec has 2 values [f(p), f(-p)].
    pub subset_evals: Vec<Vec<SecureField>>,
    // Stores the index of the first point of the domain subset corresponding to each inner Vec.
    pub subset_domain_initial_indexes: Vec<usize>,
}

impl SparseEvaluation {
    /// Creates a new SparseEvaluation.
    pub fn new(subset_evals: Vec<Vec<SecureField>>, subset_domain_initial_indexes: Vec<usize>) -> Self {
        // Basic validation, prover had more checks related to fold_step
        // TODO: Add more validation if needed (e.g., based on FOLD_STEP constants)
        assert_eq!(subset_evals.len(), subset_domain_initial_indexes.len());
        Self {
            subset_evals,
            subset_domain_initial_indexes,
        }
    }
    
    /// Folds the stored evaluations based on a line domain folding.
    /// Calls the standalone `fold_line` helper.
    pub fn fold_line(self, fold_alpha: SecureField, source_domain: LineDomain) -> Vec<SecureField> {
        zip(self.subset_evals, self.subset_domain_initial_indexes)
            .map(|(eval, domain_initial_index)| {
                // Recreate subset domain info (assuming Coset/LineDomain are correctly defined)
                let subset_coset = source_domain.coset().repeated_double(source_domain.log_size() - FOLD_STEP as u32);
                let initial_index = subset_coset.index_at(domain_initial_index);
                let fold_domain = LineDomain::new(Coset::new(initial_index, FOLD_STEP as u32));
                
                // Wrap evaluations for the helper function
                let line_eval = LineEvaluation::new(fold_domain, eval);
                
                // Call the standalone helper (currently stubbed)
                let folded_eval = crate::fri_utils::fold_line(&line_eval, fold_alpha);
                
                folded_eval.values.get(0).copied().unwrap_or_else(SecureField::zero)
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinePolyDegreeBound {
   pub log_degree_bound: u32,
}

impl LinePolyDegreeBound {
    pub fn new(log_degree_bound: u32) -> Self {
        Self { log_degree_bound }
    }

    /// Returns [None] if the unfolded degree bound is smaller than the folding factor.
    pub fn fold(self, n_folds: u32) -> Option<Self> {
        if self.log_degree_bound < n_folds {
            return None;
        }

        let log_degree_bound = self.log_degree_bound - n_folds;
        Some(Self { log_degree_bound })
    }
}

// Implement comparison with LinePolyDegreeBound
impl PartialOrd<LinePolyDegreeBound> for FriCirclePolyDegreeBound {
    fn partial_cmp(&self, other: &LinePolyDegreeBound) -> Option<core::cmp::Ordering> {
         // Compare based on the folded line bound
        Some(self.fold_to_line().log_degree_bound.cmp(&other.log_degree_bound))
    }
}

impl PartialEq<LinePolyDegreeBound> for FriCirclePolyDegreeBound {
    fn eq(&self, other: &LinePolyDegreeBound) -> bool {
        self.fold_to_line().log_degree_bound == other.log_degree_bound
    }
}

// --- End Degree Bound Structs --- 

// ... rest of file ... 