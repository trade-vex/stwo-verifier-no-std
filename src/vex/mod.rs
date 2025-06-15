use crate::air::{Component, ComponentProver};
use crate::backend::Backend;
use crate::channel::Blake2sChannel;
use crate::constraint_framework::preprocessed_columns::PreProcessedColumnId;
use crate::constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, Relation, RelationEntry, TraceLocationAllocator, INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX
};
use crate::fields::m31::M31;
use crate::fields::Field;
use crate::pcs::{CommitmentSchemeVerifier, PcsConfig};
use crate::vcs::blake2_merkle::Blake2sMerkleChannel;
use crate::{channel, VerificationError};
use alloc::vec;
use alloc::vec::Vec;
use core::array;
use alloc::format;
use itertools::{izip, chain};
use core::error::Error;
use core::iter;
use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Mul, Sub};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use crate::vcs::blake2_merkle::Blake2sMerkleHasher;
use num_traits::One;
use crate::flatten;
use crate::verify;
use itertools::Itertools;
use constants::{EXTERNAL_ROUND_CONSTS, INTERNAL_ROUND_CONSTS, MAT_DIAG16_M_1};

pub mod constants;

use crate::{
    channel::Channel,
    fields::{
        m31::BaseField, qm31::SecureField, secure_column::SECURE_EXTENSION_DEGREE, FieldExpOps,
    },
    pcs::TreeVec,
    relation,
    vcs::ops::MerkleHasher,
    StarkProof,
};

#[derive(Serialize, Deserialize)]
pub struct VexProof<H: MerkleHasher> {
    pub stark_proof: StarkProof<H>,
    pub claim: VexClaim,
    pub interaction_claim: VexInteractionClaim,
}

/// Claim for the Vex Prover
/// Claim containts public inputs, initial state, final state and all the components
/// and LogSizes for each component
#[derive(Serialize, Deserialize)]
pub struct VexClaim {
    /// The Initial State of the Matching Engine
    pub initial_state: StateFeltsWrapper,
    /// The Final State of the Matching Engine
    pub final_state: StateFeltsWrapper,
    /// processor claim
    pub processor_claim: Claim<ProcessorColumn>,
    /// buy insert claim
    pub buy_insert_claim: Claim<InsertionsColumn>,
    /// sell insert claim
    pub sell_insert_claim: Claim<InsertionsColumn>,
    /// poseidon claim
    pub poseidon_claim: Claim<PoseidonColumn>,
    /// strictly less than claim
    pub strict_less_than_claim: Claim<LessThanColumn>,
    /// less than claim
    pub less_than_claim: Claim<LessThanColumn>,
    /// add claim
    pub add_claim: Claim<AddColumn>,
    /// bytes component claim
    pub bytes_claim: Claim<BytesPreProcessedColumn>,
    /// Buy Aggressive Match Claim
    pub buy_aggressive_match_claim: Claim<MatchColumn<Aggressive>>,
    /// Sell Aggressive Match Claim
    pub sell_aggressive_match_claim: Claim<MatchColumn<Aggressive>>,
    /// Buy Passive Match Claim
    pub buy_passive_match_claim: Claim<MatchColumn<Passive>>,
    /// Sell Passive Match Claim
    pub sell_passive_match_claim: Claim<MatchColumn<Passive>>,
    /// Buy Aggressive Partial Match Claim
    pub buy_aggressive_partial_match_claim: Claim<PartialMatchColumn<Aggressive>>,
    /// Sell Aggressive Partial Match Claim
    pub sell_aggressive_partial_match_claim: Claim<PartialMatchColumn<Aggressive>>,
    /// Buy Passive Partial Match Claim
    pub buy_passive_partial_match_claim: Claim<PartialMatchColumn<Passive>>,
    /// Sell Passive Partial Match Claim
    pub sell_passive_partial_match_claim: Claim<PartialMatchColumn<Passive>>,
}

impl VexClaim {
    /// mix all components log sizes and public inputs into the channel
    pub fn mix_into(&self, channel: &mut impl Channel) {
        self.bytes_claim.mix_into(channel);
        self.poseidon_claim.mix_into(channel);
        self.strict_less_than_claim.mix_into(channel);
        self.less_than_claim.mix_into(channel);
        self.add_claim.mix_into(channel);
        self.processor_claim.mix_into(channel);
        self.buy_insert_claim.mix_into(channel);
        self.sell_insert_claim.mix_into(channel);
        self.buy_aggressive_match_claim.mix_into(channel);
        self.sell_aggressive_match_claim.mix_into(channel);
        self.buy_passive_match_claim.mix_into(channel);
        self.sell_passive_match_claim.mix_into(channel);
        self.buy_aggressive_partial_match_claim.mix_into(channel);
        self.sell_aggressive_partial_match_claim.mix_into(channel);
        self.buy_passive_partial_match_claim.mix_into(channel);
        self.sell_passive_partial_match_claim.mix_into(channel);
    }

    /// Returns the total log size of all components
    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        TreeVec::concat_cols(
            [
                self.bytes_claim.log_sizes(),
                self.poseidon_claim.log_sizes(),
                self.strict_less_than_claim.log_sizes(),
                self.less_than_claim.log_sizes(),
                self.add_claim.log_sizes(),
                self.processor_claim.log_sizes(),
                self.buy_insert_claim.log_sizes(),
                self.sell_insert_claim.log_sizes(),
                self.buy_aggressive_match_claim.log_sizes(),
                self.sell_aggressive_match_claim.log_sizes(),
                self.buy_passive_match_claim.log_sizes(),
                self.sell_passive_match_claim.log_sizes(),
                self.buy_aggressive_partial_match_claim.log_sizes(),
                self.sell_aggressive_partial_match_claim.log_sizes(),
                self.buy_passive_partial_match_claim.log_sizes(),
                self.sell_passive_partial_match_claim.log_sizes(),
            ]
            .into_iter(),
        )
    }
}

/// Const trait that defines the number of columns in the trace table
pub trait TraceSize {
    /// Number of columns in preprocessed trace table
    const PREPROCESSED_COLS: usize;
    /// Number of columns in the main trace table
    const MAIN_COLS: usize;
    /// Number of columns in the interaction trace table
    const INTERACTION_COLS: usize;

    // Compile-time validation
    const ASSERT: () = assert!(Self::MAIN_COLS > 0 && Self::INTERACTION_COLS > 0);
}

/// Generic Claim to implement for claims each component
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct Claim<T: TraceSize> {
    pub log_size: u32,
    _marker: PhantomData<T>,
}

impl<T: TraceSize> Claim<T> {
    pub const fn new(log_size: u32) -> Self {
        _ = T::ASSERT;

        Self {
            log_size,
            _marker: PhantomData,
        }
    }

    #[inline(always)]
    pub const fn main_cols() -> usize {
        T::MAIN_COLS
    }

    #[inline(always)]
    pub const fn interaction_cols() -> usize {
        T::INTERACTION_COLS
    }

    #[inline]
    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        TreeVec::new(vec![
            vec![self.log_size; T::PREPROCESSED_COLS],
            vec![self.log_size; T::MAIN_COLS],
            vec![self.log_size; T::INTERACTION_COLS],
        ])
    }

    #[inline(always)]
    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(u64::from(self.log_size));
    }
}

/// Generic InteractionClaim to implement for interaction claims each component

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct InteractionClaim<T: TraceSize> {
    pub claimed_sum: SecureField,
    _marker: PhantomData<T>,
}

impl<T: TraceSize> InteractionClaim<T> {
    pub const fn new(claimed_sum: SecureField) -> Self {
        let _ = T::ASSERT;

        Self {
            claimed_sum,
            _marker: PhantomData,
        }
    }

    #[inline(always)]
    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_felts(&[self.claimed_sum]);
    }
}

/// Interaction Elements for all the components of the system.
/// Interaction elements are used to combine values that are "used" or "yielded" by the components.
pub struct VexInteractionElements {
    pub instruction_elements: InstructionElements,
    pub state_elements: StateElements,
    pub poseidon_elements: PoseidonElements,
    pub less_than_elements: LessThanElements,
    pub strict_less_than_elements: StrictLessThanElements,
    pub less_than_u8_elements: LessThanU8Elements,
    pub range_check_u8_elements: RangeCheckU8Elements,
    pub match_elements: MatchElements,
    pub add_elements: AddElements,
}

impl VexInteractionElements {
    /// Draw all the interaction elements for the components.
    pub fn draw(channel: &mut impl Channel) -> Self {
        Self {
            instruction_elements: InstructionElements::draw(channel),
            state_elements: StateElements::draw(channel),
            poseidon_elements: PoseidonElements::draw(channel),
            less_than_elements: LessThanElements::draw(channel),
            strict_less_than_elements: StrictLessThanElements::draw(channel),
            less_than_u8_elements: LessThanU8Elements::draw(channel),
            range_check_u8_elements: RangeCheckU8Elements::draw(channel),
            match_elements: MatchElements::draw(channel),
            add_elements: AddElements::draw(channel),
        }
    }
}

relation!(InstructionElements, {
    InstructionColumn::N_INSTRUCTION_FELTS
});
relation!(StateElements, N_STATE_FELTS);
relation!(PoseidonElements, N_ELEMENTS);
relation!(LessThanElements, 17);
relation!(StrictLessThanElements, 17);
relation!(LessThanU8Elements, 3);
relation!(RangeCheckU8Elements, 2);
relation!(MatchElements, 16);
relation!(AddElements, 24);

/// Interaction Claim for the Vex Prover
/// Contains LogUp Sum for each component
#[derive(Serialize, Deserialize)]
pub struct VexInteractionClaim {
    /// Processor component interaction claim
    pub processor_interaction_claim: InteractionClaim<ProcessorColumn>,
    /// Buy insert component interaction claim
    pub buy_insert_interaction_claim: InteractionClaim<InsertionsColumn>,
    /// Sell insert component interaction claim
    pub sell_insert_interaction_claim: InteractionClaim<InsertionsColumn>,
    /// Poseidon component interaction claim
    pub poseidon_interaction_claim: InteractionClaim<PoseidonColumn>,
    /// Strictly less than component interaction claim
    pub strict_less_than_interaction_claim: InteractionClaim<LessThanColumn>,
    /// Less than component interaction claim
    pub less_than_interaction_claim: InteractionClaim<LessThanColumn>,
    /// Add component interaction claim
    pub add_interaction_claim: InteractionClaim<AddColumn>,
    /// Bytes component interaction claim
    pub bytes_interaction_claim: InteractionClaim<BytesPreProcessedColumn>,
    /// Buy Aggressive Match Interaction Claim
    pub buy_aggressive_match_interaction_claim: InteractionClaim<MatchColumn<Aggressive>>,
    /// Sell Aggressive Match Interaction Claim
    pub sell_aggressive_match_interaction_claim: InteractionClaim<MatchColumn<Aggressive>>,
    /// Buy Passive Match Interaction Claim
    pub buy_passive_match_interaction_claim: InteractionClaim<MatchColumn<Passive>>,
    /// Sell Passive Match Interaction Claim
    pub sell_passive_match_interaction_claim: InteractionClaim<MatchColumn<Passive>>,
    /// Buy Aggressive Partial Match Interaction Claim
    pub buy_aggressive_partial_match_interaction_claim:
        InteractionClaim<PartialMatchColumn<Aggressive>>,
    /// Sell Aggressive Partial Match Interaction Claim
    pub sell_aggressive_partial_match_interaction_claim:
        InteractionClaim<PartialMatchColumn<Aggressive>>,
    /// Buy Passive Partial Match Interaction Claim
    pub buy_passive_partial_match_interaction_claim: InteractionClaim<PartialMatchColumn<Passive>>,
    /// Sell Passive Partial Match Interaction Claim
    pub sell_passive_partial_match_interaction_claim: InteractionClaim<PartialMatchColumn<Passive>>,
}

impl VexInteractionClaim {
    /// mix all logups into the channel
    pub fn mix_into(&self, channel: &mut impl Channel) {
        self.bytes_interaction_claim.mix_into(channel);
        self.poseidon_interaction_claim.mix_into(channel);
        self.strict_less_than_interaction_claim.mix_into(channel);
        self.less_than_interaction_claim.mix_into(channel);
        self.add_interaction_claim.mix_into(channel);
        self.processor_interaction_claim.mix_into(channel);
        self.buy_insert_interaction_claim.mix_into(channel);
        self.sell_insert_interaction_claim.mix_into(channel);
        self.buy_aggressive_match_interaction_claim
            .mix_into(channel);
        self.sell_aggressive_match_interaction_claim
            .mix_into(channel);
        self.buy_passive_match_interaction_claim.mix_into(channel);
        self.sell_passive_match_interaction_claim.mix_into(channel);
        self.buy_aggressive_partial_match_interaction_claim
            .mix_into(channel);
        self.sell_aggressive_partial_match_interaction_claim
            .mix_into(channel);
        self.buy_passive_partial_match_interaction_claim
            .mix_into(channel);
        self.sell_passive_partial_match_interaction_claim
            .mix_into(channel);
    }

    /// Returns the total logup sum of all components
    fn components_logup_sum(&self) -> SecureField {
        let mut sum = SecureField::zero();
        sum += self.processor_interaction_claim.claimed_sum;
        sum += self.buy_insert_interaction_claim.claimed_sum;
        sum += self.sell_insert_interaction_claim.claimed_sum;
        sum += self.poseidon_interaction_claim.claimed_sum;
        sum += self.strict_less_than_interaction_claim.claimed_sum;
        sum += self.less_than_interaction_claim.claimed_sum;
        sum += self.add_interaction_claim.claimed_sum;
        sum += self.bytes_interaction_claim.claimed_sum;
        sum += self.buy_aggressive_match_interaction_claim.claimed_sum;
        sum += self.sell_aggressive_match_interaction_claim.claimed_sum;
        sum += self.buy_passive_match_interaction_claim.claimed_sum;
        sum += self.sell_passive_match_interaction_claim.claimed_sum;
        sum += self
            .buy_aggressive_partial_match_interaction_claim
            .claimed_sum;
        sum += self
            .sell_aggressive_partial_match_interaction_claim
            .claimed_sum;
        sum += self.buy_passive_partial_match_interaction_claim.claimed_sum;
        sum += self
            .sell_passive_partial_match_interaction_claim
            .claimed_sum;
        sum
    }

    /// Returns the logup sum of all components and yields the initial state and final state
    /// This Must be Zero if all the lookups were correct
    pub fn logup_sum(&self, claim: &VexClaim, state_elements: &StateElements) -> SecureField {
        let initial_state_comb: SecureField = state_elements.combine(&claim.initial_state.0);
        let final_state_comb: SecureField = state_elements.combine(&claim.final_state.0);
        self.components_logup_sum() + final_state_comb.inverse() - initial_state_comb.inverse()
    }
}

pub type StateFelts<F> = [F; N_STATE_FELTS];

pub const N_STATE_FELTS: usize = 34;
pub const N_INSTRUCTION_FELTS: usize = InstructionColumn::N_INSTRUCTION_FELTS;
pub const MERKLE_HEIGHT: usize = 20;
pub const MERKLE_WIDTH: usize = 1 << MERKLE_HEIGHT; // number of leaves at the bottom of the tree
pub const N_LEAF_FELTS: usize = 41; // number of felts in a leaf
pub const N_U64_FELTS: usize = 8; // number of felts in a u64
pub const N_ORDER_FELTS: usize = 3 * N_U64_FELTS; // order contains Price(8Felts), Volume(8Felts), Time(8Felts)
pub const N_LOG_INSTANCES_PER_ROW: usize = 3;
pub const N_INSTANCES_PER_ROW: usize = 1 << N_LOG_INSTANCES_PER_ROW;
/// Index: 0-16: Initial State
/// Index: 16-80: First 4 Full Rounds End: 16 + 4 * 16 = 80
/// Index: 80-94: 14 Partial Rounds End Applied to state[0]: 80 + 14 = 94
/// Index: 94-158: Last 4 Full Rounds End: 94 + 4 * 16 = 158
/// Index: 158: Is Real Column
const N_COLUMNS_PER_REP: usize = N_STATE + N_STATE * N_FULL_ROUNDS + N_PARTIAL_ROUNDS + 1;
// N_INSTANCES_PER_ROW * N_COLUMNS_PER_REP
const N_POS_COLUMNS: usize = N_INSTANCES_PER_ROW * N_COLUMNS_PER_REP;

pub const N_PARTIAL_ROUNDS: usize = 14;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const N_FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;
pub const N_STATE: usize = 16;
pub const N_HASH: usize = 8;
pub const N_ELEMENTS: usize = N_STATE + N_HASH;

pub struct InstructionColumn;

impl InstructionColumn {
    pub const INITIAL_STATE: usize = 0;
    pub const OPCODE: usize = Self::INITIAL_STATE + N_STATE_FELTS;
    pub const LOW_MERKLE_PROOF: usize = Self::OPCODE + 1;
    pub const LOW_MERKLE_PATH: usize = Self::LOW_MERKLE_PROOF + MERKLE_HEIGHT * N_HASH;
    pub const UPDATED_LOW_MERKLE_PATH: usize = Self::LOW_MERKLE_PATH + (MERKLE_HEIGHT + 1) * N_HASH;
    pub const LOW_INDEX: usize = Self::UPDATED_LOW_MERKLE_PATH + (MERKLE_HEIGHT + 1) * N_HASH;
    pub const LOW_LEAF: usize = Self::LOW_INDEX + MERKLE_HEIGHT;
    pub const MERKLE_PROOF: usize = Self::LOW_LEAF + N_LEAF_FELTS;
    pub const MERKLE_PATH: usize = Self::MERKLE_PROOF + MERKLE_HEIGHT * N_HASH;
    pub const UPDATED_MERKLE_PATH: usize = Self::MERKLE_PATH + (MERKLE_HEIGHT + 1) * N_HASH;
    pub const INDEX: usize = Self::UPDATED_MERKLE_PATH + (MERKLE_HEIGHT + 1) * N_HASH;
    pub const LEAF: usize = Self::INDEX + MERKLE_HEIGHT;
    pub const FINAL_STATE: usize = Self::LEAF + N_LEAF_FELTS;
    pub const IS_REAL: usize = Self::FINAL_STATE + N_STATE_FELTS;
    pub const N_INSTRUCTION_FELTS: usize = Self::IS_REAL + 1;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StateFeltsWrapper(#[serde(with = "m31_array_serde")] pub [BaseField; 34]);

pub mod m31_array_serde {
    use crate::fields::m31::M31;
    use alloc::vec::Vec;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(arr: &[M31; 34], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        arr.iter()
            .map(|m| m.0)
            .collect::<Vec<u32>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[M31; 34], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = <Vec<u32>>::deserialize(deserializer)?;
        if vec.len() != 34 {
            return Err(serde::de::Error::custom("Expected 34 elements"));
        }
        let mut arr = [M31(0); 34];
        for (i, v) in vec.into_iter().enumerate() {
            arr[i] = M31(v);
        }
        Ok(arr)
    }
}

/// Processor Column
/// Each row of the trace is a Instruction field elements arranged as per the `InstructionColumn`
/// The last field is a flag to indicate if the row is real or padded
#[derive(Debug, Clone)]
pub struct ProcessorColumn;

impl TraceSize for ProcessorColumn {
    const PREPROCESSED_COLS: usize = 1;
    const MAIN_COLS: usize = N_INSTRUCTION_FELTS;
    /// 1st Column:"use initial state" and "yield final state" logups are batched
    /// 2nd Column: "use instruction elements"
    const INTERACTION_COLS: usize = 2 * SECURE_EXTENSION_DEGREE;
}
#[derive(Debug, Clone)]
pub struct InsertionsColumn;

impl TraceSize for InsertionsColumn {
    /// is_first column
    const PREPROCESSED_COLS: usize = 1;
    const MAIN_COLS: usize = N_INSTRUCTION_FELTS;
    /// number of poseidon hashes: 4 times for leaf hashes
    ///     - 1 for low_merkle_proof
    ///     - 1 for updated low_leaf
    ///     - 1 for merkle_proof for inserted leaf
    ///     - 1 for updated leaf
    /// 4*MERKLE_HEIGHT for merkle paths verification
    /// Total Poseidon Interactions: 4 + 4*MERKLE_HEIGHT
    /// inserted time < low_time, low.next_time => 2 strict less than checks
    /// inserted price checks for low and next => 1 strict and 1 non-strict less than checks
    /// Total Strict Less Than Interactions: 3
    /// Total Non Strict Less Than Interactions: 1
    /// 1 column for yielding the final result
    /// Total Columns: 4 + 4*MERKLE_HEIGHT + 3 + 1 + 1 = 4*MERKLE_HEIGHT + 9
    const INTERACTION_COLS: usize = (4 * MERKLE_HEIGHT + 9) * SECURE_EXTENSION_DEGREE;
}

#[derive(Debug, Clone)]
pub struct PoseidonColumn;

impl TraceSize for PoseidonColumn {
    // is_first column
    const PREPROCESSED_COLS: usize = 1;
    // initial state + state transitions for each round + final state + is_real
    const MAIN_COLS: usize = N_POS_COLUMNS;
    // initial state + final hash is combined in 1 interaction column for 1 instance
    // per row => N_INSTANCES_PER_ROW interaction columns
    const INTERACTION_COLS: usize = N_INSTANCES_PER_ROW * SECURE_EXTENSION_DEGREE;
}

/// LessThanColumn represents a Column for the starting limb of a field in LessThanOp
#[derive(Debug, Clone)]
pub struct LessThanColumn;

impl LessThanColumn {
    pub const A: usize = 0;
    pub const B: usize = Self::A + N_U64_FELTS;
    pub const C: usize = Self::B + N_U64_FELTS;
    pub const FLAGS: usize = Self::C + 1;
    pub const A_COMPARISON_BYTE: usize = Self::FLAGS + N_U64_FELTS;
    pub const B_COMPARISON_BYTE: usize = Self::A_COMPARISON_BYTE + 1;
    pub const IS_REAL: usize = Self::B_COMPARISON_BYTE + 1;
}

impl TraceSize for LessThanColumn {
    // is_first column
    const PREPROCESSED_COLS: usize = 1;
    // last field's index + offset
    const MAIN_COLS: usize = Self::IS_REAL + 1;
    // 1 Interaction Column for LessThanU8 check
    // 1 Interaction Column for yielding the result
    const INTERACTION_COLS: usize = SECURE_EXTENSION_DEGREE;
}

#[derive(Debug, Clone)]
pub struct AddColumn;

impl AddColumn {
    /// Starting index for the first operand (a) columns
    pub const A: usize = 0;
    /// Starting index for the second operand (b) columns
    pub const B: usize = Self::A + N_U64_FELTS;
    /// Starting index for the result (c) columns
    pub const C: usize = Self::B + N_U64_FELTS;
    /// Starting index for carry bits
    pub const CARRY: usize = Self::C + N_U64_FELTS;
    /// Index for the "is real" flag column
    pub const IS_REAL: usize = Self::CARRY + (N_U64_FELTS - 1);
}

impl TraceSize for AddColumn {
    // 1 is_first pre-processed column
    const PREPROCESSED_COLS: usize = 1;
    // last field's index + offset
    const MAIN_COLS: usize = Self::IS_REAL + 1;

    // Number of interaction columns includes:
    // - 6 column for RangeCheckU8Elements
    // - 1 column for yielding the result
    const INTERACTION_COLS: usize = 7 * SECURE_EXTENSION_DEGREE;
}

/// Bytes Component is the PreProcessed Table for Binary Operations b/w pair of ELEMENT_BITS elements.
#[derive(Debug, Clone)]
pub enum BytesPreProcessedColumn {
    A = 0,
    B = 1,
    CLessThanU8 = 2,
}
impl BytesPreProcessedColumn {
    pub fn preprocessed_id(&self) -> PreProcessedColumnId {
        PreProcessedColumnId {
            id: format!("preprocessed_bytes_column_{:?}", self),
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
            Self::CLessThanU8 => 2,
        }
    }
}


impl TraceSize for BytesPreProcessedColumn {
    /// A, B, CLessThanU8, is_first
    const PREPROCESSED_COLS: usize = 4;
    /// multiplicities of less than, and range check operations
    const MAIN_COLS: usize = 2;
    /// (less than, range check) batched interaction columns
    const INTERACTION_COLS: usize = SECURE_EXTENSION_DEGREE;
}

/// Match Column
/// Each row of the trace is a Instruction field elements.
/// The last field is a flag to indicate if the row is real or padded
#[derive(Debug, Clone)]
pub struct MatchColumn<T> {
    /// marker for type
    _marker: PhantomData<T>,
}

impl<T: OrderMatchType> TraceSize for MatchColumn<T> {
    /// is_first column
    const PREPROCESSED_COLS: usize = 1;
    const MAIN_COLS: usize = N_INSTRUCTION_FELTS;
    /// number of poseidon hashes: 4 times for leaf hashes
    ///     - 1 for 0th leaf
    ///     - 1 for updated 0th leaf
    ///     - 1 for merkle_proof for matched leaf
    ///     - 1 for updated matched leaf (leaf.active = zero)
    /// 4*MERKLE_HEIGHT for merkle paths verification
    /// Total Poseidon Interactions: 4 + 4*MERKLE_HEIGHT
    /// Match Invariant: MAX(buy_imt) >= MIN(sell_imt) only in Aggressive Side
    /// Total Non Strict Less Than Interactions: 1
    /// When an Aggressive Match is made (price, volume) is yielded
    /// When an Passive Match is made (price, volume) is used
    /// 1 column for Match Elements (price, volume)
    /// 1 column for yielding the final result
    /// Total Columns: 4 + 4*MERKLE_HEIGHT + 3 + 1 + 1 = 4*MERKLE_HEIGHT + 9
    const INTERACTION_COLS: usize =
        ((4 * MERKLE_HEIGHT + 6) + T::LESSTHANCOL) * SECURE_EXTENSION_DEGREE;
}

/// Type markers for Buy and Sell sides
#[derive(Debug, Clone, Copy)]
pub struct Aggressive;
#[derive(Debug, Clone, Copy)]
pub struct Passive;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    Aggressive,
    Passive,
}

/// Order match type marker trait with compile-time constants
pub trait OrderMatchType: 'static + Copy + Send + Sync + Clone + Copy + Debug {
    /// Associated constant for match type name
    const NAME: &'static str;
    /// Associated constant for match type variant
    /// Match Invariant is only checked for Aggressive Side
    /// The Match Elements are yielded for Aggressive Side and used for Passive Side
    const MATCHTYPE: MatchType;
    /// Indicates number of LessThan interaction columns
    const LESSTHANCOL: usize;
    /// get the name of the match type
    fn name() -> &'static str {
        match Self::MATCHTYPE {
            MatchType::Aggressive => "Aggressive",
            MatchType::Passive => "Passive",
        }
    }
    /// get the type of the match
    fn match_type() -> MatchType {
        Self::MATCHTYPE
    }
}

impl OrderMatchType for Aggressive {
    const NAME: &'static str = "Aggressive";
    const MATCHTYPE: MatchType = MatchType::Aggressive;
    const LESSTHANCOL: usize = 1;
}
impl OrderMatchType for Passive {
    const NAME: &'static str = "Passive";
    const MATCHTYPE: MatchType = MatchType::Passive;
    const LESSTHANCOL: usize = 0;
}

/// Match Column
/// Each row of the trace is a Instruction field elements.
/// The last field is a flag to indicate if the row is real or padded
#[derive(Debug, Clone)]
pub struct PartialMatchColumn<T> {
    /// marker for type
    _marker: PhantomData<T>,
}

impl<T: OrderMatchType> TraceSize for PartialMatchColumn<T> {
    /// is_first column
    const PREPROCESSED_COLS: usize = 1;
    const MAIN_COLS: usize = N_INSTRUCTION_FELTS;
    /// number of poseidon hashes: 3 times for leaf hashes
    ///     - 1 for 0th leaf
    ///     - 1 for merkle_proof for matched leaf
    ///     - 1 for updated matched leaf (leaf.active = zero)
    /// 3*MERKLE_HEIGHT for merkle paths verification
    /// Total Poseidon Interactions: 3 + 3*MERKLE_HEIGHT
    /// Match Invariant: MAX(buy_imt) >= MIN(sell_imt) only in Aggressive Side
    /// Total Non Strict Less Than Interactions: 1
    /// When an Aggressive Match is made (price, volume) is yielded
    /// When an Passive Match is made (price, volume) is used
    /// 1 column for Add Elements (filled_volume + remaining_volume, volume)
    /// 1 column for Match Elements (price, volume)
    /// 1 column for yielding the final result
    /// Total Columns: 3 + 3*MERKLE_HEIGHT + 1 + 1 + 1 = 4*MERKLE_HEIGHT + 9
    const INTERACTION_COLS: usize =
        ((3 * MERKLE_HEIGHT + 6) + T::LESSTHANCOL) * SECURE_EXTENSION_DEGREE;
}

/// Verify VexProof
pub fn verify_vex(
    VexProof {
        claim,
        interaction_claim,
        stark_proof,
    }: VexProof<Blake2sMerkleHasher>,
) -> Result<(), VexVerificationError> {
    // default config
    let config = PcsConfig::default();
    let channel = &mut Blake2sChannel::default();
    let commitment_scheme_verifier =
        &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let log_sizes = &claim.log_sizes();

    // preprocessed trace
    commitment_scheme_verifier.commit(
        stark_proof.0.commitments[PREPROCESSED_TRACE_IDX],
        &log_sizes[PREPROCESSED_TRACE_IDX],
        channel,
    );

    // main trace
    claim.mix_into(channel);
    commitment_scheme_verifier.commit(
        stark_proof.0.commitments[ORIGINAL_TRACE_IDX],
        &log_sizes[ORIGINAL_TRACE_IDX],
        channel,
    );

    // interaction trace
    let interaction_elements = VexInteractionElements::draw(channel);
    // Check that the lookup sum is valid
    if !interaction_claim
        .logup_sum(&claim, &interaction_elements.state_elements)
        .is_zero()
    {
        return Err(VexVerificationError::InvalidLogupSum);
    };
    interaction_claim.mix_into(channel);
    commitment_scheme_verifier.commit(
        stark_proof.0.commitments[INTERACTION_TRACE_IDX],
        &log_sizes[INTERACTION_TRACE_IDX],
        channel,
    );

    // Verify the proof
    let component_builder = VexComponents::new(&claim, &interaction_elements, &interaction_claim);
    let components = component_builder.provers();

    verify(
        &components,
        channel,
        commitment_scheme_verifier,
        stark_proof,
    )
    .map_err(VexVerificationError::Stark)
}

pub enum VexVerificationError {
    InvalidLogupSum,
    Stark(VerificationError),
}

impl Debug for VexVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VexVerificationError::InvalidLogupSum => {
                write!(f, "Total Lookup sum must be zero")
            }
            VexVerificationError::Stark(err) => {
                write!(f, "Stark error: {}", err)
            }
        }
    }
}

// impl Display for VexVerificationError {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         Debug::fmt(self, f)
//     }
// }

// impl Error for VexVerificationError {
//     fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
//         match self {
//             VexVerificationError::Stark(err) => Some(err),
//             _ => Some(self),
//         }
//     }
// }

/// VexComponents is the main struct that holds all the components of the system.
pub struct VexComponents {
    processor: ProcessorComponent,
    buy_insert: BuyInsertionComponent,
    sell_insert: SellInsertionComponent,
    poseidon: PoseidonComponent,
    strict_less_than: StrictLessThanComponent,
    less_than: LessThanComponent,
    add_component: AddComponent,
    bytes: BytesComponent,
    buy_aggressive_match: BuyAgessiveMatchComponent,
    sell_aggressive_match: SellAggressiveMatchComponent,
    buy_passive_match: BuyPassiveMatchComponent,
    sell_passive_match: SellPassiveMatchComponent,
    buy_aggressive_partial_match: BuyAgessivePartialMatchComponent,
    sell_aggressive_partial_match: SellAggressivePartialMatchComponent,
    buy_passive_partial_match: BuyPassivePartialMatchComponent,
    sell_passive_partial_match: SellPassivePartialMatchComponent,
}

impl VexComponents {
    /// Create a new instance of VexComponents.
    pub fn new(
        claim: &VexClaim,
        interaction_elements: &VexInteractionElements,
        interaction_claim: &VexInteractionClaim,
    ) -> Self {
        let tree_span_provider = &mut TraceLocationAllocator::default();

        let bytes = BytesComponent::new(
            tree_span_provider,
            BytesEval {
                claim: claim.bytes_claim.clone(),
                less_than_u8_elements: interaction_elements.less_than_u8_elements.clone(),
                range_check_u8_elements: interaction_elements.range_check_u8_elements.clone(),
            },
            interaction_claim.bytes_interaction_claim.claimed_sum,
        );

        let poseidon = PoseidonComponent::new(
            tree_span_provider,
            PoseidonEval {
                claim: claim.poseidon_claim.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
            },
            interaction_claim.poseidon_interaction_claim.claimed_sum,
        );

        let strict_less_than = StrictLessThanComponent::new(
            tree_span_provider,
            LessThanEval {
                claim: claim.strict_less_than_claim.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                strict_less_than_elements: interaction_elements.strict_less_than_elements.clone(),
                less_than_u8_elements: interaction_elements.less_than_u8_elements.clone(),
            },
            interaction_claim
                .strict_less_than_interaction_claim
                .claimed_sum,
        );

        let less_than = LessThanComponent::new(
            tree_span_provider,
            LessThanEval {
                claim: claim.less_than_claim.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                strict_less_than_elements: interaction_elements.strict_less_than_elements.clone(),
                less_than_u8_elements: interaction_elements.less_than_u8_elements.clone(),
            },
            interaction_claim.less_than_interaction_claim.claimed_sum,
        );

        let add_component = AddComponent::new(
            tree_span_provider,
            AddEval {
                claim: claim.add_claim.clone(),
                range_check_u8_elements: interaction_elements.range_check_u8_elements.clone(),
                add_elements: interaction_elements.add_elements.clone(),
            },
            interaction_claim.add_interaction_claim.claimed_sum,
        );

        let processor = ProcessorComponent::new(
            tree_span_provider,
            ProcessorEval {
                claim: claim.processor_claim.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                state_elements: interaction_elements.state_elements.clone(),
            },
            interaction_claim.processor_interaction_claim.claimed_sum,
        );

        let buy_insert = BuyInsertionComponent::new(
            tree_span_provider,
            InsertionsEval {
                claim: claim.buy_insert_claim.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                strict_less_than_elements: interaction_elements.strict_less_than_elements.clone(),
                _side: PhantomData::<Buy>,
            },
            interaction_claim.buy_insert_interaction_claim.claimed_sum,
        );

        let sell_insert = SellInsertionComponent::new(
            tree_span_provider,
            InsertionsEval {
                claim: claim.sell_insert_claim.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                strict_less_than_elements: interaction_elements.strict_less_than_elements.clone(),
                _side: PhantomData::<Sell>,
            },
            interaction_claim.sell_insert_interaction_claim.claimed_sum,
        );

        let buy_aggressive_match = BuyAgessiveMatchComponent::new(
            tree_span_provider,
            MatchEval {
                claim: claim.buy_aggressive_match_claim.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                match_elements: interaction_elements.match_elements.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                _side: PhantomData::<Buy>,
                _type: PhantomData::<Aggressive>,
            },
            interaction_claim
                .buy_aggressive_match_interaction_claim
                .claimed_sum,
        );

        let sell_aggressive_match = SellAggressiveMatchComponent::new(
            tree_span_provider,
            MatchEval {
                claim: claim.sell_aggressive_match_claim.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                match_elements: interaction_elements.match_elements.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                _side: PhantomData::<Sell>,
                _type: PhantomData::<Aggressive>,
            },
            interaction_claim
                .sell_aggressive_match_interaction_claim
                .claimed_sum,
        );

        let buy_passive_match = BuyPassiveMatchComponent::new(
            tree_span_provider,
            MatchEval {
                claim: claim.buy_passive_match_claim.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                match_elements: interaction_elements.match_elements.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                _side: PhantomData::<Buy>,
                _type: PhantomData::<Passive>,
            },
            interaction_claim
                .buy_passive_match_interaction_claim
                .claimed_sum,
        );

        let sell_passive_match = SellPassiveMatchComponent::new(
            tree_span_provider,
            MatchEval {
                claim: claim.sell_passive_match_claim.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                match_elements: interaction_elements.match_elements.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                _side: PhantomData::<Sell>,
                _type: PhantomData::<Passive>,
            },
            interaction_claim
                .sell_passive_match_interaction_claim
                .claimed_sum,
        );

        let buy_aggressive_partial_match = BuyAgessivePartialMatchComponent::new(
            tree_span_provider,
            PartialMatchEval {
                claim: claim.buy_aggressive_partial_match_claim.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                match_elements: interaction_elements.match_elements.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                add_elements: interaction_elements.add_elements.clone(),
                _side: PhantomData::<Buy>,
                _type: PhantomData::<Aggressive>,
            },
            interaction_claim
                .buy_aggressive_partial_match_interaction_claim
                .claimed_sum,
        );

        let sell_aggressive_partial_match = SellAggressivePartialMatchComponent::new(
            tree_span_provider,
            PartialMatchEval {
                claim: claim.sell_aggressive_partial_match_claim.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                match_elements: interaction_elements.match_elements.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                add_elements: interaction_elements.add_elements.clone(),
                _side: PhantomData::<Sell>,
                _type: PhantomData::<Aggressive>,
            },
            interaction_claim
                .sell_aggressive_partial_match_interaction_claim
                .claimed_sum,
        );

        let buy_passive_partial_match = BuyPassivePartialMatchComponent::new(
            tree_span_provider,
            PartialMatchEval {
                claim: claim.buy_passive_partial_match_claim.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                match_elements: interaction_elements.match_elements.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                add_elements: interaction_elements.add_elements.clone(),
                _side: PhantomData::<Buy>,
                _type: PhantomData::<Passive>,
            },
            interaction_claim
                .buy_passive_partial_match_interaction_claim
                .claimed_sum,
        );

        let sell_passive_partial_match = SellPassivePartialMatchComponent::new(
            tree_span_provider,
            PartialMatchEval {
                claim: claim.sell_passive_partial_match_claim.clone(),
                poseidon_elements: interaction_elements.poseidon_elements.clone(),
                less_than_elements: interaction_elements.less_than_elements.clone(),
                match_elements: interaction_elements.match_elements.clone(),
                instruction_elements: interaction_elements.instruction_elements.clone(),
                add_elements: interaction_elements.add_elements.clone(),
                _side: PhantomData::<Sell>,
                _type: PhantomData::<Passive>,
            },
            interaction_claim
                .sell_passive_partial_match_interaction_claim
                .claimed_sum,
        );

        Self {
            processor,
            strict_less_than,
            less_than,
            add_component,
            buy_insert,
            sell_insert,
            poseidon,
            bytes,
            buy_aggressive_match,
            sell_aggressive_match,
            buy_passive_match,
            sell_passive_match,
            buy_aggressive_partial_match,
            sell_aggressive_partial_match,
            buy_passive_partial_match,
            sell_passive_partial_match,
        }
    }

    /// Returns the ComponentProver of each components whose log sizes are in decreasing order.
    pub fn provers(&self) -> Vec<&dyn Component> {
        vec![
            &self.bytes,
            &self.poseidon,
            &self.strict_less_than,
            &self.less_than,
            &self.add_component,
            &self.processor,
            &self.buy_insert,
            &self.sell_insert,
            &self.buy_aggressive_match,
            &self.sell_aggressive_match,
            &self.buy_passive_match,
            &self.sell_passive_match,
            &self.buy_aggressive_partial_match,
            &self.sell_aggressive_partial_match,
            &self.buy_passive_partial_match,
            &self.sell_passive_partial_match,
        ]
    }

    // Returns the Component of each components whose log sizes are in decreasing order.
    // pub fn components(&self) -> Vec<&dyn Component> {
    //     self.provers()
    //         .into_iter()
    //         .map(|component| component as &dyn Component)
    //         .collect()
    // }
}

pub type BytesComponent = FrameworkComponent<BytesEval>;

pub struct BytesEval {
    pub claim: Claim<BytesPreProcessedColumn>,
    pub less_than_u8_elements: LessThanU8Elements,
    pub range_check_u8_elements: RangeCheckU8Elements,
}

impl FrameworkEval for BytesEval {
    fn log_size(&self) -> u32 {
        16
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        16 + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Retrieve preprocessed columns
        let a = eval.get_preprocessed_column(BytesPreProcessedColumn::A.preprocessed_id());
        let b = eval.get_preprocessed_column(BytesPreProcessedColumn::B.preprocessed_id());
        let c_less_than =
            eval.get_preprocessed_column(BytesPreProcessedColumn::CLessThanU8.preprocessed_id());

        // Retrieve Multiplicities
        let less_than_u8_mult = eval.next_trace_mask();
        let range_check_u8_mult = eval.next_trace_mask();

        // Yields a < b = c_less_than
        eval.add_to_relation(RelationEntry::new(
            &self.less_than_u8_elements,
            E::EF::from(-less_than_u8_mult),
            &[a.clone(), b.clone(), c_less_than.clone()],
        ));

        // Yields a, b < 256
        eval.add_to_relation(RelationEntry::new(
            &self.range_check_u8_elements,
            E::EF::from(-range_check_u8_mult),
            &[a.clone(), b.clone()],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}

pub type PoseidonComponent = FrameworkComponent<PoseidonEval>;

#[derive(Clone)]
pub struct PoseidonEval {
    pub claim: Claim<PoseidonColumn>,
    pub poseidon_elements: PoseidonElements,
}

impl FrameworkEval for PoseidonEval {
    fn log_size(&self) -> u32 {
        self.claim.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.claim.log_size + 2
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        for _ in 0..N_INSTANCES_PER_ROW {
            // is_real determines if the operation is padded or not.
            let is_real = eval.next_trace_mask();

            // is_real must be a boolean.
            eval.add_constraint(is_real.clone() * (is_real.clone() - E::F::one()));

            let mut state: [_; N_STATE] = array::from_fn(|_| eval.next_trace_mask());

            // Initial state is added to the relation.
            let initial_state = state.clone();

            // First Half full rounds.
            (0..N_HALF_FULL_ROUNDS).for_each(|round| {
                (0..N_STATE).for_each(|i| {
                    state[i] += EXTERNAL_ROUND_CONSTS[round][i];
                });
                apply_external_round_matrix(&mut state);
                state = array::from_fn(|i| pow5(state[i].clone()));
                state.iter_mut().for_each(|s| {
                    let m = eval.next_trace_mask();
                    eval.add_constraint(s.clone() - m.clone());
                    *s = m;
                });
            });

            // Partial rounds.
            (0..N_PARTIAL_ROUNDS).for_each(|round| {
                state[0] += INTERNAL_ROUND_CONSTS[round];
                apply_internal_round_matrix(&mut state);
                state[0] = pow5(state[0].clone());
                let m = eval.next_trace_mask();
                eval.add_constraint(state[0].clone() - m.clone());
                state[0] = m;
            });

            // Last Half full rounds.
            (0..N_HALF_FULL_ROUNDS).for_each(|round| {
                (0..N_STATE).for_each(|i| {
                    state[i] += EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
                });
                apply_external_round_matrix(&mut state);
                state = array::from_fn(|i| pow5(state[i].clone()));
                state.iter_mut().for_each(|s| {
                    let m = eval.next_trace_mask();
                    eval.add_constraint(s.clone() - m.clone());
                    *s = m;
                });
            });

            // Add Initial State and hash to the relation.
            let values = initial_state.iter().chain(&state[0..8]);
            eval.add_to_relation(RelationEntry::new(
                &self.poseidon_elements,
                -E::EF::from(is_real.clone()),
                &values.cloned().collect_vec(),
            ))
        }

        eval.finalize_logup();
        eval
    }
}
pub fn apply_external_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    // Applies circ(2M4, M4, M4, M4).
    for i in 0..4 {
        [
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ] = apply_m4([
            state[4 * i].clone(),
            state[4 * i + 1].clone(),
            state[4 * i + 2].clone(),
            state[4 * i + 3].clone(),
        ]);
    }
    for j in 0..4 {
        let s =
            state[j].clone() + state[j + 4].clone() + state[j + 8].clone() + state[j + 12].clone();
        for i in 0..4 {
            state[4 * i + j] += s.clone();
        }
    }
}

pub fn apply_internal_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let sum = state[1..]
        .iter()
        .cloned()
        .fold(state[0].clone(), |acc, s| acc + s);
    state.iter_mut().enumerate().for_each(|(i, s)| {
        (*s) = s.clone() * MAT_DIAG16_M_1[i] + sum.clone();
    });
}

pub fn pow5<F: FieldExpOps>(x: F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x.clone()
}
#[inline(always)]
pub fn apply_m4<F>(x: [F; 4]) -> [F; 4]
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let t0 = x[0].clone() + x[1].clone();
    let t02 = t0.clone() + t0.clone();
    let t1 = x[2].clone() + x[3].clone();
    let t12 = t1.clone() + t1.clone();
    let t2 = x[1].clone() + x[1].clone() + t1.clone();
    let t3 = x[3].clone() + x[3].clone() + t0.clone();
    let t4 = t12.clone() + t12.clone() + t3.clone();
    let t5 = t02.clone() + t02.clone() + t2.clone();
    let t6 = t3.clone() + t5.clone();
    let t7 = t2.clone() + t4.clone();
    [t6, t5, t7, t4]
}

pub type StrictLessThanComponent = FrameworkComponent<LessThanEval<true>>;
pub type LessThanComponent = FrameworkComponent<LessThanEval<false>>;

#[derive(Clone)]
pub struct LessThanEval<const STRICT: bool> {
    pub claim: Claim<LessThanColumn>,
    pub less_than_u8_elements: LessThanU8Elements,
    pub less_than_elements: LessThanElements,
    pub strict_less_than_elements: StrictLessThanElements,
}

#[derive(Debug)]
pub struct LessThanOp<F> {
    // first operand
    a: [F; N_U64_FELTS],
    // second operand
    b: [F; N_U64_FELTS],
    // result of the comparison
    c: F,
    // flag is 1 for the most significant byte where a[i] is not equal to b[i]
    // flag is 1 for the most significant byte where a[i] is not equal to b[i]
    flags: [F; N_U64_FELTS],
    // First byte of the first operand where a[i] is not equal to b[i] from the most significant byte
    a_comparison_byte: F,
    // First byte of the second operand where a[i] < b[i] from the most significant byte
    b_comparison_byte: F,
    // is real flag to check if the operation is not among the dummy padded operations
    is_real: F,
}

impl<F> LessThanOp<F> {
    /// from_eval returns a LessThanOp instance from a given EvalAtRow instance
    fn from_eval<E: EvalAtRow>(eval: &mut E) -> LessThanOp<E::F> {
        let a = array::from_fn(|_| eval.next_trace_mask());
        let b = array::from_fn(|_| eval.next_trace_mask());
        let c = eval.next_trace_mask();
        let flags = array::from_fn(|_| eval.next_trace_mask());
        let a_comparison_byte = eval.next_trace_mask();
        let b_comparison_byte = eval.next_trace_mask();
        let is_real = eval.next_trace_mask();
        LessThanOp {
            a,
            b,
            c,
            flags,
            a_comparison_byte,
            b_comparison_byte,
            is_real,
        }
    }
}

impl<const STRICT: bool> FrameworkEval for LessThanEval<STRICT> {
    fn log_size(&self) -> u32 {
        self.claim.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.claim.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let op = LessThanOp::<E::F>::from_eval(&mut eval);

        // is_real must be a boolean
        eval.add_constraint(op.is_real.clone() * (op.is_real.clone() - E::F::one()));
        // Each flag must be boolean
        let mut sum_flags = E::F::zero();
        for flag in op.flags.iter() {
            eval.add_constraint(flag.clone() * (E::F::one() - flag.clone()));
            sum_flags = sum_flags.clone() + flag.clone();
        }
        // sum must be either 0 or 1
        // 0 if a is equal to b
        // 1 if a is not equal to b
        eval.add_constraint(sum_flags.clone() * (E::F::one() - sum_flags.clone()));

        // a_comparison_byte and b_comparison_byte must be equal to the first bytes where a[i] is not equal to b[i]
        let mut is_inequality_visited = E::F::zero();
        let mut a_comparison_byte = E::F::zero();
        let mut b_comparison_byte = E::F::zero();
        for (a_byte, b_byte, flag) in izip!(
            op.a.clone().into_iter().rev(),
            op.b.clone().into_iter().rev(),
            op.flags.into_iter().rev()
        ) {
            is_inequality_visited = is_inequality_visited.clone() + flag.clone();
            a_comparison_byte = a_comparison_byte.clone() + a_byte.clone() * flag.clone();
            b_comparison_byte = b_comparison_byte.clone() + b_byte.clone() * flag;

            // if inequality is not visited yet then a_byte must be equal to b_byte
            eval.add_constraint(
                (E::F::one() - is_inequality_visited.clone()) * (a_byte.clone() - b_byte.clone()),
            );
        }
        eval.add_constraint(op.a_comparison_byte.clone() - a_comparison_byte.clone());
        eval.add_constraint(op.b_comparison_byte.clone() - b_comparison_byte.clone());

        // c must be a boolean
        eval.add_constraint(op.c.clone() * (op.c.clone() - E::F::one()));

        // if a and b are equal i.e sum_flags is 0
        // is_inequality_visited must be 0
        // a_comparison_byte must be 0
        // b_comparison_byte must be 0
        eval.add_constraint((E::F::one() - sum_flags.clone()) * is_inequality_visited.clone());
        eval.add_constraint((E::F::one() - sum_flags.clone()) * a_comparison_byte.clone());
        eval.add_constraint((E::F::one() - sum_flags.clone()) * b_comparison_byte.clone());
        // if strict: the result must be 0 if a is equal to b
        // if not strict: the result must be 1 if a is equal to b
        if STRICT {
            eval.add_constraint((E::F::one() - sum_flags.clone()) * op.c.clone());
        } else {
            eval.add_constraint((E::F::one() - sum_flags.clone()) * (E::F::one() - op.c.clone()));
        }
        // c must be 1 if a_comparision_byte is less than b_comparison_byte
        // c must be 0 if a_comparision_byte is greater than b_comparison_byte
        // Look Up if the c has been set correctly and "use" the result of the comparison bytes
        // If strict, the result must be 1 if a_comparision_byte is less than b_comparison_byte
        // the less_than_u8_elements result is strictly 1 if a_comparision_byte is less than b_comparison_byte
        // therefore if a is equal to b, the result for less_than_u8_elements must be 0
        let c = if STRICT {
            op.c.clone()
        } else {
            sum_flags.clone() * op.c.clone()
        };
        eval.add_to_relation(RelationEntry::new(
            &self.less_than_u8_elements,
            E::EF::from(op.is_real.clone()),
            &[op.a_comparison_byte, op.b_comparison_byte, c.clone()],
        ));

        // Yield the Results
        let values: Vec<E::F> =
            chain!(op.a.into_iter(), op.b.into_iter(), iter::once(op.c)).collect();
        if STRICT {
            eval.add_to_relation(RelationEntry::new(
                &self.strict_less_than_elements,
                -E::EF::from(op.is_real.clone()),
                &values,
            ));
        } else {
            eval.add_to_relation(RelationEntry::new(
                &self.less_than_elements,
                -E::EF::from(op.is_real.clone()),
                &values,
            ));
        }
        eval.finalize_logup_in_pairs();
        eval
    }
}

pub type AddComponent = FrameworkComponent<AddEval>;

#[derive(Clone)]
pub struct AddEval {
    /// Claim about the trace, including log size and other properties
    pub claim: Claim<AddColumn>,
    /// Relation for checking byte-wise addition correctness
    pub range_check_u8_elements: RangeCheckU8Elements,
    /// Relation for storing and verifying complete addition results
    pub add_elements: AddElements,
}

impl FrameworkEval for AddEval {
    /// Returns the logarithmic size of the claim.
    fn log_size(&self) -> u32 {
        self.claim.log_size
    }

    /// Computes the maximum constraint degree bound
    /// This helps in polynomial commitment scheme and constraint verification
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.claim.log_size + 1
    }

    /// Evaluates constraints for an addition operation on a row.
    ///
    /// Steps performed:
    /// 1. Validate the `is_real` flag (boolean check).
    /// 2. Ensure correct byte-wise addition with carry propagation.
    /// 3. Ensure carry bits are boolean.
    /// 4. Perform U8 range checks on inputs and outputs.
    /// 5. Generate interaction relations for verification.
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Extract the addition operation details from the current row
        let op = AddOp::<E::F>::from_eval(&mut eval);

        // Base value for overflow check (256 in the field)
        let base = E::F::from(BaseField::from(256));

        // CONSTRAINT 1: Ensure `is_real` is a boolean (0 or 1)
        eval.add_constraint(op.is_real.clone() * (op.is_real.clone() - E::F::one()));

        // CONSTRAINT 2: Enforce byte-wise addition with carry.
        let overflow_0 = op.a[0].clone() + op.b[0].clone() - op.c[0].clone();

        // Ensure overflow is either 0 or 256
        eval.add_constraint(overflow_0.clone() * (overflow_0.clone() - base.clone()));

        // Validate carry for the first byte
        // If carry is 1, overflow must be 256
        // If carry is 0, overflow must be 0
        eval.add_constraint(op.carry[0].clone() * (overflow_0.clone() - base.clone()));
        eval.add_constraint((op.carry[0].clone() - E::F::one()) * overflow_0);

        // CONSTRAINT 3: Middle bytes addition with carry propagation
        // Check each intermediate byte addition, ensuring correct carry handling
        for i in 1..N_U64_FELTS - 1 {
            let overflow_i =
                op.a[i].clone() + op.b[i].clone() + op.carry[i - 1].clone() - op.c[i].clone();

            // Ensure overflow is either 0 or 256
            eval.add_constraint(overflow_i.clone() * (overflow_i.clone() - base.clone()));

            // Validate carry for intermediate bytes
            eval.add_constraint(op.carry[i].clone() * (overflow_i.clone() - base.clone()));
            eval.add_constraint((op.carry[i].clone() - E::F::one()) * overflow_i);
        }

        // CONSTRAINT 4: Last byte addition (with incoming carry, no outgoing carry)
        let last_index = N_U64_FELTS - 1;
        let overflow_last =
            op.a[last_index].clone() + op.b[last_index].clone() + op.carry[last_index - 1].clone()
                - op.c[last_index].clone();

        // Ensure last byte overflow is either 0 or 256
        eval.add_constraint(overflow_last.clone() * (overflow_last - base));

        // CONSTRAINT 5: Ensure all carry bits are boolean (0 or 1)
        for i in 0..N_U64_FELTS - 1 {
            eval.add_constraint(op.carry[i].clone() * (op.carry[i].clone() - E::F::one()));
        }

        let values: Vec<E::F> =
            chain!(op.a.into_iter(), op.b.into_iter(), op.c.into_iter()).collect();

        // CONSTRAINT 6: Add range checks for each byte of a, b, and c.
        for i in (0..24).step_by(4) {
            eval.add_to_relation(RelationEntry::new(
                &self.range_check_u8_elements,
                E::EF::from(op.is_real.clone()),
                &[values[i].clone(), values[i + 1].clone()],
            ));
            eval.add_to_relation(RelationEntry::new(
                &self.range_check_u8_elements,
                E::EF::from(op.is_real.clone()),
                &[values[i + 2].clone(), values[i + 3].clone()],
            ));
        }

        // // CONSTRAINT 7: Yield the complete addition results
        eval.add_to_relation(RelationEntry::new(
            &self.add_elements,
            -E::EF::from(op.is_real.clone()),
            &values,
        ));
        // Finalize the logup (logarithmic lookup) in pairs
        eval.finalize_logup_in_pairs();
        eval
    }
}

#[derive(Debug)]
pub struct AddOp<F> {
    /// First input operand, represented as an array of N limbs
    a: [F; N_U64_FELTS],

    /// Second input operand, represented as an array of N limbs
    b: [F; N_U64_FELTS],

    /// Result of the addition, represented as an array of N limbs
    c: [F; N_U64_FELTS],

    /// Carry bits for intermediate byte additions (N_U64_FELTS - 1 carries)
    /// Each carry represents whether the previous byte addition resulted in an overflow
    carry: [F; N_U64_FELTS - 1],

    /// Flag to indicate if this is a "real" operation or a padding operation, helps distinguish between actual computations and dummy rows added for trace alignment
    is_real: F,
}

impl<F> AddOp<F> {
    /// Extracts an AddOp instance from an evaluation row.
    /// An AddOp struct with field elements extracted from the evaluation context
    fn from_eval<E: EvalAtRow>(eval: &mut E) -> AddOp<E::F> {
        // Extract field elements for each component of the addition operation
        let a = array::from_fn(|_| eval.next_trace_mask());
        let b = array::from_fn(|_| eval.next_trace_mask());
        let c = array::from_fn(|_| eval.next_trace_mask());
        let carry = array::from_fn(|_| eval.next_trace_mask());
        let is_real = eval.next_trace_mask();

        AddOp {
            a,
            b,
            c,
            carry,
            is_real,
        }
    }
}

pub type ProcessorComponent = FrameworkComponent<ProcessorEval>;

#[derive(Clone)]
pub struct ProcessorEval {
    pub claim: Claim<ProcessorColumn>,
    pub state_elements: StateElements,
    pub instruction_elements: InstructionElements,
}

impl FrameworkEval for ProcessorEval {
    fn log_size(&self) -> u32 {
        self.claim.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.claim.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let op = Instruction::<E::F>::from_eval(&mut eval);

        // is_real must be a boolean
        eval.add_constraint(op.is_real.clone() * (op.is_real.clone() - E::F::one()));

        let mult = E::EF::from(op.is_real.clone());

        let initial_state: Vec<E::F> = flatten!(
            op.initial_state.n.clone(),
            op.initial_state.buy_root.clone(),
            op.initial_state.best_buy_price.clone(),
            op.initial_state.sell_root.clone(),
            op.initial_state.best_sell_price.clone(),
            op.initial_state.op_code.clone()
        );

        // use the initial state
        eval.add_to_relation(RelationEntry::new(
            &self.state_elements,
            mult.clone(),
            &initial_state,
        ));

        let values: Vec<E::F> = flatten!(
            op.initial_state.n.clone(),
            op.initial_state.buy_root,
            op.initial_state.best_buy_price,
            op.initial_state.sell_root,
            op.initial_state.best_sell_price,
            op.initial_state.op_code,
            op.opcode.clone(),
            op.low_merkle_proof,
            op.low_merkle_path,
            op.updated_low_merkle_path,
            op.low_index,
            op.low_leaf,
            op.merkle_proof,
            op.merkle_path,
            op.updated_merkle_path,
            op.index,
            op.leaf,
            op.final_state.n.clone(),
            op.final_state.buy_root.clone(),
            op.final_state.best_buy_price.clone(),
            op.final_state.sell_root.clone(),
            op.final_state.best_sell_price.clone(),
            op.final_state.op_code.clone(),
            op.is_real
        );
        // use the instruction elements to update the state to the final state
        eval.add_to_relation(RelationEntry::new(
            &self.instruction_elements,
            mult.clone(),
            &values,
        ));

        // ensure that the state count is updated correctly
        eval.add_constraint(op.final_state.n.clone() - op.initial_state.n.clone() - E::F::one());

        // the instructions opcode must be the same as the final state opcode
        eval.add_constraint(op.opcode.clone() - op.final_state.op_code.clone());

        let final_state: Vec<E::F> = flatten!(
            op.final_state.n,
            op.final_state.buy_root,
            op.final_state.best_buy_price,
            op.final_state.sell_root,
            op.final_state.best_sell_price,
            op.final_state.op_code
        );

        // yield the final state
        eval.add_to_relation(RelationEntry::new(
            &self.state_elements,
            -mult.clone(),
            &final_state,
        ));

        // the inital and final state relations are batched in pairs in the first interaction column
        // the instruction elements are in the second interaction column
        eval.finalize_logup_batched(&vec![0, 1, 0]);
        eval
    }
}

/// A Merkle proof consisting of the sibling hashes for each level from the leaf to the root.
pub type MerkleProof<F> = [Hash<F>; MERKLE_HEIGHT];
/// A Merkle path consisting of the resulting hash at each level from the leaf to the root.
pub type MerklePath<F> = [Hash<F>; MERKLE_HEIGHT + 1];
/// LeafFelts is an array of felts representing the leaf node.
pub type LeafFelts<F> = [F; N_LEAF_FELTS];
/// IndexBits is bit decomposition of the index
/// 0 => left, 1 => right
/// starting from the leaf to the root
pub type IndexBits<F> = [F; MERKLE_HEIGHT];
/// PriceTimeFelts is an array of felts representing the PriceTime.
pub type PriceTimeFelts<F> = [F; 2 * N_U64_FELTS];
/// Hash contain 8 BaseField elements.
pub type Hash<F> = [F; 8];
/// Price Felts
pub type PriceFelts<F> = [F; 8];

#[derive(Clone, Copy, Debug)]
pub struct Instruction<F> {
    /// initial state before the instruction is applied
    pub initial_state: State<F>,
    /// The opcode of the instruction
    pub opcode: F,
    /// Low Leafs Merkle Proof to which the instruction applies
    /// Merkle Proof contains sibling hashes of the leafs in the path from the leaf to the root
    pub low_merkle_proof: MerkleProof<F>,
    /// Low Leafs Merkle Path to which the instruction applies
    /// Merkle Path containts the hash of the leafs in the path from the leaf to the root
    pub low_merkle_path: MerklePath<F>,
    /// Updated Low Leafs Merkle Path after the instruction is applied
    pub updated_low_merkle_path: MerklePath<F>,
    /// Low Leafs Index in the IMT
    pub low_index: IndexBits<F>,
    // @todo:rename this field
    /// Additional Data for Instruction
    /// Insertions: Contains Actual Low Leaf
    /// Updates: First N_U64_FELTS contain new Volume, rest zero
    /// PartialMatch: First N_U64_FELTS contain Filled Volume,
    ///               Next N_U64_FELTS contain Remaining Volume,
    /// this is because we dont need low leaf when verifying constraints
    /// the low leaf can be constructed from side and leaf.
    pub low_leaf: LeafFelts<F>,
    /// Merkle Proof of the leaf to which the instruction applies
    pub merkle_proof: MerkleProof<F>,
    /// Merkle Path of the leaf to which the instruction applies
    pub merkle_path: MerklePath<F>,
    /// Updated Merkle Path after the instruction is applied
    pub updated_merkle_path: MerklePath<F>,
    /// Index of the leaf in the IMT
    pub index: IndexBits<F>,
    /// Leaf to which the instruction applies
    pub leaf: LeafFelts<F>,
    /// final state after the instruction is applied
    pub final_state: State<F>,
    /// is_real flag to check if the operation is not among the dummy padded operations
    pub is_real: F,
}

impl<F> Instruction<F> {
    /// from_eval returns a LessThanOp instance from a given EvalAtRow instance
    pub fn from_eval<E: EvalAtRow>(eval: &mut E) -> Instruction<E::F> {
        let initial_state = State::<E::F>::from_eval(eval);
        let opcode = eval.next_trace_mask();
        let low_merkle_proof = array::from_fn(|_| array::from_fn(|_| eval.next_trace_mask()));
        let low_merkle_path = array::from_fn(|_| array::from_fn(|_| eval.next_trace_mask()));
        let updated_low_merkle_path =
            array::from_fn(|_| array::from_fn(|_| eval.next_trace_mask()));
        let low_index = array::from_fn(|_| eval.next_trace_mask());
        let low_leaf = array::from_fn(|_| eval.next_trace_mask());
        let merkle_proof = array::from_fn(|_| array::from_fn(|_| eval.next_trace_mask()));
        let merkle_path = array::from_fn(|_| array::from_fn(|_| eval.next_trace_mask()));
        let updated_merkle_path = array::from_fn(|_| array::from_fn(|_| eval.next_trace_mask()));
        let index = array::from_fn(|_| eval.next_trace_mask());
        let leaf = array::from_fn(|_| eval.next_trace_mask());
        let final_state = State::<E::F>::from_eval(eval);
        let is_real = eval.next_trace_mask();
        Instruction {
            initial_state,
            opcode,
            low_merkle_proof,
            low_merkle_path,
            updated_low_merkle_path,
            low_index,
            low_leaf,
            merkle_proof,
            merkle_path,
            updated_merkle_path,
            index,
            leaf,
            final_state,
            is_real,
        }
    }
}

pub struct LeafColumn;

impl LeafColumn {
    pub const ACTIVE: usize = 0;
    pub const VOLUME: usize = Self::ACTIVE + 1;
    pub const LABEL: usize = Self::VOLUME + N_U64_FELTS;
    pub const NEXT: usize = Self::LABEL + 2 * N_U64_FELTS;

    pub const PRICE: usize = Self::LABEL;
    pub const TIME: usize = Self::PRICE + N_U64_FELTS;
    pub const NEXT_PRICE: usize = Self::NEXT;
    pub const NEXT_TIME: usize = Self::NEXT_PRICE + N_U64_FELTS;
}

pub type BuyInsertionComponent = FrameworkComponent<InsertionsEval<Buy>>;
pub type SellInsertionComponent = FrameworkComponent<InsertionsEval<Sell>>;

#[derive(Clone)]
pub struct InsertionsEval<S> {
    pub claim: Claim<InsertionsColumn>,
    pub poseidon_elements: PoseidonElements,
    pub less_than_elements: LessThanElements,
    pub strict_less_than_elements: StrictLessThanElements,
    pub instruction_elements: InstructionElements,
    pub _side: PhantomData<S>,
}

impl<S: OrderSide> FrameworkEval for InsertionsEval<S> {
    fn log_size(&self) -> u32 {
        self.claim.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.claim.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let op = Instruction::<E::F>::from_eval(&mut eval);

        // is_real must be a boolean
        eval.add_constraint(op.is_real.clone() * (op.is_real.clone() - E::F::one()));

        // opcode must be equal to the instruction's opcode
        eval.add_constraint(op.opcode.clone() - E::F::from(S::op_code(IMTOperation::Insertion)));

        let mult = E::EF::from(op.is_real.clone());

        // low_leaf must be active
        eval.add_constraint(E::F::one() - op.low_leaf[0].clone());

        let low_price: [E::F; N_U64_FELTS] =
            array::from_fn(|i| op.low_leaf[LeafColumn::PRICE + i].clone());
        let low_time: [E::F; N_U64_FELTS] =
            array::from_fn(|i| op.low_leaf[LeafColumn::TIME + i].clone());
        let inserted_price: [E::F; N_U64_FELTS] =
            array::from_fn(|i| op.leaf[LeafColumn::PRICE + i].clone());
        let inserted_time: [E::F; N_U64_FELTS] =
            array::from_fn(|i| op.leaf[LeafColumn::TIME + i].clone());
        let next_price: [E::F; N_U64_FELTS] =
            array::from_fn(|i| op.low_leaf[LeafColumn::NEXT_PRICE + i].clone());
        let next_time: [E::F; N_U64_FELTS] =
            array::from_fn(|i| op.low_leaf[LeafColumn::NEXT_TIME + i].clone());
        // // time of inserted leaf must be greater than time of low leaf and low leaf's next
        eval.add_to_relation(RelationEntry::new(
            &self.strict_less_than_elements,
            mult.clone(),
            &chain!(
                low_time.iter().cloned(),
                inserted_time.iter().cloned(),
                [E::F::one()]
            )
            .collect_vec(),
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.strict_less_than_elements,
            mult.clone(),
            &chain!(
                next_time.iter().cloned(),
                inserted_time.iter().cloned(),
                [E::F::one()]
            )
            .collect_vec(),
        ));
        match S::side() {
            Side::Buy => {
                // price of inserted leaf must be less than price of low leaf price.
                eval.add_to_relation(RelationEntry::new(
                    &self.less_than_elements,
                    mult.clone(),
                    &chain!(
                        inserted_price.iter().cloned(),
                        low_price.iter().cloned(),
                        [E::F::one()]
                    )
                    .collect_vec(),
                ));
                // price of next must be stritly less than price of inserted leaf
                eval.add_to_relation(RelationEntry::new(
                    &self.strict_less_than_elements,
                    mult.clone(),
                    &chain!(
                        next_price.iter().cloned(),
                        inserted_price.iter().cloned(),
                        [E::F::one()]
                    )
                    .collect_vec(),
                ));

                // initial state's buy root hash must be equal to the root hash of the merkle tree
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.initial_state.buy_root[i].clone()
                            - op.low_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }
            }
            Side::Sell => {
                // price of low leaf must less than price of inserted leaf
                eval.add_to_relation(RelationEntry::new(
                    &self.less_than_elements,
                    mult.clone(),
                    &chain!(
                        low_price.iter().cloned(),
                        inserted_price.iter().cloned(),
                        [E::F::one()]
                    )
                    .collect_vec(),
                ));

                // price of inserted leaf must be strictly less than price of next
                eval.add_to_relation(RelationEntry::new(
                    &self.strict_less_than_elements,
                    mult.clone(),
                    &chain!(
                        inserted_price.iter().cloned(),
                        next_price.iter().cloned(),
                        [E::F::one()]
                    )
                    .collect_vec(),
                ));

                // initial state's sell root hash must be equal to the root hash of the merkle tree
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.initial_state.sell_root[i].clone()
                            - op.low_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }
            }
        }

        // the low leafs next value must be equal to the inserted leaf's next before the insertion
        for i in 0..2 * N_U64_FELTS {
            eval.add_constraint(
                op.low_leaf[LeafColumn::NEXT + i].clone() - op.leaf[LeafColumn::NEXT + i].clone(),
            );
        }

        // eval low leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.low_merkle_proof.clone(),
            op.low_merkle_path.clone(),
            op.low_leaf.clone(),
            op.low_index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );
        let mut updated_low_leaf = op.low_leaf.clone();
        updated_low_leaf[LeafColumn::NEXT..].clone_from_slice(&op.leaf[9..25]);
        // eval updated low leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.low_merkle_proof.clone(),
            op.updated_low_merkle_path.clone(),
            updated_low_leaf,
            op.low_index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );

        // the resultant root hash from updating low_leaf must be equal the path of inactive leaf
        // this ensures that both leaf updates are consistent
        for i in 0..N_HASH {
            eval.add_constraint(
                op.updated_low_merkle_path[MERKLE_HEIGHT][i].clone()
                    - op.merkle_path[MERKLE_HEIGHT][i].clone(),
            );
        }

        let inactive_leaf: [E::F; N_LEAF_FELTS] = array::from_fn(|_| E::F::zero());

        // eval empty leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.merkle_proof.clone(),
            op.merkle_path.clone(),
            inactive_leaf,
            op.index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );
        // eval updated leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.merkle_proof.clone(),
            op.updated_merkle_path.clone(),
            op.leaf.clone(),
            op.index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );

        // ensure that the state count is updated correctly
        eval.add_constraint(op.final_state.n.clone() - op.initial_state.n.clone() - E::F::one());
        match S::side() {
            Side::Buy => {
                // final state's buy root hash must be equal to the root in the inserted leaf's merkle path
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.final_state.buy_root[i].clone()
                            - op.updated_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }

                // the initial priority for sell IMT must be equal to the final priority
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        op.initial_state.best_sell_price[i].clone()
                            - op.final_state.best_sell_price[i].clone(),
                    );
                }

                // the initial priority for buy IMT must change only if the low leaf is the first leaf in the buy imt
                // if the priority of the leaf changes, it must be equal to the inserted leaf's price_time
                let first_leaf_price_time = first_price_time_felts::<E, Buy>();
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        (op.final_state.best_buy_price[i].clone()
                            - op.initial_state.best_buy_price[i].clone())
                            * (op.low_leaf[LeafColumn::PRICE + i].clone()
                                - first_leaf_price_time[i].clone()),
                    );

                    eval.add_constraint(
                        (op.final_state.best_buy_price[i].clone()
                            - op.initial_state.best_buy_price[i].clone())
                            * (op.final_state.best_buy_price[i].clone()
                                - op.leaf[LeafColumn::PRICE + i].clone()),
                    );
                }
            }
            Side::Sell => {
                // initial state's sell root hash must be equal to the root in the inserted leaf's merkle path
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.final_state.sell_root[i].clone()
                            - op.updated_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }

                // the initial priority for buy IMT must be equal to the final priority
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        op.initial_state.best_buy_price[i].clone()
                            - op.final_state.best_buy_price[i].clone(),
                    );
                }

                // the initial priority for sell IMT must change only if the low leaf is the first leaf in the sell IMT
                // if the priority of the leaf changes, it must be equal to the inserted leaf's price_time
                let first_leaf_price_time = first_price_time_felts::<E, Sell>();
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        (op.final_state.best_sell_price[i].clone()
                            - op.initial_state.best_sell_price[i].clone())
                            * (op.low_leaf[LeafColumn::PRICE + i].clone()
                                - first_leaf_price_time[i].clone()),
                    );

                    eval.add_constraint(
                        (op.final_state.best_sell_price[i].clone()
                            - op.initial_state.best_sell_price[i].clone())
                            * (op.final_state.best_sell_price[i].clone()
                                - op.leaf[LeafColumn::PRICE + i].clone()),
                    );
                }
            }
        }

        let values: Vec<E::F> = flatten!(
            op.initial_state.n,
            op.initial_state.buy_root,
            op.initial_state.best_buy_price,
            op.initial_state.sell_root,
            op.initial_state.best_sell_price,
            op.initial_state.op_code,
            op.opcode,
            op.low_merkle_proof,
            op.low_merkle_path,
            op.updated_low_merkle_path,
            op.low_index,
            op.low_leaf,
            op.merkle_proof,
            op.merkle_path,
            op.updated_merkle_path,
            op.index,
            op.leaf,
            op.final_state.n,
            op.final_state.buy_root,
            op.final_state.best_buy_price,
            op.final_state.sell_root,
            op.final_state.best_sell_price,
            op.final_state.op_code,
            op.is_real
        );
        // yield the results
        eval.add_to_relation(RelationEntry::new(
            &self.instruction_elements,
            -mult,
            &values,
        ));
        eval.finalize_logup();
        eval
    }
}

pub fn eval_merkle_proof<E: EvalAtRow>(
    eval: &mut E,
    proof: MerkleProof<E::F>,
    path: MerklePath<E::F>,
    leaf: LeafFelts<E::F>,
    index_bits: IndexBits<E::F>,
    poseidon_elements: &PoseidonElements,
    mult: E::EF,
) {
    // evaluate leaf hash
    let leaf: Vec<E::F> = leaf[0..N_STATE].into();
    eval.add_to_relation(RelationEntry::new(
        poseidon_elements,
        mult.clone(),
        &chain!(leaf.iter().cloned(), path[0].clone().into_iter()).collect::<Vec<_>>(),
    ));

    let mut curr = path[0].clone();
    for (i, (sibling, hash)) in proof.iter().zip(path.iter().skip(1)).enumerate() {
        let index_bit = index_bits[i].clone();
        let first: [E::F; N_HASH] = array::from_fn(|j| {
            index_bit.clone() * sibling[j].clone()
                + (E::F::one() - index_bit.clone()) * curr[j].clone()
        });
        let second: [E::F; N_HASH] = array::from_fn(|j| {
            index_bit.clone() * curr[j].clone()
                + (E::F::one() - index_bit.clone()) * sibling[j].clone()
        });
        let values: Vec<E::F> = chain!(
            first.into_iter(),
            second.into_iter(),
            hash.clone().into_iter()
        )
        .collect();
        eval.add_to_relation(RelationEntry::new(poseidon_elements, mult.clone(), &values));
        curr = hash.clone();
    }
}

pub enum IMTOperation {
    Insertion,
    Update,
    Deletion,
    MatchAggressive,
    MatchPassive,
    PartialMatchAggressive,
    PartialMatchPassive,
}

pub enum Side {
    Buy,
    Sell,
}

/// Type markers for Buy and Sell sides
#[derive(Debug, Clone, Copy)]
pub struct Buy;
#[derive(Debug, Clone, Copy)]
pub struct Sell;

/// Order side marker trait with compile-time constants
pub trait OrderSide: 'static + Copy + Send + Sync + Clone + Copy + Debug {
    /// Associated constant for side name
    const NAME: &'static str;
    /// Associated constant for side variant
    const SIDE: Side;
    /// side marker
    fn side() -> Side {
        Self::SIDE
    }
    /// get op code based on the imt operation
    fn op_code(op: IMTOperation) -> BaseField;
    /// get the complement opcode, i.e., the opcode for the other side
    fn complement_op_code(op: IMTOperation) -> BaseField {
        match Self::side() {
            Side::Buy => Self::op_code(op) + BaseField::one(),
            Side::Sell => Self::op_code(op) - BaseField::one(),
        }
    }
    /// get the name of the side
    fn name() -> &'static str {
        match Self::side() {
            Side::Buy => "Buy",
            Side::Sell => "Sell",
        }
    }
}

impl OrderSide for Buy {
    const NAME: &'static str = "Buy";
    const SIDE: Side = Side::Buy;

    fn op_code(op: IMTOperation) -> BaseField {
        match op {
            IMTOperation::Insertion => BaseField::from_u32_unchecked(0),
            IMTOperation::Deletion => BaseField::from_u32_unchecked(2),
            IMTOperation::Update => BaseField::from_u32_unchecked(4),
            IMTOperation::MatchAggressive => BaseField::from_u32_unchecked(6),
            IMTOperation::MatchPassive => BaseField::from_u32_unchecked(8),
            IMTOperation::PartialMatchAggressive => BaseField::from_u32_unchecked(10),
            IMTOperation::PartialMatchPassive => BaseField::from_u32_unchecked(12),
        }
    }
}

impl OrderSide for Sell {
    const NAME: &'static str = "Sell";
    const SIDE: Side = Side::Sell;
    fn op_code(op: IMTOperation) -> BaseField {
        match op {
            IMTOperation::Insertion => BaseField::from_u32_unchecked(1),
            IMTOperation::Deletion => BaseField::from_u32_unchecked(3),
            IMTOperation::Update => BaseField::from_u32_unchecked(5),
            IMTOperation::MatchAggressive => BaseField::from_u32_unchecked(7),
            IMTOperation::MatchPassive => BaseField::from_u32_unchecked(9),
            IMTOperation::PartialMatchAggressive => BaseField::from_u32_unchecked(11),
            IMTOperation::PartialMatchPassive => BaseField::from_u32_unchecked(13),
        }
    }
}

pub fn first_price_time_felts<E: EvalAtRow, S: OrderSide>() -> PriceTimeFelts<E::F> {
    let mut price_time = array::from_fn(|_| E::F::zero());
    match S::side() {
        Side::Buy => {
            for i in 0..N_U64_FELTS {
                price_time[i] = E::F::from(M31(255))
            }
        }
        Side::Sell => {} // sell sides first price time is default/zeros
    }
    price_time
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct State<F> {
    /// ith state
    pub n: F,
    /// root hash of the Buy IMT
    pub buy_root: Hash<F>,
    /// the order which should be matched first in the Buy IMT
    pub best_buy_price: PriceFelts<F>,
    /// root hash of the Sell IMT
    pub sell_root: Hash<F>,
    /// the order which should be matched first in the Sell IMT
    pub best_sell_price: PriceFelts<F>,
    /// the op code that resulted in this state
    pub op_code: F,
}

impl<F> State<F> {
    /// Creates a new State.
    pub fn new(
        n: F,
        buy_root: Hash<F>,
        best_buy_price: PriceFelts<F>,
        sell_root: Hash<F>,
        best_sell_price: PriceFelts<F>,
        op_code: F,
    ) -> Self {
        State {
            n,
            buy_root,
            best_buy_price,
            sell_root,
            best_sell_price,
            op_code,
        }
    }

    /// from_eval returns a State instance from a given EvalAtRow instance
    pub fn from_eval<E: EvalAtRow>(eval: &mut E) -> State<E::F> {
        let n = eval.next_trace_mask();
        let buy_root = array::from_fn(|_| eval.next_trace_mask());
        let best_buy_price = array::from_fn(|_| eval.next_trace_mask());
        let sell_root = array::from_fn(|_| eval.next_trace_mask());
        let best_sell_price = array::from_fn(|_| eval.next_trace_mask());
        let op_code = eval.next_trace_mask();
        State {
            n,
            buy_root,
            best_buy_price,
            sell_root,
            best_sell_price,
            op_code,
        }
    }
}

#[macro_export]
macro_rules! flatten {
    ($($x:expr),*) => {{
        let mut result = Vec::new();

        $(
            // Handle different input types
            flatten_single(&mut result, $x);
        )*

        result.try_into().unwrap()
    }};
}

// Helper function to handle different input types
pub fn flatten_single<F>(acc: &mut Vec<F>, input: impl Flatten<F>) {
    input.flatten(acc);
}

// Trait to abstract flattening behavior
pub trait Flatten<F> {
    fn flatten(&self, acc: &mut Vec<F>);
}

// Flattening for F
impl<F: Clone> Flatten<F> for F {
    fn flatten(&self, acc: &mut Vec<F>) {
        acc.push(self.clone());
    }
}

// Flattening for [F; N]
impl<F: Clone, const N: usize> Flatten<F> for [F; N] {
    fn flatten(&self, acc: &mut Vec<F>) {
        acc.extend_from_slice(self);
    }
}

// Flattening for [[F; WIDTH]; HEIGHT]
impl<F: Clone, const HEIGHT: usize, const WIDTH: usize> Flatten<F> for [[F; WIDTH]; HEIGHT] {
    fn flatten(&self, acc: &mut Vec<F>) {
        for row in self.iter() {
            acc.extend_from_slice(row);
        }
    }
}

pub type BuyAgessiveMatchComponent = FrameworkComponent<MatchEval<Buy, Aggressive>>;
pub type BuyPassiveMatchComponent = FrameworkComponent<MatchEval<Buy, Passive>>;

pub type SellAggressiveMatchComponent = FrameworkComponent<MatchEval<Sell, Aggressive>>;
pub type SellPassiveMatchComponent = FrameworkComponent<MatchEval<Sell, Passive>>;

#[derive(Clone)]
pub struct MatchEval<S, T: OrderMatchType> {
    pub claim: Claim<MatchColumn<T>>,
    pub poseidon_elements: PoseidonElements,
    pub less_than_elements: LessThanElements,
    pub instruction_elements: InstructionElements,
    pub match_elements: MatchElements,
    pub _side: PhantomData<S>,
    pub _type: PhantomData<T>,
}

impl<S: OrderSide, T: OrderMatchType> FrameworkEval for MatchEval<S, T> {
    fn log_size(&self) -> u32 {
        self.claim.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.claim.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let op = Instruction::<E::F>::from_eval(&mut eval);

        // is_real must be a boolean
        eval.add_constraint(op.is_real.clone() * (op.is_real.clone() - E::F::one()));

        // match leaf must be active
        eval.add_constraint(E::F::one() - op.leaf[LeafColumn::ACTIVE].clone());

        let mult = E::EF::from(op.is_real.clone());

        match T::MATCHTYPE {
            MatchType::Aggressive => {
                // opcode must be equal to the instruction's opcode
                eval.add_constraint(
                    op.opcode.clone() - E::F::from(S::op_code(IMTOperation::MatchAggressive)),
                );
                eval.add_constraint(
                    (op.initial_state.op_code.clone()
                        - E::F::from(S::op_code(IMTOperation::Insertion)))
                        * (op.initial_state.op_code.clone()
                            - E::F::from(S::complement_op_code(IMTOperation::MatchPassive))),
                );
                let price: [E::F; N_U64_FELTS] =
                    array::from_fn(|i| op.leaf[LeafColumn::PRICE + i].clone());

                let (trade_price, less_than_values): ([E::F; N_U64_FELTS], Vec<E::F>) =
                    match S::SIDE {
                        Side::Buy => {
                            // opcode must be equal to the instruction's opcode
                            let trade_price =
                                array::from_fn(|i| op.initial_state.best_sell_price[i].clone());
                            let values = chain!(
                                trade_price.iter().cloned(),
                                price.iter().cloned(),
                                [E::F::one()]
                            )
                            .collect_vec();
                            (trade_price, values)
                        }
                        Side::Sell => {
                            let trade_price =
                                array::from_fn(|i| op.initial_state.best_buy_price[i].clone());
                            let values = chain!(
                                price.iter().cloned(),
                                trade_price.iter().cloned(),
                                [E::F::one()]
                            )
                            .collect_vec();
                            (trade_price, values)
                        }
                    };

                eval.add_to_relation(RelationEntry::new(
                    &self.less_than_elements,
                    mult.clone(),
                    &less_than_values,
                ));

                let volume: [E::F; N_U64_FELTS] =
                    array::from_fn(|i| op.leaf[LeafColumn::VOLUME + i].clone());
                let values = chain!(trade_price.into_iter(), volume.into_iter()).collect_vec();
                eval.add_to_relation(RelationEntry::new(
                    &self.match_elements,
                    -mult.clone(),
                    &values,
                ));
            }
            MatchType::Passive => {
                // opcode must be equal to the instruction's opcode
                eval.add_constraint(
                    op.opcode.clone() - E::F::from(S::op_code(IMTOperation::MatchPassive)),
                );
                eval.add_constraint(
                    (op.initial_state.op_code.clone()
                        - E::F::from(S::complement_op_code(IMTOperation::MatchAggressive)))
                        * (op.initial_state.op_code.clone()
                            - E::F::from(S::complement_op_code(
                                IMTOperation::PartialMatchAggressive,
                            ))),
                );

                let price: [E::F; N_U64_FELTS] =
                    array::from_fn(|i| op.leaf[LeafColumn::PRICE + i].clone());
                let volume: [E::F; N_U64_FELTS] =
                    array::from_fn(|i| op.leaf[LeafColumn::VOLUME + i].clone());
                let values = chain!(price.into_iter(), volume.into_iter()).collect_vec();
                eval.add_to_relation(RelationEntry::new(
                    &self.match_elements,
                    mult.clone(),
                    &values,
                ));
            }
        }

        // Can we construct the entire low leaf here? and potentially reduce the number of constraints
        // ensure that the low leaf is the first leaf
        // low_leaf's next must point to leaf
        let first_price_time_felts = first_price_time_felts::<E, S>();
        // assert active is set to 1
        eval.add_constraint(E::F::one() - op.low_leaf[0].clone());
        // assert volume must be zero
        for i in 0..N_U64_FELTS {
            eval.add_constraint(op.low_leaf[LeafColumn::VOLUME + i].clone());
        }
        // assert leaf's price_time is equal to the first price_time
        for i in 0..2 * N_U64_FELTS {
            eval.add_constraint(
                first_price_time_felts[i].clone() - op.low_leaf[LeafColumn::PRICE + i].clone(),
            );
        }
        // assert low leaf's next is equal to leaf's next
        for i in 0..2 * N_U64_FELTS {
            eval.add_constraint(
                op.leaf[LeafColumn::PRICE + i].clone() - op.low_leaf[LeafColumn::NEXT + i].clone(),
            );
        }

        // assert initial state root
        match S::side() {
            Side::Buy => {
                // initial state's buy root hash must be equal to the root hash of the merkle tree
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.initial_state.buy_root[i].clone()
                            - op.low_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }
            }
            Side::Sell => {
                // initial state's sell root hash must be equal to the root hash of the merkle tree
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.initial_state.sell_root[i].clone()
                            - op.low_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }
            }
        }

        // eval low leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.low_merkle_proof.clone(),
            op.low_merkle_path.clone(),
            op.low_leaf.clone(),
            op.low_index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );

        // low leaf will now point to next highest priority
        let mut updated_low_leaf = op.low_leaf.clone();
        updated_low_leaf[LeafColumn::NEXT..N_LEAF_FELTS]
            .clone_from_slice(&op.leaf[LeafColumn::NEXT..N_LEAF_FELTS]);

        // eval updated low leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.low_merkle_proof.clone(),
            op.updated_low_merkle_path.clone(),
            updated_low_leaf,
            op.low_index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );

        // the resultant root hash from updating low_leaf must be equal the path of matched leaf
        // this ensures that both leaf updates are consistent
        for i in 0..N_HASH {
            eval.add_constraint(
                op.updated_low_merkle_path[MERKLE_HEIGHT][i].clone()
                    - op.merkle_path[MERKLE_HEIGHT][i].clone(),
            );
        }

        // eval matched leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.merkle_proof.clone(),
            op.merkle_path.clone(),
            op.leaf.clone(),
            op.index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );

        // updates matched leaf active flag to 0
        let mut updated_leaf = op.leaf.clone();
        updated_leaf[LeafColumn::ACTIVE] = E::F::zero();

        // eval updated leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.merkle_proof.clone(),
            op.updated_merkle_path.clone(),
            updated_leaf,
            op.index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );

        // ensure that the state count is updated correctly
        eval.add_constraint(op.final_state.n.clone() - op.initial_state.n.clone() - E::F::one());
        match S::side() {
            Side::Buy => {
                // final state's buy root hash must be equal to the root in the matched leaf's updated merkle path
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.final_state.buy_root[i].clone()
                            - op.updated_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }

                // the initial priority for sell IMT must be equal to the final priority
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        op.initial_state.best_sell_price[i].clone()
                            - op.final_state.best_sell_price[i].clone(),
                    );
                }

                // the final root hash for sell IMT must be equal to the initial root hash
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.final_state.sell_root[i].clone() - op.initial_state.sell_root[i].clone(),
                    );
                }

                // the final priority will be equal to matched leaf's next price_time
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        op.final_state.best_buy_price[i].clone()
                            - op.leaf[LeafColumn::NEXT_PRICE + i].clone(),
                    );
                }
            }
            Side::Sell => {
                // initial state's sell root hash must be equal to the root in the matched leaf's updated merkle path
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.final_state.sell_root[i].clone()
                            - op.updated_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }

                // the initial priority for buy IMT must be equal to the final priority
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        op.initial_state.best_buy_price[i].clone()
                            - op.final_state.best_buy_price[i].clone(),
                    );
                }

                // the final root hash for buy IMT must be equal to the initial root hash
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.final_state.buy_root[i].clone() - op.initial_state.buy_root[i].clone(),
                    );
                }

                // the final priority will be equal to matched leaf's next price_time
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        op.final_state.best_sell_price[i].clone()
                            - op.leaf[LeafColumn::NEXT_PRICE + i].clone(),
                    );
                }
            }
        }

        let values: Vec<E::F> = flatten!(
            op.initial_state.n,
            op.initial_state.buy_root,
            op.initial_state.best_buy_price,
            op.initial_state.sell_root,
            op.initial_state.best_sell_price,
            op.initial_state.op_code,
            op.opcode,
            op.low_merkle_proof,
            op.low_merkle_path,
            op.updated_low_merkle_path,
            op.low_index,
            op.low_leaf,
            op.merkle_proof,
            op.merkle_path,
            op.updated_merkle_path,
            op.index,
            op.leaf,
            op.final_state.n,
            op.final_state.buy_root,
            op.final_state.best_buy_price,
            op.final_state.sell_root,
            op.final_state.best_sell_price,
            op.final_state.op_code,
            op.is_real
        );
        // yield the results
        eval.add_to_relation(RelationEntry::new(
            &self.instruction_elements,
            -mult,
            &values,
        ));
        eval.finalize_logup();
        eval
    }
}

pub type BuyAgessivePartialMatchComponent = FrameworkComponent<PartialMatchEval<Buy, Aggressive>>;
pub type BuyPassivePartialMatchComponent = FrameworkComponent<PartialMatchEval<Buy, Passive>>;

pub type SellAggressivePartialMatchComponent =
    FrameworkComponent<PartialMatchEval<Sell, Aggressive>>;
pub type SellPassivePartialMatchComponent = FrameworkComponent<PartialMatchEval<Sell, Passive>>;

#[derive(Clone)]
pub struct PartialMatchEval<S, T: OrderMatchType> {
    pub claim: Claim<PartialMatchColumn<T>>,
    pub poseidon_elements: PoseidonElements,
    pub less_than_elements: LessThanElements,
    pub instruction_elements: InstructionElements,
    pub match_elements: MatchElements,
    pub add_elements: AddElements,
    pub _side: PhantomData<S>,
    pub _type: PhantomData<T>,
}

impl<S: OrderSide, T: OrderMatchType> FrameworkEval for PartialMatchEval<S, T> {
    fn log_size(&self) -> u32 {
        self.claim.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.claim.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let op = Instruction::<E::F>::from_eval(&mut eval);

        // is_real must be a boolean
        eval.add_constraint(op.is_real.clone() * (op.is_real.clone() - E::F::one()));

        // match leaf must be active
        eval.add_constraint(E::F::one() - op.leaf[LeafColumn::ACTIVE].clone());

        let mult = E::EF::from(op.is_real.clone());

        // extract filled volume and remaining volume contained in the instruction's low leaf
        let filled_volume: [E::F; N_U64_FELTS] = array::from_fn(|i| op.low_leaf[i].clone());

        let remaining_volume: [E::F; N_U64_FELTS] =
            array::from_fn(|i| op.low_leaf[N_U64_FELTS + i].clone());
        match T::MATCHTYPE {
            MatchType::Aggressive => {
                // opcode must be equal to the instruction's opcode
                eval.add_constraint(
                    op.opcode.clone()
                        - E::F::from(S::op_code(IMTOperation::PartialMatchAggressive)),
                );
                eval.add_constraint(
                    (op.initial_state.op_code.clone()
                        - E::F::from(S::op_code(IMTOperation::Insertion)))
                        * (op.initial_state.op_code.clone()
                            - E::F::from(S::complement_op_code(IMTOperation::MatchPassive))),
                );

                let price: [E::F; N_U64_FELTS] =
                    array::from_fn(|i| op.leaf[LeafColumn::PRICE + i].clone());

                let (trade_price, less_than_values): ([E::F; N_U64_FELTS], Vec<E::F>) =
                    match S::SIDE {
                        Side::Buy => {
                            // opcode must be equal to the instruction's opcode
                            let trade_price =
                                array::from_fn(|i| op.initial_state.best_sell_price[i].clone());
                            let values = chain!(
                                trade_price.iter().cloned(),
                                price.iter().cloned(),
                                [E::F::one()]
                            )
                            .collect_vec();
                            (trade_price, values)
                        }
                        Side::Sell => {
                            let trade_price =
                                array::from_fn(|i| op.initial_state.best_buy_price[i].clone());
                            let values = chain!(
                                price.iter().cloned(),
                                trade_price.iter().cloned(),
                                [E::F::one()]
                            )
                            .collect_vec();
                            (trade_price, values)
                        }
                    };

                eval.add_to_relation(RelationEntry::new(
                    &self.less_than_elements,
                    mult.clone(),
                    &less_than_values,
                ));

                let values = chain!(trade_price.into_iter(), filled_volume.clone().into_iter())
                    .collect_vec();
                eval.add_to_relation(RelationEntry::new(
                    &self.match_elements,
                    -mult.clone(),
                    &values,
                ));
            }
            MatchType::Passive => {
                // opcode must be equal to the instruction's opcode
                eval.add_constraint(
                    op.opcode.clone() - E::F::from(S::op_code(IMTOperation::PartialMatchPassive)),
                );

                eval.add_constraint(
                    (op.initial_state.op_code.clone()
                        - E::F::from(S::complement_op_code(IMTOperation::MatchAggressive)))
                        * (op.initial_state.op_code.clone()
                            - E::F::from(S::complement_op_code(
                                IMTOperation::PartialMatchAggressive,
                            ))),
                );
                let price: [E::F; N_U64_FELTS] =
                    array::from_fn(|i| op.leaf[LeafColumn::PRICE + i].clone());
                let values =
                    chain!(price.into_iter(), filled_volume.clone().into_iter()).collect_vec();
                eval.add_to_relation(RelationEntry::new(
                    &self.match_elements,
                    mult.clone(),
                    &values,
                ));
            }
        }

        // remaining volume + filled volume must be equal to the initial volume
        let add_elements = chain!(
            filled_volume.iter().cloned(),
            remaining_volume.iter().cloned(),
            op.leaf[LeafColumn::VOLUME..LeafColumn::PRICE]
                .iter()
                .cloned()
        )
        .collect_vec();
        eval.add_to_relation(RelationEntry::new(
            &self.add_elements,
            mult.clone(),
            &add_elements,
        ));

        let mut low_leaf: [E::F; N_LEAF_FELTS] = array::from_fn(|_| E::F::zero());
        low_leaf[LeafColumn::ACTIVE] = E::F::one();
        let first_price_time_felts = first_price_time_felts::<E, S>();
        low_leaf[LeafColumn::LABEL..(2 * N_U64_FELTS + LeafColumn::LABEL)]
            .clone_from_slice(&first_price_time_felts[..(2 * N_U64_FELTS)]);
        low_leaf[LeafColumn::NEXT..(2 * N_U64_FELTS + LeafColumn::NEXT)]
            .clone_from_slice(&op.leaf[LeafColumn::LABEL..(2 * N_U64_FELTS + LeafColumn::LABEL)]);
        // low index must be 0
        for i in 0..MERKLE_HEIGHT {
            eval.add_constraint(op.low_index[i].clone());
        }

        // assert initial state root
        match S::side() {
            Side::Buy => {
                // initial state's buy root hash must be equal to the root hash of the merkle tree
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.initial_state.buy_root[i].clone()
                            - op.low_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }
            }
            Side::Sell => {
                // initial state's sell root hash must be equal to the root hash of the merkle tree
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.initial_state.sell_root[i].clone()
                            - op.low_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }
            }
        }

        // eval low leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.low_merkle_proof.clone(),
            op.low_merkle_path.clone(),
            low_leaf.clone(),
            op.low_index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );

        // the root hash from low leaf's merkle path must be equal the path of matched leaf
        for i in 0..N_HASH {
            eval.add_constraint(
                op.low_merkle_path[MERKLE_HEIGHT][i].clone()
                    - op.merkle_path[MERKLE_HEIGHT][i].clone(),
            );
        }
        // eval matched leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.merkle_proof.clone(),
            op.merkle_path.clone(),
            op.leaf.clone(),
            op.index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );

        // updates matched leaf active flag to 0
        let mut updated_leaf = op.leaf.clone();
        updated_leaf[LeafColumn::VOLUME..(N_U64_FELTS + LeafColumn::VOLUME)]
            .clone_from_slice(&remaining_volume[..N_U64_FELTS]);
        // eval updated leaf's merkle proof
        eval_merkle_proof(
            &mut eval,
            op.merkle_proof.clone(),
            op.updated_merkle_path.clone(),
            updated_leaf,
            op.index.clone(),
            &self.poseidon_elements,
            mult.clone(),
        );

        // ensure that the state count is updated correctly
        eval.add_constraint(op.final_state.n.clone() - op.initial_state.n.clone() - E::F::one());
        match S::side() {
            Side::Buy => {
                // final state's buy root hash must be equal to the root in the matched leaf's updated merkle path
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.final_state.buy_root[i].clone()
                            - op.updated_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }

                // the initial priority for sell IMT must be equal to the final priority
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        op.initial_state.best_sell_price[i].clone()
                            - op.final_state.best_sell_price[i].clone(),
                    );
                }

                // the final root hash for sell IMT must be equal to the initial root hash
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.final_state.sell_root[i].clone() - op.initial_state.sell_root[i].clone(),
                    );
                }

                // the final priority of the buy side remains the same.
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        op.final_state.best_buy_price[i].clone()
                            - op.initial_state.best_buy_price[i].clone(),
                    );
                }
            }
            Side::Sell => {
                // initial state's sell root hash must be equal to the root in the matched leaf's updated merkle path
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.final_state.sell_root[i].clone()
                            - op.updated_merkle_path[MERKLE_HEIGHT][i].clone(),
                    );
                }

                // the initial priority for buy IMT must be equal to the final priority
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        op.initial_state.best_buy_price[i].clone()
                            - op.final_state.best_buy_price[i].clone(),
                    );
                }

                // the final root hash for buy IMT must be equal to the initial root hash
                for i in 0..N_HASH {
                    eval.add_constraint(
                        op.final_state.buy_root[i].clone() - op.initial_state.buy_root[i].clone(),
                    );
                }

                // the final priority of the sell side remains the same.
                for i in 0..N_U64_FELTS {
                    eval.add_constraint(
                        op.final_state.best_sell_price[i].clone()
                            - op.initial_state.best_sell_price[i].clone(),
                    );
                }
            }
        }
        let values: Vec<E::F> = flatten!(
            op.initial_state.n,
            op.initial_state.buy_root,
            op.initial_state.best_buy_price,
            op.initial_state.sell_root,
            op.initial_state.best_sell_price,
            op.initial_state.op_code,
            op.opcode,
            op.low_merkle_proof,
            op.low_merkle_path,
            op.updated_low_merkle_path,
            op.low_index,
            op.low_leaf,
            op.merkle_proof,
            op.merkle_path,
            op.updated_merkle_path,
            op.index,
            op.leaf,
            op.final_state.n,
            op.final_state.buy_root,
            op.final_state.best_buy_price,
            op.final_state.sell_root,
            op.final_state.best_sell_price,
            op.final_state.op_code,
            op.is_real
        );
        // yield the results
        eval.add_to_relation(RelationEntry::new(
            &self.instruction_elements,
            -mult,
            &values,
        ));
        eval.finalize_logup();
        eval
    }
}
