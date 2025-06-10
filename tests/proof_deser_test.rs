// #![cfg(test)]

// // --- Prover Imports (needed for proof generation) ---
// use itertools::Itertools;
// use num_traits::{One as ProverOne, Zero as ProverZero};
// use stwo_prover::constraint_framework::{
//     EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
// };
// use stwo_prover::core::backend::simd::m31::LOG_N_LANES;
// use stwo_prover::core::backend::simd::SimdBackend;
// use stwo_prover::core::backend::{Col, Column};
// use stwo_prover::core::channel::Blake2sChannel as ProverChannel;
// use stwo_prover::core::fields::m31::BaseField as ProverBaseField;
// use stwo_prover::core::fields::qm31::SecureField as ProverSecureField;
// use stwo_prover::core::fields::FieldExpOps as ProverFieldExpOps;
// use stwo_prover::core::pcs::{CommitmentSchemeProver, PcsConfig as ProverPcsConfig};
// use stwo_prover::core::poly::circle::{CanonicCoset, CircleEvaluation, PolyOps};
// use stwo_prover::core::poly::BitReversedOrder;
// use stwo_prover::core::prover::prove;
// use stwo_prover::core::prover::StarkProof as ProverStarkProof;
// use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleChannel as ProverMerkleChannel;
// use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleHasher as ProverBlake2sHasher;
// use stwo_prover::core::ColumnVec;
// // --- End Prover Imports ---

// // --- Verifier Imports ---
// use stwo_verifier_no_std::backend::Blake2sMerkleHasher;
// use stwo_verifier_no_std::channel::MerkleHasher;
// use stwo_verifier_no_std::types::fri::FriProof;
// use stwo_verifier_no_std::types::pcs::PcsConfig;
// // --- End Verifier Imports ---

// use alloc::vec::Vec;
// use serde_json;
// use stwo_verifier_no_std::types::MerkleDecommitment;

// // --- Test Component Definitions (copied/adapted from integration_test.rs) ---
// const FIB_SEQUENCE_LENGTH: usize = 10; // Smaller for faster testing

// #[derive(Clone)]
// pub struct TestFibInput {
//     a: stwo_prover::core::backend::simd::m31::PackedBaseField,
//     b: stwo_prover::core::backend::simd::m31::PackedBaseField,
// }

// #[derive(Clone)]
// pub struct TestWideFibonacciEval {
//     pub log_n_rows: u32,
// }
// impl FrameworkEval for TestWideFibonacciEval {
//     fn log_size(&self) -> u32 {
//         self.log_n_rows
//     }
//     fn max_constraint_log_degree_bound(&self) -> u32 {
//         self.log_n_rows + 1
//     }
//     fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
//         let mut a = eval.next_trace_mask();
//         let mut b = eval.next_trace_mask();
//         for _ in 2..FIB_SEQUENCE_LENGTH {
//             let c = eval.next_trace_mask();
//             eval.add_constraint(c.clone() - (a.square() + b.square()));
//             a = b;
//             b = c;
//         }
//         eval
//     }
// }
// type TestWideFibonacciComponent = FrameworkComponent<TestWideFibonacciEval>;

// fn generate_test_trace(
//     log_n_instances: u32,
// ) -> ColumnVec<CircleEvaluation<SimdBackend, ProverBaseField, BitReversedOrder>> {
//     let n_instances_per_packed = 1 << LOG_N_LANES;
//     let n_packed_fields = 1 << (log_n_instances - LOG_N_LANES);
//     let inputs = (0..n_packed_fields)
//         .map(|i| TestFibInput {
//             a: stwo_prover::core::backend::simd::m31::PackedBaseField::one(),
//             b: stwo_prover::core::backend::simd::m31::PackedBaseField::from_array(
//                 core::array::from_fn(|j| {
//                     ProverBaseField::from_u32_unchecked((i * n_instances_per_packed + j) as u32)
//                 }),
//             ),
//         })
//         .collect_vec();

//     let mut trace = (0..FIB_SEQUENCE_LENGTH)
//         .map(|_| Col::<SimdBackend, ProverBaseField>::zeros(1 << log_n_instances))
//         .collect_vec();

//     for (vec_index, input) in inputs.iter().enumerate() {
//         let mut a = input.a;
//         let mut b = input.b;
//         trace[0].data[vec_index] = a;
//         trace[1].data[vec_index] = b;
//         trace.iter_mut().skip(2).for_each(|col| {
//             let c = a.square() + b.square();
//             col.data[vec_index] = c;
//             a = b;
//             b = c;
//         });
//     }

//     let domain = CanonicCoset::new(log_n_instances).circle_domain();
//     trace
//         .into_iter()
//         .map(|eval| CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(domain, eval))
//         .collect_vec()
// }

// // --- Helper to generate prover proof OBJECT ---
// fn generate_prover_proof() -> ProverStarkProof<ProverBlake2sHasher> {
//     let log_n_instances = LOG_N_LANES + 1; // Example size
//     let prover_config = ProverPcsConfig::default();
//     let twiddles = SimdBackend::precompute_twiddles(
//         CanonicCoset::new(log_n_instances + 1 + prover_config.fri_config.log_blowup_factor)
//             .circle_domain()
//             .half_coset,
//     );

//     let prover_channel = &mut ProverChannel::default();
//     let mut commitment_scheme = CommitmentSchemeProver::<SimdBackend, ProverMerkleChannel>::new(
//         prover_config.clone(),
//         &twiddles,
//     );

//     // Preprocessed trace (empty)
//     let mut tree_builder = commitment_scheme.tree_builder();
//     tree_builder.extend_evals([]);
//     tree_builder.commit(prover_channel);

//     // Trace.
//     let trace = generate_test_trace(log_n_instances);
//     let mut tree_builder = commitment_scheme.tree_builder();
//     tree_builder.extend_evals(trace);
//     tree_builder.commit(prover_channel);

//     // Component
//     let component = TestWideFibonacciComponent::new(
//         &mut TraceLocationAllocator::default(),
//         TestWideFibonacciEval {
//             log_n_rows: log_n_instances,
//         },
//         ProverSecureField::zero(),
//     );

//     // Prove
//     prove::<SimdBackend, ProverMerkleChannel>(&[&component], prover_channel, commitment_scheme)
//         .expect("Proving failed")
// }

// #[test]
// fn test_config_deser() {
//     let proof = generate_prover_proof();
//     let config_ser = serde_json::to_string(&proof.0.config).unwrap();

//     let config_deser: PcsConfig = serde_json::from_str(&config_ser).unwrap();

//     // check pow_bits equality
//     assert_eq!(proof.0.config.pow_bits, config_deser.pow_bits);

//     // check fri_config equality
//     assert_eq!(
//         proof.0.config.fri_config.log_blowup_factor,
//         config_deser.fri_config.log_blowup_factor
//     );
//     assert_eq!(
//         proof.0.config.fri_config.log_last_layer_degree_bound,
//         config_deser.fri_config.log_last_layer_degree_bound
//     );
//     assert_eq!(
//         proof.0.config.fri_config.n_queries,
//         config_deser.fri_config.n_queries
//     );
// }

// #[test]
// fn test_commitments_deser() {
//     let proof = generate_prover_proof();
//     let commitments_ser = serde_json::to_string(&proof.0.commitments).unwrap();
//     let commitments_deser: Vec<<Blake2sMerkleHasher as MerkleHasher>::Hash> =
//         serde_json::from_str(&commitments_ser).unwrap();

//     // check individual hashes in commitments_deser
//     for (i, hash) in proof.0.commitments.iter().enumerate() {
//         assert_eq!(hash.0, commitments_deser[i].0);
//     }
// }

// #[test]
// fn test_sampled_values_deser() {
//     let proof = generate_prover_proof();
//     let sampled_values_ser = serde_json::to_string(&proof.0.sampled_values).unwrap();
//     let _sampled_values_deser: Vec<Vec<Vec<ProverSecureField>>> =
//         serde_json::from_str(&sampled_values_ser).unwrap();
// }

// #[test]
// fn test_decommitments_deser() {
//     let proof = generate_prover_proof();
//     let decommitments_ser = serde_json::to_string(&proof.0.decommitments).unwrap();
//     let _decommitments_deser: Vec<MerkleDecommitment<Blake2sMerkleHasher>> =
//         serde_json::from_str(&decommitments_ser).unwrap();
// }

// #[test]
// fn test_queried_values_deser() {
//     let proof = generate_prover_proof();
//     let queried_values_ser = serde_json::to_string(&proof.0.queried_values).unwrap();
//     let _queried_values_deser: Vec<Vec<ProverBaseField>> =
//         serde_json::from_str(&queried_values_ser).unwrap();
// }

// #[test]
// fn test_fri_proof_deser() {
//     let proof = generate_prover_proof();
//     let fri_proof_ser = serde_json::to_string(&proof.0.fri_proof).unwrap();
//     let _fri_proof_deser: FriProof<Blake2sMerkleHasher> =
//         serde_json::from_str(&fri_proof_ser).unwrap();
// }
