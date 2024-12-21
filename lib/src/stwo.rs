use crate::circuit::Circuit;
use itertools::{chain, Itertools};
use serde::{Deserialize, Serialize};
use stwo_prover::constraint_framework::logup::LookupElements;
use stwo_prover::core::backend::simd::column::BaseColumn;
use stwo_prover::core::backend::simd::m31::LOG_N_LANES;
use stwo_prover::core::backend::simd::SimdBackend;
use stwo_prover::core::backend::BackendForChannel;
use stwo_prover::core::channel::MerkleChannel;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::pcs::{CommitmentSchemeProver, PcsConfig};
use stwo_prover::core::poly::circle::{CanonicCoset, CircleEvaluation, PolyOps};
use stwo_prover::core::poly::BitReversedOrder;
use stwo_prover::core::prover::{prove, StarkProof, LOG_BLOWUP_FACTOR};
use stwo_prover::core::vcs::ops::MerkleHasher;
use stwo_prover::core::InteractionElements;
use stwo_prover::examples::plonk::{
    gen_interaction_trace, gen_trace, PlonkCircuitTrace, PlonkComponent,
};
use tracing::{span, Level};

impl From<&Circuit> for PlonkCircuitTrace {
    fn from(circuit: &Circuit) -> Self {
        assert!(circuit.num_rows.is_power_of_two());
        let log_n_rows = circuit.num_rows.ilog2();

        let mult = BaseColumn::from_iter(circuit.mult.iter().map(|&x| M31::from(x)));
        let a_wire = BaseColumn::from_iter(circuit.idx_a.iter().map(|&x| M31::from(x)));
        let b_wire = BaseColumn::from_iter(circuit.idx_b.iter().map(|&x| M31::from(x)));
        let c_wire = (0..(1 << log_n_rows)).clone().map(|i| i.into()).collect();
        let op = BaseColumn::from_iter(circuit.op.iter().copied());
        let a_val = BaseColumn::from_iter(circuit.idx_a.iter().map(|&i| circuit.output_wires[i]));
        let b_val = BaseColumn::from_iter(circuit.idx_b.iter().map(|&i| circuit.output_wires[i]));
        let c_val = BaseColumn::from_iter(circuit.output_wires.iter().copied());

        PlonkCircuitTrace {
            mult,
            a_wire,
            b_wire,
            c_wire,
            op,
            a_val,
            b_val,
            c_val,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PlonkVerifierParams<MC: MerkleChannel> {
    pub log_n_rows: u32,
    pub constant_tree_hash: <MC::H as MerkleHasher>::Hash,
}

impl<MC: MerkleChannel> PlonkVerifierParams<MC> {
    pub fn preprocess(config: PcsConfig, circuit: &Circuit) -> Self
    where
        SimdBackend: BackendForChannel<MC>,
    {
        assert!(circuit.num_rows.is_power_of_two());
        let log_n_rows = circuit.num_rows.ilog2();
        assert!(log_n_rows >= LOG_N_LANES);

        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_n_rows + LOG_BLOWUP_FACTOR + 1)
                .circle_domain()
                .half_coset,
        );

        let mult = BaseColumn::from_iter(circuit.mult.iter().map(|&x| M31::from(x)));
        let a_wire = BaseColumn::from_iter(circuit.idx_a.iter().map(|&x| M31::from(x)));
        let b_wire = BaseColumn::from_iter(circuit.idx_b.iter().map(|&x| M31::from(x)));
        let c_wire = (0..(1 << log_n_rows)).clone().map(|i| i.into()).collect();
        let op = BaseColumn::from_iter(circuit.op.iter().copied());

        let dummy_channel = &mut MC::C::default();
        let max_degree = log_n_rows + 1;

        let commitment_scheme =
            &mut CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(
            chain!([mult, a_wire, b_wire, c_wire, op].into_iter().map(|col| {
                CircleEvaluation::<SimdBackend, M31, BitReversedOrder>::new(
                    CanonicCoset::new(log_n_rows).circle_domain(),
                    col,
                )
            }))
            .collect_vec(),
            max_degree,
        );
        tree_builder.commit(dummy_channel);

        Self {
            log_n_rows,
            constant_tree_hash: commitment_scheme.trees.first().unwrap().commitment.root(),
        }
    }
}

pub fn prove_plonk<MC: MerkleChannel>(
    config: PcsConfig,
    circuit: PlonkCircuitTrace,
) -> (PlonkComponent, StarkProof<MC::H>)
where
    SimdBackend: BackendForChannel<MC>,
{
    assert!(circuit.a_wire.length.is_power_of_two());
    let log_n_rows = circuit.a_wire.length.ilog2();
    assert!(log_n_rows >= LOG_N_LANES);

    // Precompute twiddles.
    let span = span!(Level::INFO, "Precompute twiddles").entered();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_n_rows + LOG_BLOWUP_FACTOR + 1)
            .circle_domain()
            .half_coset,
    );
    span.exit();

    // Setup protocol.
    let channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeProver::new(config, &twiddles);

    // Trace.
    let span = span!(Level::INFO, "Trace").entered();
    let trace = gen_trace(log_n_rows, &circuit);
    let max_degree = log_n_rows + 1;
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace, max_degree);
    tree_builder.commit(channel);
    span.exit();

    // Draw lookup element.
    let lookup_elements = LookupElements::draw(channel);

    // Interaction trace.
    let span = span!(Level::INFO, "Interaction").entered();
    let (trace, claimed_sum) = gen_interaction_trace(log_n_rows, &circuit, &lookup_elements);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace, max_degree);
    tree_builder.commit(channel);
    span.exit();

    // Constant trace.
    let span = span!(Level::INFO, "Constant").entered();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain!([
            circuit.mult,
            circuit.a_wire,
            circuit.b_wire,
            circuit.c_wire,
            circuit.op
        ]
        .into_iter()
        .map(|col| {
            CircleEvaluation::<SimdBackend, M31, BitReversedOrder>::new(
                CanonicCoset::new(log_n_rows).circle_domain(),
                col,
            )
        }))
        .collect_vec(),
        max_degree,
    );
    tree_builder.commit(channel);
    span.exit();

    // Prove constraints.
    let component = PlonkComponent {
        log_n_rows,
        lookup_elements,
        claimed_sum,
    };

    let proof = prove::<SimdBackend, MC>(
        &[&component],
        channel,
        &InteractionElements::default(),
        commitment_scheme,
    )
    .unwrap();

    (component, proof)
}

#[cfg(test)]
mod tests {
    use super::{prove_plonk, PlonkVerifierParams};
    use crate::circuit::Mode;
    use crate::from_r1cs::circom::load_r1cs_and_witness;
    use crate::from_r1cs::r1cs_constraint_processor::generate_circuit;
    use ark_std::rand::SeedableRng;
    use std::io::Cursor;
    use stwo_prover::constraint_framework::logup::LookupElements;
    use stwo_prover::core::channel::Sha256Channel;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
    use stwo_prover::core::prover::{verify, LOG_BLOWUP_FACTOR};
    use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleChannel;
    use stwo_prover::core::InteractionElements;
    use stwo_prover::examples::plonk::PlonkCircuitTrace;

    // test instruction:
    // RUSTFLAGS="-C target-cpu=native" RUST_LOG_SPAN_EVENTS="enter,close" RUST_LOG="none,circle_plonk=info,stwo_prover=info" cargo test test_simd_plonk_prove --no-default-features --release -- --nocapture
    #[test_log::test]
    fn test_simd_plonk_prove() {
        let r1cs = include_bytes!("test.r1cs");
        let witness = include_bytes!("output.wtns");

        let circom_circuit =
            load_r1cs_and_witness(Cursor::new(r1cs), Cursor::new(witness)).unwrap();

        let mut circuit = generate_circuit(circom_circuit.clone(), Mode::PROVE).unwrap();
        assert!(circuit.is_constraint_satisfied());
        assert_eq!(circuit.num_rows, 6332);

        let mut prng = rand_chacha::ChaCha20Rng::seed_from_u64(0);
        assert!(circuit.is_logup_satisfied(&mut prng, &circuit.input_maps));

        circuit.pad_to_next_power_of_2();

        assert_ne!(
            LOG_BLOWUP_FACTOR, 1,
            "For some unknown reason, blowup factor 2^1 doesn't work"
        );
        let config = PcsConfig {
            pow_bits: 10,
            fri_config: FriConfig::new(0, 4, 64),
        };

        let trace: PlonkCircuitTrace = PlonkCircuitTrace::from(&circuit);

        // Get from environment variable:
        let log_n_instances = trace.a_wire.length.ilog2();

        // Prove.
        let (component, proof) = prove_plonk::<Sha256MerkleChannel>(config, trace);

        // Verify.
        // TODO: Create Air instance independently.
        let channel = &mut Sha256Channel::default();
        let commitment_scheme = &mut CommitmentSchemeVerifier::<Sha256MerkleChannel>::new(config);

        // Decommit.
        // Retrieve the expected column sizes in each commitment interaction, from the AIR.
        let max_degree = log_n_instances + 1;

        let sizes = TreeVec::new(vec![
            vec![max_degree; 3],
            vec![max_degree; 8],
            vec![max_degree; 5],
        ]);

        // Trace columns.
        commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
        // Draw lookup element.
        let lookup_elements = LookupElements::<2>::draw(channel);
        assert_eq!(lookup_elements, component.lookup_elements);
        // TODO(spapini): Check claimed sum against first and last instances.
        // Interaction columns.
        commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
        // Constant columns.
        commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);

        // Test computation of the constant commitment
        let expected_constant_commitment = {
            let vk = PlonkVerifierParams::<Sha256MerkleChannel>::preprocess(config, &circuit);
            vk.constant_tree_hash
        };
        assert_eq!(expected_constant_commitment, proof.commitments[2]);

        verify(
            &[&component],
            channel,
            &InteractionElements::default(),
            commitment_scheme,
            proof,
        )
        .unwrap();
    }
}
