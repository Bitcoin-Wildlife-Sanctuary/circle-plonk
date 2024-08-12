use crate::circuit::Circuit;
use itertools::{chain, Itertools};
use stwo_prover::constraint_framework::logup::LookupElements;
use stwo_prover::core::backend::simd::column::BaseColumn;
use stwo_prover::core::backend::simd::m31::LOG_N_LANES;
use stwo_prover::core::backend::simd::SimdBackend;
use stwo_prover::core::channel::{BWSSha256Channel, Channel};
use stwo_prover::core::fields::m31::{BaseField, M31};
use stwo_prover::core::fields::IntoSlice;
use stwo_prover::core::pcs::CommitmentSchemeProver;
use stwo_prover::core::poly::circle::{CanonicCoset, CircleEvaluation, PolyOps};
use stwo_prover::core::poly::BitReversedOrder;
use stwo_prover::core::prover::{prove, StarkProof, LOG_BLOWUP_FACTOR};
use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hasher;
use stwo_prover::core::vcs::bws_sha256_merkle::BWSSha256MerkleHasher;
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

pub fn prove_plonk(
    circuit: PlonkCircuitTrace,
) -> (PlonkComponent, StarkProof<BWSSha256MerkleHasher>) {
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
    let channel = &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[])));
    let commitment_scheme = &mut CommitmentSchemeProver::new(LOG_BLOWUP_FACTOR, &twiddles);

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
        chain!([circuit.a_wire, circuit.b_wire, circuit.c_wire, circuit.op]
            .into_iter()
            .map(|col| {
                CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(
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

    let proof = prove::<SimdBackend, _, _>(
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
    use super::prove_plonk;
    use crate::circuit::Mode;
    use crate::from_r1cs::r1cs_constraint_processor::generate_circuit;
    use crate::from_r1cs::TestCircuit;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;
    use stwo_prover::constraint_framework::logup::LookupElements;
    use stwo_prover::core::channel::{BWSSha256Channel, Channel};
    use stwo_prover::core::fields::m31::BaseField;
    use stwo_prover::core::fields::IntoSlice;
    use stwo_prover::core::pcs::{CommitmentSchemeVerifier, TreeVec};
    use stwo_prover::core::prover::{verify, LOG_BLOWUP_FACTOR};
    use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hasher;
    use stwo_prover::core::InteractionElements;
    use stwo_prover::examples::plonk::PlonkCircuitTrace;

    // test instruction:
    // RUSTFLAGS="-C target-cpu=native" RUST_LOG_SPAN_EVENTS="enter,close" RUST_LOG="none,circle_plonk=info,stwo_prover=info" cargo test test_simd_plonk_prove --no-default-features --release -- --nocapture
    #[test_log::test]
    fn test_simd_plonk_prove() {
        assert_ne!(
            LOG_BLOWUP_FACTOR, 1,
            "For some unknown reason, blowup factor 2^1 doesn't work"
        );

        let mut prng = rand_chacha::ChaCha20Rng::seed_from_u64(0);
        let test_circuit = TestCircuit::rand(&mut prng);
        let mut circuit = generate_circuit(test_circuit.clone(), Mode::PROVE).unwrap();
        circuit.pad_to_next_power_of_2();

        let trace: PlonkCircuitTrace = PlonkCircuitTrace::from(&circuit);

        // Get from environment variable:
        let log_n_instances = trace.a_wire.length.ilog2();

        // Prove.
        let (component, proof) = prove_plonk(trace);

        // Verify.
        // TODO: Create Air instance independently.
        let channel = &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[])));
        let commitment_scheme = &mut CommitmentSchemeVerifier::new();

        // Decommit.
        // Retrieve the expected column sizes in each commitment interaction, from the AIR.
        let max_degree = log_n_instances + 1;

        let sizes = TreeVec::new(vec![
            vec![max_degree; 4],
            vec![max_degree; 8],
            vec![max_degree; 4],
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
