use circle_plonk_lib::circuit::Mode;
use circle_plonk_lib::from_r1cs::circom::{load_r1cs_and_witness, load_r1cs_only};
use circle_plonk_lib::from_r1cs::r1cs_constraint_processor::generate_circuit;
use circle_plonk_lib::stwo::{prove_plonk, PlonkVerifierParams};
use clap::{Parser, Subcommand};
use num_traits::Zero;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::Write;
use stwo_prover::constraint_framework::logup::LookupElements;
use stwo_prover::core::channel::Sha256Channel;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;
use stwo_prover::core::fri::FriConfig;
use stwo_prover::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo_prover::core::prover::{verify, StarkProof};
use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
use stwo_prover::core::InteractionElements;
use stwo_prover::examples::plonk::{PlonkCircuitTrace, PlonkComponent};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Preprocess the circuit
    Preprocess {
        /// Path to the R1CS file
        #[arg(short, long)]
        r1cs: String,

        /// Path to the preprocessed parameters file
        #[arg(short, long)]
        out_vk: String,
    },

    /// Generate a proof
    Prove {
        /// Path to the R1CS file
        #[arg(short, long)]
        r1cs: String,

        /// Path to the witness file
        #[arg(short, long)]
        witness: String,

        /// Path to the output proof file
        #[arg(short, long)]
        out_proof: String,
    },

    /// Verify a proof
    Verify {
        /// Path to the preprocessed parameters file
        #[arg(short, long)]
        vk: String,

        /// Path to the proof file
        #[arg(short, long)]
        proof: String,

        /// Path to the input mapping
        #[arg(short, long)]
        map: String,

        /// Path to the public input
        #[arg(short, long)]
        input: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let config = PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(0, 4, 64),
    };

    match cli.command {
        Commands::Preprocess { r1cs, out_vk } => {
            let r1cs_data = File::open(r1cs).unwrap();
            let circom_circuit = load_r1cs_only(r1cs_data).unwrap();
            let mut circuit = generate_circuit(circom_circuit.clone(), Mode::INDEX).unwrap();
            circuit.pad_to_next_power_of_2();
            let vk = PlonkVerifierParams::<Sha256MerkleChannel>::preprocess(config, &circuit);

            let mut out_vk = File::create(out_vk).unwrap();
            out_vk.write(&bincode::serialize(&vk).unwrap()).unwrap();
        }
        Commands::Prove {
            r1cs,
            witness,
            out_proof,
        } => {
            let r1cs_data = File::open(r1cs).unwrap();
            let witness_data = File::open(witness).unwrap();

            let circom_circuit = load_r1cs_and_witness(r1cs_data, witness_data).unwrap();
            let mut circuit = generate_circuit(circom_circuit.clone(), Mode::PROVE).unwrap();
            circuit.pad_to_next_power_of_2();

            assert!(circuit.is_constraint_satisfied());

            let trace: PlonkCircuitTrace = PlonkCircuitTrace::from(&circuit);
            let (_, proof) = prove_plonk::<Sha256MerkleChannel>(config, trace);

            let mut out_proof = File::create(out_proof).unwrap();
            out_proof
                .write(&bincode::serialize(&proof).unwrap())
                .unwrap();
        }
        Commands::Verify {
            vk,
            proof,
            map,
            input,
        } => {
            let vk_data = File::open(vk).unwrap();
            let vk: PlonkVerifierParams<Sha256MerkleChannel> =
                bincode::deserialize_from(vk_data).unwrap();

            let proof_data = File::open(proof).unwrap();
            let proof: StarkProof<Sha256MerkleHasher> =
                bincode::deserialize_from(proof_data).unwrap();

            let channel = &mut Sha256Channel::default();
            let commitment_scheme =
                &mut CommitmentSchemeVerifier::<Sha256MerkleChannel>::new(config);

            let max_degree = vk.log_n_rows + 1;
            let sizes = TreeVec::new(vec![
                vec![max_degree; 3],
                vec![max_degree; 8],
                vec![max_degree; 5],
            ]);

            commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
            let lookup_elements = LookupElements::<2>::draw(channel);
            commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
            commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);
            assert_eq!(vk.constant_tree_hash, proof.commitments[2]);

            let map_data = File::open(map).unwrap();

            #[derive(Deserialize, Debug)]
            struct InputMap(Vec<(String, usize, usize)>);
            let map: InputMap = bincode::deserialize_from(map_data).unwrap();

            let total_input = map.0.iter().map(|(_, _, n)| n).sum::<usize>();
            let mut input_vec = vec![0u32; total_input];

            let input_data = File::open(input).unwrap();
            let input: Value = serde_json::from_reader(input_data).unwrap();

            for (k, start, len) in map.0.iter() {
                assert!(input.get(&k).is_some());
                let entries = input.get(&k).unwrap();
                if *len == 1 {
                    if entries.is_array() {
                        input_vec[*start - 1] =
                            (entries[0].as_u64().unwrap() % ((1 << 31) - 1)) as u32;
                    } else if entries.is_u64() {
                        input_vec[*start - 1] =
                            (entries.as_u64().unwrap() % ((1 << 31) - 1)) as u32;
                    } else {
                        unimplemented!()
                    }
                } else {
                    assert!(entries.is_array());
                    assert_eq!(entries.as_array().unwrap().len(), *len);

                    let arr = entries.as_array().unwrap();
                    for i in 0..*len {
                        input_vec[*start - 1 + i] =
                            (arr[i].as_u64().unwrap() % ((1 << 31) - 1)) as u32;
                    }
                }
            }

            let claimed_sum = {
                let mut denominators =
                    vec![M31::from(1) + lookup_elements.alpha - lookup_elements.z];
                for (i, v) in input_vec.iter().enumerate() {
                    denominators.push(
                        M31::from(i + 2) + lookup_elements.alpha * M31::from(*v)
                            - lookup_elements.z,
                    );
                }

                let mut denominator_inverses = vec![QM31::zero(); denominators.len()];
                QM31::batch_inverse(&denominators, &mut denominator_inverses);
                denominator_inverses.iter().sum::<QM31>()
            };

            let component = PlonkComponent {
                log_n_rows: vk.log_n_rows,
                lookup_elements,
                claimed_sum,
            };

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
}
