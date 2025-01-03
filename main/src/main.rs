use circle_plonk_lib::circuit::Mode;
use circle_plonk_lib::from_r1cs::circom::{load_r1cs_and_witness, load_r1cs_only};
use circle_plonk_lib::from_r1cs::r1cs_constraint_processor::generate_circuit;
use circle_plonk_lib::stwo::{prove_plonk, PlonkVerifierParams};
use clap::{Parser, Subcommand, ValueEnum};
use num_traits::Zero;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::Write;
use stwo_prover::constraint_framework::logup::LookupElements;
use stwo_prover::core::channel::MerkleChannel;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;
use stwo_prover::core::fri::FriConfig;
use stwo_prover::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo_prover::core::prover::{verify, StarkProof};
use stwo_prover::core::vcs::blake3_merkle::Blake3MerkleChannel;
use stwo_prover::core::vcs::poseidon31_merkle::Poseidon31MerkleChannel;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleChannel;
use stwo_prover::core::InteractionElements;
use stwo_prover::examples::plonk::{PlonkCircuitTrace, PlonkComponent};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show information about the circuit
    Info {
        /// Path to the R1CS file
        #[arg(short, long)]
        r1cs: String,
    },

    /// Preprocess the circuit
    Preprocess {
        /// Path to the R1CS file
        #[arg(short, long)]
        r1cs: String,

        /// Path to the preprocessed parameters file
        #[arg(short, long)]
        out_vk: String,

        #[arg(long)]
        #[clap(value_enum, default_value = "sha256")]
        hash: Hash,
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

        #[arg(long)]
        #[clap(value_enum, default_value = "sha256")]
        hash: Hash,
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

        #[arg(long)]
        #[clap(value_enum, default_value = "sha256")]
        hash: Hash,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Hash {
    /// Blake3
    BLAKE3,
    /// SHA256
    SHA256,
    /// Poseidon31
    POSEIDON31,
}

fn main() {
    let cli = Cli::parse();

    let config = PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(0, 5, 16),
    };

    match cli.command {
        Commands::Info { r1cs } => {
            let r1cs_data = File::open(r1cs).unwrap();
            let circom_circuit = load_r1cs_only(r1cs_data).unwrap();
            println!(
                "R1CS constraints: {}",
                circom_circuit.r1cs.constraints.len()
            );
            let mut circuit = generate_circuit(circom_circuit.clone(), Mode::INDEX).unwrap();
            println!("Circle-Plonk constraints: {}", circuit.num_rows);
            circuit.pad_to_next_power_of_2();
        }
        Commands::Preprocess { r1cs, out_vk, hash } => {
            let r1cs_data = File::open(r1cs).unwrap();
            let circom_circuit = load_r1cs_only(r1cs_data).unwrap();
            let mut circuit = generate_circuit(circom_circuit.clone(), Mode::INDEX).unwrap();
            circuit.pad_to_next_power_of_2();

            let mut out_vk = File::create(out_vk).unwrap();

            match hash {
                Hash::BLAKE3 => {
                    let vk =
                        PlonkVerifierParams::<Blake3MerkleChannel>::preprocess(config, &circuit);
                    out_vk.write(&bincode::serialize(&vk).unwrap()).unwrap();
                }
                Hash::SHA256 => {
                    let vk =
                        PlonkVerifierParams::<Sha256MerkleChannel>::preprocess(config, &circuit);
                    out_vk.write(&bincode::serialize(&vk).unwrap()).unwrap();
                }
                Hash::POSEIDON31 => {
                    let vk = PlonkVerifierParams::<Poseidon31MerkleChannel>::preprocess(
                        config, &circuit,
                    );
                    out_vk.write(&bincode::serialize(&vk).unwrap()).unwrap();
                }
            }
        }
        Commands::Prove {
            r1cs,
            witness,
            out_proof,
            hash,
        } => {
            let r1cs_data = File::open(r1cs).unwrap();
            let witness_data = File::open(witness).unwrap();

            let circom_circuit = load_r1cs_and_witness(r1cs_data, witness_data).unwrap();
            let mut circuit = generate_circuit(circom_circuit.clone(), Mode::PROVE).unwrap();
            assert!(circuit.is_constraint_satisfied());

            let mut prng = ChaCha20Rng::seed_from_u64(0);
            assert!(circuit.is_logup_satisfied(&mut prng, &circuit.input_maps));

            circuit.pad_to_next_power_of_2();

            let trace: PlonkCircuitTrace = PlonkCircuitTrace::from(&circuit);
            let mut out_proof = File::create(out_proof).unwrap();

            match hash {
                Hash::BLAKE3 => {
                    let (_, proof) = prove_plonk::<Blake3MerkleChannel>(config, trace);
                    out_proof
                        .write(&bincode::serialize(&proof).unwrap())
                        .unwrap();
                }
                Hash::SHA256 => {
                    let (_, proof) = prove_plonk::<Sha256MerkleChannel>(config, trace);
                    out_proof
                        .write(&bincode::serialize(&proof).unwrap())
                        .unwrap();
                }
                Hash::POSEIDON31 => {
                    let (_, proof) = prove_plonk::<Poseidon31MerkleChannel>(config, trace);
                    out_proof
                        .write(&bincode::serialize(&proof).unwrap())
                        .unwrap();
                }
            }
        }
        Commands::Verify {
            vk,
            proof,
            map,
            input,
            hash,
        } => {
            let vk_data = File::open(vk).unwrap();
            let proof_data = File::open(proof).unwrap();
            let map_data = File::open(map).unwrap();

            match hash {
                Hash::BLAKE3 => {
                    verify_proof::<Blake3MerkleChannel>(config, &vk_data, &proof_data, &map_data, &input)
                }
                Hash::SHA256 => {
                    verify_proof::<Sha256MerkleChannel>(config, &vk_data, &proof_data, &map_data, &input)
                }
                Hash::POSEIDON31 => {
                    verify_proof::<Poseidon31MerkleChannel>(config, &vk_data, &proof_data, &map_data, &input)
                }
            }
        }
    }
}

fn verify_proof<MC: MerkleChannel>(
    config: PcsConfig,
    vk_data: &File,
    proof_data: &File,
    map_data: &File,
    input: &String,
)
where for<'a> <MC as MerkleChannel>::H : Deserialize<'a>
{
    let vk: PlonkVerifierParams<MC> =
        bincode::deserialize_from(vk_data).unwrap();
    let max_degree = vk.log_n_rows + 1;

    #[derive(Deserialize, Debug)]
    struct InputMap(Vec<(String, usize, usize)>);
    let map: InputMap = bincode::deserialize_from(map_data).unwrap();

    let mut input_vec = vec![0u32; vk.num_inputs - 1];

    let input_data = File::open(input).unwrap();
    let input: Value = serde_json::from_reader(input_data).unwrap();

    for (k, start, len) in map.0.iter() {
        if *start < vk.num_inputs {
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
    }

    let sizes = TreeVec::new(vec![
        vec![max_degree; 3],
        vec![max_degree; 8],
        vec![max_degree; 5],
    ]);
    let channel = &mut MC::C::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<MC>::new(config);
    let proof: StarkProof<MC::H> =
        bincode::deserialize_from(proof_data).unwrap();
    commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
    let lookup_elements = LookupElements::<2>::draw(channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
    commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);
    assert_eq!(vk.constant_tree_hash, proof.commitments[2]);

    let claimed_sum = {
        let mut denominators =
            vec![M31::from(1) + lookup_elements.alpha - lookup_elements.z];
        for (i, v) in input_vec.iter().take(vk.num_inputs).enumerate() {
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