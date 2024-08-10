use crate::circuit::Mode;
use crate::from_r1cs::r1cs_constraint_processor::generate_circuit;
use crate::from_r1cs::TestCircuit;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;

#[test]
fn test_groth16_weight() {
    let mut prng = rand_chacha::ChaCha20Rng::seed_from_u64(0);

    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Weight);

    let test_circuit = TestCircuit::rand(&mut prng);
    test_circuit.generate_constraints(cs.clone()).unwrap();

    assert_eq!(cs.num_instance_variables(), 33);
    assert_eq!(cs.num_witness_variables(), 3723);
    assert_eq!(cs.num_constraints(), 3802);

    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_groth16_constraints() {
    let mut prng = rand_chacha::ChaCha20Rng::seed_from_u64(0);

    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);

    let test_circuit = TestCircuit::rand(&mut prng);
    test_circuit.generate_constraints(cs.clone()).unwrap();

    assert_eq!(cs.num_instance_variables(), 65);
    assert_eq!(cs.num_witness_variables(), 2029);
    assert_eq!(cs.num_constraints(), 2074);

    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_conversion() {
    let mut prng = rand_chacha::ChaCha20Rng::seed_from_u64(0);
    let test_circuit = TestCircuit::rand(&mut prng);

    for _ in 0..10 {
        let circuit = generate_circuit(test_circuit.clone(), Mode::PROVE).unwrap();
        assert!(circuit.is_constraint_satisfied());
        assert!(circuit.is_logup_satisfied(&mut prng, &circuit.input_maps));
        assert_eq!(circuit.num_rows, 29265);
    }

    let circuit = generate_circuit(test_circuit, Mode::INDEX).unwrap();
    assert_eq!(circuit.num_rows, 29265);
}
