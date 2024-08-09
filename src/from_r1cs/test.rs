use crate::circuit::Mode;
use crate::field::FM31;
use crate::from_r1cs::r1cs_constraint_processor::generate_circuit;
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
};
use ark_std::rand::{Rng, SeedableRng};
use ark_std::UniformRand;

#[derive(Clone)]
pub struct TestCircuit {
    pub a: ark_bn254::Fr,
    pub b: ark_bn254::Fr,
}

impl UniformRand for TestCircuit {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let a = ark_bn254::Fr::rand(rng);
        let b = ark_bn254::Fr::rand(rng);

        Self { a, b }
    }
}

impl ConstraintSynthesizer<FM31> for TestCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<FM31>,
    ) -> ark_relations::r1cs::Result<()> {
        let a_var = EmulatedFpVar::<ark_bn254::Fr, FM31>::new_input(cs.clone(), || Ok(self.a))?;

        let b_var = EmulatedFpVar::<ark_bn254::Fr, FM31>::new_witness(cs.clone(), || Ok(self.b))?;

        let c_var = EmulatedFpVar::<ark_bn254::Fr, FM31>::new_witness(cs, || Ok(self.a * self.b))?;

        let mul_res = a_var * b_var;
        mul_res.enforce_equal(&c_var)?;

        Ok(())
    }
}

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
        assert!(circuit.is_satisfied());
        assert_eq!(circuit.num_gates, 29266);
    }

    let circuit = generate_circuit(test_circuit, Mode::INDEX).unwrap();
    assert_eq!(circuit.num_gates, 29266);
}
