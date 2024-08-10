use crate::field::FM31;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_std::rand::Rng;
use ark_std::UniformRand;

pub mod r1cs_constraint_processor;

pub mod circom;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub(crate) struct TestCircuit {
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
