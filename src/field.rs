use ark_ff::{Fp64, MontBackend, MontConfig, PrimeField};
use stwo_prover::core::fields::m31::M31;

#[derive(MontConfig)]
#[modulus = "2147483647"]
#[generator = "7"]
pub struct FM31Config;
pub type FM31 = Fp64<MontBackend<FM31Config, 1>>;

pub const FM31_ONE: FM31 = ark_ff::MontFp!("1");
pub const FM31_ZERO: FM31 = ark_ff::MontFp!("0");

pub fn to_m31(v: &FM31) -> M31 {
    M31::reduce(v.into_bigint().0[0])
}

#[cfg(test)]
mod test {
    use super::FM31;
    use ark_algebra_test_templates::*;

    test_field!(fm31; FM31; mont_prime_field);
}
