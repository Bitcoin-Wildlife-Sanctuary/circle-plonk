use ark_ff::Zero;
use stwo_prover::core::fields::m31::M31;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Mode {
    INDEX,
    PROVE,
}

impl Default for Mode {
    fn default() -> Self {
        Self::INDEX
    }
}

#[derive(Default)]
pub struct Circuit {
    pub num_witness_elements: usize,
    pub constraints: Vec<Constraint>,
    pub mode: Mode,
    pub witness_values: Vec<M31>,
}

#[derive(Debug)]
pub struct Constraint {
    pub q_l: M31,
    pub q_r: M31,
    pub q_m: M31,
    pub q_o: M31,
    pub q_c: M31,

    pub w_l: usize,
    pub w_r: usize,
    pub w_o: usize,

    pub pi: M31,
}

impl Circuit {
    pub fn new() -> Circuit {
        Circuit::default()
    }

    pub fn new_variable(&mut self, value: M31) -> usize {
        let var = self.num_witness_elements;
        self.num_witness_elements += 1;

        self.witness_values.push(value);

        var
    }

    pub fn new_constraint(&mut self, constraint: Constraint) {
        self.constraints.push(constraint);
    }

    pub fn get_value(&self, idx: usize) -> M31 {
        self.witness_values[idx]
    }

    pub fn is_satisfied(&self) -> bool {
        for constraint in self.constraints.iter() {
            let mut sum = M31::zero();

            let w_l = self.get_value(constraint.w_l);
            let w_r = self.get_value(constraint.w_r);
            let w_o = self.get_value(constraint.w_o);

            sum += constraint.q_l * w_l;
            sum += constraint.q_r * w_r;
            sum += constraint.q_m * w_l * w_r;
            sum += constraint.q_o * w_o;
            sum += constraint.q_c;
            sum -= constraint.pi;

            if !sum.is_zero() {
                return false;
            }
        }

        return true;
    }
}
