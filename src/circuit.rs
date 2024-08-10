use ark_ff::{One, Zero};
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use std::collections::HashMap;
use std::ops::Neg;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::FieldExpOps;

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
    pub num_rows: usize,
    pub mode: Mode,
    pub output_wires: Vec<M31>,

    pub op: Vec<M31>,
    pub idx_a: Vec<usize>,
    pub idx_b: Vec<usize>,
    pub mult: Vec<usize>,

    pub input_maps: Vec<(usize, M31)>,

    pub constant_maps: HashMap<M31, usize>,
}

impl Circuit {
    pub fn new() -> Circuit {
        let mut circuit = Self::default();

        circuit.num_rows += 1;
        circuit.output_wires.push(M31::zero());
        circuit.op.push(M31::one());
        circuit.idx_a.push(0);
        circuit.idx_b.push(0);
        circuit.mult.push(2);

        circuit
    }

    pub fn new_row(&mut self, op: M31, idx_a: usize, idx_b: usize) -> usize {
        let value = op * (self.get_output_wire(idx_a) + self.get_output_wire(idx_b))
            + (M31::one() - op) * self.get_output_wire(idx_a) * self.get_output_wire(idx_b);

        let idx = self.num_rows;
        self.num_rows += 1;
        self.output_wires.push(value);
        self.op.push(op);
        self.idx_a.push(idx_a);
        self.idx_b.push(idx_b);
        self.mult.push(0);

        self.increase_output_count(idx_a);
        self.increase_output_count(idx_b);

        idx
    }

    pub fn new_constant(&mut self, constant: M31) -> usize {
        if self.constant_maps.contains_key(&constant) {
            *self.constant_maps.get(&constant).unwrap()
        } else {
            let idx = self.new_row(constant, 1, 0);
            self.constant_maps.insert(constant, idx);
            idx
        }
    }

    pub fn add(&mut self, idx_a: usize, idx_b: usize) -> usize {
        self.new_row(M31::one(), idx_a, idx_b)
    }

    pub fn mul(&mut self, idx_a: usize, idx_b: usize) -> usize {
        self.new_row(M31::zero(), idx_a, idx_b)
    }

    pub fn neg(&mut self, idx: usize) -> usize {
        self.mul_by_constant(idx, M31::one().neg())
    }

    pub fn zero_test(&mut self, idx: usize) {
        let helper = self.num_rows;
        self.num_rows += 1;
        self.output_wires.push(M31::zero()); // it can be any value
        self.op.push(M31::one());
        self.idx_a.push(idx);
        self.idx_b.push(helper);
        self.mult.push(1);

        self.increase_output_count(idx);
    }

    pub fn mul_by_constant(&mut self, idx: usize, constant: M31) -> usize {
        self.new_row(constant, idx, 0)
    }

    pub fn new_input(&mut self, input: M31) -> usize {
        let idx = self.num_rows;
        self.num_rows += 1;
        self.output_wires.push(input);
        self.op.push(M31::one());
        self.idx_a.push(idx);
        self.idx_b.push(0);
        self.mult.push(0); // input is done by intentionally reducing the mult by one causing the need to externally supply it

        self.input_maps.push((idx, input));

        self.increase_output_count(0);

        idx
    }

    pub fn new_witness(&mut self, witness: M31) -> usize {
        let idx = self.num_rows;
        self.num_rows += 1;
        self.output_wires.push(witness);
        self.op.push(M31::one());
        self.idx_a.push(idx);
        self.idx_b.push(0);
        self.mult.push(1);

        self.increase_output_count(0);

        idx
    }

    pub fn get_output_wire(&self, idx: usize) -> M31 {
        self.output_wires[idx]
    }

    pub fn increase_output_count(&mut self, idx: usize) {
        self.mult[idx] += 1;
    }

    pub fn is_constraint_satisfied(&self) -> bool {
        assert_eq!(self.num_rows, self.output_wires.len());
        assert_eq!(self.num_rows, self.op.len());
        assert_eq!(self.num_rows, self.idx_a.len());
        assert_eq!(self.num_rows, self.idx_b.len());
        assert_eq!(self.num_rows, self.mult.len());

        for (((&output_wire, &op), &idx_a), &idx_b) in self
            .output_wires
            .iter()
            .zip(self.op.iter())
            .zip(self.idx_a.iter())
            .zip(self.idx_b.iter())
        {
            let mut sum = M31::zero();

            let w_a = self.get_output_wire(idx_a);
            let w_b = self.get_output_wire(idx_b);
            let w_c = output_wire;

            sum += op * (w_a + w_b);
            sum += (M31::one() - op) * w_a * w_b;
            sum -= w_c;

            if !sum.is_zero() {
                return false;
            }
        }

        return true;
    }

    pub fn pad_to_next_power_of_2(&mut self) {
        let num_rows = self.num_rows;

        let next_power_of_2 = num_rows.next_power_of_two();
        for _ in 0..next_power_of_2 {
            self.num_rows += 1;
            self.output_wires.push(M31::zero());
            self.op.push(M31::zero());
            self.idx_a.push(0);
            self.idx_b.push(0);
            self.mult.push(0);

            self.increase_output_count(0);
            self.increase_output_count(0);
        }
    }

    pub fn is_logup_satisfied<R: RngCore>(&self, prng: &mut R, inputs: &[(usize, M31)]) -> bool {
        let alpha = M31::rand(prng);
        let z = M31::rand(prng);

        let mut sum = M31::zero();

        if self.num_rows > 0 {
            let mut denominators = vec![];
            for (idx_c, (&idx_a, &idx_b)) in self.idx_a.iter().zip(self.idx_b.iter()).enumerate() {
                denominators.push(M31::from(idx_a) + alpha * self.output_wires[idx_a] - z);
                denominators.push(M31::from(idx_b) + alpha * self.output_wires[idx_b] - z);
                denominators.push(M31::from(idx_c) + alpha * self.output_wires[idx_c] - z);
            }

            let mut denominator_inverses = vec![M31::zero(); denominators.len()];
            M31::batch_inverse(&denominators, &mut denominator_inverses);

            for (group, &mult) in denominator_inverses.chunks_exact(3).zip(self.mult.iter()) {
                sum += group[0];
                sum += group[1];
                sum -= M31::from(mult) * group[2];
            }
        }

        if !inputs.is_empty() {
            let mut denominators = vec![];
            for &(id, v) in inputs.iter() {
                denominators.push(M31::from(id) + alpha * v - z);
            }

            let mut denominator_inverses = vec![M31::zero(); denominators.len()];
            M31::batch_inverse(&denominators, &mut denominator_inverses);

            for &v in denominator_inverses.iter() {
                sum -= v;
            }
        }

        sum.is_zero()
    }
}
