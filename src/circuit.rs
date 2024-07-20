use ark_ff::{One, Zero};
use std::collections::HashMap;
use std::ops::Neg;
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
    pub num_gates: usize,
    pub mode: Mode,
    pub output_wires: Vec<M31>,

    pub op: Vec<M31>,
    pub idx_a: Vec<usize>,
    pub idx_b: Vec<usize>,
    pub mult: Vec<usize>,

    pub constant_maps: HashMap<M31, usize>,
}

impl Circuit {
    pub fn new() -> Circuit {
        let mut circuit = Self::default();

        // push zero
        circuit.num_gates += 1;
        circuit.output_wires.push(M31::zero());
        circuit.op.push(M31::one());
        circuit.idx_a.push(0);
        circuit.idx_b.push(0);
        circuit.mult.push(0);

        // push one (needs to be externally enforced)
        circuit.num_gates += 1;
        circuit.output_wires.push(M31::one());
        circuit.op.push(M31::zero());
        circuit.idx_a.push(1);
        circuit.idx_b.push(1);
        circuit.mult.push(2);

        circuit
    }

    pub fn new_gate(&mut self, op: M31, idx_a: usize, idx_b: usize) -> usize {
        let value = op * (self.get_output_wire(idx_a) + self.get_output_wire(idx_b))
            + (M31::one() - op) * self.get_output_wire(idx_a) * self.get_output_wire(idx_b);

        let idx = self.num_gates;
        self.num_gates += 1;
        self.output_wires.push(value);
        self.op.push(op);
        self.idx_a.push(idx_a);
        self.idx_b.push(idx_b);
        self.mult.push(0);

        idx
    }

    pub fn new_constant(&mut self, constant: M31) -> usize {
        if self.constant_maps.contains_key(&constant) {
            *self.constant_maps.get(&constant).unwrap()
        } else {
            let idx = self.new_gate(constant, 1, 0);
            self.constant_maps.insert(constant, idx);
            idx
        }
    }

    pub fn add(&mut self, idx_a: usize, idx_b: usize) -> usize {
        self.new_gate(M31::one(), idx_a, idx_b)
    }

    pub fn mul(&mut self, idx_a: usize, idx_b: usize) -> usize {
        self.new_gate(M31::zero(), idx_a, idx_b)
    }

    pub fn neg(&mut self, idx: usize) -> usize {
        self.mul_by_constant(idx, M31::one().neg())
    }

    pub fn zero_test(&mut self, idx: usize) {
        let helper = self.num_gates;
        self.num_gates += 1;
        self.output_wires.push(M31::zero()); // it can be any value
        self.op.push(M31::one());
        self.idx_a.push(idx);
        self.idx_b.push(helper);
        self.mult.push(1);
    }

    pub fn mul_by_constant(&mut self, idx: usize, constant: M31) -> usize {
        self.new_gate(constant, idx, 0)
    }

    pub fn new_input(&mut self, input: M31) -> usize {
        let idx = self.num_gates;
        self.num_gates += 1;
        self.output_wires.push(input);
        self.op.push(M31::one());
        self.idx_a.push(idx);
        self.idx_b.push(0);
        self.mult.push(1);

        idx
    }

    pub fn get_output_wire(&self, idx: usize) -> M31 {
        self.output_wires[idx]
    }

    pub fn increase_output_count(&mut self, idx: usize) {
        self.mult[idx] += 1;
    }

    pub fn is_satisfied(&self) -> bool {
        assert_eq!(self.num_gates, self.output_wires.len());
        assert_eq!(self.num_gates, self.op.len());
        assert_eq!(self.num_gates, self.idx_a.len());
        assert_eq!(self.num_gates, self.idx_b.len());
        assert_eq!(self.num_gates, self.mult.len());

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
}
