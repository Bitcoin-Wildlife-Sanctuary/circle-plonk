/*
    Copyright 2022 iden3 association.

    This file is part of snarkjs.

    snarkjs is a free software: you can redistribute it and/or
    modify it under the terms of the GNU General Public License as published by the
    Free Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    snarkjs is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    snarkjs. If not, see <https://www.gnu.org/licenses/>.
*/
use crate::circuit::{Circuit, Mode};
use crate::field::{to_m31, FM31};
use ark_ff::{Field, One, Zero};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use std::collections::HashMap;
use stwo_prover::core::fields::m31::M31;

pub struct OnDemandAllocator {
    pub assignments: Vec<M31>,
    pub mapping: HashMap<usize, usize>,
    pub num_input: usize,
}

impl OnDemandAllocator {
    pub fn new(assignments: Vec<M31>, num_input: usize) -> Self {
        Self {
            assignments,
            mapping: HashMap::new(),
            num_input,
        }
    }

    pub fn get(&mut self, circuit: &mut Circuit, idx: usize) -> usize {
        if let Some(&v) = self.mapping.get(&idx) {
            v
        } else {
            let v = if idx < self.num_input {
                circuit.new_input(self.assignments[idx])
            } else {
                circuit.new_witness(self.assignments[idx])
            };
            self.mapping.insert(idx, v);
            v
        }
    }

    pub fn is_allocated(&self, idx: usize) -> bool {
        self.mapping.contains_key(&idx)
    }

    pub fn set_allocated(&mut self, idx: usize, allocated: usize) {
        assert!(!self.is_allocated(idx));
        self.mapping.insert(idx, allocated);
    }
}

pub fn generate_circuit<C: ConstraintSynthesizer<FM31>>(
    circuit: C,
    mode: Mode,
) -> ark_relations::r1cs::Result<Circuit> {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Weight);
    if mode == Mode::INDEX {
        cs.set_mode(SynthesisMode::Setup);
    } else {
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
    }
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();

    // copy-and-paste the values
    let num_variables = cs.num_instance_variables() + cs.num_witness_variables();

    let mut assignments = Vec::<M31>::with_capacity(num_variables);
    if mode == Mode::PROVE {
        for elem in cs.borrow().unwrap().instance_assignment.iter() {
            assignments.push(to_m31(elem));
        }
        for elem in cs.borrow().unwrap().witness_assignment.iter() {
            assignments.push(to_m31(elem));
        }
    } else {
        assignments.resize(num_variables, M31::zero());
    }

    let mut allocator = OnDemandAllocator::new(assignments, cs.num_instance_variables());

    let mut output = Circuit::new();

    for i in 0..cs.num_instance_variables() {
        allocator.get(&mut output, i);
    }

    let matrices = cs.to_matrices().unwrap();

    // witness values layout
    // - zero_var
    // - one_var
    // - instance_vars
    // - witness_vars

    for ((a, b), c) in matrices
        .a
        .iter()
        .zip(matrices.b.iter())
        .zip(matrices.c.iter())
    {
        let lct_a = get_linear_combination_type(a);
        let lct_b = get_linear_combination_type(b);

        if lct_a == LinearCombinationType::NULLABLE || lct_b == LinearCombinationType::NULLABLE {
            let c = sort_linear_combinations(c);
            process_r1cs_addition_constraint(&mut output, &mut allocator, &c);
        } else if let LinearCombinationType::CONSTANT(a_constant) = lct_a {
            process_r1cs_equal_constraint(&mut output, &mut allocator, b, a_constant, c);
        } else if let LinearCombinationType::CONSTANT(b_constant) = lct_b {
            process_r1cs_equal_constraint(&mut output, &mut allocator, a, b_constant, c);
        } else {
            let a = sort_linear_combinations(a);
            let b = sort_linear_combinations(b);
            let c = sort_linear_combinations(c);
            process_r1cs_multiplication_constraint(&mut output, &mut allocator, &a, &b, &c);
        }
    }

    Ok(output)
}

pub fn process_r1cs_equal_constraint(
    circuit: &mut Circuit,
    allocator: &mut OnDemandAllocator,
    a_or_b: &[(FM31, usize)],
    constant: FM31,
    c: &[(FM31, usize)],
) {
    let (a_or_b, constant, c) = if c.len() == 1 && !allocator.is_allocated(c[0].1) {
        (a_or_b, constant, c)
    } else if a_or_b.len() == 1 && !allocator.is_allocated(a_or_b[0].1) {
        (c, constant.inverse().unwrap(), a_or_b)
    } else {
        (a_or_b, constant, c)
    };

    let mut v = reduce_coefs(circuit, allocator, a_or_b);
    if !constant.is_one() {
        v = circuit.mul_by_constant(v, to_m31(&constant));
    }

    if c.len() == 1 && !allocator.is_allocated(c[0].1) {
        if !c[0].0.is_one() {
            v = circuit.mul_by_constant(v, to_m31(&c[0].0.inverse().unwrap()));
        }
        allocator.set_allocated(c[0].1, v);
    } else {
        let c = reduce_coefs(circuit, allocator, c);
        let c_neg = circuit.neg(c);
        let sum = circuit.add(v, c_neg);
        circuit.zero_test(sum);
    }
}

pub fn sort_linear_combinations(lin_com: &[(FM31, usize)]) -> Vec<(FM31, usize)> {
    let mut lin_com = lin_com.to_vec();
    lin_com.sort_unstable_by(|&(_, a_idx), &(_, b_idx)| a_idx.cmp(&b_idx));
    lin_com
}

pub fn reduce_coefs(
    circuit: &mut Circuit,
    allocator: &mut OnDemandAllocator,
    c: &[(FM31, usize)],
) -> usize {
    let mut k = FM31::zero();
    let mut cs = vec![];

    for &(coeff, idx) in c.iter() {
        if idx == 0 {
            k += coeff;
        } else if !coeff.is_zero() {
            cs.push((idx, coeff));
        }
    }

    if cs.len() == 0 {
        return 0;
    }

    let mut sum = allocator.get(circuit, cs[0].0);
    if !cs[0].1.is_one() {
        sum = circuit.mul_by_constant(sum, to_m31(&cs[0].1));
    };

    for entry in cs.iter().skip(1) {
        let mut v = allocator.get(circuit, entry.0);
        if !entry.1.is_one() {
            v = circuit.mul_by_constant(v, to_m31(&entry.1));
        }
        sum = circuit.add(sum, v);
    }

    if !k.is_zero() {
        let constant = circuit.new_constant(to_m31(&k));
        sum = circuit.add(sum, constant);
    }

    sum
}

pub fn process_r1cs_addition_constraint(
    circuit: &mut Circuit,
    allocator: &mut OnDemandAllocator,
    c: &[(FM31, usize)],
) {
    let c = reduce_coefs(circuit, allocator, c);
    circuit.zero_test(c);
}

pub fn process_r1cs_multiplication_constraint(
    circuit: &mut Circuit,
    allocator: &mut OnDemandAllocator,
    a: &[(FM31, usize)],
    b: &[(FM31, usize)],
    c: &[(FM31, usize)],
) {
    let a = reduce_coefs(circuit, allocator, a);
    let b = reduce_coefs(circuit, allocator, b);

    if c.len() == 1 && !allocator.is_allocated(c[0].1) {
        let mut v = circuit.mul(a, b);
        if !c[0].0.is_one() {
            v = circuit.mul_by_constant(v, to_m31(&c[0].0.inverse().unwrap()));
        }
        allocator.set_allocated(c[0].1, v);
    } else {
        let c = reduce_coefs(circuit, allocator, c);

        let a_mul_b = circuit.mul(a, b);
        let c_neg = circuit.neg(c);
        let sum = circuit.add(a_mul_b, c_neg);
        circuit.zero_test(sum);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LinearCombinationType {
    VARIABLE,
    CONSTANT(FM31),
    NULLABLE,
}

pub fn get_linear_combination_type(row: &[(FM31, usize)]) -> LinearCombinationType {
    let mut k = FM31::zero();
    let mut n = 0;

    for &(coeff, idx) in row.iter() {
        if idx == 0 {
            k += coeff;
        } else {
            n += 1;
        }
    }

    if n > 0 {
        return LinearCombinationType::VARIABLE;
    }
    if !k.is_zero() {
        return LinearCombinationType::CONSTANT(k);
    }
    return LinearCombinationType::NULLABLE;
}
