#!/bin/sh

cargo run preprocess --r1cs lib/src/test.r1cs --out-vk vk.tmp
cargo run prove --r1cs lib/src/test.r1cs --witness lib/src/output.wtns --out-proof proof.tmp
cargo run verify --vk vk.tmp --input lib/src/input.json --proof proof.tmp --map lib/src/test.map