// https://github.com/aadomn/aes 2020
// https://crates.io/crates/tfhe

use crate::aes128_keyschedule_lut;
use aes128_keyschedule_lut::le_load_32;

#[cfg(feature = "gpu")]
use tfhe::CompressedServerKey;
#[cfg(not(feature = "gpu"))]
use tfhe::generate_keys;
use tfhe::prelude::*;
use tfhe::{ClientKey, ConfigBuilder, FheUint32, set_server_key};

use std::time::{Duration, Instant};

#[allow(dead_code)]
fn print_hex_u8(label: &str, data: &[u8]) {
    let hex_output: String = data.iter().map(|byte| format!("{:02x}", byte)).collect();

    println!("{}          {}", label, hex_output);
}

fn print_hex_u32(label: &str, data: &[u32]) {
    let hex_output: String = data.iter().map(|byte| format!("{:08x}", byte)).collect();

    println!("{}          {}", label, hex_output);
}

fn print_hex_fhe_u32(label: &str, enc_data: &Vec<FheUint32>, client_key: &ClientKey) {
    let mut state: Vec<u32> = Vec::new();

    for (_i_, enc_value) in enc_data.iter().enumerate() {
        // Decrypt each value and store it in the state array
        state.push(enc_value.decrypt(client_key));
    }

    let hex_output: String = state.iter().map(|byte| format!("{:08x}", byte)).collect();

    println!("{}          {}", label, hex_output);
}

#[inline]
fn swap_move_idx(slice: &mut [u32; 32], idx1: usize, idx2: usize, mask: u32, n: u8) {
    let tmp = (slice[idx2] ^ (slice[idx1] >> n)) & mask;
    slice[idx2] ^= tmp;
    slice[idx1] ^= tmp << n;
}

#[inline]
fn le_store_32(out: &mut [u8], value: u32) {
    out.copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn packing(out: &mut [u32; 32], input: &[u8; 128]) {
    // Load 32-bit values from the input and perform the swaps as per the original C code
    for i in 0..8 {
        out[i] = le_load_32(&input[i * 16..i * 16 + 4]);
        out[i + 8] = le_load_32(&input[i * 16 + 4..i * 16 + 8]);
        out[i + 16] = le_load_32(&input[i * 16 + 8..i * 16 + 12]);
        out[i + 24] = le_load_32(&input[i * 16 + 12..i * 16 + 16]);

        swap_move_idx(out, i, i + 8, 0x00ff00ff, 8);
        swap_move_idx(out, i + 16, i + 24, 0x00ff00ff, 8);
        //swap_move(&mut out[i], &mut out[i + 8], 0x00ff00ff, 8);
        //swap_move(&mut out[i + 16], &mut out[i + 24], 0x00ff00ff, 8);
    }

    // SwapMove for next set of operations
    for i in 0..16 {
        swap_move_idx(out, i, i + 16, 0x0000ffff, 16);
        //swap_move(&mut out[i], &mut out[i + 16], 0x0000ffff, 16);
    }

    // Final SwapMove stages
    for i in (0..32).step_by(8) {
        swap_move_idx(out, i + 1, i, 0x55555555, 1);
        swap_move_idx(out, i + 3, i + 2, 0x55555555, 1);
        swap_move_idx(out, i + 5, i + 4, 0x55555555, 1);
        swap_move_idx(out, i + 7, i + 6, 0x55555555, 1);

        swap_move_idx(out, i + 2, i, 0x33333333, 2);
        swap_move_idx(out, i + 3, i + 1, 0x33333333, 2);
        swap_move_idx(out, i + 6, i + 4, 0x33333333, 2);
        swap_move_idx(out, i + 7, i + 5, 0x33333333, 2);

        swap_move_idx(out, i + 4, i, 0x0f0f0f0f, 4);
        swap_move_idx(out, i + 5, i + 1, 0x0f0f0f0f, 4);
        swap_move_idx(out, i + 6, i + 2, 0x0f0f0f0f, 4);
        swap_move_idx(out, i + 7, i + 3, 0x0f0f0f0f, 4);

        //swap_move(&mut out[i + 1], &mut out[i], 0x55555555, 1);
        //swap_move(&mut out[i + 3], &mut out[i + 2], 0x55555555, 1);
        //swap_move(&mut out[i + 5], &mut out[i + 4], 0x55555555, 1);
        //swap_move(&mut out[i + 7], &mut out[i + 6], 0x55555555, 1);

        //swap_move(&mut out[i + 2], &mut out[i], 0x33333333, 2);
        //swap_move(&mut out[i + 3], &mut out[i + 1], 0x33333333, 2);
        //swap_move(&mut out[i + 6], &mut out[i + 4], 0x33333333, 2);
        //swap_move(&mut out[i + 7], &mut out[i + 5], 0x33333333, 2);

        //swap_move(&mut out[i + 4], &mut out[i], 0x0f0f0f0f, 4);
        //swap_move(&mut out[i + 5], &mut out[i + 1], 0x0f0f0f0f, 4);
        //swap_move(&mut out[i + 6], &mut out[i + 2], 0x0f0f0f0f, 4);
        //swap_move(&mut out[i + 7], &mut out[i + 3], 0x0f0f0f0f, 4);
    }
}

#[inline]
fn unpacking(out: &mut [u8; 128], input: &mut [u32; 32]) {
    // First loop: perform SwapMove operations for each segment
    for i in (0..32).step_by(8) {
        swap_move_idx(input, i + 1, i, 0x55555555, 1);
        swap_move_idx(input, i + 3, i + 2, 0x55555555, 1);
        swap_move_idx(input, i + 5, i + 4, 0x55555555, 1);
        swap_move_idx(input, i + 7, i + 6, 0x55555555, 1);

        swap_move_idx(input, i + 2, i, 0x33333333, 2);
        swap_move_idx(input, i + 3, i + 1, 0x33333333, 2);
        swap_move_idx(input, i + 6, i + 4, 0x33333333, 2);
        swap_move_idx(input, i + 7, i + 5, 0x33333333, 2);

        swap_move_idx(input, i + 4, i, 0x0f0f0f0f, 4);
        swap_move_idx(input, i + 5, i + 1, 0x0f0f0f0f, 4);
        swap_move_idx(input, i + 6, i + 2, 0x0f0f0f0f, 4);
        swap_move_idx(input, i + 7, i + 3, 0x0f0f0f0f, 4);
        /*
        swap_move(&mut input[i + 1], &mut input[i], 0x55555555, 1);
        swap_move(&mut input[i + 3], &mut input[i + 2], 0x55555555, 1);
        swap_move(&mut input[i + 5], &mut input[i + 4], 0x55555555, 1);
        swap_move(&mut input[i + 7], &mut input[i + 6], 0x55555555, 1);

        swap_move(&mut input[i + 2], &mut input[i], 0x33333333, 2);
        swap_move(&mut input[i + 3], &mut input[i + 1], 0x33333333, 2);
        swap_move(&mut input[i + 6], &mut input[i + 4], 0x33333333, 2);
        swap_move(&mut input[i + 7], &mut input[i + 5], 0x33333333, 2);

        swap_move(&mut input[i + 4], &mut input[i], 0x0f0f0f0f, 4);
        swap_move(&mut input[i + 5], &mut input[i + 1], 0x0f0f0f0f, 4);
        swap_move(&mut input[i + 6], &mut input[i + 2], 0x0f0f0f0f, 4);
        swap_move(&mut input[i + 7], &mut input[i + 3], 0x0f0f0f0f, 4);
        */
    }

    // SwapMove for the next step
    for i in 0..16 {
        swap_move_idx(input, i, i + 16, 0x0000ffff, 16);
        //swap_move(&mut input[i], &mut input[i + 16], 0x0000ffff, 16);
    }

    // Second loop: perform additional SwapMove and store the result in the output
    for i in 0..8 {
        swap_move_idx(input, i, i + 8, 0x00ff00ff, 8);
        swap_move_idx(input, i + 16, i + 24, 0x00ff00ff, 8);
        //swap_move(&mut input[i], &mut input[i + 8], 0x00ff00ff, 8);
        //swap_move(&mut input[i + 16], &mut input[i + 24], 0x00ff00ff, 8);

        le_store_32(&mut out[i * 16..i * 16 + 4], input[i]);
        le_store_32(&mut out[i * 16 + 4..i * 16 + 8], input[i + 8]);
        le_store_32(&mut out[i * 16 + 8..i * 16 + 12], input[i + 16]);
        le_store_32(&mut out[i * 16 + 12..i * 16 + 16], input[i + 24]);
    }
}

#[inline]
fn sbox(state: &mut [u32]) {
    let (mut t0, mut t1, mut t2, mut t3, mut t4, mut t5, mut t6, mut t7, t8, t9);
    let (mut t10, mut t11, mut t12, mut t13, mut t14, mut t15, mut t16, mut t17);

    t0 = state[3] ^ state[5];
    t1 = state[0] ^ state[6];
    t2 = t1 ^ t0;
    t3 = state[4] ^ t2;
    t4 = t3 ^ state[5];
    t5 = t2 & t4;
    t6 = t4 ^ state[7];
    t7 = t3 ^ state[1];
    t8 = state[0] ^ state[3];
    t9 = t7 ^ t8;
    t10 = t8 & t9;
    t11 = state[7] ^ t9;
    t12 = state[0] ^ state[5];
    t13 = state[1] ^ state[2];
    t14 = t4 ^ t13;
    t15 = t14 ^ t9;
    t16 = t0 & t15;
    t17 = t16 ^ t10;

    state[1] = t14 ^ t12;
    state[2] = t12 & t14;
    state[2] ^= t10;
    state[4] = t13 ^ t9;
    state[5] = t1 ^ state[4];
    t3 = t1 & state[4];
    t10 = state[0] ^ state[4];
    t13 ^= state[7];
    state[3] ^= t13;
    t16 = state[3] & state[7];
    t16 ^= t5;
    t16 ^= state[2];
    state[1] ^= t16;
    state[0] ^= t13;
    t16 = state[0] & t11;
    t16 ^= t3;
    state[2] ^= t16;
    state[2] ^= t10;
    state[6] ^= t13;
    t10 = state[6] & t13;
    t3 ^= t10;
    t3 ^= t17;
    state[5] ^= t3;
    t3 = state[6] ^ t12;
    t10 = t3 & t6;
    t5 ^= t10;
    t5 ^= t7;
    t5 ^= t17;
    t7 = t5 & state[5];
    t10 = state[2] ^ t7;
    t7 ^= state[1];
    t5 ^= state[1];
    t16 = t5 & t10;
    state[1] ^= t16;
    t17 = state[1] & state[0];
    t11 = state[1] & t11;
    t16 = state[5] ^ state[2];
    t7 &= t16;
    t7 ^= state[2];
    t16 = t10 ^ t7;
    state[2] &= t16;
    t10 ^= state[2];
    t10 &= state[1];
    t5 ^= t10;
    t10 = state[1] ^ t5;
    state[4] &= t10;
    t11 ^= state[4];
    t1 &= t10;
    state[6] &= t5;
    t10 = t5 & t13;
    state[4] ^= t10;
    state[5] ^= t7;
    state[2] ^= state[5];
    state[5] = t5 ^ state[2];
    t5 = state[5] & t14;
    t10 = state[5] & t12;
    t12 = t7 ^ state[2];
    t4 &= t12;
    t2 &= t12;
    t3 &= state[2];
    state[2] &= t6;
    state[2] ^= t4;
    t13 = state[4] ^ state[2];
    state[3] &= t7;
    state[1] ^= t7;
    state[5] ^= state[1];
    t6 = state[5] & t15;
    state[4] ^= t6;
    t0 &= state[5];
    state[5] = state[1] & t9;
    state[5] ^= state[4];
    state[1] &= t8;
    t6 = state[1] ^ state[5];
    t0 ^= state[1];
    state[1] = t3 ^ t0;
    t15 = state[1] ^ state[3];
    t2 ^= state[1];
    state[0] = t2 ^ state[5];
    state[3] = t2 ^ t13;
    state[1] = state[3] ^ state[5];
    t0 ^= state[6];
    state[5] = t7 & state[7];
    t14 = t4 ^ state[5];
    state[6] = t1 ^ t14;
    state[6] ^= t5;
    state[6] ^= state[4];
    state[2] = t17 ^ state[6];
    state[5] = t15 ^ state[2];
    state[2] ^= t6;
    state[2] ^= t10;
    t14 ^= t11;
    t0 ^= t14;
    state[6] ^= t0;
    state[7] = t1 ^ t0;
    state[4] = t14 ^ state[3];
}

#[inline]
fn sbox_fhe(state: &mut [FheUint32]) {
    let start = Instant::now();

    let (mut t0, mut t1, mut t2, mut t3, mut t4, mut t5, mut t6, mut t7, t8, t9);
    let (mut t10, mut t11, mut t12, mut t13, mut t14, mut t15, mut t16, mut t17);

    t0 = &state[3] ^ &state[5];
    t1 = &state[0] ^ &state[6];
    t2 = &t1 ^ &t0;
    t3 = &state[4] ^ &t2;
    t4 = &t3 ^ &state[5];
    t5 = &t2 & &t4;
    t6 = &t4 ^ &state[7];
    t7 = &t3 ^ &state[1];
    t8 = &state[0] ^ &state[3];
    t9 = &t7 ^ &t8;
    t10 = &t8 & &t9;
    t11 = &state[7] ^ &t9;
    t12 = &state[0] ^ &state[5];
    t13 = &state[1] ^ &state[2];
    t14 = &t4 ^ &t13;
    t15 = &t14 ^ &t9;
    t16 = &t0 & &t15;
    t17 = &t16 ^ &t10;

    state[1] = &t14 ^ &t12;
    state[2] = &t12 & &t14;
    state[2] = &state[2] ^ &t10;
    state[4] = &t13 ^ &t9;
    state[5] = &t1 ^ &state[4];
    t3 = &t1 & &state[4];
    t10 = &state[0] ^ &state[4];
    t13 = &t13 ^ &state[7];
    state[3] = &state[3] ^ &t13;
    t16 = &state[3] & &state[7];
    t16 = &t16 ^ &t5;
    t16 = &t16 ^ &state[2];
    state[1] = &state[1] ^ &t16;
    state[0] = &state[0] ^ &t13;
    t16 = &state[0] & &t11;
    t16 = &t16 ^ &t3;
    state[2] = &state[2] ^ &t16;
    state[2] = &state[2] ^ &t10;
    state[6] = &state[6] ^ &t13;
    t10 = &state[6] & &t13;
    t3 = &t3 ^ &t10;
    t3 = &t3 ^ &t17;
    state[5] = &state[5] ^ &t3;
    t3 = &state[6] ^ &t12;
    t10 = &t3 & &t6;
    t5 = &t5 ^ &t10;
    t5 = &t5 ^ &t7;
    t5 = &t5 ^ &t17;
    t7 = &t5 & &state[5];
    t10 = &state[2] ^ &t7;
    t7 = &t7 ^ &state[1];
    t5 = &t5 ^ &state[1];
    t16 = &t5 & &t10;
    state[1] = &state[1] ^ &t16;
    t17 = &state[1] & &state[0];
    t11 = &state[1] & &t11;
    t16 = &state[5] ^ &state[2];
    t7 = &t7 & &t16;
    t7 = &t7 ^ &state[2];
    t16 = &t10 ^ &t7;
    state[2] = &state[2] & &t16;
    t10 = &t10 ^ &state[2];
    t10 = &t10 & &state[1];
    t5 = &t5 ^ &t10;
    t10 = &state[1] ^ &t5;
    state[4] = &state[4] & &t10;
    t11 = &t11 ^ &state[4];
    t1 = &t1 & &t10;
    state[6] = &state[6] & &t5;
    t10 = &t5 & &t13;
    state[4] = &state[4] ^ &t10;
    state[5] = &state[5] ^ &t7;
    state[2] = &state[2] ^ &state[5];
    state[5] = &t5 ^ &state[2];
    t5 = &state[5] & &t14;
    t10 = &state[5] & &t12;
    t12 = &t7 ^ &state[2];
    t4 = &t4 & &t12;
    t2 = &t2 & &t12;
    t3 = &t3 & &state[2];
    state[2] = &state[2] & &t6;
    state[2] = &state[2] ^ &t4;
    t13 = &state[4] ^ &state[2];
    state[3] = &state[3] & &t7;
    state[1] = &state[1] ^ &t7;
    state[5] = &state[5] ^ &state[1];
    t6 = &state[5] & &t15;
    state[4] = &state[4] ^ &t6;
    t0 = &t0 & &state[5];
    state[5] = &state[1] & &t9;
    state[5] = &state[5] ^ &state[4];
    state[1] = &state[1] & &t8;
    t6 = &state[1] ^ &state[5];
    t0 = &t0 ^ &state[1];
    state[1] = &t3 ^ &t0;
    t15 = &state[1] ^ &state[3];
    t2 = &t2 ^ &state[1];
    state[0] = &t2 ^ &state[5];
    state[3] = &t2 ^ &t13;
    state[1] = &state[3] ^ &state[5];
    t0 = &t0 ^ &state[6];
    state[5] = &t7 & &state[7];
    t14 = &t4 ^ &state[5];
    state[6] = &t1 ^ &t14;
    state[6] = &state[6] ^ &t5;
    state[6] = &state[6] ^ &state[4];
    state[2] = &t17 ^ &state[6];
    state[5] = &t15 ^ &state[2];
    state[2] = &state[2] ^ &t6;
    state[2] = &state[2] ^ &t10;
    t14 = &t14 ^ &t11;
    t0 = &t0 ^ &t14;
    state[6] = &state[6] ^ &t0;
    state[7] = &t1 ^ &t0;
    state[4] = &t14 ^ &state[3];

    println!("sbox_fhe time       {:.2?}", start.elapsed());
}

#[inline]
fn shiftrows(state: &mut [u32]) {
    // Shifts the bits to the right by a specified amount, n, wrapping the truncated bits to the beginning of the resulting integer.
    // Please note this isn’t the same operation as the >> shifting operator!

    for i in 8..16 {
        state[i] = state[i].rotate_right(8);
    }
    for i in 16..24 {
        state[i] = state[i].rotate_right(16);
    }
    for i in 24..32 {
        state[i] = state[i].rotate_right(24);
    }
}

#[inline]
fn shiftrows_fhe(state: &mut [FheUint32]) {
    let start = Instant::now();

    for i in 8..16 {
        state[i] = state[i].clone().rotate_right(8 as u8);
    }
    for i in 16..24 {
        state[i] = state[i].clone().rotate_right(16 as u8);
    }
    for i in 24..32 {
        state[i] = state[i].clone().rotate_right(24 as u8);
    }

    println!("shiftrows_fhe time  {:.2?}", start.elapsed());
}

#[inline]
fn mixcolumns(state: &mut [u32]) {
    let tmp2_0;
    let tmp2_1;
    let tmp2_2;
    let tmp2_3;
    let mut tmp;
    let mut tmp_bis;
    let mut tmp0_0;
    let mut tmp0_1;
    let mut tmp0_2;
    let mut tmp0_3;
    let mut tmp1_0;
    let mut tmp1_1;
    let mut tmp1_2;
    let mut tmp1_3;

    tmp2_0 = state[0] ^ state[8];
    tmp2_1 = state[8] ^ state[16];
    tmp2_2 = state[16] ^ state[24];
    tmp2_3 = state[24] ^ state[0];
    tmp0_0 = state[7] ^ state[15];
    tmp0_1 = state[15] ^ state[23];
    tmp0_2 = state[23] ^ state[31];
    tmp0_3 = state[31] ^ state[7];
    tmp = state[7];
    state[7] = tmp2_0 ^ tmp0_2 ^ state[15];
    state[15] = tmp2_1 ^ tmp0_2 ^ tmp;
    tmp = state[23];
    state[23] = tmp2_2 ^ tmp0_0 ^ state[31];
    state[31] = tmp2_3 ^ tmp0_0 ^ tmp;

    tmp1_0 = state[6] ^ state[14];
    tmp1_1 = state[14] ^ state[22];
    tmp1_2 = state[22] ^ state[30];
    tmp1_3 = state[30] ^ state[6];
    tmp = state[6];
    state[6] = tmp0_0 ^ tmp2_0 ^ state[14] ^ tmp1_2;
    tmp_bis = state[14];
    state[14] = tmp0_1 ^ tmp2_1 ^ tmp1_2 ^ tmp;
    tmp = state[22];
    state[22] = tmp0_2 ^ tmp2_2 ^ tmp1_3 ^ tmp_bis;
    state[30] = tmp0_3 ^ tmp2_3 ^ tmp1_0 ^ tmp;

    tmp0_0 = state[5] ^ state[13];
    tmp0_1 = state[13] ^ state[21];
    tmp0_2 = state[21] ^ state[29];
    tmp0_3 = state[29] ^ state[5];
    tmp = state[5];
    state[5] = tmp1_0 ^ tmp0_1 ^ state[29];
    tmp_bis = state[13];
    state[13] = tmp1_1 ^ tmp0_2 ^ tmp;
    tmp = state[21];
    state[21] = tmp1_2 ^ tmp0_3 ^ tmp_bis;
    state[29] = tmp1_3 ^ tmp0_0 ^ tmp;

    tmp1_0 = state[4] ^ state[12];
    tmp1_1 = state[12] ^ state[20];
    tmp1_2 = state[20] ^ state[28];
    tmp1_3 = state[28] ^ state[4];
    tmp = state[4];
    state[4] = tmp0_0 ^ tmp2_0 ^ tmp1_1 ^ state[28];
    tmp_bis = state[12];
    state[12] = tmp0_1 ^ tmp2_1 ^ tmp1_2 ^ tmp;
    tmp = state[20];
    state[20] = tmp0_2 ^ tmp2_2 ^ tmp1_3 ^ tmp_bis;
    state[28] = tmp0_3 ^ tmp2_3 ^ tmp1_0 ^ tmp;

    tmp0_0 = state[3] ^ state[11];
    tmp0_1 = state[11] ^ state[19];
    tmp0_2 = state[19] ^ state[27];
    tmp0_3 = state[27] ^ state[3];
    tmp = state[3];
    state[3] = tmp1_0 ^ tmp2_0 ^ tmp0_1 ^ state[27];
    tmp_bis = state[11];
    state[11] = tmp1_1 ^ tmp2_1 ^ tmp0_2 ^ tmp;
    tmp = state[19];
    state[19] = tmp1_2 ^ tmp2_2 ^ tmp0_3 ^ tmp_bis;
    state[27] = tmp1_3 ^ tmp2_3 ^ tmp0_0 ^ tmp;

    tmp1_0 = state[2] ^ state[10];
    tmp1_1 = state[10] ^ state[18];
    tmp1_2 = state[18] ^ state[26];
    tmp1_3 = state[26] ^ state[2];
    tmp = state[2];
    state[2] = tmp0_0 ^ tmp1_1 ^ state[26];
    tmp_bis = state[10];
    state[10] = tmp0_1 ^ tmp1_2 ^ tmp;
    tmp = state[18];
    state[18] = tmp0_2 ^ tmp1_3 ^ tmp_bis;
    state[26] = tmp0_3 ^ tmp1_0 ^ tmp;

    tmp0_0 = state[1] ^ state[9];
    tmp0_1 = state[9] ^ state[17];
    tmp0_2 = state[17] ^ state[25];
    tmp0_3 = state[25] ^ state[1];
    tmp = state[1];
    state[1] = tmp1_0 ^ tmp0_1 ^ state[25];
    tmp_bis = state[9];
    state[9] = tmp1_1 ^ tmp0_2 ^ tmp;
    tmp = state[17];
    state[17] = tmp1_2 ^ tmp0_3 ^ tmp_bis;
    state[25] = tmp1_3 ^ tmp0_0 ^ tmp;

    tmp = state[0];
    state[0] = tmp0_0 ^ tmp2_1 ^ state[24];
    tmp_bis = state[8];
    state[8] = tmp0_1 ^ tmp2_2 ^ tmp;
    tmp = state[16];
    state[16] = tmp0_2 ^ tmp2_3 ^ tmp_bis;
    state[24] = tmp0_3 ^ tmp2_0 ^ tmp;
}

#[inline]
fn mixcolumns_fhe(state: &mut [FheUint32]) {
    let start = Instant::now();

    let tmp2_0;
    let tmp2_1;
    let tmp2_2;
    let tmp2_3;
    let mut tmp;

    let mut tmp_bis;
    let mut tmp0_0;
    let mut tmp0_1;
    let mut tmp0_2;
    let mut tmp0_3;
    let mut tmp1_0;
    let mut tmp1_1;
    let mut tmp1_2;
    let mut tmp1_3;

    tmp2_0 = &state[0] ^ &state[8];
    tmp2_1 = &state[8] ^ &state[16];
    tmp2_2 = &state[16] ^ &state[24];
    tmp2_3 = &state[24] ^ &state[0];
    tmp0_0 = &state[7] ^ &state[15];
    tmp0_1 = &state[15] ^ &state[23];
    tmp0_2 = &state[23] ^ &state[31];
    tmp0_3 = &state[31] ^ &state[7];
    tmp = state[7].clone();
    state[7] = &tmp2_0 ^ &tmp0_2 ^ &state[15];
    state[15] = &tmp2_1 ^ &tmp0_2 ^ &tmp;
    tmp = state[23].clone();
    state[23] = &tmp2_2 ^ &tmp0_0 ^ &state[31];
    state[31] = &tmp2_3 ^ &tmp0_0 ^ &tmp;

    tmp1_0 = &state[6] ^ &state[14];
    tmp1_1 = &state[14] ^ &state[22];
    tmp1_2 = &state[22] ^ &state[30];
    tmp1_3 = &state[30] ^ &state[6];
    tmp = state[6].clone();
    state[6] = &tmp0_0 ^ &tmp2_0 ^ &state[14] ^ &tmp1_2;
    tmp_bis = state[14].clone();
    state[14] = &tmp0_1 ^ &tmp2_1 ^ &tmp1_2 ^ &tmp;
    tmp = state[22].clone();
    state[22] = &tmp0_2 ^ &tmp2_2 ^ &tmp1_3 ^ &tmp_bis;
    state[30] = &tmp0_3 ^ &tmp2_3 ^ &tmp1_0 ^ &tmp;

    tmp0_0 = &state[5] ^ &state[13];
    tmp0_1 = &state[13] ^ &state[21];
    tmp0_2 = &state[21] ^ &state[29];
    tmp0_3 = &state[29] ^ &state[5];
    tmp = state[5].clone();
    state[5] = &tmp1_0 ^ &tmp0_1 ^ &state[29];
    tmp_bis = state[13].clone();
    state[13] = &tmp1_1 ^ &tmp0_2 ^ &tmp;
    tmp = state[21].clone();
    state[21] = &tmp1_2 ^ &tmp0_3 ^ &tmp_bis;
    state[29] = &tmp1_3 ^ &tmp0_0 ^ &tmp;

    tmp1_0 = &state[4] ^ &state[12];
    tmp1_1 = &state[12] ^ &state[20];
    tmp1_2 = &state[20] ^ &state[28];
    tmp1_3 = &state[28] ^ &state[4];
    tmp = state[4].clone();
    state[4] = &tmp0_0 ^ &tmp2_0 ^ &tmp1_1 ^ &state[28];
    tmp_bis = state[12].clone();
    state[12] = &tmp0_1 ^ &tmp2_1 ^ &tmp1_2 ^ &tmp;
    tmp = state[20].clone();
    state[20] = &tmp0_2 ^ &tmp2_2 ^ &tmp1_3 ^ &tmp_bis;
    state[28] = &tmp0_3 ^ &tmp2_3 ^ &tmp1_0 ^ &tmp;

    tmp0_0 = &state[3] ^ &state[11];
    tmp0_1 = &state[11] ^ &state[19];
    tmp0_2 = &state[19] ^ &state[27];
    tmp0_3 = &state[27] ^ &state[3];
    tmp = state[3].clone();
    state[3] = &tmp1_0 ^ &tmp2_0 ^ &tmp0_1 ^ &state[27];
    tmp_bis = state[11].clone();
    state[11] = &tmp1_1 ^ &tmp2_1 ^ &tmp0_2 ^ &tmp;
    tmp = state[19].clone();
    state[19] = &tmp1_2 ^ &tmp2_2 ^ &tmp0_3 ^ &tmp_bis;
    state[27] = &tmp1_3 ^ &tmp2_3 ^ &tmp0_0 ^ &tmp;

    tmp1_0 = &state[2] ^ &state[10];
    tmp1_1 = &state[10] ^ &state[18];
    tmp1_2 = &state[18] ^ &state[26];
    tmp1_3 = &state[26] ^ &state[2];
    tmp = state[2].clone();
    state[2] = &tmp0_0 ^ &tmp1_1 ^ &state[26];
    tmp_bis = state[10].clone();
    state[10] = &tmp0_1 ^ &tmp1_2 ^ &tmp;
    tmp = state[18].clone();
    state[18] = &tmp0_2 ^ &tmp1_3 ^ &tmp_bis;
    state[26] = &tmp0_3 ^ &tmp1_0 ^ &tmp;

    tmp0_0 = &state[1] ^ &state[9];
    tmp0_1 = &state[9] ^ &state[17];
    tmp0_2 = &state[17] ^ &state[25];
    tmp0_3 = &state[25] ^ &state[1];
    tmp = state[1].clone();
    state[1] = &tmp1_0 ^ &tmp0_1 ^ &state[25];
    tmp_bis = state[9].clone();
    state[9] = &tmp1_1 ^ &tmp0_2 ^ &tmp;
    tmp = state[17].clone();
    state[17] = &tmp1_2 ^ &tmp0_3 ^ &tmp_bis;
    state[25] = &tmp1_3 ^ &tmp0_0 ^ &tmp;

    tmp = state[0].clone();
    state[0] = &tmp0_0 ^ &tmp2_1 ^ &state[24];
    tmp_bis = state[8].clone();
    state[8] = &tmp0_1 ^ &tmp2_2 ^ &tmp;
    tmp = state[16].clone();
    state[16] = &tmp0_2 ^ &tmp2_3 ^ &tmp_bis;
    state[24] = &tmp0_3 ^ &tmp2_0 ^ &tmp;

    println!("mixcol fhe time     {:.2?}", start.elapsed());
}

#[inline]
fn ark(state: &mut [u32], rkey: &[u32]) {
    for i in 0..32 {
        state[i] ^= rkey[i];
    }
}

#[inline]
fn ark_fhe(state: &mut [FheUint32], rkey: &[FheUint32]) {
    for i in 0..32 {
        state[i] = &state[i] ^ &rkey[i];
    }
}

pub fn aes128_encrypt(out: &mut [u8; 128], input: &[u8; 128], rkeys: &[u32]) {
    let mut state = [0u32; 32];

    packing(&mut state, input);
    print_hex_u32("packing ", &state);

    // offline-phase
    let start = Instant::now();
    let config = ConfigBuilder::default().build();
    #[cfg(not(feature = "gpu"))]
    let (client_key, server_keys) = generate_keys(config);
    #[cfg(feature = "gpu")]
    let client_key = ClientKey::generate(config);
    #[cfg(feature = "gpu")]
    let compressed_server_key = CompressedServerKey::new(&client_key);
    #[cfg(feature = "gpu")]
    let gpu_key = compressed_server_key.decompress_to_gpu();
    println!("gen keys time       {:.2?}", start.elapsed());

    // use vector since FheUint32
    // encrypt states using client_key
    let mut enc_state: Vec<FheUint32> = Vec::new();
    for i in 0..32 {
        match FheUint32::try_encrypt(state[i], &client_key) {
            Ok(encrypted) => {
                // If encryption is successful, push the result into the vector
                enc_state.push(encrypted);
            }
            Err(e) => {
                // Handle encryption failure
                println!("Failed to encrypt the value: {:?}", e);
            }
        }
    }
    // encrypt rkeys using client_key
    let mut enc_rkeys: Vec<FheUint32> = Vec::new();
    for i in 0..11 * 32 {
        match FheUint32::try_encrypt(rkeys[i], &client_key) {
            Ok(encrypted) => {
                // If encryption is successful, push the result into the vector
                enc_rkeys.push(encrypted);
            }
            Err(e) => {
                // Handle encryption failure
                println!("Failed to encrypt the value: {:?}", e);
            }
        }
    }
    println!("client enc state    {:.2?}", start.elapsed());

    // cloud setup
    #[cfg(not(feature = "gpu"))]
    set_server_key(server_keys);
    #[cfg(feature = "gpu")]
    set_server_key(gpu_key);

    let mut tot_ark = Duration::ZERO;
    let mut tot_sbox = Duration::ZERO;
    let mut tot_shiftrows = Duration::ZERO;
    let mut tot_mixcols = Duration::ZERO;
    for i in 0..10 {
        ark(&mut state, &rkeys[i * 32..(i + 1) * 32]);
        let start_ark = Instant::now();
        ark_fhe(&mut enc_state, &enc_rkeys[i * 32..(i + 1) * 32]); // OK
        tot_ark += start_ark.elapsed();
        print_hex_fhe_u32("ark     ", &enc_state, &client_key);

        sbox(&mut state[0..8]);
        sbox(&mut state[8..16]);
        sbox(&mut state[16..24]);
        sbox(&mut state[24..32]);

        let start_sbox = Instant::now();
        sbox_fhe(&mut enc_state[0..8]);
        print_hex_fhe_u32("sbox 1  ", &enc_state, &client_key);
        sbox_fhe(&mut enc_state[8..16]);
        print_hex_fhe_u32("sbox 2  ", &enc_state, &client_key);
        sbox_fhe(&mut enc_state[16..24]);
        print_hex_fhe_u32("sbox 3  ", &enc_state, &client_key);
        sbox_fhe(&mut enc_state[24..32]);
        print_hex_fhe_u32("sbox 4  ", &enc_state, &client_key);
        tot_sbox += start_sbox.elapsed();

        shiftrows(&mut state);
        let start_shiftrows = Instant::now();
        shiftrows_fhe(&mut enc_state);
        print_hex_fhe_u32("shiftrw ", &enc_state, &client_key);
        tot_shiftrows += start_shiftrows.elapsed();

        if i != 9 {
            mixcolumns(&mut state);
            let start_mixcols = Instant::now();
            mixcolumns_fhe(&mut enc_state);
            print_hex_fhe_u32("mixcols ", &enc_state, &client_key);
            tot_mixcols += start_mixcols.elapsed();
        }
    }

    ark(&mut state, &rkeys[320..352]);
    let start_ark = Instant::now();
    ark_fhe(&mut enc_state, &enc_rkeys[320..352]);
    print_hex_fhe_u32("ark     ", &enc_state, &client_key);
    tot_ark += start_ark.elapsed();

    // decrypt state using client key
    for (i, enc_value) in enc_state.iter().enumerate() {
        // Decrypt each value and store it in the state array
        state[i] = enc_value.decrypt(&client_key);
    }

    // at client
    unpacking(out, &mut state);

    println!("\nark       time    {:.2?}", tot_ark);
    println!("\nsbox      time    {:.2?}", tot_sbox);
    println!("\nshiftrows time    {:.2?}", tot_shiftrows);
    println!("\nmixcols   time    {:.2?}", tot_mixcols);
}
