mod aes128_barrel_tfhe;
mod aes128_keyschedule_lut;

use crate::aes128_barrel_tfhe::aes128_encrypt;
use crate::aes128_keyschedule_lut::aes128_keyschedule_lut;

use std::time::Instant;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

fn print_hex(label: &str, data: &[u8]) {
    let hex_output: String = data.iter().map(|byte| format!("{:02x}", byte)).collect();

    println!("{}          {}", label, hex_output);
}

fn main() {
    // FIPS-197 Test Input
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    let mut ga_block = GenericArray::from(plaintext);
    let cipher = Aes128::new(&GenericArray::from(key));

    cipher.encrypt_block(&mut ga_block);
    println!("ref AES             {:x}", ga_block);

    let plaintext_128: [u8; 128] = {
        let mut data = [0u8; 128];
        data[..16].copy_from_slice(&plaintext);
        data
    };
    let mut ciphertext_128 = [0u8; 128];
    let mut round_keys = vec![0u32; 11 * 32];

    aes128_keyschedule_lut(&mut round_keys, &key);

    let start = Instant::now();
    aes128_encrypt(&mut ciphertext_128, &plaintext_128, &round_keys);
    println!("out time            {:.2?}", start.elapsed());

    print_hex("plaintext ", &plaintext_128[0..16]);
    print_hex("key       ", &key);
    print_hex("cloud AES ", &ciphertext_128[0..16]);
}
