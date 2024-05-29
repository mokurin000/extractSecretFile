pub const fn encrypt_single(byte: u8) -> u8 {
    const MAGIC: u8 = 0x7F;
    byte ^ MAGIC
}

pub const fn xor_encrypt<const N: usize>(input: &[u8; N]) -> [u8; N] {
    let mut output = [0; N];
    let mut i = 0;
    while i < input.len() {
        output[i] = encrypt_single(input[i]);
        i += 1;
    }
    output
}

pub const AES_KEY_ENC: [u8; 32] = xor_encrypt(include_bytes!("../keys/aes_key"));
pub const CBC_IV_ENC: [u8; 16] = xor_encrypt(include_bytes!("../keys/cbc_iv"));
