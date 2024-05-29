use aes::{cipher::KeyIvInit, Aes256Dec};
use cbc::Decryptor;

type Aes256CbcDec = Decryptor<Aes256Dec>;

pub fn decryptor(key: &[u8; 32], iv: &[u8; 16]) -> Aes256CbcDec {
    Aes256CbcDec::new(key.into(), iv.into())
}
