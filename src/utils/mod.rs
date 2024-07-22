use std::{iter::once, process::Command};

use aes::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyInit},
    Aes256Enc,
};

use crate::Result;

pub fn kylin_register_code() -> Result<Vec<u8>> {
    let out = Command::new("kylin_gen_register").output()?;
    let stdout = out.stdout;
    let out = String::from_utf8(stdout)?;
    Ok(out.trim().as_bytes().to_owned())
}

pub fn regcode_to_key(regcode: &[u8]) -> String {
    let mut regcode = regcode.to_owned();
    let msg_len = regcode.len();
    // 2x buffer size
    regcode.extend(once(0).cycle().take(msg_len));

    let enc = Aes256Enc::new(include_bytes!("../../keys/reg_key").into())
        .encrypt_padded_mut::<Pkcs7>(&mut regcode, msg_len)
        .unwrap();
    hex_simd::encode_to_string(enc, hex_simd::AsciiCase::Lower)
}
