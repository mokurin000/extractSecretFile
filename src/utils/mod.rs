use std::process::Command;

use aes::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyInit},
    Aes256Enc,
};

use crate::Result;

pub fn serial_number() -> Result<Vec<u8>> {
    let out = Command::new("dmidecode")
        .arg("-s")
        .arg("system-serial-number")
        .output()?;
    let stdout = out.stdout;
    let out = String::from_utf8(stdout)?;
    Ok(out.trim().as_bytes().to_owned())
}

pub fn sn_to_key(serial_number: &[u8]) -> String {
    let mut regcode = serial_number.to_owned();
    let msg_len = regcode.len();
    regcode.resize(256, 0);

    let enc = Aes256Enc::new(include_bytes!("../../keys/reg_key").into())
        .encrypt_padded_mut::<Pkcs7>(&mut regcode, msg_len)
        .unwrap();
    hex_simd::encode_to_string(enc, hex_simd::AsciiCase::Lower)
}
