use std::process::Command;

use aes::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyInit},
    Aes256Enc,
};

use crate::Result;

pub fn unique_code() -> Result<Vec<u8>> {
    let out = Command::new("sh")
        .arg("-c")
        .arg("ip -o link | grep link/ether | awk '{ print $17 }' | head -1; dmidecode -s system-serial-number")
        .output()?;
    let stdout = out.stdout;
    let md5 = md5::compute(stdout);
    let hex = hex_simd::encode_to_string(md5.0, hex_simd::AsciiCase::Lower);
    Ok(hex.as_bytes().to_owned())
}

pub fn code_to_key(code: &[u8]) -> String {
    let mut regcode = code.to_owned();
    let msg_len = regcode.len();
    regcode.resize(256, 0);

    let enc = Aes256Enc::new(include_bytes!("../../keys/reg_key").into())
        .encrypt_padded_mut::<Pkcs7>(&mut regcode, msg_len)
        .unwrap();
    let md5 = md5::compute(enc);
    let hex = hex_simd::encode_to_string(md5.0, hex_simd::AsciiCase::Lower);
    unsafe { String::from_utf8_unchecked(hex.as_bytes()[..9].to_vec()) }
}
