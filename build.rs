use aes::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    Aes256Enc,
};
use cbc::Encryptor;

type Aes256CbcEnc = Encryptor<Aes256Enc>;

use std::{env, error::Error, fs, iter::once, path::Path, time::UNIX_EPOCH};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=keys/aes_key");
    println!("cargo::rerun-if-changed=keys/cbc_iv");

    encrypt_files()?;
    let now_ts = std::time::SystemTime::now().duration_since(UNIX_EPOCH)?;
    println!("cargo::rustc-env=COMPILE_TIME_UNIX={}", now_ts.as_secs());
    Ok(())
}

fn encrypt_files() -> Result<(), Box<dyn Error>> {
    let aes_key = fs::read("keys/aes_key").unwrap();
    let cbc_iv = fs::read("keys/cbc_iv").unwrap();
    let aes_key_bytes = &*aes_key;
    let cbc_iv_bytes = &*cbc_iv;

    let encryptor = Aes256CbcEnc::new(aes_key_bytes.into(), cbc_iv_bytes.into());

    let mut kyinfo = include_bytes!("res/.kyinfo").to_vec();
    let kyinfo_len = kyinfo.len();
    let mut license = include_bytes!("res/LICENSE").to_vec();
    let license_len = license.len();

    // extend to 2 times of original length
    // so we have enough space for padding
    kyinfo.extend(once(0).cycle().take(kyinfo_len));
    license.extend(once(0).cycle().take(license_len));

    let kyinfo_ct = encryptor
        .clone()
        .encrypt_padded_mut::<Pkcs7>(&mut kyinfo, kyinfo_len)
        .unwrap();
    let license_ct = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut license, license_len)
        .unwrap();

    let kyinfo_out = Path::new(&env::var("OUT_DIR")?).join(".kyinfo.enc");
    let license_out = Path::new(&env::var("OUT_DIR")?).join("LICENSE.enc");

    fs::write(kyinfo_out, kyinfo_ct)?;
    fs::write(license_out, license_ct)?;

    Ok(())
}
