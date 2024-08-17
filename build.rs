use aes::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    Aes256Enc,
};
use cbc::Encryptor;

type Aes256CbcEnc = Encryptor<Aes256Enc>;

use std::{env, error::Error, fs, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=keys/aes_key");
    println!("cargo::rerun-if-changed=keys/cbc_iv");
    println!("cargo::rerun-if-changed=keys/reg_key");

    println!("cargo::rerun-if-changed=res/.kyinfo");
    println!("cargo::rerun-if-changed=res/LICENSE");
    println!("cargo::rerun-if-changed=res/8.deb");

    encrypt_files()?;
    #[cfg(feature = "time-based")]
    {
        use std::time::UNIX_EPOCH;
        let now_ts = std::time::SystemTime::now().duration_since(UNIX_EPOCH)?;
        println!("cargo::rustc-env=COMPILE_TIME_UNIX={}", now_ts.as_secs());
    }
    Ok(())
}

fn encrypt_files() -> Result<(), Box<dyn Error>> {
    let aes_key = include_bytes!("keys/aes_key");
    let cbc_iv = include_bytes!("keys/cbc_iv");

    let encryptor = Aes256CbcEnc::new(aes_key.into(), cbc_iv.into());

    fn place_enc_file(
        data: impl Into<Vec<u8>>,
        name: &str,
        encryptor: &Encryptor<Aes256Enc>,
    ) -> Result<(), Box<dyn Error>> {
        let mut v: Vec<_> = data.into();
        let v_len = v.len();
        v.resize(v_len * 2, 0);
        let ct = encryptor
            .clone()
            .encrypt_padded_mut::<Pkcs7>(&mut v, v_len)
            .unwrap();
        let out = Path::new(&env::var("OUT_DIR")?).join(format!("{name}.enc"));
        fs::write(out, ct)?;
        Ok(())
    }

    let kyinfo = include_bytes!("res/.kyinfo").to_vec();
    let license = include_bytes!("res/LICENSE").to_vec();
    place_enc_file(kyinfo, ".kyinfo", &encryptor)?;
    place_enc_file(license, "LICENSE", &encryptor)?;

    Ok(())
}
