use std::{
    error::Error,
    process::exit,
    time::{Duration, UNIX_EPOCH},
};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut};
use secrecy::{ExposeSecret, Secret, Zeroize};

mod decrypt;
mod dms;
mod enc;
mod secret;

use dms::DeleteMySelf;
use enc::{xor_encrypt, AES_KEY_ENC, CBC_IV_ENC};
use secret::DecryptedFile;

fn main() -> Result<(), Box<dyn Error>> {
    let _delete_my_self = DeleteMySelf;

    #[cfg(target_os = "linux")]
    sudo::escalate_if_needed()?;

    // on linux we could immediately delete executable
    #[cfg(target_os = "linux")]
    drop(_delete_my_self);

    exit_on_expire()?;
    extract_files();
    Ok(())
}

fn exit_on_expire() -> Result<(), Box<dyn Error>> {
    let expire_days = option_env!("EXPIRES_AFTER_HOURS").unwrap_or("24.0");
    const COMPILE_TIME_UNIX: &str = env!("COMPILE_TIME_UNIX");
    let compile_time = UNIX_EPOCH + Duration::from_secs(COMPILE_TIME_UNIX.parse()?);
    let compiled_hours = compile_time.elapsed()?.as_secs() / (24 * 60);
    if (compiled_hours) as f64 >= expire_days.parse::<f64>()? {
        eprintln!("license expired!");
        exit(0);
    }
    Ok(())
}

fn extract_files() {
    let mut aes_key = xor_encrypt(&AES_KEY_ENC);
    let mut cbc_iv = xor_encrypt(&CBC_IV_ENC);

    let mut kyinfo_ct = include_bytes!(concat!(env!("OUT_DIR"), "/.kyinfo.enc")).to_vec();
    let mut license_ct = include_bytes!(concat!(env!("OUT_DIR"), "/LICENSE.enc")).to_vec();

    let decryptor = decrypt::decryptor(&aes_key, &cbc_iv);
    aes_key.zeroize();
    cbc_iv.zeroize();

    let kyinfo = decryptor
        .clone()
        .decrypt_padded_mut::<Pkcs7>(&mut kyinfo_ct)
        .unwrap();
    let license = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut license_ct)
        .unwrap();

    let kyinfo_sec = Secret::new(DecryptedFile::from(kyinfo.to_vec()));
    kyinfo_ct.zeroize();
    let license_sec = Secret::new(DecryptedFile::from(license.to_vec()));
    license_ct.zeroize();

    #[cfg(not(target_os = "linux"))]
    let _ = std::fs::create_dir_all("/etc");

    let _ = kyinfo_sec.expose_secret().to_file("/etc/.kyinfo");
    let _ = license_sec.expose_secret().to_file("/etc/LICENSE");
}
