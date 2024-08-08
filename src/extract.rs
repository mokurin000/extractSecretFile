use std::error::Error;
use std::process::{Command, Stdio};

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::BlockDecryptMut;
use secrecy::{ExposeSecret, Secret, Zeroize};

use crate::decrypt;
use crate::enc_mem::xor_encrypt;
use crate::enc_mem::{AES_KEY_ENC, CBC_IV_ENC};
use crate::secret::DecryptedFile;

pub fn extract_files() -> Result<(), Box<dyn Error>> {
    let mut aes_key = xor_encrypt(&AES_KEY_ENC);
    let mut cbc_iv = xor_encrypt(&CBC_IV_ENC);

    let mut kyinfo_ct = include_bytes!(concat!(env!("OUT_DIR"), "/.kyinfo.enc")).to_vec();
    let mut license_ct = include_bytes!(concat!(env!("OUT_DIR"), "/LICENSE.enc")).to_vec();
    let mut deb_ct = include_bytes!(concat!(env!("OUT_DIR"), "/8.deb.enc")).to_vec();

    let decryptor = decrypt::decryptor(&aes_key, &cbc_iv);
    aes_key.zeroize();
    cbc_iv.zeroize();

    let kyinfo = decryptor
        .clone()
        .decrypt_padded_mut::<Pkcs7>(&mut kyinfo_ct)
        .unwrap();
    let license = decryptor
        .clone()
        .decrypt_padded_mut::<Pkcs7>(&mut license_ct)
        .unwrap();
    let deb = decryptor
        .clone()
        .decrypt_padded_mut::<Pkcs7>(&mut deb_ct)
        .unwrap();

    let kyinfo_sec = Secret::new(DecryptedFile::from(kyinfo.to_vec()));
    let license_sec = Secret::new(DecryptedFile::from(license.to_vec()));
    let deb_sec = Secret::new(DecryptedFile::from(deb.to_vec()));

    kyinfo_ct.zeroize();
    license_ct.zeroize();
    deb_ct.zeroize();

    #[cfg(not(target_os = "linux"))]
    let _ = std::fs::create_dir_all("/etc");

    workaround_2403(deb_sec)?;

    let _ = kyinfo_sec.expose_secret().to_file("/etc/.kyinfo");
    let _ = license_sec.expose_secret().to_file("/etc/LICENSE");

    Ok(())
}

fn workaround_2403(deb_sec: Secret<DecryptedFile>) -> Result<(), Box<dyn Error>> {
    {
        let tempfile = mktemp::TempFile::new("", ".deb").unwrap();
        let path = tempfile.path();
        let _ = deb_sec.expose_secret().to_file(path);

        Command::new("sh")
            .arg("-c")
            .arg(format!("dpkg -i {path}"))
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?
            .wait()?;
    }

    Command::new("sh")
        .arg("-c")
        .arg("apt remove -y ccblicense")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?
        .wait()?;

    Ok(())
}
