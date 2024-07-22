use aes::cipher::block_padding::Pkcs7;
use aes::cipher::BlockDecryptMut;
use secrecy::{ExposeSecret, Secret, Zeroize};

use crate::decrypt;
use crate::enc_mem::xor_encrypt;
use crate::enc_mem::{AES_KEY_ENC, CBC_IV_ENC};
use crate::secret::DecryptedFile;

pub fn extract_files() {
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
