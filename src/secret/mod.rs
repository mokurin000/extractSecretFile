use std::{fs, io, path::Path};

use secrecy::{DebugSecret, Zeroize};

pub struct DecryptedFile(Vec<u8>);

impl DecryptedFile {
    pub fn to_file<P>(&self, path: P) -> io::Result<()>
    where
        P: AsRef<Path>,
    {
        fs::write(path, &self.0)
    }
}

impl From<Vec<u8>> for DecryptedFile {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Zeroize for DecryptedFile {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl DebugSecret for DecryptedFile {}
