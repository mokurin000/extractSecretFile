use std::error::Error;

pub mod decrypt;
pub mod dms;
pub mod enc_mem;
pub mod secret;
pub mod utils;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
