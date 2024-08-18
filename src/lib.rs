use std::error::Error;

pub mod decrypt;
pub mod enc_mem;
pub mod extract;
pub mod secret;
pub mod utils;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[cfg(feature = "online-mode")]
pub mod net;
