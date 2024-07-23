use std::io::stdin;

use extract_secret_file::utils::code_to_key;
use extract_secret_file::Result;

fn main() -> Result<()> {
    let mut regcode = String::new();
    stdin().read_line(&mut regcode)?;

    let regcode = regcode.trim();
    let _regcode = regcode.as_bytes();
    let key = code_to_key(_regcode);

    println!("{key}");

    Ok(())
}
