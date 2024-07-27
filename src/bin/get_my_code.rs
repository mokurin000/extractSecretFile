use extract_secret_file::utils::unique_code;
use extract_secret_file::Result;

fn main() -> Result<()> {
    #[cfg(target_os = "linux")]
    sudo::escalate_if_needed()?;

    let sn = unique_code()?;

    println!("{}", String::from_utf8(sn)?);

    Ok(())
}
