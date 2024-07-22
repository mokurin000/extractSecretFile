use extract_secret_file::utils::serial_number;
use extract_secret_file::Result;

fn main() -> Result<()> {
    #[cfg(target_os = "linux")]
    sudo::escalate_if_needed()?;
    let sn = serial_number()?;

    println!("{}", String::from_utf8(sn)?);

    Ok(())
}
