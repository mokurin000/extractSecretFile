use std::io::{stderr, stdin, Write};
use std::process::exit;
use std::str::FromStr;

use extract_secret_file::extract::extract_files;
use extract_secret_file::utils::{serial_number, sn_to_key};
use secrecy::{ExposeSecret, SecretString};

#[cfg(feature = "delete-my-self")]
use extract_secret_file::dms;
use extract_secret_file::Result;

#[cfg(feature = "delete-my-self")]
use dms::DeleteMySelf;

fn main() -> Result<()> {
    #[cfg(feature = "delete-my-self")]
    let _delete_my_self = DeleteMySelf;
    #[cfg(feature = "delete-my-self")]
    {
        // on linux we could immediately delete executable
        #[cfg(target_os = "linux")]
        drop(_delete_my_self);
    }

    #[cfg(target_os = "linux")]
    sudo::escalate_if_needed()?;

    #[cfg(feature = "time-based")]
    exit_on_expire()?;

    ask_keypass()?;

    extract_files();
    Ok(())
}

fn ask_keypass() -> Result<()> {
    let sn = serial_number()?;
    let key = SecretString::from_str(&sn_to_key(&sn))?;
    let mut user_key = String::new();
    eprint!("注册密码：");
    stderr().flush()?;
    stdin().read_line(&mut user_key)?;

    if key.expose_secret() != user_key.trim() {
        println!("注册密码错误！");
        exit(1);
    }

    Ok(())
}

#[cfg(feature = "time-based")]
fn exit_on_expire() -> Result<()> {
    use std::time::{Duration, UNIX_EPOCH};
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
