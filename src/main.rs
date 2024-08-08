use std::io::{stderr, stdin, Write};
use std::process::exit;

use extract_secret_file::extract::extract_files;
use extract_secret_file::net::Verify;
use extract_secret_file::utils::{code_to_key, unique_code};
use reqwest::header::CONTENT_TYPE;
use secrecy::{ExposeSecret, Secret};

#[cfg(feature = "delete-my-self")]
use extract_secret_file::dms;
use extract_secret_file::Result;

#[cfg(feature = "delete-my-self")]
use dms::DeleteMySelf;
use serde_json::json;

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

    extract_files()?;
    Ok(())
}

fn ask_keypass() -> Result<()> {
    let sn = unique_code()?;

    let key = Secret::new(code_to_key(&sn));
    eprintln!("您的序列号为: {}", String::from_utf8(sn)?);
    let mut user_key = String::new();

    eprint!("请输入注册码: ");
    stderr().flush()?;
    stdin().read_line(&mut user_key)?;

    // remove '\n' at the end
    user_key = user_key.trim().to_owned();

    match user_key.len() {
        // online mode
        8 => {
            let content = json!({
                        "serial_number": user_key,
                        "registration_code": key.expose_secret(),
            });
            let post_url = "http://8.134.130.103:8000/register";
            let client = reqwest::blocking::Client::new();
            let resp = client
                .post(post_url)
                .header(CONTENT_TYPE, "application/json")
                .json(&content)
                .send();
            let resp: Verify = match resp {
                Err(e) => {
                    eprintln!("网络错误！请稍后重试\n{e}");
                    exit(1);
                }
                Ok(r) => r.json()?,
            };

            if !resp.verified {
                println!("验证未通过！");
                println!("{:#?}", resp);
                exit(1);
            }
        }
        // offline mode
        9 => {
            if key.expose_secret() != &user_key {
                println!("注册密码错误！");
                exit(2);
            }
        }
        _ => {
            eprintln!("无效密码！");
            exit(1)
        }
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
