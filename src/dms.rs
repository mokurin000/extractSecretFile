/// do not construct me more than once
pub struct DeleteMySelf;

impl Drop for DeleteMySelf {
    fn drop(&mut self) {
        #[allow(unused)]
        use std::{env::args, fs::remove_file, process};

        let myself = args().next().unwrap();
        #[cfg(not(windows))]
        let _ = remove_file(myself);
        #[cfg(windows)]
        let _ = process::Command::new("powershell")
            .arg("-Command")
            .arg(format!("sleep 0.5; del \"{myself}\""))
            .spawn();
    }
}
