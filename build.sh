export EXPIRES_AFTER_DAYS=1
target=$(uname -m)-unknown-linux-musl
cargo build --target ${target} --release
