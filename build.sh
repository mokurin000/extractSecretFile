export EXPIRES_AFTER_DAYS=1
target=$(uname -m)-unknown-linux-musl
cargo clean
cargo build --target ${target} --release
