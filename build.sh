export EXPIRES_AFTER_HOURS=12
target=$(uname -m)-unknown-linux-musl
cargo clean
cargo build --target ${target} --release
