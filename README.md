# extract-secret-file

aes_key: 32-bytes AES key, optionally plain text
iv: 16-bytes IV for CBC encryption, optionally plain text

## Build

set `EXPIRES_AFTER_HOURS` if you'd like to set a timer this script expires

## Build Environment

Rustc: 1.58+

```bash
cargo build --release --target=x86_64-unknown-linux-gnu  # GLIBC build
cargo build --release --target=x86_64-unknown-linux-musl # MUSL build
```

