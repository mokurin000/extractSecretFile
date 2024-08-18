#!/usr/bin/bash

target="$(uname -m)"-unknown-linux-musl

rustup target add ${target}
cargo build --release --no-default-features --target ${target}
