#!/bin/bash

rm -rf .cargo
mkdir -p .cargo
cargo vendor > .cargo/config.toml
