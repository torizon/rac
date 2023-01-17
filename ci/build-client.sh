#!/bin/bash

cargo build --target aarch64-unknown-linux-musl --release

cp target/aarch64-unknown-linux-musl/release/rac ./rac-arm
