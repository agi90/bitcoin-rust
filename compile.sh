#!/bin/bash

set -ev
cd src

cargo build
cargo test
