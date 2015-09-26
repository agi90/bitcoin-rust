#!/bin/bash

set -ev
cd src

/usr/local/bin/cargo build
/usr/local/bin/cargo test
