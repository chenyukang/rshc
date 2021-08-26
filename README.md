# rshc

[![ci](https://github.com/chenyukang/rshc/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/chenyukang/rshc/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/chenyukang/rshc/branch/main/graph/badge.svg)](https://codecov.io/gh/chenyukang/rshc)


rshc: Compile shell script(or expect script) to Rust code and binary.

**This is an script obfuscator rather than a real compiler!**

Rshc takes a script, which is specified on the command line and produces Rust source code. 

The generated source code is then compiled and linked to produce a stripped binary executable, which use the Rust compiler.

Actual execution will use process to exec the script, the but source code of script is encoded in binary with Rc4 algorithm.

This is used as:

1. For the expect script which maybe contains some password, I will compile binary and remove the script.

2. For some scripts which I want to add password for it.

## Install

You need also install rustc, because rshc will use rustc to compile to binary.

1. Install rustc if you didn't installed: 

```bash
curl https://sh.rustup.rs -sSf | sh
```

2. install the rshc cli app:

```bash
cargo install rshc
```

## Usage

```rust
rshc -f demo.sh -o demo.rs

// add a passowrd when compile it, then binary will prompt for correct password before execution
rshc -f demo.sh -o demo.rs -p
```

try it with 

```shell
./demo
```
