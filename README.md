# rshc

[![ci](https://github.com/chenyukang/rshc/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/chenyukang/rshc/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/chenyukang/rshc/branch/master/graph/badge.svg?token=AAQREZTXYK)](https://codecov.io/gh/chenyukang/rshc)


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

## Security Hardening

rshc applies multiple layers of security hardening to protect compiled scripts from reverse engineering and tampering.

### 1. RC4 Stream Cipher Encryption

The script source code is encrypted using the **RC4 (Arc4)** stream cipher with a randomly generated 128-character key. The encrypted script is embedded in the binary as a byte array and only decrypted at runtime immediately before execution.

### 2. Key Obfuscation (XOR Mask)

The RC4 encryption key is never stored in plaintext. Instead, it is split into two byte arrays — `key_mask` (random bytes) and `key_masked` (key XOR mask). At runtime, the original key is reconstructed via `key = key_mask XOR key_masked`. This prevents extraction of the encryption key through `strings` or hex editors.

### 3. Secure Script Execution via Stdin Pipe

Instead of passing the decrypted script as a command-line argument (which would expose it in `ps aux` and `/proc/*/cmdline`), the binary writes the script to the interpreter's **stdin** via `Stdio::piped()`. Process listings only show the interpreter name (e.g., `bash -s`), not the script content.

### 4. SHA-256 Password Hashing with Salt

When password protection is enabled (`-p` flag), the password is **never stored in the binary**. Instead, a random 16-byte salt is generated, and the SHA-256 hash of `password + salt` is stored. At runtime, the user's input is hashed with the same salt and compared. This makes rainbow table attacks infeasible. The SHA-256 implementation in the generated binary is self-contained (no external crate dependency).

### 5. Password Input Masking

Password input uses **termios raw mode** to disable terminal echo. Each character typed displays an asterisk (`*`), and backspace is supported. Ctrl-C restores the terminal state before exiting. This prevents shoulder-surfing and terminal history leakage.

### 6. Symbol Stripping and Size Optimization

Generated binaries are compiled with `rustc -C strip=symbols -C opt-level=z`, which removes the symbol table and debug information, and optimizes for minimal binary size. This significantly raises the difficulty of static analysis and disassembly.

### 7. Interpreter String Encryption

Interpreter names (e.g., `bash`, `ruby`, `python`, `expect`) are **XOR-encoded** with a random mask byte at compile time. At runtime, an `obf_decode()` function reconstructs the strings. This prevents identification of the target interpreter through `strings` analysis of the binary.

### 8. Error Message Obfuscation

All user-facing strings (e.g., password prompts, error messages) and internal interpreter comparison strings are stored as **XOR-encoded byte arrays** with fixed masks. The `.expect()` calls are replaced with silent `exit(1)` on failure, preventing error messages from leaking implementation details.

### 9. Memory Zeroing (Volatile Writes)

All sensitive data is **securely zeroed** after use with `std::ptr::write_volatile()` to prevent compiler optimization from eliding the zeroing. This covers:
- User password input and hash intermediate data
- Reconstructed RC4 key and its XOR components (`key_mask`, `key_masked`)
- RC4 cipher internal state (256-byte S-box, index pointers)
- Decrypted script content (both `Vec<u8>` and `String` forms)

### 10. Anti-Debugging Detection

The generated binary runs a multi-layered debugger detection routine **before any decryption** occurs:

| Check | Platform | Mechanism |
|-------|----------|-----------|
| `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` | macOS + Linux | Detects dynamic library injection / function hooking |
| `ptrace(PT_DENY_ATTACH)` | macOS | Prevents debuggers from attaching to the process |
| `sysctl` P_TRACED flag | macOS | Queries the kernel for the process's traced status |
| `ptrace(PTRACE_TRACEME)` | Linux | Fails if another debugger is already attached |
| `/proc/self/status` TracerPid | Linux | Reads the tracer PID from the proc filesystem |

All detections exit silently with code 1, leaking no information about why execution was refused.

### 11. Binary Self-Checksum (Integrity Verification)

After compilation, the **SHA-256 hash** of the entire binary is computed and appended to the file (32 bytes). At runtime, the binary reads itself via `std::env::current_exe()`, splits off the last 32 bytes as the expected checksum, and recomputes the hash of the remaining content. If the checksums do not match (indicating patching, injection, or corruption), the binary exits silently. This protects against post-compilation binary patching attacks.
