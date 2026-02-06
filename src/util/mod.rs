use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::iter::repeat;
use std::process::Command;
use sha2::{Sha256, Digest};
mod template;

#[cfg(debug_assertions)]
fn rand_string(_len: u32) -> String {
    String::from("rand_string_in_test_cfg")
}

#[cfg(not(debug_assertions))]
fn rand_string(len: u32) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                              abcdefghijklmnopqrstuvwxyz\
                              0123456789";
    return (0..len)
        .map(|_| {
            let i = rand::random::<usize>() % CHARSET.len();
            CHARSET[i] as char
        })
        .collect();
}

fn find_interp(content: &str) -> (String, String) {
    if content.starts_with("#!") {
        let lines: Vec<&str> = content.split('\n').collect();
        let first: Vec<&str> = lines[0].trim().split(' ').collect();
        if first.is_empty() {
            (String::from("bash"), content.to_owned())
        } else {
            let interp = String::from(
                first[0]
                    .split('/')
                    .collect::<Vec<&str>>()
                    .last()
                    .unwrap()
                    .to_owned(),
            );
            (interp, lines[1..lines.len()].join("\n"))
        }
    } else {
        (String::from("bash"), content.to_owned())
    }
}

fn compile_it(file: &str) {
    println!("compile it ... {}", file);
    let output = Command::new("rustc")
        .arg(file)
        .arg("-C").arg("strip=symbols")
        .arg("-C").arg("opt-level=z")
        .output()
        .expect("failed to compile");

    let stdout = output.stdout;
    let stderr = output.stderr;
    if !stdout.is_empty() {
        println!("{}", String::from_utf8_lossy(&stdout));
    }
    if !stderr.is_empty() {
        println!("{}", String::from_utf8_lossy(&stderr));
    }
    if output.status.success() {
        println!(
            "compiled success, try it with: ./{}",
            file.replace(".rs", "")
        );
    } else {
        std::process::exit(1);
    }
}

#[cfg(debug_assertions)]
fn rand_bytes(len: usize) -> Vec<u8> {
    vec![0x42; len]
}

#[cfg(not(debug_assertions))]
fn rand_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn gen_and_compile(file: &str, rs_file: &str, pass: &str) -> Result<(), Box<dyn Error>> {
    let source = fs::read_to_string(file).expect("Failed to read source file");
    let (interp, striped) = find_interp(&source);
    let rand_key = rand_string(128);
    let encoded_vec = Arc4::new(rand_key.as_bytes()).trans_str(&striped);
    let encoded_str = format!("vec!{:?}", encoded_vec);

    // Key obfuscation: split key into key_mask XOR key_masked
    let key_bytes = rand_key.as_bytes();
    let key_mask = rand_bytes(key_bytes.len());
    let key_masked: Vec<u8> = key_bytes
        .iter()
        .zip(key_mask.iter())
        .map(|(k, m)| k ^ m)
        .collect();
    let key_mask_str = format!("vec!{:?}", key_mask);
    let key_masked_str = format!("vec!{:?}", key_masked);

    // Password protection: store salted SHA-256 hash instead of the password itself
    let (pass_salt, pass_hash) = if !pass.is_empty() {
        let salt = rand_bytes(16);
        let mut data = Vec::new();
        data.extend_from_slice(pass.as_bytes());
        data.extend_from_slice(&salt);
        let hash = sha256(&data);
        (salt, hash.to_vec())
    } else {
        (vec![], vec![])
    };
    let pass_salt_str = format!("vec!{:?}", pass_salt);
    let pass_hash_str = format!("vec!{:?}", pass_hash);

    let prog = template::prog()
        .replace("{ script_code }", &encoded_str)
        .replace("{ key_mask }", &key_mask_str)
        .replace("{ key_masked }", &key_masked_str)
        .replace("{ pass_salt }", &pass_salt_str)
        .replace("{ pass_hash }", &pass_hash_str)
        .replace("{ interp }", &interp);

    File::create(rs_file)?.write_all(prog.as_bytes())?;
    compile_it(&rs_file.to_string());
    Ok(())
}

pub struct Arc4 {
    i: u8,
    j: u8,
    state: [u8; 256],
}

impl Arc4 {
    pub fn new(key: &[u8]) -> Arc4 {
        assert!(!key.is_empty() && key.len() <= 256);
        let mut rc4 = Arc4 {
            i: 0,
            j: 0,
            state: [0; 256],
        };
        for (i, x) in rc4.state.iter_mut().enumerate() {
            *x = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j
                .wrapping_add(rc4.state[i])
                .wrapping_add(key[i % key.len()]);
            rc4.state.swap(i, j as usize);
        }
        rc4
    }
    fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        self.state[(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize]
    }

    fn encode_vec(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        for (x, y) in input.iter().zip(output.iter_mut()) {
            *y = *x ^ self.next();
        }
    }

    pub fn trans_vec(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = repeat(0).take(input.len()).collect();
        self.encode_vec(input, &mut out);
        out.to_vec()
    }

    pub fn trans_str(&mut self, str: &str) -> Vec<u8> {
        self.trans_vec(&str.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::Path;

    #[test]
    fn test_find_interp() {
        let text = String::from("#!/bin/expect -f\nsend 1 2 3");
        let (interp, _) = find_interp(&text);
        println!("interp: {}", interp);
        assert!(interp == "expect");

        let text = String::from("#!/bin/bash -f\nsend 1 2 3");
        let (interp, _) = find_interp(&text);
        println!("interp: {}", interp);
        assert!(interp == "bash");

        let text = String::from("#!/bash -f\nsend 1 2 3");
        let (interp, _) = find_interp(&text);
        println!("interp: {}", interp);
        assert!(interp == "bash");

        let text = String::from("#!/bin/ruby ");
        let (interp, _) = find_interp(&text);
        println!("interp: {}", interp);
        assert!(interp == "ruby");

        let text = String::from("send 1 2 3");
        let (interp, _) = find_interp(&text);
        println!("interp: {}", interp);
        assert!(interp == "bash");
    }

    #[test]
    fn test_encode_decode() {
        let content = String::from("ahah, this is hello world!");
        let encoded = Arc4::new(b"hello").trans_str(&content.clone());
        let decoded = Arc4::new(b"hello").trans_vec(&encoded);
        let result = String::from_utf8_lossy(&decoded);
        assert!(result == content);
    }

    #[test]
    fn test_compile_run() -> Result<(), Box<dyn Error>> {
        let dir = env::current_dir()?;
        let path = format!("{}/examples", dir.display());
        env::set_current_dir(Path::new(&path)).unwrap();
        let files = fs::read_dir(path.to_owned())?;
        for file in files {
            let p = file.unwrap().path();
            let s = p.to_str().unwrap();
            if !s.ends_with(".out") && s.contains(".") {
                let out = format!("{}.out", s.replace(".", "_"));
                println!("out: {} {}", s, out);
                gen_and_compile(s, &out.to_owned(), "")?;
            }
        }

        let output = Command::new("./7_rb")
            .args(vec!["1", "2", "3"])
            .output()
            .expect("failed to execute");

        let out = String::from_utf8_lossy(&output.stdout);
        println!("now out: {}", out);
        assert!(out.trim() == "[\"1\", \"2\", \"3\"]");
        Ok(())
    }

    #[test]
    fn test_encode() {
        struct Test {
            key: &'static str,
            input: &'static str,
            output: Vec<u8>,
        }

        fn tests() -> Vec<Test> {
            vec![
                Test {
                    key: "Key",
                    input: "Plaintext",
                    output: vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3],
                },
                Test {
                    key: "Wiki",
                    input: "pedia",
                    output: vec![0x10, 0x21, 0xBF, 0x04, 0x20],
                },
                Test {
                    key: "Secret",
                    input: "Attack at dawn",
                    output: vec![
                        0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B,
                        0x9B, 0xF5,
                    ],
                },
            ]
        }

        let tests = tests();
        for t in tests.iter() {
            let result = Arc4::new(t.key.to_string().as_bytes()).trans_str(&t.input.to_string());
            assert!(result == t.output);
        }
    }

    #[test]
    fn test_key_obfuscation_xor_roundtrip() {
        // Verify that key_mask XOR key_masked correctly reconstructs the original key
        let original_key = b"rand_string_in_test_cfg";
        let key_mask = rand_bytes(original_key.len());
        let key_masked: Vec<u8> = original_key
            .iter()
            .zip(key_mask.iter())
            .map(|(k, m)| k ^ m)
            .collect();

        // Reconstruct key (same logic as in generated binary)
        let reconstructed: Vec<u8> = key_mask
            .iter()
            .zip(key_masked.iter())
            .map(|(m, d)| m ^ d)
            .collect();

        assert_eq!(reconstructed, original_key.to_vec());
    }

    #[test]
    fn test_key_obfuscation_no_plaintext_in_output() {
        // Verify that the generated .rs file does NOT contain the plaintext key
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let script = format!("{}/examples/2.sh", manifest_dir);
        let out_rs = format!("{}/examples/test_obf_check.rs", manifest_dir);

        gen_and_compile(&script, &out_rs, "").unwrap();

        let generated = fs::read_to_string(&out_rs).unwrap();
        let key = "rand_string_in_test_cfg";

        // The plaintext key string should NOT appear as a quoted string in the generated code
        assert!(
            !generated.contains(&format!("\"{}\"", key)),
            "Generated .rs file should not contain the plaintext key as a string literal"
        );

        // key_mask and key_masked byte arrays should be present instead
        assert!(
            generated.contains("key_mask"),
            "Generated .rs file should contain key_mask"
        );
        assert!(
            generated.contains("key_masked"),
            "Generated .rs file should contain key_masked"
        );

        // Clean up
        let bin_path = out_rs.replace(".rs", "");
        let _ = fs::remove_file(&out_rs);
        let _ = fs::remove_file(&bin_path);
    }

    #[test]
    fn test_key_obfuscation_decrypt_still_works() {
        // End-to-end: encrypt with original key, then decrypt using XOR-reconstructed key
        let content = "echo hello world";
        let original_key = "test_key_12345";

        // Encrypt
        let encrypted = Arc4::new(original_key.as_bytes()).trans_str(&content.to_string());

        // Simulate obfuscation
        let key_bytes = original_key.as_bytes();
        let key_mask = rand_bytes(key_bytes.len());
        let key_masked: Vec<u8> = key_bytes
            .iter()
            .zip(key_mask.iter())
            .map(|(k, m)| k ^ m)
            .collect();

        // Reconstruct key and decrypt (same as generated binary does)
        let reconstructed_key: Vec<u8> = key_mask
            .iter()
            .zip(key_masked.iter())
            .map(|(m, d)| m ^ d)
            .collect();
        let decrypted = Arc4::new(&reconstructed_key).trans_vec(&encrypted);
        let result = String::from_utf8(decrypted).unwrap();

        assert_eq!(result, content);
    }

    #[test]
    fn test_sha256_known_vectors() {
        // Test against known SHA-256 test vectors
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let empty_hash = sha256(b"");
        assert_eq!(
            empty_hash,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
                0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
                0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
            ]
        );

        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let abc_hash = sha256(b"abc");
        assert_eq!(
            abc_hash,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn test_password_hash_not_in_output() {
        // Verify that the generated .rs file contains hash/salt, not plaintext password
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let script = format!("{}/examples/2.sh", manifest_dir);
        let out_rs = format!("{}/examples/test_pass_hash_check.rs", manifest_dir);

        gen_and_compile(&script, &out_rs, "my_secret_password").unwrap();

        let generated = fs::read_to_string(&out_rs).unwrap();

        // Plaintext password must NOT appear anywhere in the generated code
        assert!(
            !generated.contains("my_secret_password"),
            "Generated .rs file must not contain plaintext password"
        );

        // Should contain hash-based fields instead
        assert!(generated.contains("pass_salt"), "Should contain pass_salt");
        assert!(generated.contains("pass_hash"), "Should contain pass_hash");

        // Clean up
        let bin_path = out_rs.replace(".rs", "");
        let _ = fs::remove_file(&out_rs);
        let _ = fs::remove_file(&bin_path);
    }
}
