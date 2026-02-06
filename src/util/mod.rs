use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::iter::repeat;
use std::process::Command;
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
    let bin_path = file.replace(".rs", "");
    let output = Command::new("rustc")
        .arg(file)
        .arg("-o")
        .arg(&bin_path)
        .arg("-C")
        .arg("strip=symbols")
        .arg("-C")
        .arg("opt-level=z")
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
        // Append self-checksum: SHA-256 of the binary appended to its end
        let bin_data = fs::read(&bin_path).expect("failed to read compiled binary");
        let hash = sha256(&bin_data);
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&bin_path)
            .expect("failed to open binary for checksum append");
        f.write_all(&hash).expect("failed to append checksum");

        println!("compiled success, try it with: ./{}", bin_path);
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

    // Interpreter string obfuscation: XOR with random mask byte
    let interp_mask_byte = rand_bytes(1)[0] | 1; // ensure non-zero
    let interp_enc: Vec<u8> = interp
        .as_bytes()
        .iter()
        .map(|b| b ^ interp_mask_byte)
        .collect();
    let interp_enc_str = format!("vec!{:?}", interp_enc);

    let prog = template::prog()
        .replace("{ script_code }", &encoded_str)
        .replace("{ key_mask }", &key_mask_str)
        .replace("{ key_masked }", &key_masked_str)
        .replace("{ pass_salt }", &pass_salt_str)
        .replace("{ pass_hash }", &pass_hash_str)
        .replace("{ interp_enc }", &interp_enc_str)
        .replace("{ interp_mask }", &format!("0x{:02x}", interp_mask_byte));

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
    #[ignore] // Requires running generated binaries (anti-debug may trigger under coverage tools) and ruby
    fn test_compile_run() -> Result<(), Box<dyn Error>> {
        let dir = env::current_dir()?;
        let path = format!("{}/examples", dir.display());
        env::set_current_dir(Path::new(&path)).unwrap();
        let files = fs::read_dir(path.to_owned())?;
        for file in files {
            let p = file.unwrap().path();
            let s = p.to_str().unwrap();
            // Only compile known script types (.sh, .rb), skip .out, .rs, and other files
            if s.ends_with(".sh") || s.ends_with(".rb") {
                let out = format!("{}.rs", s.replace(".", "_"));
                println!("out: {} {}", s, out);
                gen_and_compile(s, &out.to_owned(), "")?;
            }
        }

        // Clean up generated .rs files
        let files = fs::read_dir(path.to_owned())?;
        for file in files {
            let p = file.unwrap().path();
            let s = p.to_str().unwrap();
            if s.ends_with(".rs") {
                let _ = fs::remove_file(s);
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
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );

        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let abc_hash = sha256(b"abc");
        assert_eq!(
            abc_hash,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
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

    // ===== find_interp additional tests =====

    #[test]
    fn test_find_interp_env_shebang() {
        // #!/usr/bin/env python3 — find_interp extracts "env" (last path component)
        // This documents current behavior: env-style shebangs return "env"
        let text = "#!/usr/bin/env python3\nprint('hello')";
        let (interp, body) = find_interp(text);
        assert_eq!(interp, "env");
        assert_eq!(body, "print('hello')");
    }

    #[test]
    fn test_find_interp_strips_shebang_line() {
        // The returned content should NOT include the shebang line itself
        let text = "#!/bin/bash\necho line1\necho line2";
        let (interp, body) = find_interp(text);
        assert_eq!(interp, "bash");
        assert_eq!(body, "echo line1\necho line2");
        assert!(
            !body.contains("#!"),
            "Shebang line should be stripped from body"
        );
    }

    #[test]
    fn test_find_interp_no_shebang_preserves_content() {
        // Without shebang, content should be returned unchanged
        let text = "echo hello\necho world";
        let (interp, body) = find_interp(text);
        assert_eq!(interp, "bash");
        assert_eq!(body, text);
    }

    #[test]
    fn test_find_interp_usr_bin_env_bash() {
        // #!/usr/bin/env bash — current behavior extracts "env"
        let text = "#!/usr/bin/env bash\nset -e\necho ok";
        let (interp, body) = find_interp(text);
        assert_eq!(interp, "env");
        assert_eq!(body, "set -e\necho ok");
    }

    // ===== Arc4 additional tests =====

    #[test]
    fn test_arc4_empty_input() {
        let result = Arc4::new(b"key").trans_str(&String::new());
        assert!(result.is_empty());
    }

    #[test]
    fn test_arc4_single_byte() {
        let encrypted = Arc4::new(b"key").trans_str(&String::from("A"));
        assert_eq!(encrypted.len(), 1);
        // Decrypt and verify roundtrip
        let decrypted = Arc4::new(b"key").trans_vec(&encrypted);
        assert_eq!(decrypted, b"A");
    }

    #[test]
    fn test_arc4_large_data_roundtrip() {
        // Test with a large payload (4KB)
        let content: String = (0..4096).map(|i| (b'A' + (i % 26) as u8) as char).collect();
        let key = b"a_longer_key_for_testing";
        let encrypted = Arc4::new(key).trans_str(&content);
        assert_eq!(encrypted.len(), 4096);
        let decrypted = Arc4::new(key).trans_vec(&encrypted);
        assert_eq!(String::from_utf8(decrypted).unwrap(), content);
    }

    #[test]
    fn test_arc4_different_keys_produce_different_output() {
        let plaintext = "same input data";
        let enc1 = Arc4::new(b"key_alpha").trans_str(&plaintext.to_string());
        let enc2 = Arc4::new(b"key_beta").trans_str(&plaintext.to_string());
        assert_ne!(
            enc1, enc2,
            "Different keys should produce different ciphertext"
        );
    }

    #[test]
    fn test_arc4_same_key_same_output() {
        let plaintext = "deterministic output";
        let enc1 = Arc4::new(b"fixed_key").trans_str(&plaintext.to_string());
        let enc2 = Arc4::new(b"fixed_key").trans_str(&plaintext.to_string());
        assert_eq!(enc1, enc2, "Same key should produce identical ciphertext");
    }

    // ===== SHA-256 additional tests =====

    #[test]
    fn test_sha256_longer_input() {
        // SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        let hash = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hash,
            [
                0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
                0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
                0x19, 0xdb, 0x06, 0xc1,
            ]
        );
    }

    #[test]
    fn test_sha256_with_salt_different_salts() {
        // Same password with different salts should produce different hashes
        let pass = b"password123";
        let salt1 = vec![1u8; 16];
        let salt2 = vec![2u8; 16];

        let mut data1 = pass.to_vec();
        data1.extend_from_slice(&salt1);
        let hash1 = sha256(&data1);

        let mut data2 = pass.to_vec();
        data2.extend_from_slice(&salt2);
        let hash2 = sha256(&data2);

        assert_ne!(
            hash1, hash2,
            "Different salts should produce different hashes"
        );
    }

    // ===== gen_and_compile tests =====

    #[test]
    #[ignore] // Generated binary's anti-debug detection may trigger under coverage/CI tools
    fn test_generated_binary_runs_correctly() {
        // Compile a simple echo script and verify it produces correct output
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let script = format!("{}/examples/3.sh", manifest_dir);
        let out_rs = format!("{}/examples/test_gen_run.rs", manifest_dir);

        gen_and_compile(&script, &out_rs, "").unwrap();

        let bin_path = out_rs.replace(".rs", "");
        let output = Command::new(&bin_path)
            .args(&["hello", "world"])
            .output()
            .expect("failed to execute generated binary");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("First arg: hello"), "Got: {}", stdout);
        assert!(stdout.contains("Second arg: world"), "Got: {}", stdout);

        // Clean up
        let _ = fs::remove_file(&out_rs);
        let _ = fs::remove_file(&bin_path);
    }

    #[test]
    fn test_generated_binary_is_stripped() {
        // Verify the compiled binary has symbols stripped (smaller size, fewer symbols)
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let script = format!("{}/examples/2.sh", manifest_dir);
        let out_rs = format!("{}/examples/test_strip_check.rs", manifest_dir);

        gen_and_compile(&script, &out_rs, "").unwrap();

        let bin_path = out_rs.replace(".rs", "");

        // Check that nm finds very few (or no) symbols
        let nm_output = Command::new("nm").arg(&bin_path).output();

        match nm_output {
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // On stripped binaries, nm typically reports "no symbols" or very few
                let stdout = String::from_utf8_lossy(&output.stdout);
                let symbol_count = stdout.lines().count();
                assert!(
                    symbol_count < 200 || stderr.contains("no symbols"),
                    "Binary should have few symbols after stripping, got {} symbols",
                    symbol_count
                );
            }
            Err(_) => {
                // nm not available, skip this check
            }
        }

        // Clean up
        let _ = fs::remove_file(&out_rs);
        let _ = fs::remove_file(&bin_path);
    }

    #[test]
    fn test_no_password_generates_empty_hash() {
        // When no password is given, pass_salt and pass_hash should be empty vecs
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let script = format!("{}/examples/2.sh", manifest_dir);
        let out_rs = format!("{}/examples/test_no_pass.rs", manifest_dir);

        gen_and_compile(&script, &out_rs, "").unwrap();

        let generated = fs::read_to_string(&out_rs).unwrap();

        // Empty password should produce empty vec![] for both salt and hash
        assert!(
            generated.contains("let mut pass_salt: Vec<u8> = vec![];"),
            "Empty password should produce empty pass_salt"
        );
        assert!(
            generated.contains("let pass_hash: Vec<u8> = vec![];"),
            "Empty password should produce empty pass_hash"
        );

        // Clean up
        let _ = fs::remove_file(&out_rs);
        let _ = fs::remove_file(out_rs.replace(".rs", ""));
    }

    #[test]
    fn test_template_contains_all_placeholders() {
        let tmpl = template::prog();
        assert!(
            tmpl.contains("{ script_code }"),
            "Missing script_code placeholder"
        );
        assert!(
            tmpl.contains("{ key_mask }"),
            "Missing key_mask placeholder"
        );
        assert!(
            tmpl.contains("{ key_masked }"),
            "Missing key_masked placeholder"
        );
        assert!(
            tmpl.contains("{ pass_salt }"),
            "Missing pass_salt placeholder"
        );
        assert!(
            tmpl.contains("{ pass_hash }"),
            "Missing pass_hash placeholder"
        );
        assert!(
            tmpl.contains("{ interp_enc }"),
            "Missing interp_enc placeholder"
        );
        assert!(
            tmpl.contains("{ interp_mask }"),
            "Missing interp_mask placeholder"
        );
    }

    #[test]
    fn test_template_has_stdin_pipe() {
        // Verify template uses Stdio::piped() instead of passing script as argument
        let tmpl = template::prog();
        assert!(
            tmpl.contains("Stdio::piped()"),
            "Template should use stdin pipe for security"
        );
        assert!(
            tmpl.contains("write_all"),
            "Template should write script to stdin"
        );
    }

    #[test]
    fn test_template_has_secure_zero() {
        // Verify template includes memory zeroing for sensitive data
        let tmpl = template::prog();
        assert!(
            tmpl.contains("write_volatile"),
            "Template should use write_volatile for secure zeroing"
        );
        assert!(
            tmpl.contains("secure_zero"),
            "Template should have secure_zero function"
        );
        // Verify all sensitive data is zeroed
        assert!(
            tmpl.contains("secure_zero_vec(&mut rand_key)"),
            "RC4 key should be zeroed after use"
        );
        assert!(
            tmpl.contains("secure_zero_vec(&mut key_mask)"),
            "key_mask should be zeroed after use"
        );
        assert!(
            tmpl.contains("secure_zero_vec(&mut key_masked)"),
            "key_masked should be zeroed after use"
        );
        assert!(
            tmpl.contains("cipher.zeroize()"),
            "Arc4 state should be zeroed after decryption"
        );
    }

    #[test]
    fn test_generated_file_no_script_plaintext() {
        // Verify the original script content is NOT readable in the generated .rs file
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let script = format!("{}/examples/3.sh", manifest_dir);
        let out_rs = format!("{}/examples/test_no_plain.rs", manifest_dir);

        gen_and_compile(&script, &out_rs, "").unwrap();

        let generated = fs::read_to_string(&out_rs).unwrap();
        // The original script content should be encrypted, not plaintext
        assert!(
            !generated.contains("First arg:"),
            "Generated file should not contain plaintext script content"
        );
        assert!(
            !generated.contains("Second arg:"),
            "Generated file should not contain plaintext script content"
        );

        // Clean up
        let _ = fs::remove_file(&out_rs);
        let _ = fs::remove_file(out_rs.replace(".rs", ""));
    }

    #[test]
    fn test_interp_not_plaintext_in_output() {
        // Verify that interpreter name is XOR-encoded, not plaintext in generated code
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let script = format!("{}/examples/3.sh", manifest_dir);
        let out_rs = format!("{}/examples/test_interp_obf.rs", manifest_dir);

        gen_and_compile(&script, &out_rs, "").unwrap();

        let generated = fs::read_to_string(&out_rs).unwrap();
        // The plaintext interpreter name should NOT appear as a string literal
        assert!(
            !generated.contains("\"bash\""),
            "Generated file should not contain plaintext interpreter string"
        );
        // Should use obf_decode instead
        assert!(
            generated.contains("obf_decode"),
            "Generated file should use obf_decode for interpreter"
        );
        // Error messages should NOT be plaintext
        assert!(
            !generated.contains("\"Password: \""),
            "Generated file should not contain plaintext Password prompt"
        );
        assert!(
            !generated.contains("\"Invalid password!\""),
            "Generated file should not contain plaintext error message"
        );
        assert!(
            !generated.contains("\"failed to execute\""),
            "Generated file should not contain plaintext error message"
        );

        // Clean up
        let _ = fs::remove_file(&out_rs);
        let _ = fs::remove_file(out_rs.replace(".rs", ""));
    }

    #[test]
    fn test_template_has_anti_debug() {
        let tmpl = template::prog();
        assert!(
            tmpl.contains("detect_debugger()"),
            "Template should call detect_debugger in main"
        );
        assert!(
            tmpl.contains("PT_DENY_ATTACH"),
            "Template should use PT_DENY_ATTACH on macOS"
        );
        assert!(
            tmpl.contains("PTRACE_TRACEME"),
            "Template should use PTRACE_TRACEME on Linux"
        );
        assert!(
            tmpl.contains("P_TRACED"),
            "Template should check P_TRACED sysctl flag"
        );
        assert!(
            tmpl.contains("TracerPid"),
            "Template should check /proc/self/status TracerPid"
        );
        assert!(
            tmpl.contains("DYLD_INSERT_LIBRARIES"),
            "Template should detect DYLD_INSERT_LIBRARIES"
        );
        assert!(
            tmpl.contains("LD_PRELOAD"),
            "Template should detect LD_PRELOAD"
        );
    }

    #[test]
    fn test_template_has_verify_integrity() {
        let tmpl = template::prog();
        assert!(
            tmpl.contains("verify_integrity()"),
            "Template should call verify_integrity in main"
        );
        assert!(
            tmpl.contains("current_exe"),
            "Template should read own executable path"
        );
        assert!(
            tmpl.contains("split_at"),
            "Template should split binary to separate checksum"
        );
    }

    #[test]
    fn test_binary_checksum_appended() {
        // Verify that compiled binary has 32 bytes of SHA-256 appended
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let script = format!("{}/examples/2.sh", manifest_dir);
        let out_rs = format!("{}/examples/test_checksum.rs", manifest_dir);

        gen_and_compile(&script, &out_rs, "").unwrap();

        let bin_path = out_rs.replace(".rs", "");
        let data = fs::read(&bin_path).unwrap();

        // Binary must be longer than 32 bytes
        assert!(data.len() > 32);

        // Last 32 bytes should be SHA-256 of the preceding content
        let (body, stored_hash) = data.split_at(data.len() - 32);
        let computed = sha256(body);
        assert_eq!(
            &computed[..],
            stored_hash,
            "Appended checksum should match SHA-256 of binary body"
        );

        // Clean up
        let _ = fs::remove_file(&out_rs);
        let _ = fs::remove_file(&bin_path);
    }

    #[test]
    fn test_tampered_binary_exits() {
        // Verify that a tampered binary detects corruption and exits with code 1
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let script = format!("{}/examples/3.sh", manifest_dir);
        let out_rs = format!("{}/examples/test_tamper.rs", manifest_dir);

        gen_and_compile(&script, &out_rs, "").unwrap();

        let bin_path = out_rs.replace(".rs", "");

        // Tamper: flip some bytes in the middle of the binary
        let mut data = fs::read(&bin_path).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        data[mid + 1] ^= 0xFF;
        fs::write(&bin_path, &data).unwrap();

        // Run tampered binary — should exit with code 1 (integrity check failure)
        let output = Command::new(&bin_path)
            .args(&["hello", "world"])
            .output()
            .expect("failed to run tampered binary");

        assert!(
            !output.status.success(),
            "Tampered binary should exit with non-zero status"
        );
        assert!(
            output.stdout.is_empty(),
            "Tampered binary should produce no output"
        );

        // Clean up
        let _ = fs::remove_file(&out_rs);
        let _ = fs::remove_file(&bin_path);
    }
}
