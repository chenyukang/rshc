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

fn find_interp(content: &String) -> (String, String) {
    if content.starts_with("#!") {
        let lines: Vec<&str> = content.split("\n").collect();
        let first: Vec<&str> = lines[0].trim().split(" ").collect();
        if first.len() < 1 {
            (String::from("bash"), content.to_owned())
        } else {
            let interp = String::from(
                first[0]
                    .split("/")
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

fn compile_it(file: &String) {
    println!("compile it ... {}", file);
    let output = Command::new("rustc")
        .arg(file)
        .output()
        .expect("failed to compile");

    let stdout = output.stdout;
    let stderr = output.stderr;
    if stdout.len() > 0 {
        println!("{}", String::from_utf8_lossy(&stdout));
    }
    if stderr.len() > 0 {
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

pub fn gen_and_compile(file: &str, rs_file: &str, pass: &str) -> Result<(), Box<dyn Error>> {
    let source = fs::read_to_string(file).expect("Failed to read source file");
    let (interp, striped) = find_interp(&source);
    let rand_key = rand_string(128);
    let encoded_vec = Arc4::new(rand_key.as_bytes()).trans_str(&striped);
    let encoded_str = format!("vec!{:?}", encoded_vec);
    let prog = template::prog()
        .replace("{ script_code }", &encoded_str)
        .replace("{ rand_key }", &rand_key)
        .replace("{ pass }", &pass)
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
        assert!(key.len() >= 1 && key.len() <= 256);
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
        let k = self.state
            [(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize];
        k
    }

    fn encode_vec(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        for (x, y) in input.iter().zip(output.iter_mut()) {
            *y = *x ^ self.next();
        }
    }

    pub fn trans_vec(&mut self, input: &Vec<u8>) -> Vec<u8> {
        let mut out: Vec<u8> = repeat(0).take(input.len()).collect();
        self.encode_vec(input, &mut out);
        return out.to_vec();
    }

    pub fn trans_str(&mut self, str: &String) -> Vec<u8> {
        return self.trans_vec(&str.as_bytes().to_vec());
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
        env::set_current_dir(Path::new(&path)).is_ok();
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
}
