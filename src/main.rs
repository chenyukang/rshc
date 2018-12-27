extern crate clap;
extern crate crypto;

mod lib;
use clap::{Arg, App};

use std::process::{Command, Stdio};
use std::fs;
use std::fs::File;
use std::io::prelude::*;

#[allow(dead_code)]
fn run_process() {
    let output = Command::new("expect")
        .arg("-f")
        .arg("f.sh")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .output()
        .expect("failed to execute process");

    let stdout = output.stdout;

    println!("\n{}", String::from_utf8_lossy(&stdout));
}

fn compile_it(file: &String) {
    println!("compile it ...");
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
}

fn main() {
    let matches = App::new("Shell script compiled to Rustc code and binary")
        .version("0.1")
        .author("Yukang.Chen <moorekang@gmail.com>")
        .arg(Arg::with_name("file")
             .short("f")
             .long("file")
             .value_name("FILE")
             .help("the script source file")
             .required(true)
             .takes_value(true))
        .arg(Arg::with_name("pass")
             .short("p")
             .long("pass")
             .value_name("PASS")
             .help("the password used to run the script")
             .takes_value(true))
        .arg(Arg::with_name("out")
             .short("o")
             .long("out")
             .value_name("OUT")
             .help("the output file")
             .required(false)
             .takes_value(true))
        .arg(Arg::with_name("v")
             .short("v")
             .multiple(true)
             .help("Sets the level of verbosity"))
        .get_matches();


    let file = matches.value_of("file").unwrap();
    let output = matches.value_of("out").unwrap_or("");
    let pass = matches.value_of("pass").unwrap_or("");
    let rs_file = if output == "" {
            file.to_owned() + ".rs"
        } else {
            output.to_owned()
        };

    let content = fs::read_to_string(file).expect("Failed to read source file");
    let _encoded = lib::encode(content.clone(), "hello".to_string());
    let encoded_str = format!("vec!{:?}\n", content.as_bytes());
    let prog = fs::read_to_string("./src/prog.rs").expect("Failed to read prog file");
    let prog = prog.replace("{script_code}", &encoded_str)
        .replace("{pass}", &format!("\"{}\"", pass));

    File::create(&rs_file).unwrap().write_all(prog.as_bytes()).unwrap();
    compile_it(&rs_file);
}
