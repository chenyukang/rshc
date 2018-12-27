extern crate clap;
extern crate crypto;

extern crate dialoguer;

use dialoguer::{theme::ColorfulTheme, PasswordInput};

mod util;
use clap::{App, Arg};

use std::fs;
use std::fs::File;
use std::io::prelude::*;

fn main() {
    let matches = App::new("Shell script compiled to Rustc code and binary")
        .version("0.1")
        .author("Yukang.Chen <moorekang@gmail.com>")
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("the script source file")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("pass")
                .short("p")
                .long("pass")
                .help("the password used to run the script"),
        )
        .arg(
            Arg::with_name("out")
                .short("o")
                .long("out")
                .value_name("OUT")
                .help("the output file")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    let file = matches.value_of("file").unwrap();
    let output = matches.value_of("out").unwrap_or("");
    let pass = match matches.occurrences_of("pass") {
        1 => PasswordInput::with_theme(&ColorfulTheme::default())
            .with_prompt("Password")
            .with_confirmation("Repeat password", "Error: the passwords don't match.")
            .interact()
            .unwrap(),
        _ => String::from(""),
    };
    let rs_file = if output == "" {
        file.to_owned() + ".rs"
    } else {
        output.to_owned()
    };

    let content = fs::read_to_string(file).expect("Failed to read source file");
    let _encoded = util::encode(content.clone(), "hello".to_string()); // we need to encode it latter
    let (interp, content) = util::find_interp(&content);
    println!("{}", content);
    let encoded_str = format!("vec!{:?}\n", content.as_bytes());
    let prog = fs::read_to_string("./src/prog.rs").expect("Failed to read prog file");
    let prog = prog
        .replace("{ script_code }", &encoded_str)
        .replace("{ pass }", &pass)
        .replace("{ interp }", &interp);

    File::create(&rs_file)
        .unwrap()
        .write_all(prog.as_bytes())
        .unwrap();
    util::compile_it(&rs_file);
}
