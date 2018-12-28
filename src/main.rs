extern crate clap;
extern crate dialoguer;

use dialoguer::{theme::ColorfulTheme, PasswordInput};

mod util;
use clap::{App, Arg};

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
    util::gen_and_compile(&file, &rs_file, &pass);
}
