//mod lib;

use std::process::{Command, Stdio};

fn main() {
    let output = Command::new("expect")
        .arg("-f")
        .arg("f.sh")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .output()
        .expect("failed to execute process");

    let stderr = output.stderr;

    println!("stderr: {}", String::from_utf8_lossy(&stderr));
}
