use std::io;
use std::io::Write;
use std::process;
use std::process::{Command, Stdio};

fn run_process(iterp: &String, prog: &String) {
    let output = Command::new(iterp)
        .arg("-c")
        .arg(prog)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .output()
        .expect("failed to execute process");

    let stderr = output.stderr;

    println!("stderr: {}", String::from_utf8_lossy(&stderr));
}

fn main() {
    let prog = { script_code };
    let pass = "{ pass }";
    let iterp = "{ interp }";
    //println!("res: {:?}", prog);

    if pass.len() != 0 {
        let mut input = String::new();
        print!("Password: ");
        io::stdout().flush().ok();
        io::stdin()
            .read_line(&mut input)
            .ok()
            .expect("Couldn't read password");
        if input.trim() != pass {
            println!("Invalid password!");
            process::exit(1);
        }
    }
    let prog_str = String::from_utf8(prog).unwrap();
    //println!("running ...:\n {}", prog_str);
    run_process(&iterp.to_string(), &prog_str);
}
