use std::process::{Command, Stdio};
use std::process;
use std::io;
use std::io::Write;

// fn run_process(prog: &String) {
//     let output = Command::new("expect")
//         .arg("-c")
//         .arg(prog)
//         .stdin(Stdio::inherit())
//         .stdout(Stdio::inherit())
//         .output()
//         .expect("failed to execute process");

//     let stderr = output.stderr;

//     println!("stderr: {}", String::from_utf8_lossy(&stderr));
// }


fn bash_run_process(prog: &String) {
    let output = Command::new("bash")
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
    let prog = {script_code};
    let pass = {pass};
    //println!("res: {:?}", prog);

    if pass.len() != 0 {
        let mut input = String::new();
        print!("Password: ");
        io::stdout().flush().ok();
        io::stdin().read_line(&mut input).ok()
            .expect("Couldn't read password");
        if input.trim() != pass {
            println!("Invalid password!");
            process::exit(1);
        }
    }
    let prog_str = String::from_utf8(prog).unwrap();
    //println!("running ...:\n {}", prog_str);
    bash_run_process(&prog_str);
}

