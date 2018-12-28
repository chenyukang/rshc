use std::io;
use std::io::Write;
use std::process;
use std::process::{Command, Stdio};
use std::env;


fn run_process(iterp: &String, prog: &String, args: &Vec<String>) {
    let prog = format!("{}", prog.to_owned());
    //println!("{}", prog);
    let output = Command::new(iterp)
        .arg("-c")
        .arg(prog)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .expect("failed to execute process");
    //println!("status: {}", output.status.code().unwrap());
    std::process::exit(output.status.code().unwrap());
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
    let mut args = env::args().collect::<Vec<_>>();
    args[0] = String::from("");
    run_process(&iterp.to_string(), &prog_str, &args);
}
