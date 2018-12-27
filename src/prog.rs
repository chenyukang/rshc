use std::process::{Command, Stdio};

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
    //println!("res: {:?}", prog);

    let prog_str = String::from_utf8(prog).unwrap();
    //println!("running ...:\n {}", prog_str);
    bash_run_process(&prog_str);
}

