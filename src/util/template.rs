pub fn prog() -> &'static str {
    r###"
use std::io;
use std::io::Read;
use std::iter::repeat;
use std::io::Write;
use std::process;
use std::process::{Command, Stdio};
use std::env;

/// Zero out a byte slice using volatile writes to prevent compiler optimization
fn secure_zero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0); }
    }
}

/// Zero out a Vec<u8> and drop it
fn secure_zero_vec(v: &mut Vec<u8>) {
    secure_zero(v.as_mut_slice());
    v.clear();
}

/// Zero out a String's underlying buffer and drop it
fn secure_zero_string(s: &mut String) {
    unsafe {
        secure_zero(s.as_bytes_mut());
    }
    s.clear();
}

/// Decode XOR-obfuscated byte array at runtime
fn obf_decode(data: &[u8], mask: u8) -> String {
    String::from_utf8(data.iter().map(|b| b ^ mask).collect()).unwrap_or_default()
}

/// Anti-debug: detect debuggers and library injection, exit silently if found
fn detect_debugger() {
    // 1. Check for injected libraries (common hooking technique)
    for var in &["DYLD_INSERT_LIBRARIES", "LD_PRELOAD"] {
        if std::env::var(var).is_ok() {
            std::process::exit(1);
        }
    }

    // 2. macOS: PT_DENY_ATTACH prevents debugger from attaching
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn ptrace(request: i32, pid: i32, addr: *mut u8, data: i32) -> i32;
        }
        const PT_DENY_ATTACH: i32 = 31;
        unsafe { ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0); }
    }

    // 3. macOS: sysctl check for P_TRACED flag
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn sysctl(name: *const i32, namelen: u32, oldp: *mut u8, oldlenp: *mut usize, newp: *const u8, newlen: usize) -> i32;
            fn getpid() -> i32;
        }
        // CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1
        let mib: [i32; 4] = [1, 14, 1, unsafe { getpid() }];
        let mut info = [0u8; 752]; // kinfo_proc buffer (oversized for safety)
        let mut size: usize = info.len();
        let ret = unsafe {
            sysctl(mib.as_ptr(), 4, info.as_mut_ptr(), &mut size, std::ptr::null(), 0)
        };
        if ret == 0 {
            // kp_proc.p_flag at offset 32 (i32)
            let p_flag = i32::from_ne_bytes([info[32], info[33], info[34], info[35]]);
            const P_TRACED: i32 = 0x00000800;
            if p_flag & P_TRACED != 0 {
                std::process::exit(1);
            }
        }
    }

    // 4. Linux: PTRACE_TRACEME detection
    #[cfg(target_os = "linux")]
    {
        extern "C" {
            fn ptrace(request: u32, pid: u32, addr: *mut u8, data: *mut u8) -> i64;
        }
        const PTRACE_TRACEME: u32 = 0;
        let ret = unsafe { ptrace(PTRACE_TRACEME, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
        if ret == -1 {
            std::process::exit(1);
        }
        // Detach self so child processes still work
        const PTRACE_DETACH: u32 = 17;
        unsafe { ptrace(PTRACE_DETACH, 0, std::ptr::null_mut(), std::ptr::null_mut()); }
    }

    // 5. Linux: check /proc/self/status for TracerPid
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let pid_str = line.trim_start_matches("TracerPid:").trim();
                    if pid_str != "0" {
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
fn read_password_masked() -> String {
    use std::os::unix::io::AsRawFd;

    #[repr(C)]
    #[derive(Clone)]
    struct Termios {
        c_iflag: u64,
        c_oflag: u64,
        c_cflag: u64,
        c_lflag: u64,
        c_cc: [u8; 20],
        c_ispeed: u64,
        c_ospeed: u64,
    }

    extern "C" {
        fn tcgetattr(fd: i32, termios: *mut Termios) -> i32;
        fn tcsetattr(fd: i32, action: i32, termios: *const Termios) -> i32;
    }

    let stdin_fd = io::stdin().as_raw_fd();
    let mut orig = unsafe { std::mem::zeroed::<Termios>() };
    unsafe { tcgetattr(stdin_fd, &mut orig) };

    let mut raw = orig.clone();
    // Disable ICANON (canonical mode) and ECHO
    raw.c_lflag &= !(0x00000008 | 0x00000002); // ~(ECHO | ICANON) on macOS/Linux
    // Set VMIN=1, VTIME=0 for reading one byte at a time
    raw.c_cc[16] = 1; // VMIN
    raw.c_cc[17] = 0; // VTIME
    unsafe { tcsetattr(stdin_fd, 0, &raw) };

    let mut password = String::new();
    let mut buf = [0u8; 1];
    loop {
        if io::stdin().read_exact(&mut buf).is_err() {
            break;
        }
        match buf[0] {
            b'\n' | b'\r' => {
                eprint!("\n");
                break;
            }
            127 | 8 => {
                // Backspace / Delete
                if !password.is_empty() {
                    password.pop();
                    eprint!("\x08 \x08");
                    io::stderr().flush().ok();
                }
            }
            3 => {
                // Ctrl-C
                unsafe { tcsetattr(stdin_fd, 0, &orig) };
                eprint!("\n");
                process::exit(1);
            }
            c => {
                password.push(c as char);
                eprint!("*");
                io::stderr().flush().ok();
            }
        }
    }

    unsafe { tcsetattr(stdin_fd, 0, &orig) };
    password
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

    /// Securely zero out the internal RC4 state
    pub fn zeroize(&mut self) {
        for byte in self.state.iter_mut() {
            unsafe { std::ptr::write_volatile(byte, 0); }
        }
        unsafe {
            std::ptr::write_volatile(&mut self.i, 0);
            std::ptr::write_volatile(&mut self.j, 0);
        }
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4*i], chunk[4*i+1], chunk[4*i+2], chunk[4*i+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].iter().enumerate() {
            h[i] = h[i].wrapping_add(*v);
        }
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[4*i..4*i+4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn run_process(iterp: &str, prog: &String, args: &Vec<String>) {
    let mut cmd = Command::new(iterp);
    // Obfuscated interpreter name comparisons
    let m: u8 = 0x55;
    let ruby_s: [u8; 4] = [0x27, 0x20, 0x37, 0x2c];
    let python_s: [u8; 6] = [0x25, 0x2c, 0x21, 0x3d, 0x3a, 0x3b];
    let expect_s: [u8; 6] = [0x30, 0x2d, 0x25, 0x30, 0x36, 0x21];
    let ruby = obf_decode(&ruby_s, m);
    let python = obf_decode(&python_s, m);
    let expect = obf_decode(&expect_s, m);
    if iterp == ruby || iterp.contains(&python) {
        cmd.arg("-");
    } else if iterp == expect {
        cmd.arg("-f").arg("-");
    } else {
        cmd.arg("-s");
    }
    let mut child = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|_| std::process::exit(1));
    {
        let stdin = child.stdin.as_mut().unwrap_or_else(|| std::process::exit(1));
        stdin.write_all(prog.as_bytes()).unwrap_or_else(|_| std::process::exit(1));
    }
    let status = child.wait().unwrap_or_else(|_| std::process::exit(1));
    std::process::exit(status.code().unwrap_or(1));
}

fn main() {
    detect_debugger();

    let prog = { script_code };
    let mut key_mask: Vec<u8> = { key_mask };
    let mut key_masked: Vec<u8> = { key_masked };
    let mut pass_salt: Vec<u8> = { pass_salt };
    let pass_hash: Vec<u8> = { pass_hash };
    // Interpreter stored as XOR-encoded bytes
    let interp_enc: Vec<u8> = { interp_enc };
    let interp_mask: u8 = { interp_mask };
    let iterp = obf_decode(&interp_enc, interp_mask);

    if !pass_hash.is_empty() {
        // Obfuscated prompt
        let prompt: [u8; 10] = [0xfa, 0xcb, 0xd9, 0xd9, 0xdd, 0xc5, 0xd8, 0xce, 0x90, 0x8a];
        print!("{}", obf_decode(&prompt, 0xAA));
        io::stdout().flush().ok();
        let mut input = read_password_masked();
        let mut data = Vec::new();
        data.extend_from_slice(input.as_bytes());
        data.extend_from_slice(&pass_salt);
        let mut input_hash = sha256(&data);
        let matched = input_hash[..] == pass_hash[..];
        // Zero sensitive password data immediately
        secure_zero_string(&mut input);
        secure_zero_vec(&mut data);
        secure_zero(&mut input_hash);
        if !matched {
            // Obfuscated error
            let err: [u8; 17] = [0xe3, 0xc4, 0xdc, 0xcb, 0xc6, 0xc3, 0xce, 0x8a, 0xda, 0xcb, 0xd9, 0xd9, 0xdd, 0xc5, 0xd8, 0xce, 0x8b];
            println!("{}", obf_decode(&err, 0xAA));
            process::exit(1);
        }
    }
    secure_zero_vec(&mut pass_salt);

    // Reconstruct key from obfuscated parts
    let mut rand_key: Vec<u8> = key_mask.iter().zip(key_masked.iter()).map(|(m, d)| m ^ d).collect();
    // Zero key components immediately
    secure_zero_vec(&mut key_mask);
    secure_zero_vec(&mut key_masked);

    // Decrypt script
    let mut cipher = Arc4::new(&rand_key);
    secure_zero_vec(&mut rand_key);
    let mut prog_vec = cipher.trans_vec(&prog);
    cipher.zeroize();

    let mut prog_str = String::from_utf8(prog_vec.clone()).unwrap();
    secure_zero_vec(&mut prog_vec);

    let mut args = env::args().collect::<Vec<_>>();
    args.drain(0..1);
    run_process(&iterp.to_string(), &prog_str, &args);

    // Zero decrypted script (reached only if run_process doesn't exit)
    secure_zero_string(&mut prog_str);
}
"###
}
