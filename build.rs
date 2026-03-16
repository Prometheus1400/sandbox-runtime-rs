fn main() {
    #[cfg(target_os = "linux")]
    build_linux_seccomp_runner();
}

#[cfg(target_os = "linux")]
fn build_linux_seccomp_runner() {
    use std::env;
    use std::process::Command;

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR must be set");
    let output_path = format!("{out_dir}/seccomp-runner");
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());

    let status = Command::new(cc)
        .args([
            "-O2",
            "-Wall",
            "-Wextra",
            "-o",
            &output_path,
            "src/sandbox/linux/runner.c",
        ])
        .status()
        .expect("failed to invoke C compiler for seccomp runner");

    assert!(status.success(), "failed to compile seccomp runner");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("target arch must be set");
    let bpf_dst = format!("{out_dir}/unix-block.bpf");
    std::fs::write(&bpf_dst, generate_seccomp_bpf(&target_arch))
        .unwrap_or_else(|e| panic!("failed to write generated BPF filter to {}: {}", bpf_dst, e));
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[cfg(target_os = "linux")]
fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(target_os = "linux")]
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

#[cfg(target_os = "linux")]
fn generate_seccomp_bpf(target_arch: &str) -> Vec<u8> {
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    let (audit_arch, trapped_syscalls): (u32, &[u32]) = match target_arch {
        "x86_64" => (
            0xC000_003E,
            &[
                41,  // socket
                257, // openat
                437, // openat2
            ],
        ),
        "aarch64" => (
            0xC000_00B7,
            &[
                198, // socket
                56,  // openat
                437, // openat2
            ],
        ),
        other => panic!("unsupported architecture for seccomp BPF filter: {}", other),
    };

    let mut program = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, 4),
        jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, 0),
    ];

    for syscall in trapped_syscalls {
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *syscall, 0, 1));
        program.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
    }

    program.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    let mut bytes = Vec::with_capacity(program.len() * 8);
    for insn in program {
        bytes.extend_from_slice(&insn.code.to_ne_bytes());
        bytes.push(insn.jt);
        bytes.push(insn.jf);
        bytes.extend_from_slice(&insn.k.to_ne_bytes());
    }
    bytes
}
