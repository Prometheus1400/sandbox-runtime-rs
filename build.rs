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

    // Copy BPF filter to OUT_DIR for embedding
    let arch_dir = if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        panic!("unsupported architecture for seccomp BPF filter")
    };

    let bpf_src = format!("vendor/seccomp/{}/unix-block.bpf", arch_dir);
    let bpf_dst = format!("{out_dir}/unix-block.bpf");
    std::fs::copy(&bpf_src, &bpf_dst)
        .unwrap_or_else(|e| panic!("failed to copy BPF filter from {}: {}", bpf_src, e));
    println!("cargo:rerun-if-changed={bpf_src}");
}
