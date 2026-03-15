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
}
