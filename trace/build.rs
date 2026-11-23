use std::{env, fs, path::PathBuf, process::Command};

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/trace.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // vmlinux.h describes the running kernel's types (CO-RE): generated, never committed.
    let vmlinux = out.join("vmlinux.h");
    if !vmlinux.exists() {
        let dump = Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .expect("bpftool is required to build (dnf install bpftool)");
        assert!(
            dump.status.success(),
            "bpftool failed: {}",
            String::from_utf8_lossy(&dump.stderr)
        );
        fs::write(&vmlinux, dump.stdout).unwrap();
    }

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-I", out.to_str().unwrap(), "-mcpu=v3"])
        .build_and_generate(out.join("trace.skel.rs"))
        .expect("failed to build the BPF program");
    println!("cargo:rerun-if-changed={SRC}");
}
