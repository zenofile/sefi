#![feature(test)]
extern crate test;

use std::{
    fs::File,
    path::PathBuf,
    process::{Command, Stdio},
};

use test::Bencher;

#[bench]
fn bench_binary_execution(b: &mut Bencher) {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_sefi"));
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir.join("benches/data/bench_config.toml");
    let data_file = manifest_dir.join("benches/data/large_random.txt");

    assert!(bin_path.exists(), "Binary not found");
    assert!(config_path.exists(), "Config not found");
    assert!(data_file.exists(), "Data file not found");

    b.iter(|| {
        let input = File::open(&data_file).expect("Failed to open input file");

        let status = Command::new(&bin_path)
            .arg("smudge")
            .arg("--config")
            .arg(&config_path)
            .arg(&data_file)
            .stdin(Stdio::from(input))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("Failed to execute");

        assert!(status.success());
    });
}
