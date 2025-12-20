use std::{
    fs::File,
    io::{Seek, Write},
    os::fd::AsRawFd,
    path::PathBuf,
};

use assert_cmd::Command;
use memfd::MemfdOptions;
use predicates::prelude::predicate::str::{contains, diff};

fn create_memfd_with_content(name: &str, content: &str) -> File {
    let opts = MemfdOptions::default().close_on_exec(false);
    let mfd = opts.create(name).expect("failed to create memfd");
    let mut file = mfd.into_file();

    file.write_all(content.as_bytes())
        .and_then(|()| file.rewind())
        .expect("memfd write failure");

    file
}

fn create_config(content: &str) -> (File, PathBuf) {
    let file = create_memfd_with_content("config.toml", content);
    // We need to keep the file open, otherwise the FD is closed and the
    // path becomes invalid
    let mut path = PathBuf::from("/proc/self/fd/");
    path.push(file.as_raw_fd().to_string());
    (file, path)
}

#[inline]
fn filter_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sefi"))
}

#[test]
fn test_empty_config_triggers_passthrough_optimization() {
    let (_fd, config_path) = create_config("entry = []");
    let input = "This text should be passed through exactly as-is via the fast path.";

    filter_cmd()
        .arg("clean")
        .arg("--config")
        .arg(&config_path)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(diff(input));
}

#[test]
fn test_clean_mode_replaces_secrets_with_placeholders() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "REDACTED_KEY"
        secret = "super_secret_key"
    "#,
    );

    let input = "This line contains a super_secret_key that should be hidden.";
    let expected = "This line contains a REDACTED_KEY that should be hidden.";

    filter_cmd()
        .arg("clean")
        .arg("--config")
        .arg(&config_path)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(diff(expected));
}

#[test]
fn test_smudge_mode_restores_secrets_from_placeholders() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "REDACTED_KEY"
        secret = "super_secret_key"
    "#,
    );

    let input = "This line contains a REDACTED_KEY that should be restored.";
    let expected = "This line contains a super_secret_key that should be restored.";

    filter_cmd()
        .arg("smudge")
        .arg("--config")
        .arg(&config_path)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(diff(expected));
}

#[test]
fn test_multiple_entry() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "<API_KEY>"
        secret = "12345-abcde"

        [[entry]]
        placeholder = "<DB_PASS>"
        secret = "password123"
    "#,
    );

    // This previously failed because "password123" straddled the buffer
    // boundary
    let input = "Key: 12345-abcde, Pass: password123";
    let expected = "Key: <API_KEY>, Pass: <DB_PASS>";

    filter_cmd()
        .arg("clean")
        .arg("--config")
        .arg(&config_path)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(diff(expected));
}

#[test]
fn test_no_matches_passes_through_unchanged() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "REDACTED"
        secret = "secret_value"
    "#,
    );

    let input = "This text has no secrets safe to print.";

    filter_cmd()
        .arg("clean")
        .arg("--config")
        .arg(&config_path)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(diff(input));
}

#[test]
fn test_large_input_buffer_handling() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "S"
        secret = "s"
    "#,
    );

    let input = "s".repeat(20 * 1024);
    let expected = "S".repeat(20 * 1024);

    filter_cmd()
        .arg("clean")
        .arg("--config")
        .arg(&config_path)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(diff(expected));
}

#[test]
fn test_fails_with_missing_config() {
    filter_cmd()
        .arg("clean")
        .arg("--config")
        .arg("non_existent_file.toml")
        .write_stdin("some input")
        .assert()
        .failure()
        .stderr(contains("Failed to read config"));
}

#[test]
fn test_leftmost_longest_match_behavior() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "BAR"
        secret = "foo"

        [[entry]]
        placeholder = "BAZ"
        secret = "foobar"
    "#,
    );

    // This previously failed because the match "foobar" extended beyond the
    // safe buffer region
    let input = "foobar";
    let expected = "BAZ";

    filter_cmd()
        .arg("clean")
        .arg("--config")
        .arg(config_path)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(diff(expected));
}

#[test]
fn test_partial_match_at_boundary_is_preserved() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "HIDDEN"
        secret = "secret"
    "#,
    );

    let input = "This is a secre message";

    filter_cmd()
        .arg("clean")
        .arg("--config")
        .arg(&config_path)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(diff(input));
}

#[test]
fn test_pipe_clean_to_smudge_streaming() {
    use std::process::{Command, Stdio};

    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "REDACTED"
        secret = "secret_value"
        "#,
    );

    let original_input = "Data with secret_value that should be round-tripped.";
    let mut clean_proc = Command::new(env!("CARGO_BIN_EXE_sefi"))
        .arg("clean")
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clean process");

    let mut clean_stdin = clean_proc.stdin.take().expect("Failed to open clean stdin");
    std::thread::spawn(move || {
        clean_stdin
            .write_all(original_input.as_bytes())
            .expect("Failed to write to clean stdin");
    });

    let smudge_output = Command::new(env!("CARGO_BIN_EXE_sefi"))
        .arg("smudge")
        .arg("--config")
        .arg(&config_path)
        .stdin(
            clean_proc
                .stdout
                .take()
                .expect("Failed to capture clean stdout"),
        )
        .output()
        .expect("Failed to read smudge output");

    let clean_status = clean_proc.wait().expect("Failed to wait on clean process");
    assert!(clean_status.success());
    assert!(smudge_output.status.success());

    let output_str = String::from_utf8(smudge_output.stdout).expect("Output was not valid UTF-8");
    assert_eq!(output_str, original_input);
}
