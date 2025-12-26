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
fn test_multiple_entry_buffer_straddle() {
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

#[test]
fn test_boundary_enabled_ignores_partial_matches() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "REDACTED"
        secret = "secret"
        boundary = true
        "#,
    );

    // "secret" -> Should replace (exact match)
    // "secretary" -> Should NOT replace (right boundary)
    // "topsecret" -> Should NOT replace (left boundary)
    // "my_secret_key" -> Should NOT replace (underscores)
    // "secret!" -> Should replace (punctuation is not a word char)
    let input = "Found secret. Not secretary. Not topsecret. Not my_secret_key. Yes secret!";
    let expected = "Found REDACTED. Not secretary. Not topsecret. Not my_secret_key. Yes REDACTED!";

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
fn test_inactive_entry_is_ignored() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "REDACTED"
        secret = "secret_value"
        active = false
        "#,
    );

    let input = "This contains secret_value that should NOT be hidden.";

    // Expect input to pass through unchanged
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
fn test_boundary_match_at_chunk_end() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "KEY"
        secret = "12345"
        boundary = true
        "#,
    );

    // We can't easily force the internal chunk size (16KB) from integration
    // tests, but we can ensure normal "end of stream" boundary checks
    // work. If the tool panicked or duplicated data at EOF, this would
    // fail.
    let input = "prefix 12345";
    let expected = "prefix KEY";

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
fn test_boundary_disabled_replaces_partial_matches_aggressively() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "REDACTED"
        secret = "secret"
        # boundary defaults to false
        "#,
    );

    let input = "secretary topsecret";
    let expected = "REDACTEDary topREDACTED";

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
#[cfg(not(feature = "encoding"))]
fn test_encoding_fails_gracefully_without_feature() {
    let (_fd, config_path) = create_config(
        r#"
        [[entry]]
        placeholder = "REDACTED"
        secret = "secret"
        encoding = "base64"
        "#,
    );

    // Expect failure because the binary was built without base64 support
    filter_cmd()
        .arg("clean")
        .arg("--config")
        .arg(&config_path)
        .write_stdin("data")
        .assert()
        .failure()
        .stderr(contains("requires the 'encoding' feature"));
}

#[cfg(feature = "encoding")]
mod encoding_tests {
    use super::*;

    #[test]
    fn test_encoding_base64_clean_and_smudge() {
        // "test" in base64 is "dGVzdA=="
        let (_fd, config_path) = create_config(
            r#"
        [[entry]]
        placeholder = "REDACTED"
        secret = "test"
        encoding = "base64"
        "#,
        );

        // Input contains the BASE64 secret (simulating a file with encoded
        // secret)
        let input_clean = "Value: dGVzdA==";
        let expected_clean = "Value: REDACTED";

        filter_cmd()
            .arg("clean")
            .arg("--config")
            .arg(&config_path)
            .write_stdin(input_clean)
            .assert()
            .success()
            .stdout(diff(expected_clean));

        // Input contains the PLACEHOLDER
        let input_smudge = "Value: REDACTED";
        let expected_smudge = "Value: dGVzdA==";

        filter_cmd()
            .arg("smudge")
            .arg("--config")
            .arg(&config_path)
            .write_stdin(input_smudge)
            .assert()
            .success()
            .stdout(diff(expected_smudge));
    }

    #[test]
    fn test_encoding_hex_clean_and_smudge() {
        // "test" in hex is "74657374"
        let (_fd, config_path) = create_config(
            r#"
        [[entry]]
        placeholder = "KEY"
        secret = "test"
        encoding = "hex"
        "#,
        );

        // CLEAN: Hex -> Placeholder
        let input_clean = "Key=74657374";
        let expected_clean = "Key=KEY";

        filter_cmd()
            .arg("clean")
            .arg("--config")
            .arg(&config_path)
            .write_stdin(input_clean)
            .assert()
            .success()
            .stdout(diff(expected_clean));

        // SMUDGE: Placeholder -> Hex
        let input_smudge = "Key=KEY";
        let expected_smudge = "Key=74657374";

        filter_cmd()
            .arg("smudge")
            .arg("--config")
            .arg(&config_path)
            .write_stdin(input_smudge)
            .assert()
            .success()
            .stdout(diff(expected_smudge));
    }

    #[test]
    fn test_invalid_encoding_errors() {
        let (_fd, config_path) = create_config(
            r#"
        [[entry]]
        placeholder = "X"
        secret = "y"
        encoding = "rot13"
        "#,
        );

        filter_cmd()
            .arg("clean")
            .arg("--config")
            .arg(&config_path)
            .write_stdin("data")
            .assert()
            .failure()
            .stderr(contains("Unknown encoding: rot13"));
    }

    #[test]
    fn test_mixed_encodings() {
        let (_fd, config_path) = create_config(
            r#"
        [[entry]]
        placeholder = "B64"
        secret = "foo" # b64: Zm9v
        encoding = "base64"

        [[entry]]
        placeholder = "HEX"
        secret = "bar" # hex: 626172
        encoding = "hex"

        [[entry]]
        placeholder = "PLAIN"
        secret = "baz"
        encoding = "none"
        "#,
        );

        // Clean: All secrets (encoded or plain) -> Placeholders
        let input = "Zm9v | 626172 | baz";
        let expected = "B64 | HEX | PLAIN";

        filter_cmd()
            .arg("clean")
            .arg("--config")
            .arg(&config_path)
            .write_stdin(input)
            .assert()
            .success()
            .stdout(diff(expected));
    }
}
