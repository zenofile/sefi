#![feature(likely_unlikely)]

use std::{
    fs,
    hint::unlikely,
    io::{self, Read, Write},
    path::PathBuf,
};

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::Deserialize;
use tracing::{debug, info, level_filters::LevelFilter};

#[derive(Parser)]
#[command(name = "sefi")]
struct Cli {
    /// Do not output anything to stderr
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Increase verbosity level (-v, -vv, -vvv, etc.)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[arg(value_enum)]
    mode: Mode,

    /// Path to the config file (e.g., .git/secrets.toml)
    #[arg(short, long)]
    config: PathBuf,

    /// Optional filename (passed by git as %f)
    pub file: Option<PathBuf>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Mode {
    Smudge,
    Clean,
}

#[derive(Deserialize)]
struct Config {
    entry: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    placeholder: String,
    secret: String,
}

struct StreamReplacer<'a, W> {
    ac: &'a AhoCorasick,
    patterns: &'a [String],
    replacements: &'a [String],
    writer: W,
    overlap: usize,
    pub count: usize,
    pub path: Option<PathBuf>,
}

// Try to manually implement AhoCorasick::stream_replace_all_with
impl<W: Write> StreamReplacer<'_, W> {
    fn process(&mut self, chunk: &[u8], is_eof: bool) -> Result<usize> {
        let mut last_idx = 0;

        // Calculate safe limit based on stored overlap overlap is length of
        // longest secret - "password123" is 11 chars, so overlap is 10.
        let safe_len = if is_eof {
            chunk.len()
        } else {
            chunk.len().saturating_sub(self.overlap)
        };

        // We initially plan to process up to safe_len, but if we find a match
        // that straddles the boundary, we must stop *before* that match starts
        let mut limit = safe_len;

        for mat in self.ac.find_iter(chunk) {
            if unlikely(mat.end() > safe_len) {
                limit = mat.start();
                break;
            }

            // Write content before match
            self.writer.write_all(&chunk[last_idx..mat.start()])?;

            // Replacement
            let pattern_idx = mat.pattern().as_usize();
            let matched_text = &self.patterns[pattern_idx];
            let replacement_text = &self.replacements[pattern_idx];

            // Log with filename if available
            if let Some(path) = &self.path {
                info!(
                    "File: {:?} | Replacing '{}' -> '{}'",
                    path, matched_text, replacement_text
                );
            } else {
                info!("Replacing '{}' -> '{}'", matched_text, replacement_text);
            }

            self.writer.write_all(replacement_text.as_bytes())?;
            self.count += 1;

            last_idx = mat.end();
        }

        if last_idx < safe_len {
            self.writer.write_all(&chunk[last_idx..limit])?;
            Ok(limit)
        } else {
            Ok(last_idx)
        }
    }
}

#[allow(clippy::significant_drop_tightening)]
fn main() -> Result<()> {
    const BUF_SIZE_ALIGNED: usize = 1024 << 4; // 16 KiB

    let cli = Cli::parse();

    // Logging
    {
        let level_filter = if cli.quiet {
            LevelFilter::OFF
        } else {
            match cli.verbose {
                0 => LevelFilter::WARN,
                1 => LevelFilter::INFO,
                2 => LevelFilter::DEBUG,
                _ => LevelFilter::TRACE,
            }
        };

        let use_ansi = io::IsTerminal::is_terminal(&std::io::stdout());
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(level_filter.into()),
            )
            .with_writer(std::io::stderr)
            .with_ansi(use_ansi)
            .init();
    }

    let config: Config = {
        let config_content = fs::read_to_string(&cli.config)
            .with_context(|| format!("Failed to read config from {}", cli.config.display()))?;
        toml::from_str(&config_content)?
    };

    // Fastpath: try to coerce the std to splice(2) the data through if
    // there are no entries
    if config.entry.is_empty() {
        debug!("Passthrough mode");
        let mut stdin = io::stdin().lock();
        let mut stdout = io::stdout().lock();
        io::copy(&mut stdin, &mut stdout)?;

        return Ok(());
    }

    let mut patterns = Vec::with_capacity(config.entry.len());
    let mut replacements = Vec::with_capacity(config.entry.len());

    for entry in config.entry {
        match cli.mode {
            Mode::Smudge => {
                patterns.push(entry.placeholder);
                replacements.push(entry.secret);
            }
            Mode::Clean => {
                patterns.push(entry.secret);
                replacements.push(entry.placeholder);
            }
        }
    }

    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(&patterns)
        .context("Failed to build Aho-Corasick automaton")?;

    // Calculate buffer parameters *before* locking
    let max_pattern_len = patterns.iter().map(String::len).max().unwrap_or(0);

    if max_pattern_len >= BUF_SIZE_ALIGNED {
        anyhow::bail!(
            "Pattern length ({}) exceeds buffer size ({})",
            max_pattern_len,
            BUF_SIZE_ALIGNED
        );
    }

    let mut buffer = [0u8; BUF_SIZE_ALIGNED];
    let mut total = 0;

    // EXPLICITLY ALLOW HOLDING THE LOCK
    // We intentionally hold the lock for the entire duration of the loop to
    // avoid the overhead of re-acquiring it on every read
    let mut stdin = io::stdin().lock();
    let stdout = io::stdout().lock();

    let mut replacer = StreamReplacer {
        ac: &ac,
        patterns: &patterns,
        replacements: &replacements,
        writer: stdout,
        overlap: max_pattern_len.saturating_sub(1),
        count: 0,
        path: cli.file,
    };

    loop {
        // Fill the buffer
        let bytes = stdin.read(&mut buffer[total..])?;
        if unlikely(bytes == 0) {
            // EOF: Process remainder
            replacer.process(&buffer[..total], true)?;
            break;
        }
        total += bytes;

        let processed = replacer.process(&buffer[..total], false)?;

        // Move remaining tail to start
        buffer.copy_within(processed..total, 0);
        total -= processed;
    }

    if replacer.count > 0 {
        info!(mode = ?cli.mode, count = replacer.count, "Replaced secrets in stream");
    } else {
        info!("No secrets found to replace.");
    }

    Ok(())
}
