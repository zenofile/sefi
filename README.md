# sefi

**sefi** is a stream editor designed to act as a Git filter driver. It automatically substitutes secrets from your code when you commit (_clean_) and restores them when you checkout (_smudge_).

## Features

- **Bidirectional Replacement**:
  - `clean`: Replaces secrets with safe placeholders before committing
  - `smudge`: Restores placeholders back to secrets after checkout
- **Stream Processing**: Reads from `stdin` and writes to `stdout` with efficient buffering, suitable for large files
- **High Performance**: Uses the [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) algorithm to scan for multiple secrets simultaneously in a single pass
- **Configurable**: Driven by a simple TOML configuration file
- **Robust**: Handles edge cases like patterns spanning buffer boundaries and leftmost-longest matching

## Installation

### From source

    cargo build --release
Binary will be at target/release/sefi

For optimized native builds:

    cargo build --profile release-native


## Configuration

Create a configuration file (e.g., `.git/secrets.toml`) to define your substitutions.
**Do not commit this file if it contains secrets!**

### Configuration file format

```toml
[[entry]]
placeholder = "REDACTED_API_KEY"
secret = "sk-1234567890abcdefghijklmnop"

[[entry]]
placeholder = "<YOUR_PASSWORD_HERE>"
secret = "MyActualP@ssw0rd!"

[[entry]]
placeholder = "<DB_CONNECTION>"
secret = "postgresql://user:pass@localhost:5432/db"
```

### Recommended setup

Create config in .git directory (safe from accidental commits)

    touch .git/secrets.toml
    # Add your substitutions

    cat >> .git/secrets.toml << 'EOF'
    [[entry]]
    placeholder = "REDACTED_API_KEY"
    secret = "your-actual-secret-here"
    EOF

## Usage

### Manual invocation

#### Test the filter directly by piping data:

**Clean mode** (replace secrets with placeholders):

    echo "My secret is: sk-1234567890abcdefghijklmnop" | sefi clean --config .git/secrets.toml
    Output: My secret is: REDACTED_API_KEY

**Smudge mode** (restore secrets from placeholders):

    echo "My secret is: REDACTED_API_KEY" | sefi smudge --config .git/secrets.toml
    Output: My secret is: sk-1234567890abcdefghijklmnop

### Git Integration

Configure Git to automatically filter files using `sefi`.

#### Step 1: Configure git filter

Add the filter definition to your `.git/config` or local git config:

    git config filter.sefi.clean "sefi clean --config .git/secrets.toml"
    git config filter.sefi.smudge "sefi smudge --config .git/secrets.toml"
    git config filter.sefi.required true

Alternatively, add directly to `.git/config`:

    [filter "sefi"]
    clean = sefi clean --config .git/secrets.toml
    smudge = sefi smudge --config .git/secrets.toml
    required = true

#### Step 2: Assign filter to files

Create or edit `.gitattributes` in your repository root:

Apply filter to specific files:

    config/database.yml filter=sefi
    .env filter=sefi
    secrets.json filter=sefi

Or apply to all files in a directory:

    config/** filter=sefi
    Or apply to files matching a pattern

    *.secret filter=sefi

#### Step 3: Test the setup

Check current filter status:

    git check-attr filter config/database.yml
    Force re-filter existing files

    git add --renormalize .


## How It Works

1. **On Commit (`clean`)**: Git pipes the file content through `sefi clean`, which replaces all secrets with placeholders before storing in the repository
2. **On Checkout (`smudge`)**: Git pipes the stored content through `sefi smudge`, which restores the placeholders back to secrets in your working directory
