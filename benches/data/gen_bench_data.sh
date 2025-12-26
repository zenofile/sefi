#!/usr/bin/env bash
set -e

# Configuration
PROJECT_ROOT="$(git rev-parse --show-toplevel)"

if [[ -z $PROJECT_ROOT ]]; then
    exit 1
fi

DATA_DIR="${PROJECT_ROOT}/benches/data"
DATA_FILE="$DATA_DIR/large_random.txt"
CONFIG_FILE="${DATA_DIR}/bench_config.toml"
SIZE_MB=128

# Create directory
mkdir -vp "$DATA_DIR"

echo "Setting up benchmark data in $DATA_DIR..."

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Creating $CONFIG_FILE..."
    cat > "$CONFIG_FILE" <<EOF
entry = [
    { active = true, placeholder = "REDACTED", secret = "API_KEY_12345", boundary = true },
    { active = true, placeholder = "HIDDEN",   secret = "SUPER_SECRET_TOKEN", boundary = false }
]
EOF
else
    echo "Config file already exists."
fi

if [[ ! -f "$DATA_FILE" ]]; then
    echo "Generating ${SIZE_MB}MB test file: $DATA_FILE..."

    # - base64: gets random printable data
    # - head -c: limits size (base64 expands data, so we grab ~7.5M raw to get ~10M encoded)
    # - fold: wraps lines so awk can process them
    # - awk: appends a secret to every line for high density matches

    head -c "$((SIZE_MB * 750 * 1024))" /dev/urandom | base64 | fold -w 100 | \
    awk 'BEGIN{srand()} {
        # 50% chance to insert a secret at the end of the line
        if (rand() < 0.5) {
            print $0 " " (rand() < 0.5 ? "API_KEY_12345" : "SUPER_SECRET_TOKEN");
        } else {
            print $0;
        }
    }' > "$DATA_FILE"

    echo "Done. File size: $(du -h "$DATA_FILE" | cut -f1)"
else
    echo "Data file already exists. Skipping generation."
fi

echo "Benchmark setup complete."

