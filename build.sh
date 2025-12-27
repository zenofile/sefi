#!/usr/bin/env bash

set -eu

IMAGE="docker.io/rustlang/rust:nightly-slim"
BUILD_USER=$LOGNAME
PROJECT_ROOT="$PWD"

log_info() {
    echo -e "\033[1;34m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
}

check_dependencies() {
    if ! command -v podman &> /dev/null; then
        log_error "Podman is not installed or not in PATH."
        exit 1
    fi
}

check_project() {
    if [[ ! -f "${PROJECT_ROOT}/Cargo.toml" ]]; then
        log_error "No 'Cargo.toml' found in the current directory."
        log_error "Please run this script from the root of your Rust project."
        exit 1
    fi
}

main() {
    log_info "Checking prerequisites..."
    check_dependencies
    check_project

    log_info "Starting build in container..."
    log_info "User: $BUILD_USER"
    log_info "Image: $IMAGE"

    if podman run -it --rm \
        --network=host \
        --security-opt=label=disable \
        --tmpfs=/tmp \
        --userns=keep-id \
        --user=root \
        --env "BUILD_USER=$BUILD_USER" \
        --volume="$PROJECT_ROOT:/build:rw" \
        --pull=missing \
        "$IMAGE" \
        /bin/bash -c "
            echo 'Installing dependencies...' && \
            apt-get update -qq && \
            apt-get install -y -qq pkg-config libssl-dev libcurl4-openssl-dev && \
            rustup component add rust-src && \
            echo 'Switching to user $BUILD_USER for build...' && \
            exec runuser -u \"\${BUILD_USER}\" -- /bin/bash -c '
                cargo \
                    -Z unstable-options \
                    -Z build-std=std,panic_abort \
                    -Z build-std-features=default \
                    -C /build build \
                    --profile=release-native \
                    --target=\"\$(rustc --print host-tuple)\"
            '
        ";then
        log_info "Build completed successfully!"
    else
        log_error "Build failed."
        exit 1
    fi
}

main "$@"
