# syntax=docker/dockerfile:1
#
# Image for Anthropic's OSS Scanner (https://red.anthropic.com/oss-scanner/). The scanner builds this file with a fresh
# checkout of the enrolled branch as the context, then audits the image offline on a smaller machine (2 CPUs, 8 GB).
# threat_model.md beside this file says what is in scope and how to use what this file builds.
#
# The build fetches every crate in Cargo.lock, then prebuilds in the dev profile (debug assertions and overflow checks
# on) the binaries the release image ships (see the repository Dockerfile) and the test binaries of the crates that
# parse untrusted input. The scanner allows 45 minutes for the clone, this file and its own layers, and iroha_core
# alone is about 1.5M lines, so the compile steps share one deadline, OSS_SCANNER_BUDGET_MINUTES after the first RUN.
# A step still running at the deadline stops, keeps what it compiled and lets the build finish. A compile error still
# fails the build, and the scanner emails the log to primary_contact. /opt/oss-scanner/build.log in the image records
# how each step ended.
#
# Dockerfile.dockerignore beside this file replaces the repository's .dockerignore for this build, so the image keeps
# the whole checkout, .git included.

FROM debian:trixie

ARG OSS_SCANNER_BUDGET_MINUTES=30

# The workspace's profile.dev turns incremental compilation on and profile.test turns it off. Without
# CARGO_INCREMENTAL=0, `cargo test` recompiles every workspace crate that `cargo build` compiled.
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    CARGO_INCREMENTAL=0 \
    CARGO_TERM_COLOR=never \
    RUST_BACKTRACE=1

# The deadline clock starts here. build-essential compiles the C in blst, ring and zstd-sys, and mold links the large
# binaries. Tests call git, python3 and openssl, and the localnet start script needs python3.
RUN mkdir -p /opt/oss-scanner \
    && echo $(( $(date +%s) + ${OSS_SCANNER_BUDGET_MINUTES} * 60 )) > /opt/oss-scanner/deadline \
    && apt-get update && apt-get install -y --no-install-recommends \
         build-essential ca-certificates curl git mold openssl python3 \
    && rm -rf /var/lib/apt/lists/*

# The toolchain rust-toolchain.toml pins, with rustfmt and clippy for checking patches.
COPY rust-toolchain.toml /tmp/rust-toolchain.toml
RUN channel=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' /tmp/rust-toolchain.toml) \
    && test -n "$channel" \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
       | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "$channel" --component rustfmt,clippy \
    && rm /tmp/rust-toolchain.toml \
    && rustc --version

# Each node binary is close to 1 GB; mold links them in seconds.
COPY <<'EOF' /usr/local/cargo/config.toml
[target.'cfg(target_os = "linux")']
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
EOF

# within-budget NAME COMMAND...: run COMMAND until the shared deadline. Reaching the deadline is not a failure: the
# step keeps what it compiled, and rerunning the same command offline finishes it.
COPY --chmod=0755 <<'EOF' /usr/local/bin/within-budget
#!/bin/sh
set -u
name=$1
shift
left=$(( $(cat /opt/oss-scanner/deadline) - $(date +%s) ))
if [ "$left" -lt 60 ]; then
    echo "$name: skipped, the build deadline had passed" | tee -a /opt/oss-scanner/build.log
    exit 0
fi
started=$(date +%s)
timeout --kill-after=60 "$left" "$@"
status=$?
took=$(( $(date +%s) - started ))
case "$status" in
    0) outcome="done in ${took}s" ;;
    124 | 137) outcome="stopped at the deadline after ${took}s, unfinished"; status=0 ;;
    *) outcome="failed with exit status $status after ${took}s" ;;
esac
echo "$name: $outcome" | tee -a /opt/oss-scanner/build.log
exit "$status"
EOF

# TODO: drop this workaround once crates/iroha_plonk/build.rs stops deleting its own rerun-if-changed input. As it
# stands, every Cargo invocation reruns that script, then recompiles iroha_plonk and everything above it
# (sorafs_manifest, iroha_data_model, ivm, iroha_core, the node). On the audit machine every `cargo` command would
# then rebuild the node. pin-iroha-plonk puts the input back with a date in 2000. Edits to the files the script
# watches still rerun it; only the detection of new source files is skipped.
COPY --chmod=0755 <<'EOF' /usr/local/bin/pin-iroha-plonk
#!/bin/sh
# Stop iroha_plonk's build script from rerunning in every build configuration under /src/target (see
# .oss-scanner/Dockerfile). Run it again after building a new configuration that includes iroha_plonk.
for out in /src/target/debug/build/iroha_plonk-*/out; do
    if [ -d "$out" ]; then
        touch -t 200001010000 "$out/native-source-rescan-required"
    fi
done
EOF

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Every crate in Cargo.lock, for every platform and feature, so the audit can build other configurations offline.
RUN cargo fetch --locked

# The release image's binaries plus the Kotodama compiler, built together as the repository Dockerfile builds them
# (adding koto changes no features).
RUN within-budget "release binaries" cargo build --locked \
      -p irohad -p iroha_cli -p iroha_torii -p kotodama_toolchain \
      --features irohad/external-software-signer-bin \
      --bin iroha3d --bin iroha3d_taira --bin sorafs_governance_dag --bin sorafs_external_software_signer \
      --bin iroha --bin attachment_sanitizer --bin koto

# kagami next: a network needs at least four validators (3f + 1), and `kagami localnet generate` writes one. It is
# built on its own because building it with the binaries above would unify its test-only features
# (iroha_core/iroha-core-tests, among others) into iroha3d.
RUN within-budget "kagami" cargo build --locked -p iroha_kagami --bin kagami

# Test binaries, each built exactly as `cargo test -p <crate>` resolves it. Cargo resolves features per invocation,
# so each crate's tests are a separate build from the node's. The most useful come first, and the deadline decides how
# far the list gets.
RUN within-budget "norito tests" cargo test --locked --no-run -p norito
RUN within-budget "iroha_sumeragi simulator tests" cargo test --locked --no-run -p iroha_sumeragi --features sim
RUN within-budget "iroha_crypto tests" cargo test --locked --no-run -p iroha_crypto
RUN within-budget "ivm tests" cargo test --locked --no-run -p ivm
RUN within-budget "iroha_p2p tests" cargo test --locked --no-run -p iroha_p2p

RUN pin-iroha-plonk

# Record which binaries start, then print the log, so the scanner's build output shows what the audit gets.
RUN for bin in iroha3d iroha3d_taira iroha kagami koto attachment_sanitizer; do \
      if [ ! -x "target/debug/$bin" ]; then echo "$bin: not built"; \
      elif "target/debug/$bin" --help >/dev/null 2>&1; then echo "$bin: built, --help works"; \
      else echo "$bin: built, but --help failed"; fi; \
    done >> /opt/oss-scanner/build.log \
    && cat /opt/oss-scanner/build.log

# Everything is fetched. From here on Cargo must not try to reach a registry.
ENV CARGO_NET_OFFLINE=true
