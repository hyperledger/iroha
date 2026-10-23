# syntax=docker/dockerfile:1
#
# Image for Anthropic's OSS Scanner (https://red.anthropic.com/oss-scanner/). The scanner builds this file with a fresh
# checkout of the enrolled branch as the context, then audits the image offline on a smaller machine (2 CPUs, 8 GB).
# threat_model.md beside this file says what is in scope and how to use what this file builds.
#
# The build fetches every crate in Cargo.lock, then prebuilds in the dev profile (debug assertions and overflow checks
# on) the binaries the release image ships (see the repository Dockerfile) and the test binaries of the crates that
# parse untrusted input. The scanner allows 45 minutes for the clone, this file and its own layers, and iroha_core
# alone is about 1.5M lines, so the compile steps share one OSS_SCANNER_BUDGET_MINUTES budget after dependency fetch.
# The deadline is initialized in the compilation RUN, so rebuilding changed source never reuses a cached deadline.
# Every prebuild must finish before the deadline; timeouts, compile errors and abnormal exits fail the build.
# /opt/oss-scanner/build.log in the image records how each step ended. Package installation, toolchain
# installation, fetching dependencies and exporting/unpacking the image
# also count toward the scanner's overall limit. Leave time for those outside this compilation budget: exporting
# and unpacking the compiled artifacts alone can take over eleven minutes.
#
# Dockerfile.dockerignore beside this file replaces the repository's .dockerignore for this build, so the image keeps
# the whole checkout, .git included.

FROM debian:trixie

# The workspace's profile.dev turns incremental compilation on and profile.test turns it off. Without
# CARGO_INCREMENTAL=0, `cargo test` recompiles every workspace crate that `cargo build` compiled.
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    CARGO_INCREMENTAL=0 \
    CARGO_TERM_COLOR=never \
    RUST_BACKTRACE=1

# build-essential compiles the C in blst, ring and zstd-sys, and mold links the large binaries. Tests call git,
# python3 and openssl, and the localnet start script needs python3.
RUN mkdir -p /opt/oss-scanner \
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

# within-budget NAME COMMAND...: run COMMAND until the shared deadline. An incomplete prebuild fails the image.
COPY --chmod=0755 <<'EOF' /usr/local/bin/within-budget
#!/bin/sh
set -u
name=$1
shift
left=$(( $(cat /opt/oss-scanner/deadline) - $(date +%s) ))
if [ "$left" -lt 60 ]; then
    echo "$name: skipped, the build deadline had passed" | tee -a /opt/oss-scanner/build.log
    exit 124
fi
started=$(date +%s)
timeout --kill-after=60 "$left" "$@"
status=$?
took=$(( $(date +%s) - started ))
case "$status" in
    0) outcome="done in ${took}s" ;;
    124) outcome="stopped at the deadline after ${took}s, unfinished" ;;
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

# Build the release image's binaries, Kotodama compiler and Kagami in one feature graph so Kagami does not rebuild
# the node's large dependency tree. Kagami adds the data model's exact-12 conformance helpers, not test-fixtures.
# A network needs at least four validators (3f + 1), and `kagami localnet generate` writes one.
# The opt-in build-features package aligns dependency features across Cargo invocations so the test prebuilds
# reuse the production data model. Explicit target filters leave its support binary and unused owners unbuilt.
# Keep Crypto's FHE fixtures and Sumeragi's sim feature separate from model-dependent tests: both change
# data-model dependency fingerprints. Select all default library/integration harnesses;
# example-only build checks can be compiled offline when needed. Pin the source-rescan sentinel between Cargo
# invocations, before it can invalidate reusable dependencies. Timings and sizes make remaining costs visible.
# Initialize the shared deadline in this RUN so cached setup layers cannot consume a future compilation budget.
ARG OSS_SCANNER_BUDGET_MINUTES=28
RUN echo $(( $(date +%s) + ${OSS_SCANNER_BUDGET_MINUTES} * 60 )) > /opt/oss-scanner/deadline \
    && within-budget "release binaries and kagami" cargo build --locked --timings \
         -p irohad -p iroha_cli -p iroha_torii -p kotodama_toolchain -p iroha_kagami -p oss-scanner-build-features \
         --features irohad/external-software-signer-bin,oss-scanner-build-features/scanner \
         --bin iroha3d --bin iroha3d_taira --bin sorafs_governance_dag --bin sorafs_external_software_signer \
         --bin iroha --bin attachment_sanitizer --bin koto --bin kagami \
    && pin-iroha-plonk && du -sh target \
    && sha256sum target/debug/iroha3d target/debug/iroha3d_taira target/debug/sorafs_governance_dag \
         target/debug/sorafs_external_software_signer target/debug/iroha target/debug/attachment_sanitizer \
         target/debug/koto target/debug/kagami > /opt/oss-scanner/binaries.sha256 \
    && within-budget "codec VM and P2P tests" cargo test --locked --no-run --timings --lib --tests \
         -p norito -p ivm -p iroha_p2p -p oss-scanner-build-features \
         --features oss-scanner-build-features/scanner \
    && pin-iroha-plonk && du -sh target \
    && within-budget "crypto and simulator tests" cargo test --locked --no-run --timings --lib --tests \
         -p iroha_crypto -p iroha_sumeragi -p oss-scanner-build-features \
         --features iroha_sumeragi/sim,oss-scanner-build-features/scanner \
    && pin-iroha-plonk && du -sh target \
    && sha256sum --check /opt/oss-scanner/binaries.sha256

# Record CLI startup and internal-subprocess availability, then print what the audit gets.
# attachment_sanitizer requires its parent's private IPC setup and intentionally has no --help CLI.
RUN status=0; for bin in iroha3d iroha3d_taira sorafs_governance_dag sorafs_external_software_signer iroha kagami koto attachment_sanitizer; do \
      if [ ! -x "target/debug/$bin" ]; then echo "$bin: not built"; status=1; \
      elif [ "$bin" = attachment_sanitizer ]; then echo "$bin: built, internal subprocess (no --help CLI)"; \
      elif "target/debug/$bin" --help >/dev/null 2>&1; then echo "$bin: built, --help works"; \
      else echo "$bin: built, but --help failed"; status=1; fi; \
    done >> /opt/oss-scanner/build.log \
    && cat /opt/oss-scanner/build.log && test "$status" = 0

# Everything is fetched. From here on Cargo must not try to reach a registry.
ENV CARGO_NET_OFFLINE=true
