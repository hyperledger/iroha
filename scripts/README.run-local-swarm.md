# Bare-metal local swarm

Run `scripts/run_local_swarm.sh --help` from the repository root. It requires Bash,
Python 3 and either Cargo or existing `target/release/{iroha3d,iroha,kagami}` binaries.
It creates four bare-metal peers using the script's existing local demo identities.
`BASE`, ports, build choice and storage reset retain their existing meanings.

Provide paired `GENESIS_PUBLIC_KEY_FILE` and `GENESIS_PRIVATE_KEY_FILE` inputs,
together with `GENESIS_CREATION_TIME_MS` as canonical unsigned 64-bit Unix
milliseconds. The signer receives that exact timestamp. The script creates no
fresh genesis signing key and uses no implicit wall-clock network identity.
Wallet loads are ordinary transactions authenticated by finalized blocks.

`RESET_STORAGE` defaults to `0`, preserving prior storage. Explicitly set it to
`1` to delete prior storage. Every other reset value is rejected before any
output or build. Missing genesis inputs also fail before creating `BASE`,
building binaries or resetting storage.

`BASE` must be an owner-only directory. All generated stop, config, client,
genesis, log and PID paths are checked for symlinks, hardlinks, foreign ownership
and group/other writes before any output changes. Existing private configs and
scripts with public permissions are refused. The private-file writer checks the
opened inode before truncation and refuses symlinks and public existing files.

Generated node and client configurations have owner-only permissions. Every
node configuration references the exact generated genesis identity. The script
runs the daemon's `--check-config` against all four configurations before starting
any peer. The daemon retains its ordinary private-key parsing and genesis checks.

The generated `stop.sh` checks process ownership before signaling peers.
Use `cd "$BASE" && ./stop.sh` to stop a launched swarm.
