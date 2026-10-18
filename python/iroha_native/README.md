# Iroha native Python boundary

`iroha-native` owns the packaged `iroha_native._crypto` Rust extension and its
strict loader. Both the full SDK and Torii account operations use this one
cryptographic and canonical identity authority. ABI 30, all eleven account key
algorithms, and full multisig policies are mandatory. Missing native artifacts
fail explicitly; there is no alternate module, structural validator, or build
output search path. The loader creates the extension from its inspected packaged
filesystem spec and rejects pre-seeded or replaced modules; callers must obtain
the native module through `load_crypto_extension()`.

Build this wheel with `IROHA_PYTHON_SKIP_RUNTIME_LINK=1 maturin build --release`
in this directory using the repository toolchain, then install it alongside the
pure `iroha-python` wheel.
The build setting omits the CPython shared-library link used by Rust test
executables; packaged extensions resolve Python symbols from their interpreter.
The workspace preserves the extension's symbols in dev, release and deploy
profiles because stripping this Mach-O library on the pinned macOS toolchain
produces a LINKEDIT string pool that dyld refuses to load.
The Rust crate remains at `../iroha_python/iroha_python_rs`; no transport package
is imported by this native boundary.

The maintained SoraFS and privacy Python gates capture the complete clean-source
identity before compilation and recheck it through packaging and qualification.
The SoraFS gate uses one freshly built, authenticated wheel for installed and
natural source tests; the privacy gate preserves the checkout native artifact.
Source promotion preserves the original artifact in an ignored private backup,
uses host atomic no-overwrite renames for both the backup and the same fresh
native physical object, and retains a sealed delivery receipt. The fresh backup
and its existing immediate parent are synced before source removal; no newly
created ancestor durability is claimed. Private temporary and partial objects
are retained on refusal, so cleanup never unlinks a shared source name. Backups are diagnostic artifacts and are
never searched by the loader. An interrupted promotion fails qualification;
its original artifact and intent remain available for explicit recovery.
Promotion requires descriptor-relative filesystem operations and the Linux
`renameat2(RENAME_NOREPLACE)` or macOS `renameatx_np(RENAME_EXCL)` operation.
Unsupported hosts or filesystems are refused without an overwrite fallback. Owner-only file permissions apply on Unix; this is not a Windows
ACL guarantee. The delivery tool itself does not load native code or independently
establish build provenance; the maintained build, ABI and installed-wheel owners
do that.
