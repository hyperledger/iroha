# Frozen worker I/O error guard

The [analysis](analysis/report.json) checks the exact entry path of the remaining
worker-only `std::io::Error` destructor in both frozen ARM64 images. The loaded
error word is masked with `3` and compared with `1`. Tags `0`, `2` and `3` take a
literal restore-and-return path, with an 80-byte local SP decrement and no call.
Only tag `1` enters the custom-error body containing the dynamic destructor at
`0x100001684` (portable) or `0x1000039d8` (accelerated). All fourteen instructions
on this entry/return path are checked; unfamiliar code fails with `UNKNOWN`.

This is a conditional local instruction result. **The original worker indirect
frontier stays open.** The helper selects it from the frozen failure-frontier
report; each image also contains another identically named standard-library
destructor, which is not substituted for this frontier. It records all direct
callers without claiming they all receive a non-custom error.

## Charged read-path source argument

The retained installed Rust 1.93.1 sources show the following ordinary path:

- `Read for File` forwards to `Read for &File`, then to the Unix `File` and
  `FileDesc`. `FileDesc::read` calls native `read`; `cvt` converts `-1` using
  `last_os_error` and `from_raw_os_error` into the scalar `Os` representation.
- `File` uses the default `read_exact`. Its loop propagates these errors,
  discards `Interrupted`, or returns `READ_EXACT_EOF` when the buffer is short.
  That constant uses an aligned static message; it does not create `Custom`.
- On this target, the bitpacked representation uses tag `2` for `Os`, `0` for
  the static message and `1` for `Custom`. The alignment assertions and
  representation selection are included in the retained excerpts.

Thus the concrete charged `File::read`/`read_exact` calls in the frozen worker
have no source path constructing a custom boxed error. Combined with source to
compiler correspondence, valid representation and memory safety, this explains
why their error destruction takes the checked return path. This is not compiled
whole-worker variant-flow analysis. Open/metadata/setup errors, panic/unwind,
signals, callbacks, corrupted state and other runtime behavior are excluded.
Repeated `Interrupted` reads also have no universal retry/time bound here.

Seven complete source snapshots and exact reviewed ranges are retained. Five
are pinned by the older native-source audit, whose exact hash is checked. The
two additional files (`std/fs.rs` and `std/sys/pal/unix/mod.rs`) were compared
byte-for-byte with the upstream commit before their hashes were fixed in the
helper. The report links the corresponding
[Rust error representation](https://github.com/rust-lang/rust/blob/01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf/library/std/src/io/error/repr_bitpacked.rs),
[File implementation](https://github.com/rust-lang/rust/blob/01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf/library/std/src/fs.rs)
and other source files. This provenance does not independently attest the
standard-library machine build or installed native libraries.

## Reproduce

```sh
python3.11 scripts/parliament_ballot_io_error_guard.py --output /tmp/parliament-io-guard-new
python3.11 -m pytest -q scripts/tests/parliament_ballot_io_error_guard_test.py
shasum -a 256 -c docs/validation/parliament_ballot_io_error_guard/SHA256SUMS
```

The output must be a new directory. `--rustdoc-src` overrides the installed
source HTML path. The helper checks frozen manifests, source/build identities,
executable hashes and input stability; it does not rebuild or execute a worker.
The validation receipt records tests and the forced qualification refusal.

TODO: establish whole-worker variant flow or bound all remaining destructor
paths; account for native `read`, errno access, loader, failure and exceptional
resources. No full stack/workspace certificate or profile qualification follows
from this result, and production stays gated.
