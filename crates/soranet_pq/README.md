# soranet_pq

`soranet_pq` provides the post-quantum cryptography building blocks required by
the SoraNet handshake and relay tooling. It wraps the current ML-KEM
(FIPS 203) and ML-DSA (FIPS 204) parameter sets and exposes helpers for
deterministic HKDF derivations and hedged randomness.

## Features

- ML-KEM-512/768/1024 key generation, encapsulation, and decapsulation helpers.
- ML-DSA-44/65/87 key generation, detached signing, and verification helpers.
- HKDF derivation with protocol domain labels (`DH/es`, `KEM/1`, …).
- ChaCha20-based hedged RNG that mixes seed material with live OS entropy and
  reports whether the OS entropy draw succeeded.

## Example

```rust
use soranet_pq::{
    decapsulate_mlkem, encapsulate_mlkem, generate_mldsa_keypair_from_os,
    generate_mlkem_keypair_from_os, sign_mldsa_from_os, verify_mldsa, MlDsaSuite,
    MlKemSuite,
};

// ML-KEM handshake
let kem_keys = generate_mlkem_keypair_from_os(MlKemSuite::MlKem768).unwrap();
let (shared_a, ct) = soranet_pq::encapsulate_mlkem_from_os(
    MlKemSuite::MlKem768,
    kem_keys.public_key(),
)
.unwrap();
let shared_b = decapsulate_mlkem(MlKemSuite::MlKem768, kem_keys.secret_key(), ct.as_bytes()).unwrap();
assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());

// ML-DSA signatures
let dsa_keys = generate_mldsa_keypair_from_os(MlDsaSuite::MlDsa65)
    .expect("ML-DSA keypair generation should succeed");
let message = b"taikai-circuit";
let sig = sign_mldsa_from_os(MlDsaSuite::MlDsa65, dsa_keys.secret_key(), b"", message).unwrap();
verify_mldsa(MlDsaSuite::MlDsa65, dsa_keys.public_key(), b"", message, sig.as_bytes()).unwrap();
```

## Notes

- Secrets are wrapped in `Zeroizing` containers so memory is scrubbed on drop.
- ML-KEM validation rejects noncanonical 12-bit polynomial coefficients
  (values outside `q = 3329`) in public keys and in the secret-key private
  component, and secret-key validation applies the same check to the embedded
  public key before verifying `H(ek)`.
- ML-DSA secret-key validation reconstructs the committed public key, verifies
  the embedded `tr = H(pk)` value, and rejects noncanonical or internally
  inconsistent secret material before signing draws randomness.
- SoraNet ML-KEM and ML-DSA entry points require explicit hedged RNG objects or
  the fallible `_from_os` convenience helpers.
- SoraNet ML-DSA key generation, secret-key recovery, and signing use a safe
  portable Rust implementation of the FIPS 204 polynomial operations. The
  `pqcrypto-mldsa` dependency is used through public byte-oriented interfaces;
  no private PQClean C structures cross into Rust.
  Verification selects the portable CLEAN implementation when AArch64 NEON or
  SHA3 capability is unavailable. Supported hardware retains the existing
  accelerated verifier, and other architectures retain upstream dispatch.
  `verify_mldsa65_detached` preserves the typed verifier API for Iroha and IVM
  consumers so they share the same hardware guard.
- The typed-key `sign_mldsa65_detached` helper retains the ISO 20022 caller's
  pqcrypto key decoding, empty FIPS context, direct OS randomness, and entropy
  failure behavior. It uses the same capability guard and a CLEAN signing
  fallback. This helper does not add SoraNet's canonical-key checks or hedged
  RNG policy to that existing signing API.

## Independent known-answer coverage

The crate retains the six pinned PQClean count-zero responses and also checks a
[50-case official NIST ACVP subset](tests/fixtures/acvp/README.md) across all
ML-KEM and ML-DSA parameter sets. Tests compare independently published outputs,
strict key checks, implicit rejection, signature rejection and context/message
binding. The subset's source revision, full-source hashes, selected case IDs and
reproduction command are documented with the fixtures. This bounded coverage
does not claim ACVP certification or cross-platform qualification.

## C FFI

Workspace builds emit the Rust library. Build the C-compatible artifacts
explicitly with Cargo's crate-type override; Rust does not support conditional
crate types in source attributes.
A ready-to-use header lives at `crates/soranet_pq/include/soranet_pq.h` and
mirrors the exported symbols in `src/ffi.rs`:

```bash
# Build the release C artifacts and copy the header for your project
cargo rustc -p soranet_pq --release --lib \
  --crate-type=rlib,cdylib,staticlib
cp crates/soranet_pq/include/soranet_pq.h /path/to/project/include/
```

Developers that have [`cbindgen`](https://github.com/mozilla/cbindgen) installed
can regenerate the header after editing the FFI surface:

```bash
cbindgen --config crates/soranet_pq/cbindgen.toml \
         --crate soranet_pq \
         --output crates/soranet_pq/include/soranet_pq.h
```

The generated header exposes the `soranet_mlkem_*` and `soranet_mldsa_*` entry
points alongside the shared error codes used throughout the C ABI. Buffer
lengths use `size_t` on every platform. Writable buffers and scalar outputs
must be disjoint from the other live ranges passed to the same call; overlap is
rejected with `SORANET_PQ_ERR_BUFFER_OVERLAP` before any pointer is
dereferenced.
