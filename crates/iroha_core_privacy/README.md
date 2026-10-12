# Native privacy and execution proofs

`iroha_core_privacy` owns native privacy engines, compiled protocol profiles,
privacy state records and validation plans, verified ledger effects, and
deterministic execution proof relations. It has no dependency on `iroha_core`
or the P2P runtime. Core owns world-state storage, transaction authority,
admission, and application of the returned effects; this crate never opens or
commits a node's world state.

`privacy_verifier::verify_privacy_envelope_v1` is the single dispatch of the
thirteen action roles of the twelve registered protocols. It resolves the one
role of an envelope, asks the typed registry in `privacy_dispatch`
(`PRIVACY_ROLE_DISPATCH_TABLE_V1`) whether that role is verified, runs the
role's native verifier and seals only an effect of that role. A role the
registry records as unsupported returns the typed
`PrivacyVerificationErrorV1::UnsupportedOperation` with its concrete
limitation; it never succeeds. The registry keeps verification, the effect
class, whether the effect is reachable, and delivery as separate facts, and no
role is recorded as delivered.

The implementation uses `ivm` for prepared-contract execution diagnostics and
the IVM step relation, alongside `ivm_abi` for ABI constants. It uses
`fastpq_prover` for accelerated Goldilocks transforms and `fastpq_isi` for the
shared FASTPQ profile identity. These dependencies retain their existing
runtime implementations, including deterministic acceleration and fallback
behavior. The transitive graph therefore includes IVM's configuration and
Sumeragi dependencies. The crate boundary removes Core ownership; it does not
claim an isolated cryptographic-only dependency graph.

Explicit Norito schema identities are independent of the Rust crate location.
The existing `iroha_core::privacy_*` schema names and fixed logging targets
remain the canonical identities. No facade or fallback decoder is provided
at the old public Core module paths. Source-bound compiled manifests name
the current owner paths; historical table preimages retain their original
source paths and hashes.

Default features are `zk-stark` and `simd`. `zk-stark` supplies the ZK-ACE STARK
backend and its compiled profile. `simd` enables SHA-3's assembly backend without
changing outputs. Node and SDK consumers declare their required verifier
features explicitly. `privacy-release-evidence` adds the native evidence
constructors and exact-twelve conformance model; `test-utils` exposes fixture
material without node storage. Neither evidence nor fixture features belong
in production shipping graphs. These features do not introduce runtime
switches for IVM syscalls or opcodes.

Bootle/Lantern interprets its five fixed `u64` rejection-constant limbs through
an explicit 64-byte little-endian integer encoding on both 32-bit and 64-bit
hosts. The constants, Q256 thresholds, random draw order and sampling-profile
identity remain unchanged. Known-answer tests pin all four integer constants,
exact reciprocal floor bounds, standard/bimodal thresholds and the profile digest.

Focused validation uses the checkout's persistent Cargo lane and native
jobserver:

```sh
scripts/cargo_fast.sh --target-slot zk --stable-local-metadata --incremental -- check -p iroha_core_privacy --lib
scripts/cargo_fast.sh --target-slot zk --stable-local-metadata --incremental -- check -p iroha_core_privacy --lib --features test-utils,privacy-release-evidence
scripts/cargo_fast.sh --target-slot zk --stable-local-metadata --incremental -- test -p iroha_core_privacy --lib
scripts/cargo_fast.sh --target-slot zk --stable-local-metadata --incremental -- test -p iroha_core_privacy --lib material_fixture
```

The ordinary suite preserves protocol assertions and ignored qualification
tests. Passing component tests does not establish native privacy release
qualification or whole-network settlement readiness.
