# Contextual BLS single-signature verification

Both BLS orientations use `canonical.rs` for checked, canonical, nonidentity
point parsing and `uncached.rs` for the single-signature relation. The checked
W3f/Ark decoder writes roundtrips into fixed 96-byte backing. Conversion to the
fixed blstrs point representation also checks canonical encoding, subgroup and
identity. The synchronous blst core borrows the message without retaining it.

The transcript is Iroha's existing W3f basic-ciphersuite prefix followed by
`for signing messages` and the message, with the one-byte hash-to-field DST
`[1]`. It is not the Ethereum PoP transcript. Wire bytes and this transcript
are shared across all hardware.

`Signature::verify` validates the public key first, then returns `BadSignature`
for all-zero or wrong-length signature material. The typed `BlsImpl::verify`
diagnoses all-zero signature material before typed-key identity. Other parser
reasons retain exact canonical/identity/decoder distinctions. Supplied typed
keys must also pass subgroup validation; manually constructing a point does
not bypass the public verification contract.

Ordinary verification may retain an exact positive-verdict cache. The digest
only selects a bucket; full public-key, message and signature bytes establish
a hit, after canonical parsing. It does not retain a prepared-key cache or
enter the generic decoded-key cache for BLS. Admission calls the same parser
and relation without any retained verification cache.

The parser retains the actual typed `ark_serialize::SerializationError`; it
never infers a decoder reason from input flags. The supported borrowed point
decoders return allocation-free failures. The ordinary public `Error::Parse`
adapter materializes its exact diagnostic String outside that core.
Positive-cache backing, public diagnostic Strings, aggregate verification,
PoP cache retention and signing allocations have separate lifetime owners.
This single-signature boundary does not establish their funding or complete
authenticated-State capture.

`uncached_tests.rs` verifies independently generated W3f and blst signatures,
exact upstream message points and allocation observation. Permanent
`consolidation_tests.rs` controls assert a compact table of specified parser
diagnostics, facade precedence, every compressed-flag family, field boundaries,
suffixes, typed subgroup tripwires and retained-cache bypass. Shipping source
contains no copied retired parser or single-signature verifier.

## Consensus suite

`consensus.rs` (`iroha_crypto::bls::consensus`) is the only BLS API that signs
under the IETF min-pk proof-of-possession tag `DST_SIG`
(`specs/sumeragi.md` §1 item 6); the verify-only Ethereum sync-committee API
shares only its hash-to-curve. It signs `SHA-256(P)` only for a preimage `P`
that matches one allowlist row exactly (Sumeragi kinds `0x01`–`0x05` and the
RS16 availability statements); `ConsensusDigest` has no other constructor.
Signing reuses the checked scalar decoding and blinded split of `signing.rs`
with no augmentation. Verification requires canonical, in-subgroup,
non-identity points, a non-identity aggregate key, PoP-admitted keys without
repetition (per group) or keys from an authenticated committee root, and
distinct digests across `AggregateVerify` groups. Every consensus verifier runs
on one `blst` pairing context; `ConsensusAggregateScratch` admits its exact
backing before allocation like `BlsNormalAggregateScratch` and then verifies
without heap allocation, and the free functions use an unfunded context. The
w3f transcript above and the w3f proof of possession are unchanged, so neither
suite's signatures verify in the other.
`fixtures/sccp/bls_consensus_rust_v1.json` holds the shared vectors; its unit
test regenerates the file and fails on any difference.
`consensus/tests/python_reference.rs` reproduces every row of the independent
Python reference `bls_consensus_v1.json` (`scripts/sccp_reference`), including
RFC 9380 vectors and a captured Ethereum mainnet sync-committee aggregate.
