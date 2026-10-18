# Ethereum BLS12-381 vectors

These 98 JSON files are the byte-for-byte upstream files consumed by the SCCP
Python reference and its Rust, EVM and TON replay suites. They live with the
SCCP fixtures because `bls_consensus_v1.json` imports every file here.

- Upstream: <https://github.com/ethereum/bls12-381-tests>
- Release: <https://github.com/ethereum/bls12-381-tests/releases/tag/v0.1.2>
- Tag commit: `89ff3a86f1a9b89a555495f7535c853cda589320`
- Asset: `bls_tests_json.tar.gz` (8,204 bytes)
- Archive SHA-256: `0dc1dfabfa7b3e0f8e8029f9cb2bb8733597526fa085b18f160d2c4eb0b448bc`
- License: **CC0-1.0**, <https://creativecommons.org/publicdomain/zero/1.0/>
- Per-file SHA-256: `manifest.json`; the importer checks every file, the exact
  file set, and the manifest's pinned SHA-256 before reading vector data.

The signature operations use the IETF POP DST
`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` and 32-byte messages. The four
`hash_to_G2` vectors instead use the RFC 9380 test DST
`QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_` and UTF-8 messages.
Canonical infinity passes the generic deserialization suite; SCCP key and
signature admission additionally requires a nonidentity point.
