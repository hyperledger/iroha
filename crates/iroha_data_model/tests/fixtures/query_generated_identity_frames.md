# Generated query identity capture

`query_generated_identity_frames.json` records the current 129 query types and
173 typed payloads. Each case retains canonical JSON and complete root, `Vec`,
`Option` and `BTreeMap<u8, T>` frames (692 frames in total), together with the
actual native compiler name and both directional codec identity hashes.

Fixture SHA-256: `dad58b68ffcd197b336236527e383dec9a061c1dade40d8487b3781edfb835ec`.

The scoped contract-manifest query is `FindContractManifestByArtifactId`. Its
native capture binds `DataSpaceId::new(u64::MAX)` and the canonical contract hash
in every frame; the retired hash-only query has no alias or fallback decoder.
The capture uses the same typed JSON and four-context decode/re-encode checks as
the permanent fixture test, without constructing bytes from nominal names.

The ignored `print_generated_query_identity_frames` maintenance test prints the
complete native capture for explicit review; the fixture is that output
formatted with two-space indentation and sorted keys. The ignored
`print_scoped_manifest_query_identity_frame` maintenance test prints the native
scoped row alone. The permanent
`generated_queries_preserve_captured_frames` test compares the current catalog's
exact identity, both codec hashes, canonical JSON and all four frame contexts
against this fixture. These codec checks do not establish live query execution
or release qualification.
