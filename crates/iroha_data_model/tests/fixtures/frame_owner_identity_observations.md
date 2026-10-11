# Frame owner identity observations

`frame_owner_identity_observations.json` contains 52 independently observed
serializer/deserializer identities for 27 model frame owners. The two private
commitment-material owners implement only serialization; no decoder was added.

The observations came from the original codec before the frame-identity cutover,
source SHA-256 `728f117b6a49428099460043e0aa152947073d4581e773938d5f29b53328ecfe`.
All selected original-code probes passed. The instrumented model test build
reported 91 `unnameable_test_items` warnings from unrelated function-local probes;
these warnings remain in the capture evidence and are not production qualification.

Fixture SHA-256:
`53464a17aa48bcdaea70b1692c3d76e546c60d64152f6bee1b11680f84403670`.

Before adding the declarations, every owner item body was compared byte-for-byte
with that reference source. Co-located tests check nominal names, frame roots and
each captured direction. Existing payload roundtrips and signed-byte fixtures
remain separate checks; these observations do not establish release readiness.

`additional_frame_owner_identity_observations.json` preserves another 46
serializer/deserializer observations for 23 production owners whose typed frames
are exercised by the model test suite. They were collected from the same original
source and executable, and all selected probes passed. Two additional test-only
receipt probes were observed but are excluded from this production fixture.
Every production owner body again matched the reference byte-for-byte.

Additional fixture SHA-256:
`70a60b15402c0a7145adfcb7807f9ed55251b408e44b4b04df53ecdc62b5b19d`.

The two directions for one retired owner were removed from each fixture.
All surviving observations retain their original captured values; the fixture
digests and counts above describe the retained production owners.

`http_frame_owner_identity_observations.json` adds six original compiler
observations for the SDK's framed `DaIngestRequest`, `DaIngestReceipt` and
`ValidationFail` operations. All six retained original-code probes pass; the
item bodies and attributes match the original source. The validation error keeps
its actual `iroha_data_model::executor::model::ValidationFail` identity despite
its public reexport. HTTP fixture SHA-256:
`ed7393ee2bb6487a1f390c911770db49430a885af8ab39a3e60953f5b016570f`.

The shared test checker verifies all three immutable files, all 104 direction
records and all 53 distinct production owners. Malformed test-only frame producers use
explicit test identities and are qualified by their rejection tests separately.
