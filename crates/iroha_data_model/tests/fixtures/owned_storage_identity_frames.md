# Storage wrapper identities

`owned_storage_identity_frames.json` preserves 144 complete frames across nine
values, 40 nominal identities and two declared layouts (0x00 and COMPACT_LEN).
It covers account details, asset quantities, NFT and RWA storage values, and a
boxed string whose root identity already projects to `String`.

Fixture bytes: 360,896. SHA-256:
`3d291812d99e26e8e85860f0521a2790d201af1dfc3e2e04d10b7d6f92204f53`.

The capture ran before the `Owned<T>`, `AccountDetails`, `NftData` and `RwaData`
identity declarations were added. Compiler-observed names, both directional
hashes, bare payloads, complete frames and JSON were recorded. The retained
988-input source manifest has SHA-256
`e9f3dd3e334ff1642482e9e70b58026372335ebb6c21da1e938101f1a7486157`.
Those inputs remained unchanged through the capture. Eleven retired source
paths were removed afterward; surviving hashes are unchanged. The original
manifest count and digest remain in the capture record. This is development
evidence, not a sealed release candidate or complete feature qualification.
The [capture record](owned_storage_identity_capture.json) retains the observed
artifact and harness identities, validation result and scope limitations.
The [retained input manifest](owned_storage_identity_capture_inputs.json)
is kept alongside it so the surviving source hashes remain inspectable
without local build outputs.

`Owned<T>` forwards the inner type's root frame and preserves its bytes.
Generic parents retain the wrapper's distinct nominal identity: vectors,
options and maps must reject the corresponding unwrapped container's header.
The permanent tests compare the declared identities directly with this frozen
capture and check truncation and exact `SchemaMismatch` rejection. A separate
marker-only test requires neither a binary nor a JSON codec, including through
nested wrappers. The temporary capture writer is removed.

The initial layout matrix exposed invalid metadata frames. Entry serializers
were merging default compact flags into explicit fixed-width layouts; the
handwritten packed writer also failed to advertise its offset table. The
capture above follows the correction: inherited field layouts, checked packed
offsets and streamed entry payloads. The prior failing logs remain under
untracked `target/architecture-redesign/owned-storage-identity/`. They are not
accepted frame fixtures. Default tuple/metadata bytes remain covered by the
existing parity tests; no alternate decoding path was added. Records for the
retired packed layouts were dropped when Norito v1 was pinned to the non-packed
layouts; surviving bytes are unchanged.

The JSON map uses string keys. The separately discovered numeric JSON map-key
writer mismatch remains a distinct correction; this fixture does not qualify
that writer.
