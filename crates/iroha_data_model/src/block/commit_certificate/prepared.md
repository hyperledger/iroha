# Prepared certificate custody

`PreparedCommitCertificate` measures the four opaque canonical certificate byte
children through `CanonicalParts`' generated Norito field traversal. It admits
their exact array layouts and the immutable shared control together in the
original source pool before allocation or fill. Empty children retain zero-layout
charges without requesting backing storage. Allocator refusal retains the same
charges and already allocated siblings; retry never obtains replacement credit.
Completion moves those original owners into the prepaid shared control. Credits
return only when its final reader releases the actual leaves and control.

`PreparedSignedBlockSignaturesDecode` uses this owner through the canonical
`Option<CommitCertificate>` field, including `Some` with four empty children. The
caller retains the actual charged input, while the decoder retains original
signature and certificate owners across refusals. Canonical
wire bytes, advertised flags, complete field consumption and enclosing logical
limit causes remain mandatory. Logical codec-work quotas do not fund physical
storage, and prepared custody does not authenticate finality.

TODO: physically fund the complete `SignedBlock` payload, transactions, results,
DA, witnesses and execution/private-authority contexts, plus the decoded
certificate header/QC/result/availability semantic graphs. `NativeFinalitySource` preserves an opaque borrow of the actual charged source
and its canonically validated frame span. The native reader rejects a foreign
prepared source pool before block decoding or control admission. Its nested
`SignedBlock` decoder still owns unfunded payload/result/DA graphs; this source
provenance establishes no complete native proof funding. Whole-node, 31-seat, restart and network
qualification remain open.
