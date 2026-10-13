# Compact KAGEMUSHA proof artifacts

## Objective

Reduce the mandatory mobile proof catalogue from the measured 18,688,496,481
compressed bytes to at most 10 MiB, while retaining every supported operation,
the exact native circuit relations, authenticated verification keys, hardware
authorization, and fully offline proof generation and verification.

The original dense catalogue contained 505 proving keys, 505 verification keys
and 19 shared descriptors. Dense proving-key originals account for 99.9895% of its
download. The native importer already synthesizes their fixed and permutation
tables independently before comparing them and checking every verification-key
commitment. Sending a second copy of those deterministic tables is unnecessary.

## Implementation contract

- The sole proving-key original becomes `PIPACPK1 || descriptor_digest32 ||
  LE32(vk_bytes) || canonical_vk || copy_digest32 || source_fingerprint32`.
- The existing source fingerprint binds the descriptor, selector activations,
  copy mapping, fixed columns and permutation columns. It remains untrusted
  lookup data, never a serialized source-admission capability.
- Import reconstructs the tables from the installed witnessless circuit, checks
  descriptor, selectors, copy digest and source fingerprint, and checks every
  original verification-key commitment. Strict metadata admission returns only
  descriptor/VK metadata and an opaque seal, without constructing proving FFTs,
  masks or coset caches. Full PK import also constructs those proving buffers.
- Opaque source-admission seals are minted after successful strict native source
  admission or an exact closed built-in member check. The latter accepts only
  immutable native entries exported from independent complete strict qualification
  and bound to the actual source-input identity. Decoded artifact metadata alone
  cannot create a seal or supply expected commitment identities.
- Identical public columns may reuse a previously computed commitment within
  the same immutable pinned-parameter owner. This private runtime memo retains
  at most 8,192 column digests and computed points, is shared only by owner
  clones, and accepts no original VK point or declared source fingerprint as a
  cache entry. Every source and original commitment is still checked; no global
  or persisted cache and no lazily deferred operation-graph admission is added.
  The measured generation-2 originals contain 981 unique Pallas k16 columns and
  284/97/5,666 unique Vesta k12/k14/k16 columns. The bound accommodates this
  working set; a 4,096-entry limit would evict Vesta k16 entries before all
  originals had been traversed. These counts describe SHA-checked public DATA,
  not authority to admit source or a measured setup-time improvement.
- ARM64 source hashing enables the existing SHA-256 implementation's hardware
  instructions with runtime CPU detection and its portable fallback. Hash bytes
  and source admission rules do not change; unsupported Windows assembly is
  excluded from this dependency feature.
- The signed inventory, original hashes, compressed-file hashes, bounded
  decoding, private file custody and complete operation graph remain mandatory.
- Within one complete qualification batch, the first route for each signed
  Receive program admits its entire source under the selected strict or exact
  compiled-profile path. Later selector aliases may
  share that exact immutable owner and its private member-bound seals after
  checking installation, complete ordered Q identities, program, variant,
  context, members and current resource limits. Each alias rereads and checks
  its Omega descriptor/VK and all A/W descriptor/VK/PK originals. Send retains
  route-specific qualification because each owner enforces its own control mask;
  sharing a whole Send owner would erase that runtime policy distinction.
  All route identities remain distinct and final Omega closure remains eager.
- The complete Q batch may share signature-source metadata and its private seal
  only after its own native admission, with exact ordered signature slots,
  fixed keys, member and original identity. Every hit checks the bound source,
  typed profile, current limits and rereads all descriptor/VK/PK originals.
  Each program still derives its current recipe and retains its distinct identity.
  Every QSigma source is admitted independently; signature reuse never admits it.
- Built-in batch reuse additionally authenticates each current compiled role
  against its bounded descriptor/VK/compact-PK originals and compares the exact
  binding, verifier and opaque source seal to the cached typed owner. Public
  strict entry points remain strict.
- A typed built-in importer may reuse canonical descriptor/VK metadata only
  after all three current originals pass their compiled member pins and exact
  byte comparisons. Both importers share bounded compact-PK framing checks;
  the strict importer still decodes and reconstructs its actual source. A
  cached source seal is never an input to the new admission capability.
- Each immutable parameter owner may memoize the original ordered sum of a
  generator prefix in at most 29 cells. Clones share computed public points;
  independent owners remain separate. No caller can insert a point, and memo
  state never changes parameter encoding, identity or proof bytes.
- Verifying-key selector admission checks canonical packed extents and zero
  padding, then tests pairwise overlap directly on those bits. Native synthesis
  and packed admission share the same ordered compression planner and descriptor
  map check. Strict source admission still compares every native activation;
  no source authority is inferred from a decoded bitmap.
- Complete admission may retain a bounded transient snapshot of compressed
  public originals. Every unique stored/decoded original and each logical role
  is checked; the actual original identities, immutable metadata, names and
  ancestry are revalidated before an owner can return, including error exits.
  The same observed-file map remains with live runtime imports. No expanded
  tables or snapshot bytes persist on disk or survive admission in the wallet.
- No dense-format production fallback, remote prover, on-demand network fetch
  during payments, signature-only monetary path, or feature switch is added.

## Goals and completion evidence

1. **Compact engine originals:** replace the dense serializer and importer;
   enforce exact lengths and allocation bounds, cancellation and rejection of
   the retired format.
2. **Security and proof parity:** test source, descriptor, selector, copy,
   fingerprint and commitment mutations; reproduce proofs with the same
   randomness using generated and compact-imported keys. Cover both Pasta
   curves and the wallet's admission/reconstruction path.
3. **Measured complete catalogue:** produce and authenticate the current full
   catalogue from canonical source, compress it, report all original and
   metadata byte counts, and enforce the 10 MiB mobile delivery budget.
4. **Storage, memory and offline wallet integration:** retain only compact
   originals on disk, with no expanded-table disk cache. Measure native import,
   reconstruction and proof times and component-process peak memory; distinguish
   host measurements from phone results. Measure cold wallet opening separately
   from enrollment: source qualification is process-local and repeats after a
   process restart. Preserve complete source admission unless an equally strong
   alternative is established. Validate real operation composition with all
   required material local, including Send/Receive and onward spending, and
   verify that missing or changed material fails closed.
5. **Delivery:** rebuild the canonical native/SDK and BPNG consumers, publish
   the compact generation through `png2-deploy` on the approved OVH host, and
   verify the deployed sizes and signed runtime selection. Report separately
   any physical-device checks that cannot be performed here.

## Current state (2026-10-13 JST)

The signed generation-3 carrier meets the download budget: **5,017,489 bytes
(4.785 MiB)** including all metadata. Its 1,029 originals occupy 3,885,985
compressed bytes and decode to 117,796,512 bytes in total; decoding is streamed,
not retained as a second disk copy. The four metadata files add 1,131,504 bytes.
The preceding complete dense carrier was 18,689,631,983 bytes. The coordinated
release task reports the generation-3 server cutover and signed runtime
selection complete on the approved OVH host. Shipping native v9/G3 remains
separate from the unshipped startup optimizations below.
An independent public HTTPS check retrieved all 1,029 encoded originals with
their exact stored extents and hashes. Ten initial connection timeouts passed
one targeted retry; this verifies the served bytes, not uninterrupted
availability or phone download latency. The retained result is
`../bpng/png2-deploy/output/compact-wallet-20261012/public-originals-check-20261013-v1/retry-timeouts-1/result.json`.

Production scheme:
`aed95157c9a15d6affd07e150a36fc3ff48cba3fa8d7f5065978e48ba3b22bb9`.
Manifest:
`929a468417604b2c34e8f7ea8ed08b1c100a16a2537a772ec96bfe2fc24bfbaa`.
Byte counts and deployment handoff are retained in
`../bpng/png2-deploy/output/compact-wallet-20261012/carrier-handoff.json`
and `carrier-inspection.json`.

### Phone loading and storage

On the Pixel 6 (ARM64, Android API 37), isolated complete source-graph loading
passed all 32 programs and 52 routes under both paths:

| Captured diagnostic | Native total | Peak process RSS | Allocated carrier storage |
| --- | ---: | ---: | ---: |
| Strict source reconstruction, v8 | 701.473 s | 576,408 KiB | 7,224 KiB |
| First generated built-in profile | 103.837 s | 708,032 KiB | 7,232 KiB |
| Bounded snapshot, batch reuse and pinned parameters (c66) | 57.735 s | 552,012 KiB | 7,224 KiB |
| Generator-prefix memo and validated metadata reuse (5a62) | 18.303 s | 551,832 KiB | 7,232 KiB |
| Packed selector validation and closing snapshot reuse (351234) | 14.201 s | 551,748 KiB | 7,224 KiB |

The first built-in run spent 17.765 s in pack/parameter loading and 85.829 s in
complete graph admission. The 5a62 diagnostic spent 1.112 s and 17.026 s
respectively (18.334 s wall time), reducing native loading time by 68.3% from
c66 while leaving peak memory effectively unchanged. The later 351234 run spent
1.064 s in pack/parameter loading and 12.966 s in complete graph admission
(14.241 s wall time), a further 22.4% reduction from the preceding single run.
Peak memory remained effectively unchanged. Both runs' temporary/output
directories remained empty and carrier allocation did not grow. These are isolated public-file diagnostic
processes, not complete app startup, enrollment or payment timings; filesystem
caches may be warm and runs were not a controlled statistical comparison.
Neither loading time nor memory use is acceptable evidence of low-end-phone
readiness. Peak process RSS is not steady-state catalogue memory. Both apps
retain the same admitted native owner across payments, but source qualification
is process-local and repeats after restart or owner retirement. It is not a
one-time installation cost.

Both engineering and production compiled profiles were independently exported
by the strict generator. Complete host inspections and actual typed wrapper
regression passed, including changed originals, missing/foreign roles,
cancellation, exact compact-PK rebuild and a same-schema foreign plan rejection.
The current optimization adds exact batch reuse, removes redundant immutable
file snapshot checks at the same read fences, and snapshots bounded compressed
public DATA during complete admission. The c66 candidate passes complete production and engineering host inspection,
63 focused snapshot/parameter/witness tests, the typed wrapper regression, and
94 signature plus 175 Receive batch controls. The later b6 candidate adds the
private fee-witness repair below; both complete 908-member profiles were
independently exported through strict source reconstruction. The 5a62 candidate
adds the private generator-prefix memo and exact validated-metadata reuse. Its
15 focused tests include genuine proof-byte parity, bounds, malformed originals,
foreign typed metadata and cancellation. Both complete strict exports reproduce
all 908 preceding profile members byte-for-byte except the source identity;
fresh complete host inspections, typed wrapper and all 94 signature/175 Receive
batch controls pass. Its phone timing measures the copied diagnostic binary,
not either packaged app.

Four public parameter constructor probes on the Pixel produced exact canonical
byte/native-pin parity. Combined derivation took 17.147 s versus 0.956 s for
pinned decoding. The generic native parameter constructor now embeds those four exact arrays
and checks the existing native pins on decode; selected decoding failures never
fall back to derivation. This adds 9,699,600 source-asset bytes per native slice
(29,098,800 across a universal three-ABI Android package before packaging).
The b6 arm64 Android library is 62,320,952 bytes, an increase of 10,272,936
bytes from v9; its Apple device static archive is 119,364,064 bytes, an increase
of 10,915,824 bytes. These are native binary/archive sizes, not final APK/IPA
downloads or installed app sizes. Do not describe the 4.785 MiB catalogue as the
total app download. The one-trial constructor measurements exclude file reading
and post-constructor equality checks; whole-child memory and time include them.

Corrected Android build 37 and iOS build 20261012231728 have completed packaging.
The actual Google Play-signed universal Android APK is 202,502,649 bytes. Its
stable and versioned direct downloads match the complete APK hash, and an
in-place Pixel update preserved the admitted signer and original installation.
The four catalogue metadata files in that APK match the compact generation-3
handoff exactly. A bounded warm launch loaded JNI without a crash, but the
device keyguard prevented wallet/session acceptance checks. The AAB is
105,204,401 bytes; neither universal-package size is a Play per-device estimate.
The iOS App Store export is 59,460,655 bytes and the signed device IPA is
45,233,031 bytes; these are complete exported packages, not Apple's final
per-device download estimate or installed storage. The coordinated owner
verified the iPhone's in-place installation and version. Apple reports this
exact build valid, approved and in active public TestFlight testing. Interactive
device acceptance remains pending. Those packages precede the separately tested 351234
startup optimizations; no final APK/IPA size or app startup claim is inferred
from the diagnostic CLI.

The records are in `output/compact-wallet-phone-20261012/phone-v8/` and
`output/compiled-source-registry-20261013/phone-builtin-v1/`,
`phone-builtin-v2/`, `phone-builtin-v3/`, `phone-builtin-v4/`,
`phone-parameters-v1/`, and `host-consumers-v4/`. A read-only host sample identified packed
selector expansion/planning and physical snapshot checks as remaining hotspots.
Direct packed-bit validation now passes focused planner/descriptor/key tests,
including both-curve proof parity. Reusing the already checked snapshot at
the closing fence passes all 20 encoded/snapshot adversarial tests. The 351234
candidate passes both complete strict exports with every one of the 908 member
entries unchanged except source identity, both complete host inspections, the
typed wrapper regression and all 94 signature/175 Receive batch controls. Its
14.201-second phone result is recorded above. Matching shipping libraries require
a fresh source capture that includes the SDK test-packaging fix; that resource
packaging change does not alter the native proof implementation.

### Real proofs and retained monetary recovery

Generated-versus-compact-imported proof bytes match for four Sigma Send/Receive
fixtures across both Pasta curves and four k16 Q-signature fixtures. On the
Pixel, Sigma key reconstruction/import took 69–247 ms and proofs 667–872 ms;
one-/two-slot Q-signature key reconstruction took 1.281/1.014 s and proof plus
self-verification took 31.087/24.931 s. The combined Q test peaked at 527,692 KiB.
These deterministic component fixtures do not represent hardware-authorized
whole payments. Records: `output/compact-wallet-phone-20261012/phone-component-sigma/`
and the corresponding Q-signature component output.

The retained engineering journey passes native Bootstrap/Activate, executed A
funding and finality-backed Load; Load and both recipient Bootstrap folds;
exact completed A Send recovery during a signature outage with unchanged sender
state; B Receive/retry/deduplication and its complete fold; B→C Send/exact retry;
and C Receive/restart/exact retry and its complete fold. Value conservation
assertions pass with 100 units owned and zero burned. All proof material is local.

The first continuation verifies A's ArchiveReceive package, unchanged money and
exact immediate retry, but fails while folding A's earlier retained Send
sequence 2 after checkpoint ordinal 5. The zero-fee preparation path used
unauthenticated dummy paths instead of the predecessor fee-map opening. The
repair keeps the authenticated no-op witness private to proof assembly so the
persisted canonical capsule retains exactly its original insertion list.

Eight focused tests pass, including empty/populated fee maps, positive-fee
insertions and exact capsule-byte preservation. One guarded continuation of the
same retained Send now passes the actual previously failing checkpoint 6, with
unchanged monetary snapshot and exact completed Payment after reopening; it
creates zero keys, signatures or monetary operations. The same retained Send
has since completed checkpoints 7–10 and its final Omega fold. A's retained
ArchiveReceive then completed all 22 checkpoints and its final Omega fold;
exact replay after restart passes with unchanged monetary value. The same
continuation also completed B's retained Send through all 11 checkpoints and
its final Omega fold. It is running B's ArchiveStatus and then C Unload.
That remaining archive fold, Unload, local Core settlement and native confirmation
remain unproved until it finishes.
No successful enrollment, Load, Send or Receive is repeated. Records are in
`../bpng/png2-deploy/output/compact-wallet-native-journey-20261013/` and
`output/compiled-source-registry-20261013/fee-recovery-core-v2/`.

### Outstanding completion conditions

- Reduce the measured 14.201-second catalogue opening further while preserving
  complete source admission; repeat phone loading, memory and disk measurements
  for the selected binary and measure actual app/package sizes.
- Finish the retained monetary continuation through Archive and Unload;
  keep real proofs, finality, exact retries and permanent deduplication intact.
- Rebuild and validate the current Android/iOS native consumers, then hand off
  only a matching tested candidate through the coordinated deployment owner.
- Keep complete payment latency, the two-second durable-completion target,
  low-memory devices and physical-device recovery explicitly unqualified until
  their own measurements pass. Small downloads alone do not establish them.
