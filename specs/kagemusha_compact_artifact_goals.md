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
- V2 descriptor bindings retain the exact frame after the canonical decoder has
  re-encoded it for byte equality and validated every descriptor rule. Binding
  computes the same V2-domain digest without repeating validation and encoding;
  malformed frames and invalid arithmetic or transcript profiles still fail
  before a binding is constructed. This removes duplicate work, not admission.
- Complete admission may retain a bounded transient snapshot of compressed
  public originals. Every unique stored/decoded original and each logical role
  is checked; the actual original identities, immutable metadata, names and
  ancestry are revalidated before an owner can return, including error exits.
  The same observed-file map remains with live runtime imports. No expanded
  tables or snapshot bytes persist on disk or survive admission in the wallet.
- Retail delivery packages the complete authenticated carrier with the app:
  all 1,029 compact originals and the four metadata files. Apps stage these exact
  local originals into private custody and use the unchanged strict native
  admission path. Packaging does not confer proof authority or replace signed
  inventory, source, original-hash, bounds or complete-graph checks. Setup does
  not require 1,029 separate artifact HTTP requests. Missing or changed bundled
  material refuses admission; payment generation and verification use local
  material and never trigger a download. App acceptance records must verify the
  actual complete bundle and this local installation path.
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

## Current state (2026-10-15 Asia/Taipei)

The signed generation-4 carrier meets the download budget: **5,017,539 bytes
(4.785 MiB)** including all metadata. Its 1,029 originals occupy 3,886,035
compressed bytes and decode to 117,796,512 bytes in total; decoding is streamed,
not retained as a second disk copy. The four metadata files add 1,131,504 bytes.
The preceding complete dense carrier was 18,689,631,983 bytes. The compact
carrier is about 3,725 times smaller. Neither that count nor the streamed
decoded total is an estimate of the whole app's installed storage.

Both independent complete strict exports pass for canonical native source
`491cc207bdaf92af72cf07c21b95c0455d9ad081aca1240a1e7511f8774cd1ae`.
Each contains 908 members and 2,725 original bindings; every member matches the
preceding qualified profile except source identity and equivalent numeric
formatting. Matching generated DATA has SHA-256
`dffe37c171f8bf6c17377d564678acff31fbc4b792bb77be32fc0b5801dcc10d`.
The ABI 29 Android three-ABI and host libraries and both Apple iOS 18 slices
are rebuilt and accepted against that pair. The maintained source evaluator
still matches at 2026-10-14 16:08 UTC; SDK worker changes do not alter native inputs.

Current host tests pass complete graph reuse and original/role controls, typed
wrapper and compact-key reconstruction controls, and H4 Install/Activate layout
selection. With network access denied, the production carrier passes native
admission in 10.298 seconds and reaches the first unavailable custody-root
callback; a changed signature is rejected before any platform callback. This
is host admission evidence, not a phone opening time or successful enrollment.

The shared Swift and Kotlin SDKs now execute heavy native calls on bounded
8 MiB workers after a physical iPhone finality decoder exhausted its dispatch
stack. All 101 focused SDK/host checks pass, including genuine public finality
decoding from a measured 524 KiB simulator caller. Synchronous ownership,
original errors and separate capacity for payment and folding/snapshot work
are preserved. This repair changes neither proof relations nor native DATA.
The release owner reports Android 40 and iPhone 80107 delivered and installed.
Their physical activation, Load and offline Send/Receive acceptance remain
pending. The coordinated validator update completed against all four retained
ledgers at height 66. Fresh checks at 2026-10-14 16:06 UTC confirm all four
current validators and all six public readiness endpoints; the deployment owner
released the phone-test hold. The earlier successful engineering journey below
retains its original binary identity and is not current-source phone evidence.

The iPhone has completed user authentication and resumed its saved activation,
but has not completed Load. A foreground profile finds repeated native directory
ancestry validation dominating cursor advancement. The next candidate narrows
cached directory selection while preserving complete ancestry and leaf checks;
host before/after measurements and replacement, mode and ACL controls are in
progress. It requires fresh strict exports and matched native libraries before
phone acceptance. The installed phones still use the accepted source above.
Core wallet-ledger recovery also returns HTTP 503; closed-stage diagnostics pass
their unchanged-response regression and await service deployment. Direct
activation finality proofs checked by the device owner are being served
successfully. The separate incoming-payment signer-restricted lookup is repaired
and passes its public-proof HTTP regressions; deployment is in progress.
Android 40's three registration transactions have finalized. These observations
do not yet establish hardware wallet activation or an offline transfer.

Exact current results are retained in
`output/current-source-wallet-20261014/current-source-validation-handoff-v1.json`,
`production-strict-v5/`, `engineering-strict-v5/`,
`native-admission-current-v5/` and `completion-source-audit-v1/` under the same
current-source output directory. Carrier counts, all decoded hashes and the
runtime signature were checked in
`../bpng/png2-deploy/output/current-source-20261014/gen4-carrier-local-validation-v1/result.json`.
Independent reads of Android 39's AAB and Play-signed APK and iPhone 80107's IPA
confirm all 1,033 carrier files are byte-identical to this generation. All 1,029
single-frame originals also pass bounded decompression, raw-length and raw-hash
checks without decoded disk writes. The three packaged Android native hashes
match the accepted source; the iPhone executable contains the same source
identity and its static input matches the release record. The whole APK, AAB
and IPA are respectively 205,282,687, 109,200,480 and 64,500,937 bytes. These are
complete package sizes, not store per-device downloads or installed storage.
The result and the limits of static-link and physical-device verification are in
`output/current-source-wallet-20261014/carrier-completion-audit-v1/audit.json`.
Android 40's subsequent 109,200,651-byte AAB and 205,282,687-byte Play-signed
APK independently pass the same 1,033-file carrier and three-native-library
comparison, with version 40 and minimum API 26 confirmed from their actual
manifests. The APK SHA-256 is
`1ccb3cfa38bcb931b0615b05b8fdeaf68b684a4991aa0858a86a38c618982afc`.
These package checks do not establish physical installation or wallet acceptance;
see `output/current-source-wallet-20261014/android40-carrier-audit-v1/aab-audit.json`
and `apk-audit.json` in the same directory.
An independent public HTTPS check also retrieves all 1,033 generation-4 files
with exact stored sizes and hashes, with no retry. The served financial
selection matches the locally verified signed runtime. The result is
`output/current-source-wallet-20261014/public-carrier-audit-v1/result.json`.
This confirms the published bytes; app installation uses its complete local
bundle, and the public check does not measure PNG connectivity or phone speed.

Production scheme:
`ce12ce4dff53395d3f1bbad62dec9097c41aa5401664bd5841296dcd19a84fc0`.
Manifest:
`96ffc4b776f552fa73cc101508adad3f9b170bab63e15e2fdb96fdc464f72091`.

### Earlier phone loading and storage measurements

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

Android build 38's Play-signed universal APK is **202,453,497 bytes**. Its
stable and immutable direct downloads match the complete APK hash. The in-place
Pixel update from 37 to 38 preserved the original installation. By 03:48 UTC on
2026-10-13, the deployment owner had verified all three saved-registration ledger
steps, successful account activation and session creation. The Pixel displayed
Complete KYC at step 4 of 5, with KYC not submitted. That observation establishes
registration, not offline wallet setup or a physical offline payment.
The packaged three-ABI native libraries and generation-3 runtime match the e6/v2
handoff exactly, including 16 KiB native alignment. Play review and interactive
app acceptance are separate from direct publication. This is a universal APK
size, not a Play per-device download or installed-storage estimate.

The 2026-10-13 03:30 UTC handoff records iOS build **20261013030704** archived,
exported and installed in place. Its App Store IPA is **59,463,699 bytes** and its signed device IPA is
**45,220,858 bytes**. These are complete exports, not Apple's final per-device
download estimate or installed storage. The app consumes the independently
checked v3 device-only SDK, ABI 29/iOS 18, with production App Attest entitlement
and the exact generation-3 runtime. The separately completed full v3 SDK also
contains the simulator slice. All 2,011 device archive member payloads match;
only the archive symbol-index header timestamp differs between the early and
full packages. No extra native compilation or protocol variant was introduced.

That handoff records 32 migration/opening and 33 artifact-delivery simulator
tests, plus 147 native private-filesystem tests including six Apple ancestry
cases. Build 20261013030704 contains no temporary ancestry diagnostic, launches
with the expected native ABI and preserves the 1,029 compact originals. Its
handoff records `uploaded=false` and `hardware_setup_verified=false`. The
03:54 UTC physical retry passed native installation, then encountered an E1
clock refusal. Diagnostic build 20261013040510 confirmed the sandbox denied
`kern.bootsessionuuid` while the sleep-inclusive Mach clock remained available.
These dated observations do not establish hardware enrollment or an offline
payment. The retained app record is
`../bpng/png2-ios/output/iphone-offline-setup-20261013/final-build-handoff.json`;
Android publication is recorded in
`../bpng/png2-android/output/sogeri-final-release/android38-20261013/play38-publication-install-completion.json`.
Those package records contain no whole-app startup or payment timing. Subsequent
package, complete-bundle and physical acceptance results belong in the immutable
`final-delivery-evidence-index-*.json` records under
`../bpng/png2-deploy/output/compact-wallet-20261012/`; they must identify the exact
app, native library, carrier and actual operation observed.

The records are in `output/compact-wallet-phone-20261012/phone-v8/` and
`output/compiled-source-registry-20261013/phone-builtin-v1/`,
`phone-builtin-v2/`, `phone-builtin-v3/`, `phone-builtin-v4/`,
`phone-parameters-v1/`, and `host-consumers-v6/`. A read-only host sample identified packed
selector expansion/planning and physical snapshot checks as remaining hotspots.
Direct packed-bit validation now passes focused planner/descriptor/key tests,
including both-curve proof parity. Reusing the already checked snapshot at
the closing fence passes all 20 encoded/snapshot adversarial tests. The 351234
candidate passes both complete strict exports with every one of the 908 member
entries unchanged except source identity, both complete host inspections, the
typed wrapper regression and all 94 signature/175 Receive batch controls. Its
14.201-second phone result is recorded above. Shipping Android e6/v2 includes
the SDK test-packaging resource fix; Apple 8bf/v3 additionally fixes private
filesystem ancestor access on Apple platforms. Both complete strict v8 exports
match all 908 preceding members except source identity. Host-consumers-v6 passes
both complete profiles, the actual typed wrapper regression and all 94 signature
and 175 Receive batch controls under Apple 8bf/7ddd source/DATA. These records do
not relabel the earlier 351234 phone measurement as a timing of the shipped apps.

The E1 implementation now uses an opaque process-bound, suspend-inclusive native
reading for its five transient elapsed checks. It does not query the custody
boot identity to authorize a live enrollment. Storage checks bracket every
reading; checked duration conversion and the strict floor-milliseconds-plus-one
bound preserve the exclusive signed permit/session deadline. Restart discards
live authority and requires a fresh nonce-bound permit without extending the
original attempt dates. The definitive-absence path rechecks after phase
adoption and before recording a dispatch or generating a hardware key. Returned
vendor originals retain their existing custody and recovery rules. Persisted
time anchors, boot-stamped durability and controlled-payment checks are unchanged.
The clock override and simulated domain exist only in unit tests; production
reads the native clock directly. The boot-denied regression was observed to fail
before the repair with `Provider(Unavailable(Io(1)))`. Final focused test outcomes
and rebuilt consumer acceptance are recorded under
`output/iphone-offline-setup-20261013/` and the delivery index above; source review
alone is not a passing test or a physical-device result. Consumers need a matching
rebuilt native library to receive this E1 runtime repair.

Registry maintenance binds generated DATA to the finalized canonical native
source census. Native package trees, fixtures and explicitly declared external
inputs are included. Unrelated client roots and ordinary top-level/docs/specs
Markdown are excluded; `NativeBridge.swift` and native-consumed documentation
remain explicit inputs. Changes to selected inputs require a fresh strict
generator, independent complete profile exports and exact member parity before
installing matching DATA. Generated DATA is excluded from its own source hash.
Compiler-input containment is checked separately. Exact captures and validation
results remain in retained output records; earlier artifacts keep their original
identities and are never relabelled as results for a later build.

### Real proofs and retained monetary recovery

Generic engine fixtures check generated-versus-compact-imported proof-byte
parity across both Pasta curves. Four Sigma Send/Receive fixtures separately
verify imported proofs and exact proving-key/verifying-key continuity on both
curves; they do not compare two generated and imported proof byte strings.
Four k16 Q-signature fixtures include generated-versus-imported proof-byte
comparison. These results retain their recorded source identities. On the
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
its final Omega fold. An external task interruption stopped B's ArchiveStatus
after checkpoint 7. The exact retained-state continuation now passes as one
terminal native test: it completes the remaining ArchiveStatus fold and restart
replay, then the first C Unload and its fold, using the same retained originals.
It also publishes a model-valid, deliberately bad Sigma fixture and confirms
native proof rejection. Native result `exchange-recovery-5/result.json` and
`12-retained-b-archive-continuation-passed.json` retain these results; no earlier
monetary operation was repeated.

The corrected local Core settlement test passes. The prior failed attempt is
preserved: it expected ledger execution for a malformed claim that routing
correctly refused. The test-only repair verifies the exact account/signature
model refusals, a model-valid bad-Sigma native proof rejection at height 8, and
a real signed Log at height 9. The genuine C payout executes once at height 6;
exact replay and fresh-State replay preserve final online balances A=900, B=0,
C=100 and reserve=0, with total supply 1,000 unchanged.

The same retained C owner then confirms the actual certified settlement in a
separate native process. It ingests heights 1–9, rejects premature confirmation,
retains the exact height-6 result after reopening at heights 5, 6 and 9, and
rejects changed claims/transactions. The monetary snapshot stays unchanged and
no new payment signature is produced. Core stage 13 and native stage 14 each
pass one selected test with zero failures; the aggregate result is
`native-journey-recovery-7-completed.json`. The Core test uses the corrected
8d432c5 fixture; the native continuation uses the copied host-v5 e6/f798 owner.
This is real proof/ledger/finality composition with software hardware and
issuer fixtures and three votes of a four-seat committee. It is not live
four-validator P2P, physical hardware or disk/power-loss qualification.
No successful enrollment, Load, Send or Receive is repeated. Records are in
`../bpng/png2-deploy/output/compact-wallet-native-journey-20261013/` and
`output/compiled-source-registry-20261013/fee-recovery-core-v2/`.

### Delivery acceptance

The selected Android and iPhone delivery records must demonstrate the complete
bundled carrier, exact native/runtime selection, local artifact installation and
interactive hardware wallet setup. Build, host-test, packaging and in-place
installation results establish only their recorded scopes. Physical offline
operation requires its own observation. Keep later package and acceptance
results in the immutable delivery index above so a new observation does not
change the native source census or relabel an earlier binary.

### Remaining performance goals

- Reduce the measured 14.201-second catalogue opening further while preserving
  complete source admission; repeat phone loading, memory and disk measurements
  for the selected binary and measure actual app/package sizes.
- Keep complete payment latency, the two-second durable-completion target,
  low-memory devices and physical-device recovery explicitly unqualified until
  their own measurements pass. Small downloads alone do not establish them.

The compact-catalogue objective and the broader performance goals have different
completion scopes. Meeting the 10 MiB budget with preserved offline proof and
source checks does not close the explicit further-opening measurement item,
whole-payment latency, low-memory readiness or physical recovery requirements.
