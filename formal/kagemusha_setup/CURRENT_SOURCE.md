# Current compact source and the setup experiment

The source refresh reviewed eight previously pinned bodies against their exact
Git preimages. It changes the package's source-consistency boundary, not the
authority of its private parameter experiment. Embedded parameters remain pinned
inputs. Generated registry bytes are recorded only as unqualified DATA in each
control run's before/after receipt, outside the maintained source manifest.
Pinning those bytes would feed their embedded source identity back into itself
through the manifest. These Python controls do not
authenticate a deployed registry, re-run its producer, or qualify a native build.

| Native owner | Old body commit | Reviewed change and remaining premise |
|---|---|---|
| `keys/keygen.rs` | `bdcc2668b8ff2128a6bb8a7a656cc6d0980ced83` | Dense original tables are replaced by witnessless source reconstruction. Both full and metadata import check source shape, quotient-domain validity, copy digest, every selector, source fingerprint and every fixed/sigma commitment before returning authority. Metadata admission omits proving-only buffers. |
| `keys/keygen/rebuild.rs` | `bdcc2668b8ff2128a6bb8a7a656cc6d0980ced83` | Admitted-source and closed compiled-member constructors mint separate opaque seals. Reconstruction still re-synthesizes the exact supplied circuit and checks its descriptor, selectors and source fingerprint before constructing buffers. A compiled-member seal is an additional authority, not a mathematical consequence of the fingerprint. |
| `keys/mod.rs` | `bdcc2668b8ff2128a6bb8a7a656cc6d0980ced83` | Exports the closed compiled-profile API. V2 binding retains the exact frame already canonically decoded and validated, mirroring V1, and hashes that checked frame without a second validate/encode pass. Generated identities, build closure, exact originals and installation require separate qualification. |
| `keys/pk/artifact.rs` | `cafedcdd35dd4d1b8727e33c1899341b3d2fac41` | Sole production original is `PIPACPK1`, containing descriptor digest, exact VK, copy digest and source fingerprint. Canonical extent precedes decoding. A source-fingerprint read returns DATA, never source authority. There is no production dense-format fallback. |
| `keys/source_fingerprint.rs` | `42fa760a41d7f17343dba0ded68e9c54ad338344` | Packed/expanded selectors hash the same low-bit-first rows. Ordinary and fused column hashing feed identical scalar bytes in fixed-then-sigma order. The additional column hashes bind the same borrowed native scalars; they cannot accept an expected VK point. |
| `keys/vk.rs` | `3dedf6f781ed8a65adb585534a1551729fd0c160` | Immutable encoded VK and commitments are shared; selectors borrow canonical bitmaps. The new packed reader preserves exact extent/padding, selector ordering and compression planning. Packed overlap is the OR of bitwise ANDs of equally sized canonical rows, equal to expanded row overlap. |
| `pcs/ipa/commit.rs` | `f963aa270de13d1a7491ca0b963660c5e0fd6ea8` | Only test observation of partial MSM calls changed; production commitment arithmetic is identical. |
| `pcs/ipa/mod.rs` | `6df11a47f7bc51ace2384696196b8507faf192c2` | Parameter owners now retain bounded public-column and generator-prefix memos and dispatch exact embedded representations. Parameter identity excludes memo state; trusted decoding and the coefficient recurrence are unchanged. |

The inventory includes the new delegated implementation owners: packed selector
views and descriptor planning, public-column/block and generator-prefix memos,
embedded parameter loading and its four originals, compact admission, the closed
registry's admission and build-time source-identity owners. Missing roles or changed
bodies refuse before the formal subjects are imported. This is the complete
delegated scope of this review, not the entire transitive native binary or its
external dependencies. Ordinary native field/group arithmetic remains a premise.

Public-column memo entries are computed over exact native scalar slices and the
immutable parameter owner. A whole-column miss sums unblinded contiguous partial
MSMs in row order, then adds `W` exactly once. Empty/all-zero blocks contribute
identity; cancellation cannot publish a partial full-column result. Equality to
the unmemoized commitment additionally assumes collision resistance of the
framed column/block digests. The generator-prefix memo performs the original
ordered monomial-generator sum exactly and requires no digest equality argument.

The old dense original reader and A1 constructor are retained historical
mathematical controls. Their exact historical artifact identities do not become
current production originals when source pins are refreshed. None of their
fourteen small proofs is a current compact-catalogue or native-wallet proof.

## Public-source sufficiency lemma for compact originals

Fix a decoded descriptor `D`, one parameter family, the exact native finalized
fixed/sigma tables `F,S`, selector activations and copy digest. Native source
synthesis and the descriptor's structural validity are premises. The current
original transports only

`PIPACPK1 || digest(D) || LE32(len(VK)) || VK || copy_digest || source_digest`.

The source digest hashes the length-prefixed canonical descriptor, copy digest,
fixed/sigma column counts, domain size, length-prefixed packed selector rows and
all canonical fixed-then-sigma scalars. Full or metadata strict import recreates
that stream from native synthesis and checks each commitment
`C_j = sum_i table[j][i] * G_lagrange[i] + W`.

Conditional on those **same** public tables, changing their transport from dense
bytes to native reconstruction changes no polynomial supplied to the known-log
simulator. Lagrange interpolation is uniquely determined by the ordered domain
values. Consequently every fixed/sigma rotated query, public-only opening value,
proof byte and transcript/arithmetic outcome is unchanged for identical
descriptor, key, parameters, instances and coins. The returned original-digest
metadata changes with the transport, and the request owner deliberately keys
retry identity by the exact original bytes. This lemma does not identify those
different request records or permit replacing an already retained original.
This is a deterministic sufficiency lemma; it
needs no new entropy or transcript assumption. It does not derive public tables
from commitments, a fingerprint, or knowledge of the generator logs.

`compact_source.py` instantiates the algebraic part of this lemma only for k≤6.
It requires explicit canonical public rows, reproduces the exact current source
hash frame, checks compact framing and every independent reference commitment,
and returns the existing `PublicSetup` polynomial view. It has no implicit source
lookup, dense fallback or production admission API. Seven controls cover six
small cases across both curves, identical off-domain/on-domain query values,
independent fingerprint framing, selector packing, canonical-source mutations,
rehashed foreign VKs and rejection of a self-consistent changed fingerprint whose
rows disagree with the VK. The existing fourteen proof cases remain unchanged.

## Remaining current construction gap

The input to the lemma must come from the **current selected relation**. An outer
rebind of a historical key preserves its old embedded recursive keys and curve
points; current compact metadata cannot reconstruct the new relation's tables.
In a chosen setup experiment, re-keying an inner verifier changes the constants
that must be passed into its consuming circuit before source synthesis. No table
hash or opaque source seal supplies that synthesis or proves recursive coherence.

The next constructive lemma is a dependency-ordered re-keying step: given an
already coherent chosen parameter family and strictly checked child descriptors,
keys and source tables, synthesize one parent with those exact child constants,
derive its own source tables and commitments, and show its hard-verifier witness
accepts the child's unchanged complete proof and binds its exact deferred
generator obligation. Native full acceptance must separately decide that obligation.
Applying that step to the actual acyclic catalogue must precede any current k16
privacy experiment. No historical table adapter or compiled registry grant can
replace it. The fixed-RP57 joint transcript law, failure/operational bounds,
erased-endpoint comparison for different histories and all-operation continuation
remain separate C12 premises after that construction.
