# NEW first-release E1 app and enrollment policy contract

This proposal fills the two current E1 policy preimage gaps. Its types, tags, domains,
serialization choices and lifetime rules are NEW first-release protocol decisions. They are
not a recovered historical grammar, external approval, or a mapping of any existing opaque
policy digest. Kagemusha has no enable switch or disabled policy variant.

Revision 2026-10-10 applies the single hardware-attestation admission rule of the
[design](kagemusha_single_design_proposal.md) §2.2. The Android app arm pins a package, a
minimum package version and a signer set. The Android enrollment arm pins a root set whose
entries each name a revocation source. No arm carries a hardware selector, a Play Integrity
field or any other vendor online verdict. This is a first-release replacement: the earlier
Android arms have no decoder, and the Model, Python projection, SDK consumers and shared
vectors change together, in the coordinated cutover of design
[§9.1](kagemusha_single_design_proposal.md#91-cutover-sequencing). Until that cutover the
contract that the code of the validator baseline, Iroha `ff7ec9457c`, implements stays in
force. These are app-attestation and issuer-policy changes: the policy frames are issuer
inputs that no ledger instruction,
validation rule or state decodes, and the E1 challenge and credential carry only their
32-byte digests.

The Native issuer selects and retains two unsigned canonical Norito originals:
`KagemushaWalletAppPolicyV1` and `KagemushaWalletEnrollmentPolicyV1`. Public clients carry
their digests in the existing E1 transcript. Neither policy construction, validation, hashing
nor E1 comparison proves operator approval. The issuer must authenticate the actual approved
selection for the scheme and asset using its genuine operator-owned configuration and
custody mechanism. There are no bundled production policies, approvals, roots or signer keys.

## Canonical frames and transcript encoding

Each policy uses canonical Norito with the existing wallet decode limits and a NEW 1024-byte
complete-frame cap. The NEW frames contain no u128 and require zero type padding, asserted
in the shipping Model without changing the preserved existing alignment contract. Decode
order is byte cap, canonical decode under payload-derived limits,
version 1, independently selected scheme, then structural rules. Pair and E1 binding checks
follow before verification or signing. The 1024 cap is an explicit conservative frame budget
for small bounded policy objects; it is not an existing published ABI size. The largest
Android enrollment-policy frame (eight Vendor roots with 16-byte adapter identifiers) and the
largest Android app-policy frame (a 255-byte package and four signers) must fit it. The
transcript sizes below do not establish that: the complete frame adds the Norito header,
u32 discriminants and field and sequence length prefixes. The Model's tests encode both
maximal policies with the actual Norito encoder and assert each complete frame is at most
1024 bytes (`new_policy_maximal_norito_frames_fit_the_complete_frame_cap`). The
canonical-frame and every-byte-substitution tests enforce Native roundtrip and
mutation rejection. Python consumes a private typed
projection and computes transcripts; it does not introduce another policy wire codec.

Hash identity uses the existing wallet `H` construction:
`SHA256("iroha:kagemusha:wallet:v1:" || ASCII(role) || 00 || LE64(body length) || body)`.
The two NEW role labels are `app-policy` and `enrollment-policy`. These identities choose
enrollment inputs; no recursive relation recomputes them. They introduce no Poseidon signing
domain, signature type, signer role or certificate chain. Existing signatures and the E1
challenge layout retain their current definitions. No signature over these unsigned policies
is invented.

Transcript integers are fixed-width little endian. Digests/pins are raw nonzero 32-byte
values. Text uses `LE32(UTF8 byte length) || exact UTF8 bytes`, preventing concatenation
ambiguity; no Unicode normalization, case folding, alternate terminator or padding is used.
Transcript tags below equal explicitly indexed Norito enum discriminants. The same number
is a u32 discriminant in the Norito frame and a single u8 byte in the hash transcript; the
two encodings are distinct and never substituted for each other. Zero and undefined enum
tags are rejected.
A count is one byte in the transcript and the Norito sequence length in the frame.

The app-policy transcript starts `LE16(version) || scheme_id`, followed by exactly one arm:

- Android tag 1: text package name, `LE64(minimum_package_version)`, `u8 signer_count`, then
  `signer_count` app-signing certificate SHA256 digests. Package grammar is dotted ASCII
  identifiers: `[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+`, at most 255 bytes. The
  minimum version is u64, including zero; an attested `versionCode` at or above it passes,
  so an app update needs no new policy. The signer set holds 1–4 nonzero digests in strictly
  ascending unsigned byte order, hence unique. It lists every signing certificate that a
  released distribution channel uses (for example an app store's signing key, the operator's
  direct-download release key and another store's signing key) and any signing-key rotation
  history; an install from a channel whose signer is absent cannot enroll. The set
  identifies certificates; real verified chains and app identities remain required. No client
  can select or override these fields.
- Apple tag 2: text App ID, nonempty and at most 255 UTF8 bytes, matching the current App
  Attest verifier. A new restrictive Team-ID grammar would be an additional protocol choice
  and is not assumed here. Production environment is mandatory and is not a selector.

An Android app transcript is `48 + package_bytes + 32 × signer_count` bytes, at most 431
(a 255-byte package and four signers); an Apple app transcript is `39 + app_id_bytes`, at
most 294. App policy is historical enrollment identity. The credential
preserves its digest across renewals; an app update never requires re-enrollment. Raising the
minimum version or changing the signer set changes only the policy that new E1 challenges
name.

The enrollment-policy transcript begins
`LE16(version) || scheme_id || asset_digest || app_policy_digest`, followed by one arm:

- Android tag 1: `u8 root_count` (1–8), then `root_count` root entries in strictly ascending
  unsigned byte order of `spki_sha256`, then `LE32(patch_floor_yyyymm)`. A root entry is
  `u8 family || family fields || spki_sha256 || u8 revocation_source`:
  - family GoogleRsa 1, no fields: Google's RSA hardware attestation root key. Pinning the
    key covers every re-issued certificate of that key.
  - family GoogleCa1 2, no fields: Google's ECDSA P-384 "Key Attestation CA1" root.
  - family Vendor 3: text `adapter_id`, 1–16 bytes matching `[a-z][a-z0-9-]*` (for example
    `huawei`). It names the implemented and qualified adapter profile (below) of an Android
    vendor whose own attestation root a reviewed policy original admits. GoogleRsa and
    GoogleCa1 entries use the `google` profile.
  - `spki_sha256`: SHA256 of the root certificate's DER `SubjectPublicKeyInfo`; nonzero and
    unique across entries.
  - `revocation_source`: GoogleAttestationStatus 1 (Google's attestation status list) or
    OperatorDenylist 2 (the operator denylist only). GoogleRsa and GoogleCa1 require 1;
    Vendor requires 2. A vendor-published revocation service would be a new source tag with
    its own reviewed adapter. The operator denylist is checked for every entry, whatever its
    named source. For a Vendor entry it is the only revocation source, so admission proves
    only that this operator had not listed the chain at the check: not comprehensive vendor
    revocation and not a bounded detection window.
- Apple tag 2: root DER SHA256. Production App Attest plus a durable fresh assertion binding
  E1 and the separately selected payment key are always required.

Both arms end with the existing 20-byte inline regulatory-policy transcript:
`LE32(permitted_controls) || LE64(blacklist_max_age_ms) || LE64(time_anchor_max_response_ms)`,
then `LE64(challenge_lifetime_ms) || LE64(attestation_lease_lifetime_ms)`.
An Android transcript is `140 + Σ root_entry_bytes`, where a Google entry is 34 bytes and a
Vendor entry `38 + adapter_id_bytes`: 174 bytes with one Google root and at most 572 bytes
with eight Vendor roots. Apple is exactly 167. Order follows the E1 scope first, platform
verification inputs second, and credential regulator/lifetime rules last. There is no field order
sorting, optional arm, extension map or compatibility decoder.

Patch floor is a valid YYYYMM in years 1900–9999. Meeting it sets the PATCH_POLICY_MET fact;
an unmet floor leaves that fact unset and never refuses E1. Apple gets no Android, patch, boot
or local-compromise facts invented from App Attest.

Adding a root, for example a `Vendor("huawei")` entry, is a reviewed policy-original change
that is data-only after that adapter is implemented and qualified (Adapter profiles, below).
The reviewer authenticates the manufacturer's ownership of every pinned root independently of
any device: Google's roots from Google's published verification procedure, and a vendor root
from the vendor's own published or signed statement or a channel the reviewer authenticates
directly with the vendor. A self-signed root certificate that a device supplies proves
nothing about who owns it and is never a pin's only evidence; a captured genuine chain shows
only that the root is in use. Removing a root or changing the signer set likewise affects
only new E1 challenges.

## Adapter profiles

Every Android root entry is validated under exactly one adapter profile: GoogleRsa and
GoogleCa1 entries under `google`, and a Vendor entry under the profile its `adapter_id`
names. A profile is reviewed code in the issuer verifier, not policy data. The issuer refuses
to select a policy original that names an adapter identifier it does not implement or a
profile that is not yet qualified. That is a configuration failure before any E1 challenge
names the policy, never an E1 outcome. Once a profile is implemented and qualified, adding,
removing or re-pinning its root entries is data only.

Each profile fixes, and the issuer enforces:

- Chain: the exact certificate order (leaf first, root last), the permitted signature
  algorithms, and that each certificate is signed by the next.
- Constraints: every issuing certificate is a CA under basic constraints, its key usage
  permits certificate signing and every path-length constraint holds; the trusted
  attestation certificate is not a CA and, where it carries key usage, permits digital
  signatures. A documented vendor deviation is recorded in the profile explicitly; there is
  no implicit leniency.
- Extensions: each permitted attestation extension OID, its schema and the chain positions
  where it may appear. A critical extension the profile does not name, a duplicated
  extension within one certificate or a permitted extension in a forbidden position rejects.
- Validity: which certificates have their validity periods evaluated at the issuer's trusted
  verification time.
- Revocation: the entry's named source plus the operator denylist; and the challenge, app,
  key, boot and patch checks of Android admission steps 4–9, which every profile applies
  unchanged.

The `google` profile follows [Google's verification
procedure](https://developer.android.com/privacy-and-security/security-key-attestation) and
the [AOSP attestation schema](https://source.android.com/docs/security/features/keystore/attestation#schema).
Its attestation extensions are the key description `1.3.6.1.4.1.11129.2.1.17` and the
provisioning information `1.3.6.1.4.1.11129.2.1.30`. Only the key description of the
certificate nearest the root that carries one is trusted; that certificate is the trusted
attestation certificate. When the provisioning information extension is present, the
trusted attestation certificate must be the certificate immediately below (toward the leaf)
the certificate nearest the root that carries it. Every certificate's validity is evaluated
except in a chain that the profile identifies as the documented factory-provisioned profile
under the GoogleRsa root, whose expired certificates stay trustworthy unless revoked. The
profile names the documented features that identify a factory-provisioned chain; a chain
that carries the provisioning information extension, or that the profile cannot identify as
factory-provisioned, is evaluated as remotely provisioned, including a chain to the RSA root.

The `huawei` profile admits Huawei's own attestation root for Android phones running EMUI or
HarmonyOS 2–4 with AndroidKeyStore, including post-2019 phones without Google Mobile
Services. Huawei's published EMUI security documentation describes iTrustee hardware
attestation and a Huawei root, device CA, device and key certificate hierarchy. That supports
pinning a genuine Huawei root; it does not establish that every such phone emits the AOSP key
description schema. The profile's chain shape, constraints, extension OIDs and positions are
therefore fixed from genuine chains captured from such phones, and enrollment tests on them
qualify it before its root entry is admitted. Where those chains carry the AOSP key
description, steps 4–9 apply to it unchanged, and a phone whose attestation lacks a required
field is refused for that evidence. No HarmonyOS NEXT or HUKS assumption applies: that
platform runs no Android apps and needs its own adapter (design §2.2). An emulator chain
ends at a software root and never qualifies a profile.

## Android admission

E5 Android evidence is the KeyMint attestation certificate chain and nothing else. The issuer
admits it only when every check below holds, in this order. The first failing check gives the
E1 refusal reason of design §2.4 shown in brackets. A failure to obtain a current revocation
source or the operator denylist is `Unavailable`, never a refusal or an admission.

1. Shape: 2–8 DER certificates, leaf first, each 1–16,384 bytes and at most 65,536 bytes in
   total [EvidenceInvalid].
2. Root and path: the last certificate is self-signed and its SPKI SHA256 equals one root
   entry, which selects the adapter profile. X.509 path validation from the leaf to that root
   succeeds under the profile: order and signatures, basic constraints, key usage, critical
   extensions and validity as Adapter profiles states. Only the documented factory-provisioned
   profile under GoogleRsa is exempt from validity evaluation; remotely provisioned chains,
   including those to GoogleRsa, and every GoogleCa1 and Vendor chain are valid at the issuer's
   trusted verification time. Revocation remains mandatory for all [UntrustedAttestationRoot].
3. Revocation: no chain certificate is listed by the entry's revocation source, and none is
   listed by the operator denylist [AttestationRevoked]. The Google status list may be reused
   only within the freshness lifetime its HTTP `Cache-Control` states; otherwise it is fetched
   for the check. A missing, failed or malformed fetch is `Unavailable`.
4. Key description: the trusted attestation certificate is the certificate nearest the root
   that carries key description `1.3.6.1.4.1.11129.2.1.17`. It is the leaf, its subject public
   key equals the E5 marker's payment key, and, when the provisioning information extension
   `1.3.6.1.4.1.11129.2.1.30` is present, it is the certificate immediately below the one
   nearest the root that carries that extension. The key description's attestation
   challenge equals the E1 `challenge_digest` [EvidenceInvalid]. Attestation version 1
   (Keymaster 2) has no app identity [AttestationWithoutAppIdentity]. The other supported
   attestation and KeyMint version pairs are exactly those AOSP documents: (2, 3), (3, 4),
   (4, 41), (100, 100), (200, 200), (300, 300), (400, 400) and (500, 500). Any other pair,
   including an undocumented equal pair, is [EvidenceInvalid]; a newly documented pair is
   added by a reviewed adapter change with its schema, never accepted implicitly. The key
   description decodes under its version's exact schema.
5. Secure hardware: the attestation and KeyMint security levels are equal and
   TrustedEnvironment (1) or StrongBox (2); attestation version 2 is TrustedEnvironment only
   [KeyNotInSecureHardware]. The attested level, never a policy selector, gives the evidence
   kind AndroidKeyMintTee or AndroidKeyMintStrongBox.
6. Key properties, hardware-enforced: purpose exactly SIGN, algorithm EC, key size 256, curve
   P-256, digest exactly SHA-256, origin GENERATED and a RootOfTrust. USAGE_COUNT_LIMIT (405)
   and ALL_APPLICATIONS (600) are absent from both authorization lists. Unknown
   context-specific tags are ignored; a duplicate or out-of-order tag rejects
   [EvidenceInvalid].
7. App identity: `attestationApplicationId` (709) is present [AttestationWithoutAppIdentity]
   and appears exactly once, in either list [EvidenceInvalid]. It names exactly one package,
   equal to the app-policy package, and lists at least one signer digest, every one in the
   signer set [AppIdentityMismatch]. The package version is at or above
   `minimum_package_version` [AppVersionBelowMinimum].
8. Boot, from the hardware-enforced RootOfTrust, whose DER shape is its version's: attestation
   version 2 has exactly the three fields `verifiedBootKey`, `deviceLocked` and
   `verifiedBootState`; versions 3, 4 and every KeyMint version also carry
   `verifiedBootHash`. A missing, extra or malformed field is [EvidenceInvalid].
   `deviceLocked` is TRUE [BootloaderUnlocked]; `verifiedBootState` is Verified and
   `verifiedBootKey` is nonzero, and for KeyMint (attestation version 100 and above)
   `verifiedBootHash` is 32 nonzero bytes [BootNotVerified]. For versions 3 and 4 the hash is
   recorded and its length and value are not required; that relaxation never admits a
   malformed RootOfTrust.
9. Patch: the hardware-enforced OS, vendor and boot patch levels are recorded; the floor sets
   only the PATCH_POLICY_MET fact.

An admitted Android evidence record carries facts HARDWARE_BACKED_KEY, BOOTLOADER_LOCKED,
VERIFIED_BOOT, APP_SIGNING_IDENTITY and REVOCATION_LIST_CLEAR, plus STRONGBOX for StrongBox and
PATCH_POLICY_MET when the floor is met. Bit 9 is reserved zero in every evidence
record. Native record validation and the credential proof relation reject it in
both enrollment and renewal evidence; no historical-credential exception exists.

Nothing else is an Android admission input: no Play Integrity token or verdict, Google
account, Google Mobile Services, Huawei Mobile Services, app-store installation, exact
version, StrongBox-only selection, patch-level refusal, model or device allowlist, second
attested key or periodic online check. StrongBox, remote versus factory provisioning and
patch levels are recorded facts that never refuse a phone.

The operator denylist is one operator-owned original that the issuer selects and
authenticates like the policy originals but holds outside them, because it changes without
changing any policy digest. It is UTF-8 JSON with exactly the members `version` (the integer
1), `sequence` (a positive integer at most 2^53 − 1) and `entries`, an array of at most
65,536 unique objects. Each entry has exactly one member. `serial` is a certificate serial
number in lowercase hexadecimal without leading zeros, the spelling of Google's status
list; it matches any chain certificate except the
leaf, whose serial the phone chooses. `spki_sha256` is 64 lowercase hexadecimal digits of
SHA256 over a certificate's DER `SubjectPublicKeyInfo`; it matches any chain certificate,
including the leaf. Duplicate members, unknown members and malformed values reject the whole
original. An empty `entries` array is a deliberate operator statement.

Updates are authenticated and rollback-protected. The issuer accepts a candidate update only
when it authenticates as the operator's genuine denylist original and its `sequence` is
greater than the highest sequence the issuer has durably accepted, or equal with
byte-identical content. The issuer retains that sequence and the accepted original's SHA256
durably, with the original; together they are the active denylist custody. Two failure
classes are distinct and each is tested (design §9.1):

- A candidate update that fails authentication, carries a lower sequence or repeats the
  current sequence with other bytes is stale or altered. It is rejected, and the intact
  authenticated current denylist stays in force and keeps deciding verifications; the
  rejection makes no verification `Unavailable`.
- The active custody itself is checked at every verification: the retained original must be
  present, readable and well formed, and its SHA256 and sequence must match the retained
  sequence record. A missing, unreadable or malformed active denylist, or a lost or
  inconsistent retained sequence record, makes that verification `Unavailable`, never an
  empty list and never an admission.

The operator's security owner supplies the compromise intelligence and retains each entry's
provenance with the update that adds it: for example a vendor security advisory, a published
leaked-key or compromised-batch report, or fork evidence the operator observes. No entry is
added automatically. The denylist proves only that this operator had not listed a chain
certificate at the check; it is not comprehensive vendor revocation and gives no bounded
detection window.

## Apple admission

E5 Apple evidence is the App Attest key identifier, the original attestation object and the
fresh first key-binding assertion. The issuer admits it only when the attestation chains to the
pinned Apple App Attestation root DER [UntrustedAttestationRoot]; the App ID equals the app
policy's and the environment is production [AppIdentityMismatch]; and the nonce, key
identifier, counter and key-binding assertion over
`H("enrollment-key-binding", challenge_digest || payment_key)` all match [EvidenceInvalid].
An admitted record carries APP_ATTEST_GENUINE_DEVICE, APP_ATTEST_KEY_BINDING and
APP_ATTEST_PRODUCTION.

## Lifetimes, custody and producer ownership

Challenge lifetime is a positive u64 with no default. The NEW accepted interval is
`created_at_ms <= trusted_now_ms < created_at_ms + lifetime`, with positive genuine server
creation time and checked u64 addition. Duration has no newly invented wall-clock ceiling.
The issuer must store creation time with the exact challenge, authenticated subject and
selected originals; request timestamps are never substitutes. A liveness check does not
consume a challenge. The durable owner must enforce single use, exact-result retries and
permanent account/wallet activation claims before any HTTP result becomes visible. Only
Issued and Refused are exact results. A refusal consumes the challenge, and a retry returns
the same refusal reason. Delivery of an Issued result's E6 is authorized separately by a fresh
eligibility observation at each delivery: a denial there withholds delivery (codes 11 and 12)
and an outage makes it `Unavailable`, neither changes the Issued result, its exact E6 or its
quota share, and a later approval returns the same E6 bytes (design §2.4). `Unavailable` and
`Unknown` are recovery states, never retained as the answer: a retry after an outage before
any effect resumes verification of the same claim, and recovery of an uncertain effect never
verifies again as a first attempt, signs a second credential or consumes the Apple counter
again (design §2.4).

Existing regulatory bits and consistency rules are preserved. Zero permitted controls does
not disable Kagemusha; it permits no extra blacklist/quota/lease restrictions. Lease lifetime
is zero iff the regulator does not permit attestation lease and otherwise positive. The NEW
initial producer computes expiry as checked `issued_at_ms + lease_lifetime` with positive
trusted issuer time. This is an attestation lease. Renewals keep
the original credential app identity/regulatory policy and require their separate current
owner contract; this E1 proposal grants no renewal signer or mutable historical identity.

Android roots are pinned by SPKI and the chain carries its root certificate, so no Android
root DER original is configured. The Apple root DER is a genuine external original selected
by the approved issuer owner, outside the public policy frame, nonempty and at most the
existing platform `MAX_CERT` bound of 16,384 bytes. Python compares SHA256 of those exact
bytes to the policy pin, then the real chain verifier runs. A self-consistent root/pin pair
is not approval.

Python's typed enrollment-policy projection digest is the selected typed enrollment-policy
digest, never a separately caller-supplied opaque pin. The KeyMint leaf-first DER originals,
or Apple attestation and assertion originals, must be retained privately before credential
signing. Native rederives the evidence digest from exact originals. Public projections or
success flags are not evidence originals or signer capabilities.

The coordinated Native issuer still owns authenticated workload purpose/method/path/body,
access subject and exact canonical account/asset scope. Every universal-dataspace token may
use offline enrollment without Parliament approval or a named-token allowlist. Under a
Bank policy, current KYC approval and freeze status come from the user's bank middleware
through the [challenge-bound eligibility SDK contract](kagemusha_enrollment_eligibility_v1.md).
Other schemes select their authorized operator and may explicitly admit public enrollment.
Parliament is an optional provider for assets it governs; it has no required protocol role.
A missing or failed bank observation never selects an operator policy implicitly. The issuer independently authenticates
current authority/routing and retains each fresh observation at its durable boundary. It owns
approved original selection, CSPRNG nonce, challenge CAS/use, durable Apple counters, genuine
time, original evidence/result retention and one genuine scheme-rooted Enrollment-role P256
signer. FI access/DPoP/workload keys are separate transport signers. It must build the current
credential with typed app digest, exact regulator/lease result and verified evidence, freeze
the actual signer output and call `verify_enrollment` against the retained exact E1/payment
key before delivery. Reusing deleted RetailEnrollment/Ed25519 authority is not an option.

Model, Python adapter, specification, digest-role inventory and shared DATA vectors form one
proposal. Swift/Kotlin/JS/C# consumers and the current issuer/Native bridge must migrate their
actual policy ownership and use these new preimages together. The shared vectors are
unadmitted public DATA with repeated placeholder pins, without root originals, approvals,
signers, device evidence or production deployment qualification. Passing them proves byte
agreement only. Canonical Native frame qualification remains a required independent check.
