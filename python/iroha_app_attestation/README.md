# Shared Iroha app attestation

Bounded server-side verifiers for the KAGEMUSHA wallet E1 enrollment evidence of app-owned
hardware keys: the Android KeyMint attestation certificate chain and Apple App Attest
attestations, assertions and fraud receipts. The package depends only on the Python standard
library and a caller-selected OpenSSL 3 executable.

Nothing here issues a credential or grants monetary authority. A verified result records what
the platform attested. The caller selects every scope value (challenge, payment key, app
policy, pinned roots) from its own authenticated policy, never from the evidence. The
credential issuer and the enrollment routes of the wallet design
(`specs/kagemusha_single_design_proposal.md` §2.2) are owned by the native Core/Torii
enrollment service. The admission contract is `specs/kagemusha_wallet_enrollment_policy_v1.md`.

There is no Play Integrity, Google account, Google Mobile Services, Huawei Mobile Services,
app-store installation, exact version, hardware selector, model allowlist or second attested
key in the admission path. Evidence fact bit 9 is reserved zero; native validators
and proof circuits reject it in enrollment and renewal records.

## Android admission

E5 Android evidence is the leaf-first KeyMint chain and nothing else.
`attestation.verify_android_key_attestation` admits it only when every step below holds, in
this order; the first failing step raises `EvidenceRefused` with its closed design §2.4 code:

1. Shape: 2–8 DER certificates, each 1–16,384 bytes, at most 65,536 bytes in total [9].
2. Root and path: the last certificate is self-signed and the SHA-256 of its DER
   `SubjectPublicKeyInfo` equals one root entry of the policy's root set, which selects the
   adapter profile. Order, names and signatures (OpenSSL, per link), permitted signature
   algorithms, basic constraints, key usage, path length, critical extensions and validity
   follow the profile [5].
3. Revocation: no certificate is listed by the root's named source or by the operator
   denylist [6]. A source that cannot be read is `VerificationUnavailable`.
4. Key description: the certificate nearest the root that carries
   `1.3.6.1.4.1.11129.2.1.17` is the leaf, its key is the E5 payment key, a provisioning
   information extension (`.30`) sits only on the certificate immediately above it, and the
   attestation challenge is the E1 challenge digest [9]. Attestation version 1 has no
   application identity [2]. The pair must be one of (2,3), (3,4), (4,41), (100,100),
   (200,200), (300,300), (400,400), (500,500) [9]. Documented AuthorizationList fields are
   type-checked; unknown context-specific tags are ignored; duplicate or out-of-order tags
   reject [9].
5. Secure hardware: equal TEE (1) or StrongBox (2) levels; version 2 is TEE only [1].
6. Key properties, hardware-enforced: SIGN, EC, 256, P-256, SHA-256, GENERATED and a
   RootOfTrust; `USAGE_COUNT_LIMIT` (405) and `ALL_APPLICATIONS` (600) absent from both
   lists [9].
7. App identity: `attestationApplicationId` (709) present [2], exactly once in either list
   [9], naming exactly the policy package and only signers of the policy signer set [7], at a
   version at or above the policy minimum [8].
8. Boot: version 2 RootOfTrust has three fields, later versions four [9]; locked [3];
   Verified with a nonzero key, and from KeyMint (100) a 32-byte nonzero boot hash [4].
9. Patch levels are recorded; meeting the floor sets only `PATCH_POLICY_MET`.

### Adapter profiles

A profile is reviewed code; the root set selects it. `google` validates GoogleRsa and
GoogleCa1 roots. Every certificate's validity is evaluated, except in the documented
factory-provisioned profile under the GoogleRsa root, whose expired certificates stay
trustworthy unless revoked: a chain to a GoogleRsa root with at least three certificates, no
provisioning information extension, and a root-issued certificate whose subject carries a
`serialNumber` attribute (Google's own verifier's factory test). Not-yet-valid certificates
are refused in every profile. Every other chain, including remotely provisioned chains to the
RSA root, keeps its validity checks.

`huawei` is a candidate AOSP key-description profile for a Vendor root and ships
**unqualified**: a policy naming it fails configuration (`android_adapter_profile`), exactly
like an unknown adapter id, matching Native's `ANDROID_VENDOR_ADAPTER_PROFILES_V1`. A
reviewed release qualifies it after genuine post-2019 no-GMS chains. Until then no Huawei root
is pinned and a chain to an unpinned root is refused with code 5. Huawei HUKS exists
on Android/EMUI too; a HUKS device certificate or SOTER RSA certificate does not
establish the P-256 key, challenge, application identity and boot assertions E1
requires. The public P40 capture in `tests/fixtures/huawei_p40_untrusted` is a
rejection fixture: its TEE claims do not override its untrusted software root.

## Revocation

`revocation.AndroidRevocation` checks Google's attestation status list for GoogleRsa and
GoogleCa1 roots and the operator denylist for every root. Google's list is fetched over HTTPS
without proxies or redirects and reused only within its `Cache-Control: max-age` (less
`Age`, at most one day) on Linux `CLOCK_BOOTTIME`; otherwise it is fetched for each check.

The operator denylist original is UTF-8 JSON with exactly `version` (1), `sequence`
(1..2^53−1) and `entries` (at most 65,536 unique one-member objects: `serial`, lowercase hex
without leading zeros, matching any non-leaf certificate; or `spki_sha256`, 64 lowercase hex,
matching any certificate). Its active custody is the owner-only file
`wallet-e1-denylist.custody` in the Android E1 store, holding the exact original with its
sequence and SHA-256, replaced atomically. A candidate is accepted only with a greater
sequence, or the same sequence and identical bytes; a stale or altered candidate is rejected
and the active list keeps deciding. Missing, unreadable, malformed or inconsistent custody
makes every Android verification unavailable, never an empty list. Serving never creates
custody.

Installation and updates are explicit operator actions with an independently reviewed pin:

```sh
iroha-wallet-e1-store-init --store-directory /absolute/private/empty/directory
iroha-wallet-e1-denylist --store-directory DIR --original /abs/wallet-e1-denylist.json \
  --sha256 <reviewed sha256> --initialize      # first custody
iroha-wallet-e1-denylist --store-directory DIR --original /abs/new.json --sha256 <pin>
```

An Android worker may also inherit FD22, the parent-authenticated candidate original (the
issuer pins its path and SHA-256 in its root-owned startup document), and offers it once at
startup under the same rules.

## Private worker

`wallet_enrollment_worker.py` is the private Linux verifier. The owner uses generation lock
FD16, protected directory FD17, Python FD18, archive FD19, configuration FD20, OpenSSL FD21
and, for Android, the optional denylist candidate FD22. Length-framed requests and replies
travel on private standard input/output with schema `iroha.kagemusha.wallet-e1-verifier.v1`.
Every reply carries `outcome` and `refusal_code`:

- `evidence`: the retained verified projection (terminal once the issuer signs);
- `refused` with one code 1–10: terminal, retained on the claim and returned unchanged on
  every Complete, Recover or Inspect;
- `unavailable`: a recovery state. An outage before any effect is recorded on the claim, and
  a Complete or Recover of the exact retained E5 while E1 is live resumes verification of the
  same claim; its first dispatch time stays the evidence time;
- `outcome_unknown`: a claim interrupted in flight, or an outage claim after E1 expires; it is
  never verified again;
- `journal`, `prepared` acknowledgements, and `rejected` for a private protocol or binding
  violation, which is never an E1 refusal.

Verification starting at or after the E1 deadline, or a trusted clock reaching it before
verification completes, is refused with ChallengeExpired (10). Inspect never claims a prepared
operation. The journal (`wallet-e1.sqlite3`, store schema v2) records each claim's first
dispatch time and exactly one outcome state. Apple counter/challenge consumption and the
evidence result commit in one FULL-synchronous transaction.

The configuration schema is `iroha.kagemusha.wallet-e1-verifier-config.v1`, version 1, with
`platform`, `app_policy_hex`, `enrollment_policy_hex`, `openssl_path`, `openssl_sha256`,
`store_directory` and `policy`. Both platform policies contain `scheme_id_hex`,
`asset_digest_hex`, `regulatory_policy`, `challenge_lifetime_ms` and
`attestation_lease_lifetime_ms`. Android adds `package_name`, `minimum_package_version`,
`app_signer_sha256` (1–4 ascending digests), `roots` (1–8 entries ascending by `spki_sha256`:
`{family: google_rsa|google_ca1, spki_sha256, revocation_source: google_attestation_status}`
or `{family: vendor, adapter_id, spki_sha256, revocation_source: operator_denylist}`) and
`patch_floor_yyyymm`; Android selects no root original. Apple adds `app_id`, `root_base64` and
`root_sha256`. Native's `issuer_worker::VerifierConfigurationV1` constructs exactly this
projection; `wallet_policy.py` rederives the Model transcripts and digests, which match
`fixtures/kagemusha/wallet_enrollment_policy_v1_vectors.json` byte for byte.

`tools/build_wallet_e1_verifier_zipapp.py` packages the explicit current source inventory into
deterministic unsigned bytes. It does not authenticate a runtime.

## Apple

`verify_apple_wallet_attestation_raw` checks the App Attest object against the pinned Apple
root [5], the App ID and production environment [7], and the key, counter and nonce over the
E1 challenge digest [9]. The key-binding assertion over the payment-key binding digest is
checked with a strictly increasing counter and single-use client data [9]. `apple_receipt.py`
verifies the App Attest CMS fraud receipt against a pinned Apple Root CA - G3.

## Tests

From this package directory, with Python 3.10+ and the selected OpenSSL 3 on `PATH`:

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests
PYTHONPATH=src:tests python3 -m pytest -q tests
```

Synthetic throwaway roots, Apple's published sample attestation and scripted Google replies
exercise the parsers, cryptographic boundaries and durable stores. They do not establish
physical-device or Huawei profile qualification.
