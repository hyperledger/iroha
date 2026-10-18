# NoritoBridge XCFramework Artifacts

Static bridge archives explicitly bundle PQClean's common SHA3/SHAKE and
architecture-specific Keccak helpers. The Apple builder links each thin slice
into a real C consumer with every archive member loaded before staging or
publication, including slices restored from CI. Its host macOS consumer also
checks SHA3-256/SHAKE256 known answers, ML-DSA signing/verification and tamper
rejection, and ML-KEM encapsulation/decapsulation.

Current source ABI: 30. ABI 30 deletes the Parliament timed-OVN wallet exports: the
four C functions `connect_norito_parliament_timed_ovn_*`, their
`CONNECT_NORITO_PARLIAMENT_TIMED_OVN_*` width constants, the
`CONNECT_NORITO_ERR_PARLIAMENT_TIMED_OVN` (`-505`) result code, and the five
`ParliamentTimedOvnNativeEndpointV1` JNI exports. The remaining result codes keep
their values. Artifacts built for ABI 29 or earlier are rejected.

ABI 29 was the KAGEMUSHA E1 admission cutover. It
deletes the first-device authentication-key JNI exports
(`NativeFirstDeviceAuthKeyJniV1.reserve`/`restore`) with their native owner. Enrollment
selector 3 takes the Android `KeyMint` chain only; the Play Integrity token input is gone.
Abandon returns result 58 for a local no-marker abandonment and result 28 with the exact
signed Abandonment frame for the marker form. The new
`connect_norito_kagemusha_wallet_enrollment_refusal_v1` and its JNI counterpart
`KagemushaWalletNativeV1.enrollmentRefusal` expose the closed E1 refusal table. The runtime
capacity results are typed: `-12` is `NotEnoughStorage` (formerly the generic no-space status,
now also Advance's commit-time reservation, which no longer appears as not-performed detail 1)
and `-14` is `NotEnoughMemory`, both checked before proving and before commit against bounds
derived from the installed relations. The BPNG v7
runtime no longer carries `firstDeviceAuthentication`, `authentication`,
`retailStageAnchorAuthority` or `consensus.finalityVerifierSha256`; Native refuses a runtime
that still does. Android runtime rows select no attestation root DER, and the CBSI session
collection keeps only the Apple root. Validator wire, ISI and state formats, wallet circuits,
the artifact producer and the verifier-pack, producer-inventory and transport formats are
unchanged. Artifacts built for ABI 28 or earlier are rejected.

ABI 28 changed
`connect_norito_kagemusha_wallet_load_original_validate_v1` (and its JNI
counterpart) to return the untrusted LoadFinality height through `out_height`,
raises the native LoadFinality original bound to 262144 bytes, and adds the
EpochProgress52/EpochBoundary53 wallet setup selectors. Wallet runtime
installation carries the exact registration-source original in its C
structure and JNI constructor. Artifacts built for ABI 27 or earlier are
rejected before any changed layout is called.
Wallet operations use typed native preparation through `execute` and durable
`request_status`; no generic wallet commit export is supported. The bridge exports native transaction and instruction
encoding, account admission, SoraFS reference validation and privacy proofs. Its Kotlin/JVM and Java/Android
`NativeSignerBridge` surface requires native-signer JNI contract revision 7.
`RegisterZkAsset` carries exactly `asset` and optional `vk_unshield`.
Transaction signing requires the genesis-derived `NetworkId`: JNI accepts
exactly 32 marked hash bytes, while the C and Swift surface accepts canonical
checksummed `NetworkId` text.

The current iOS wallet source requires 26 of the 27 wallet C exports; the refusal table
export is new at ABI 29. Its three observation and
account-codec exports preserve the same admitted Native owner and existing
account identity. Observation selectors 0–3 return bounded, explicitly framed
DATA in their own result domain; they do not establish monetary completion.
Setup 45 and result 48 remain the canonical Unload claim interface, while
setup 46 retains an exact signed Activation attempt and result 49 reports an
authenticated rejection of that attempt. Prepared Load recovery preserves
one immutable request-to-ordinal reservation. Kotlin's wallet JNI exports
gain `enrollmentRefusal` at ABI 29. These source changes require newly built matching artifacts.

Canonical KAGEMUSHA wallet objects are owned by
`iroha_data_model::kagemusha::kagemusha_wallet_v1`. The bridge exposes no
KAGEMUSHA coordinator or device runtime. Native wallet integration and device
qualification remain open.

The exact-12 privacy KAT ABI is compiled through the narrow
`iroha_data_model/privacy-exact12-conformance` feature. Shipping bridge builds
do not enable the data model's general `test-fixtures` feature, random-key
feature edge, or block-tampering helpers.

The native privacy metadata ABI exports only the local
`PrivacyCompiledProfileCatalogV1`. It intentionally has no committed height,
policy, activation, lifecycle, or readiness projection. SDKs must fetch a
fresh authoritative `PrivacyCapabilitySnapshotV1` from live Torii before
submitting a privacy proof.

The archive checksums below are historical and do not establish a current
ABI-30/revision-7 artifact. Regenerate, verify, and republish the bridge
artifacts before cutting an SDK release that depends on the current source
surface.

- `NoritoBridge.xcframework.zip`
  - SHA-256: 9bdd96f97f2eccc9e901c0500bd8f2b046c600080ebbe1213a4febba13c44efd
- `NoritoBridge-xcframework.tar.gz`
  - SHA-256: 316fe22a83f217180700e1aa8b98c00d001d8009dfbdf465717794878c75441c

Instructions:
1. Package the authenticated archive with
   `scripts/package_mobile_sdk_artifacts.sh --apple --lockfile-path <canonical-external-Cargo.lock>`;
   retain exact source, lock, tool and package provenance. Do not reuse the
   historical hashes above.
2. Publish the generated canonical
   `NoritoBridge-v<version>.xcframework.zip`, whose version comes only from
   `IrohaSwift/VERSION`, with its authenticated manifest and checksum inventory.
3. Qualify the ZIP with SwiftPM and an ordinary `IrohaSwift` dependency in
   Release, including native execution without unsafe linker flags. SwiftPM is
   the sole supported Swift packaging path. Public installation and signed
   release evidence remain distinct from local host/simulator validation; see
   [the release contract](../../docs/norito_bridge_release.md).
