# Wallet artifact command contracts

`kagemusha_wallet_artifacts` is the offline native artifact and issuer command,
built with the `dev-tools` feature. Its commands construct signed originals; they do not
register a scheme, establish device eligibility or authorize money movement.
Use a source-consistent executable and current signed genesis, certificates,
catalog and encoded transport. Historical layouts and synthetic test inputs are
not installation inputs.

## Application and session preparation

The following commands each take one absolute path to a closed JSON request:

```sh
kagemusha_wallet_artifacts --prepare-application "$PREPARATION_REQUEST"
kagemusha_wallet_artifacts --finish-application "$SIGNATURE_REQUEST"
kagemusha_wallet_artifacts --issue-session "$SESSION_REQUEST"
kagemusha_wallet_artifacts --issue-time-anchor "$TIME_REQUEST"
```

Every referenced public original is `{ "path": absolute_path, "sha256":
lowercase_sha256 }` with retained private directory and read-only file custody.
Each request selects an existing private `output_parent` and a fresh single
component `output_name`. Outputs never replace an existing name. A failed
publication leaves its partial directory for inspection; a retry uses a fresh
name. Select preparation/session output only after its completion record exists.

`--prepare-application` uses schema
`iroha.kagemusha.wallet-application-preparation.v1`. Its exact fields and bounds
are defined by `Prepare` and the typed policy validators in [application.rs](application.rs).
It authenticates the signed genesis/network pair, scheme, certificate roles,
artifact manifest, verifier pack and producer inventory, and checks the encoded
transport's exact catalog closure. The request also selects:

- The actual Android package/version and signing-certificate DER originals,
  independently selected root SPKIs and patch floor.
- The actual Apple signed application identifier and App Attestation root DER.
- Explicit regulatory controls and enrollment lifetimes.
- Independent session authorities, app scope, HTTPS origin/path and roles.
- The actual bridge ABI from the selected native artifact.

It emits typed platform policies/templates, `wallet-runtime.json`,
`application-release.json` and `application-release.signing-input`. The runtime
is bounded to 128 KiB. Its files do not substitute for APK/profile inspection,
complete proof-source qualification or finalized registration evidence.

The external application release signer signs the exact input
`UTF8("iroha.kagemusha.wallet-application-release.v1") || 0x00 || manifest`,
including the canonical manifest's final LF, with Ed25519. The tool does not
open that private key. `--finish-application`, schema
`iroha.kagemusha.wallet-application-signature-assembly.v1`, selects the manifest,
64-byte signature and independent public key, validates their structure and
signature, and emits the native signature envelope bounded to 2,048 bytes.
The compiled mobile trust root must independently match that public key.

`--issue-session` uses schema `iroha.kagemusha.wallet-session-issuance.v1`;
[session.rs](session.rs) defines its closed request. It selects the exact runtime,
issuer/audience, platform, subject, registered device UUID, roles and lifetime.
Separate outside-repository private directories retain the issuer's 32-byte
`session-issuer.ed25519.seed` and the device's P-256
`session-device-dpop.pkcs8.der`. Their public keys must match the runtime and
independent device binding. Keep the same device UUID and DPoP key on renewal;
these session keys are separate from hardware payment keys.

The command uses current system UTC and OS entropy to produce a signed token and
DPoP proof bound to that token, app, device and exact enrollment endpoint. Deliver
the unchanged private outputs promptly: DPoP expires before issuance time plus
61 seconds, or earlier at token expiry. Neither a token nor its completion record
establishes platform attestation, eligibility, native installation or finality.

`--issue-time-anchor` uses schema
`iroha.kagemusha.wallet-time-anchor-issuance.v1`; [time_anchor.rs](time_anchor.rs)
defines its exact request. Select the current `scheme` and `certificate` originals,
independently retained `scheme_id_hex` and `issuer_public_key_hex`, the actual
opened `wallet_id_hex`, and the exact 32-byte `nonce` original exported by that
wallet's live `begin-time` call. The selected outside-repository private
`custody_directory` contains only the delegated `time-anchor.pkcs8.der` needed
for this call. Its public key must match the independently selected TimeAnchor
certificate, verified under the selected scheme. The command does not issue or
replace that certificate and does not read the scheme-root or payment key.

Issuer UTC comes from the current host clock, with no caller-supplied timestamp.
The issuer is responsible for that clock's correctness. The command produces
`time-anchor.norito`, its unchanged `time-certificate.norito`, and the one-entry
`time-certificates.norito` set. Select them only after
`time-anchor-complete.json` binds their exact hashes. No output name is replaced;
an incomplete output is not success. Deliver the anchor and certificate to the
same live Native `finish-time` token, then use the anchor and certificate set for
the ordinary `refresh-time` transition. Native enforces the nonce, wallet, same
boot and monotonic response-age bound. A late response requires a fresh exchange;
this issuer record alone never establishes a retained anchor or completed
Refresh. This command is a direct response signer, not a network time service or
phone qualification result.

Run focused component tests with
`cargo iroha-fast -- test -p iroha_core_zk --features dev-tools --bin kagemusha_wallet_artifacts`.
Full integration additionally needs the current four-validator registration,
issuer and funding flow in [integration_tests](../../../../../integration_tests/README.md).
