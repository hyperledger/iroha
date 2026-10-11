# V1 server signing policy

Iroha is a public blockchain with permissioned dataspaces. Operators choose and
control their servers. No node, validator, dataspace, SoraFS service or release
gate requires an HSM, TPM, TEE, remote host attestation, hardware-generated key
or proof of key non-exportability. This policy records the user's September 13,
2026 correction and supersedes hardware prerequisites in earlier SoraFS plans.

Software signing is supported. Operators may use hardware-backed key storage,
but both implementations obey the same authorization and wire contract. Backend
labels never establish eligibility. There is no software-only admission rule,
hardware-only admission rule, compatibility profile or fallback wire schema.

## Verifiable security boundary

Peers verify exact signed bytes, authorized public keys and permissions,
purpose/network/dataspace binding, canonical encoding, consensus finality,
rotation/revocation and replay protection. Permissioned dataspaces govern
membership and access through protocol state; they do not grant control over
another operator's host. Private keys and runtime credentials stay outside
public configuration, catalogs and evidence.

The shared SoraFS custody statement records an authority's authorization of a
public signer binding and its enrollment. It contains no hardware identity,
key-origin or exportability fields. Its independent authorization and finalized
state checks remain required. Final-promotion and release-manifest verification
likewise establish signer authority and exact operation completion without
claiming how a private key was generated or stored.

An opaque provider handle names a route; it is not proof of provider capability.
A generic signer must reject a purpose whose dispatch is unimplemented. Software
support requires a functioning adapter and tested sign/recover behavior, not a
changed label or a fabricated successful receipt.

## Device-specific features

Optional KAGEMUSHA offline-money work has a separate device-state assumption:
a durable software state provider on a stock, uncompromised OS
([design](kagemusha_single_design_proposal.md)). It is not required for node
startup, validator membership, ordinary transactions or permissioned
dataspaces. It states and implements its settlement, replay and loss
assumptions and does not claim protection against a compromised OS; it cannot
impose a server HSM requirement.

## Remaining implementation and evidence

The [SoraFS goals](sorafs/v1_implementation_goals.md) and
[closure ledger](sorafs/v1_closure_ledger.md) track unfinished production adapters,
finalized state integration, release evidence and deployment qualification.
Hardware procurement or hardware-origin evidence cannot block those goals.
Local tests do not establish a deployed signer, current finalized authority,
the seventeen ready lanes or the required operational soak.
