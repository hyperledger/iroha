# ShangMi implementation contract

Iroha 3 ABI V1 includes `SM3_HASH`, `SM2_VERIFY`, `SM4_GCM_SEAL`,
`SM4_GCM_OPEN`, `SM4_CCM_SEAL` and `SM4_CCM_OPEN` in every IVM build.
The DefaultHost, CoreHost, WsvHost and ledger Core host expose the same
operations without a host enable flag or a node signing-policy switch.
The IVM dependency on `iroha_crypto` always selects its portable `sm` backend,
including CCM. Optional hardware acceleration must preserve these results.

## Operands, results and gas

The canonical operand and gas contracts are in
[`crates/ivm/docs/syscalls.md`](../../crates/ivm/docs/syscalls.md).

- SM3 hashes a Blob and returns its 32-byte digest in a Blob.
- SM2 verifies the message, signature and SEC1 public-key Blobs. An omitted
  DistID operand (`r13 = 0`) means `Sm2PublicKey::DEFAULT_DISTID`. An explicit
  Blob supplies the caller's UTF-8 DistID. The mutable process key-generation
  default and local `crypto.sm2_distid_default` cannot select verification
  semantics. Invalid signatures return false; malformed carriers retain
  their typed validation errors.
- SM4 seal returns ciphertext followed by its authentication tag. Open
  returns plaintext only after successful authentication; an invalid tag
  returns false without publishing plaintext. GCM uses a 12-byte nonce and
  16-byte tag. CCM accepts nonce lengths 7–13 and tag lengths
  `{4, 6, 8, 10, 12, 14, 16}`; `r14 = 0` selects 16 bytes.
- Quoting validates operand carriers before execution. The existing gas
  schedule charges processed bytes, including AAD and failed authenticated
  opens. Removing the retired enable switches does not waive input
  validation, gas reservation, or the host's instruction/entrypoint policy.

## Implementation and authority boundaries

`iroha_crypto::sm` owns portable SM2, SM3 and SM4 primitives. SM2 uses its
canonical portable signature relation; ECDSA on the SM2 curve is not SM2.
Optional `sm-ffi-openssl` selects the separately qualified SM3/SM4 provider.
`crypto.enable_sm_openssl_preview` and `crypto.sm_intrinsics` select local
implementations, while local hash and DistID defaults are generation
preferences. They do not enable ABI V1 syscalls.

Transaction/controller admission and peer authentication have separate
authority owners. Their committed-policy migration and qualification are
tracked by [`crypto_admission_policy.md`](../crypto_admission_policy.md)
and `specs/zk_runtime_validity_census.json`; removal of an IVM host switch
does not establish that those other consumers are complete.

## Required evidence

The current grouped test owners are:

- `ivm_group_08::sm_syscalls`: original positive/negative SM vectors,
  validation and gas checks, default-host availability, all-host result and
  gas parity, and an isolated-process test that changes the key-generation
  DistID default.
- `ivm_group_04::kotodama_sm_syscalls`: compiler-to-host SM calls and their
  operand and rejection controls.
- `iroha_core` library `pointer_abi_and_sm_tests`: ledger-host results under
  different local crypto preferences, malformed pointers, and success/failure
  telemetry when telemetry is compiled.
- `ivm` library `proof_coverage`: removal of the retired SM switch record
  and refusal of source that restores the switch or mutable default DistID.

TODO: Regenerate `crates/ivm/docs/proof_coverage_inventory.json` from the
composed source with its original generator, then execute these tests under
the default and portable feature selections. A source-only forward-port or
an older generated inventory is not current runtime evidence. Full IVM
execution-proof, SDK, provider and hardware qualification remain open.
