# Offline finalized settlement carriers

`iroha --machine app execution verify-settlement --bundle PATH` accepts a tagged settlement bundle or an index of adjacent bounded carrier files. Both require independently selected `--network-id`, `--trusted-checkpoint PATH`, `--expected-entry-hash`, `--session-id`, `--profile-id` and `--outcome-hash`. The checkpoint file contains the sole canonical `SumeragiFinalityCheckpoint` layout, selected and authenticated independently of the downloaded bundle. A scalar context digest cannot replace it.

One native verifier survives every file boundary. The first proof must reproduce the checkpoint's exact decision; every following proof must be its immediate authenticated successor, including epoch changes at a file boundary. The native certificate binds its instance, complete epoch context, authority generation, previous result and exact executed wire. An endpoint-provided filename, digest, height or committee never selects a trust root.

## Directory format

Every object rejects missing or additional fields. The index is:

```json
{
  "format": "iroha.execution.settlement-index",
  "version": 1,
  "finality_batches": [
    {
      "file": "finality-000001.json",
      "sha256": "<64 lowercase hex characters>",
      "bytes": 12345
    }
  ],
  "settlement_bundle": {
    "file": "settlement-finality.json",
    "sha256": "<64 lowercase hex characters>",
    "bytes": 23456
  }
}
```

Example lengths and digests are placeholders. `bytes` equals the actual positive UTF-8 JSON length; SHA-256 covers those exact bytes, including whitespace. They detect substitution and incomplete export, and grant no authority. Prefix references may be empty. Names must be unique, flat ASCII basenames: a nonempty stem of letters, digits, `-` or `_`, followed by `.json`, at most 128 bytes. Files are adjacent to the index. Paths, URLs, directories, symlinks and special files reject. Unix opens use `NOFOLLOW | NONBLOCK`; Windows opens use `OPEN_REPARSE_POINT` with regular-file checks. The same regular-file policy applies to the independently selected checkpoint.

Each prefix file contains:

```json
{"format":"iroha.execution.finality-batch","version":1,"finality_chain_base64":["<canonical Norito SumeragiFinalityProof in canonical base64>"]}
```

The settlement file contains:

```json
{
  "format": "iroha.execution.settlement-bundle",
  "version": 1,
  "finality_chain_base64": ["<consecutive canonical native finality proofs>"],
  "executed_block_wire_base64": "<canonical executed SignedBlockWire without its node-local certificate>",
  "block_proofs_base64": "<canonical BlockProofs>"
}
```

The final authenticated native capability binds the exact supplied executed block, wallet-signed entry hash and successful output joined to that input. Verification requires exactly one explicit `SettleGameSessionV1` for the selected session, the independently selected network/profile/outcome, and a valid compiled native execution proof. An authenticated unrelated or rejected transaction fails. Mathematical proof verification does not change the execution profile's separate qualification flag.

## Memory and work admission

Each prefix and settlement bundle has at most 96 MiB JSON, 64 MiB aggregate decoded carriers and 256 heights. Individual bounds are 36 MiB per native finality carrier, 32 MiB executed block, 16 MiB entry/output proofs and 68 MiB for the selected checkpoint. A collector must flush a prefix before either its height or byte bound is reached. A large final block may require a smaller preceding batch to fit the same aggregate bound.

The index has at most 1 MiB and 4,096 prefix references. One prefix's JSON and decoded carriers are processed at a time. The verifier retains authenticated decision state and the latest carrier, without keeping every proof frame. Exact referenced file lengths and hashes are checked before carrier decoding. Canonical Norito bounds and JSON preflight apply.

| Local work option | Default | Hard maximum |
| --- | ---: | ---: |
| `--max-finality-heights` | 65,536 heights | 1,048,576 heights |
| `--max-finality-archive-bytes` | 4 GiB | 64 GiB |

Both budgets must be positive. The byte count includes the checkpoint, every finality carrier, final executed block and entry/output proof. Indexed JSON lengths must also fit twice the chosen decoded-byte budget plus 1 MiB of framing. Raising a budget preserves the original trust pin; no automatic endpoint checkpoint or skipped-history path exists.

Only a fully successful settlement verification returns `checkpoint_base64` for deliberate durable promotion. `context_id` is a diagnostic decision digest and is never a replacement trust anchor. `finality_heights_verified` and `archive_bytes_verified` describe the actual admitted work.

## Validation scope

CLI tests use actual native BLS certificates over explicitly synthetic application outputs for the 257-height archive, inclusion, tampered quorum/PoP, wrong network/checkpoint, missing/repeated/reordered heights, file substitution and budget rejection cases. The epoch-boundary test consumes the actual Core `CertifiedTestChain` H9→10→11 output; its DKG is proved but seeded as component prestate. Core's certified-chain tests cover altered BLS certificates and authenticated schedule rejection. These fixtures do not establish live ceremony, funded settlement or validator qualification.

Run `scripts/cargo_fast.sh --stable-local-metadata --incremental -- test -p iroha_cli_lib --lib execution_finality::tests -- --nocapture`. The separately ignored expensive test must also run explicitly to claim end-to-end native execution-proof coverage. A passing source check or skipped test does not count as runtime qualification. Real four-validator settlement and wallet deployment gates remain required.
