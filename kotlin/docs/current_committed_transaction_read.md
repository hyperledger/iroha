# Current wallet-self committed-transaction read

`CommittedTransactionInclusionBridge` is the Kotlin/Android entry point. Swift
uses the same native C verifier through `CommittedTransactionQueryV1` and
`CommittedTransactionInclusionV1`. The verifier authenticates the current
selective `CommittedTransaction` against native Sumeragi finality.

1. Load the expected `NetworkId`, chain label and canonical
   `SumeragiFinalityCheckpoint` bytes from independently approved application
   configuration or a previously accepted promoted checkpoint. The checkpoint
   is bounded to 68 MiB. A Torii response cannot choose this trust anchor.
2. Durably reserve a fresh 32-byte nonce. Build
   `committedTransactionQueryPayloadHash(networkId, walletAccountId,
   transactionHash, creationTimeMs, nonce)`, sign with the wallet controller's
   Ed25519 key, and call `finalizeCommittedTransactionQuery` with the same
   arguments. The exact wallet-self query has a 100-second lifetime.
3. POST the versioned signed query once to `/v1/query`, using
   `application/x-norito` for both `Content-Type` and `Accept`. Pin application
   dataspace and tenant headers independently. Reconcile an ambiguous response
   before creating another nonce-bearing query. The Kotlin transport enforces
   HTTPS by default (or the explicit `setAllowLocalDevelopmentHttp(true)`
   exception for loopback/private IPv4 nodes), the URL prefix, one-shot dispatch,
   response provenance and bounds.
4. `candidateBlockHash(responseBytes, transactionHash)` returns `null` for a
   canonical empty page. A one-row response returns an **untrusted** routing
   hint. Fetch native `SumeragiFinalityProof` values through
   `/v1/bridge/finality/bundle/{height}`, beginning with the checkpoint-height
   proof and continuing consecutively until the candidate block hash matches.
   Bound the page to 4096 proofs and 16 MiB of JSON. Missing proofs or exhausted
   bounds leave the read pending. `getBridgeFinalityBundleJson` fetches one
   bounded JSON proof without granting it authority.
5. Call `verify(responseBytes, nativeFinalityProofChainJson, networkId,
   expectedChain, trustedCheckpoint, transactionHash)`. The native verifier
   authenticates the pinned checkpoint, contiguous proofs, exact original
   block wire, requested transaction and input/output inclusion. On success,
   use `canonicalRowBytes` and compare `outputHashBytes` with server readback.
   `resultOk=false` is authenticated rejection evidence. After accepting the
   application result, atomically retain `promotedCheckpointBytes` with that
   result for subsequent verification. Swift returns `promotedCheckpoint`.

The bridge requires ABI 30 and returns the row and promoted checkpoint in
separately owned native buffers. The application owns authenticated transport,
checkpoint selection and persistence, its device signer, nonce store and retry
journal. SDK source or syntax checks do not qualify rebuilt native artifacts.
