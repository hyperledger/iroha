# KAGEMUSHA native finality replacement

## Decision

KAGEMUSHA Load finality is verified directly from Sumeragi BLS commit
certificates, rooted in the application's independently authenticated signed
genesis and authenticated validator changes. A finality prover, recursive block
history, finality circuits and finality proving/verifying-key inventories are
not part of the first release. Retired implementations and formats are deleted;
there is no compatibility mode or fallback decoder.

The existing production profile trusts the released wallet application on a
stock uncompromised OS and its nonexportable payment key. The native wallet
must authenticate the exact successful Load receipt before requesting its signed
Advance. The monetary relation binds that receipt, its amount and ordinal, the
state transition, replay insertion and the credential-bound Advance signature.
It does not prove BLS verification inside PLONK. A modified application is outside
this selected profile; accepting a host boolean is not a replacement for the
mandatory native verification before signing. This approved tradeoff means that
a receiver does not obtain an independent BLS funding proof from the monetary
proof; funding assurance depends on the released application performing the
required native checks before using its credential-bound signing key.

## Goals

| ID | Owner | Outcome and completion criteria |
| --- | --- | --- |
| NF1 | Data model / Sumeragi | One bounded native certificate format and verifier. Pin network and global genesis scope; authenticate validator keys and proofs of possession, exactly `n - f` votes, epoch transitions and their activation heights, certified execution result and counted receipt-event inclusion. Reject malformed signatures, wrong roots, stale/substituted committees, omitted transitions, foreign receipts, trailing data and oversized inputs. |
| NF2 | Native wallet / SDK | Verify evidence before selecting a fresh Load for its Advance signature or balance mutation. Persist and authenticate exact receipt/evidence and selection for recovery: an unsigned restart may sign only that same authenticated Selected capsule; completed retry returns the retained output without a new signature or credit. Fresh admission/import must verify evidence, bind all Load terms and refuse unavailable or invalid evidence without signing. Both mobile SDKs use the same native owner. |
| NF3 | Proofs / artifact owners | Remove the recursive finality source and Load finality-verifier stage while preserving receipt binding, replay protection and authenticated Advance signatures. Rebuild the four-A/three-W Load source and affected A/W/Omega catalog, source profiles and signed inventories; no finality proof, accumulator, descriptor, proving key or verifier-key dependency remains. Historical recursive-finality originals cannot qualify the replacement. |
| NF4 | Torii / config / tools | Serve ordinary native receipt evidence with no recursive-finality worker, proof journal, artifact compiler or proof-server provisioning/storage prerequisite. Delete retired configuration and packaging fields and reject their use. Register continues through native finality. |
| NF5 | Integration / release | Pass focused model, proof, preparation, server and bridge tests, then genuine Load, restart, offline A-to-B-to-C and Unload on a four-validator network. Measure certificate bytes, verification latency and phone memory on the current candidate; do not transfer historical recursive-finality qualification or assert unmeasured millisecond/few-kilobyte results. |
| NF6 | Native wallet / Torii / SDK | Implemented: serve one bounded original boundary certificate at a time, authenticate its incumbent authority before selecting the successor, durably retain epoch authority under the wallet manifest, and resume after restart. Receipt responses contain only the receipt certificate and event path. Importing an untrusted checkpoint or replaying every full block is not a substitute. Current-candidate release qualification remains part of NF5. |

## Epoch synchronization

- Data model owns canonical `SumeragiCommitCertificateV1` transport, bounded to
  262,144 bytes, and native boundary verification. `height()` and `epoch_id()`
  expose DATA selectors, never authority.
- Native wallet custody owns `SumeragiCommitCheckpointV1` records in a
  manifest-selected authenticated epoch index. The bounded record contains the
  signed genesis context and one authenticated epoch, never a growing history.
  Only those exact locally selected bytes may reach
  `from_trusted_epoch_checkpoint`; bridge inputs cannot supply trusted records.
- Torii serves the payer-authorized receipt's exact requested boundary original
  at `/loads/{request}/epochs/{boundary}`. It does not receive a trusted client
  roster or follow an unverified successor. The terminal `/finality` response
  contains one receipt certificate and counted event proof, bounded to 262,144
  bytes; the native capsule bound is 524,288 bytes. Payment remains 10,000 bytes.
- Native bridge and SDK owners expose selected epoch progress and one original
  boundary ingestion. Sync repeats until the authenticated interval covers the
  receipt height. Native preparation restores the receipt's archived epoch and
  performs fresh BLS/event verification before Advance; delayed receipts still
  use retained older epoch authority. The SDK's 64-boundary work budget applies
  to one resumable call, not the chain's lifetime; each verified boundary is
  durably selected before the next request.
- Torii must retain the original Kura boundary certificates and receipt event paths
  required by outstanding wallets. Missing or pruned originals stop synchronization
  and Load admission; neither an HTTP response nor an imported checkpoint fills a gap.
  Epoch verification skips ordinary blocks, while long-offline catch-up and source
  retention still require release qualification.
- Focused checks cover more than 64 authenticated transitions and bounded
  checkpoint restoration. Native integration checks exercise restart between
  pages, identical retry, missing/forged/wrong-root evidence, publication
  uncertainty, delayed older receipts, and refusal without an Advance signature.

## Validation boundary

Implementation and focused tests do not establish physical-phone performance,
the complete installed monetary proof catalog or release qualification. The
remaining evidence belongs to the current candidate. The historical native9
recursive-history attempt was interrupted with only H1 recorded and no observed
exit or terminal result; it supplies no completed history or current catalog
authority. Native state synchronization must preserve authenticated schedule
continuity; an arbitrary validator list or untrusted checkpoint is never finality
authority. Bounded transport and durable epoch custody are implemented; no
one-shot response must contain the chain's epoch history. Retained epoch records
still consume storage as epochs accumulate. Focused model, codec and fixture
checks do not replace the complete monetary catalog, four-validator Load and
offline-exchange workflow, rebuilt SDK delivery or physical-phone qualification.
Server and phone costs remain unqualified.
