# Native payment resource acceptance

The canonical ceilings remain in [zk_resource_contract.json](zk_resource_contract.json).
The maximum native payment fixture is
`native_payment_network::resource_bound::fixed_maximum_payment_and_rejection_survive_http_rs16_kura_and_receipt_recovery`.
It is an explicit real-process test; source or component passes alone do not qualify it.

## Exact shape

The committed signed-transaction cap is 10,485,760 bytes. Admission measures the
canonical Norito frame: 40 header bytes, native archived-payload alignment padding,
and the signed bare payload. The SDK HTTP and workflow identity owner instead retains
the canonical V1 wire: one version byte plus that same bare payload. The test measures
both and asserts `frame = wire - 1 + 40 + padding`; it never silently treats the two
lengths as equal. The fixed resultless block payload cap is 16,777,216 bytes, with
65,536 bytes reserved by global selection, leaving 16,711,680 bytes for selection.

The fixture creates a genuine single-movement `SettleAtomic` with one signed
`reconciliation_text` metadata value. The existing intent schema permits this text,
binds every byte into its signature and intent hash, and carries it in the verified
settlement receipt. A probe uses `target - 8192` text bytes, measures the actual signed
frame, adds the exact remaining difference, and asserts the result is exactly the
fixed cap. The fixture requires absent nonces for stable signing geometry, and checks
the exact signed extent again on every certified and cold-stored carrier. Another
complete signed request is exactly one framed byte larger. No proof is padded, no alternate serializer is installed, and no allowance is raised
for measurement or execution. The numeric signed-frame cap stays independently pinned.

## Required observations

The existing four-validator paid-payment fixture supplies its signed genesis, native
fee configuration and account funds. Its existing local disk custody allowance is
1 GiB; this is inherited unchanged, not the unspecified default host budget. The
added test changes only the logger to JSON for the existing signed-RS16 process
observation parser. The ordinary case retains its original
configuration; the maximum test does not change transaction, proof, block or memory caps.

The first excess byte receives the exact permanent Torii admission envelope from each
peer, including its unique Norito content type and reject code, exact canonical body
and absence of a retry hint. It is refused before the queue and therefore cannot
legitimately exercise block, RS16 or Kura admission. The test sends the SDK-signed
canonical wire through the existing HTTP route;
this direct HTTP negative preserves the structured envelope that the SDK submit report
currently erases into display text. Account balances and height remain at genesis.
The public model byte predicate, SDK preparation/signing and Core admission also test
exact and one-over shapes. This is not a typed high-level SDK submission-refusal check.

Two actual maximum-size payments then execute: one rejects for insufficient principal,
and one moves 250,000 units. The existing rejected-payment verifier authenticates the
precise failed execution and its actual one-unit fee; it refuses a successful payment
receipt. The successful SDK operation must return the complete metadata and actual
fee receipt and credit the bank inbox once. Exact balances require two fee burns and
one principal movement; admission refusal is never called an included rejection.
Each live and cold-stored certified output also binds its fee to the original signed
input, checks the actual fee schedule (base one, all variable rates zero, one native
instruction), and requires the original success or exact principal-insufficiency error.
The expectation is independent of balance differences.

The inherited Global fixture currently authors these fee rates in node-local Nexus
configuration. It does not establish committed fee-policy authority or close F.4.
The independent committed Global/Dataspace fee migration must adapt this fixture to
the real policy owner while retaining the exact one-unit charges and receipt checks.

Each peer supplies a genesis-rooted finality proof for both original carriers. The test
requires one exact input per block, the exact signed-frame size, bounded actual
resultless payload, equal certified decision contexts, and existing local RS16 logs
showing original signed row custody/reconstruction before application. These logs are
source-bound process observations, not remote Byzantine transport proofs.

After all peers stop, the existing read-only Kura owner loads both original canonical
frames. A fresh independent verifier rechecks their certificates, original transaction
identities, decision contexts and opposite execution outcomes. All four processes then
restart from the same stores. New SDK/journal/inbox instances recover the original
success and rejected identity, preserve the complete metadata, and refuse a second
customer credit. The final height stays three, with no successor or unrelated traffic.
Network awaits, including the intermediate shutdown and process-ID lookup, use one
original finite deadline. Synchronous encoding, queries and local Kura/log reads are
checked against that deadline; local file operations are not preemptible. The test
cannot return success after expiry. Cleanup still runs after a failure.

## Remaining private maximum boundary

The native payment above carries no confidential proof. It does not establish X.2/P.20
private-settlement maxima. The current separate private carrier ceiling is 4,194,304
V1 signed-wire/instruction bytes; it is numerically below the 10 MiB transaction cap
and its canonical signed frame at that wire ceiling is 4,194,343 bytes.
Including the global selection reserve gives 4,259,879 bytes. The resource contract
uses the canonical writer's checked 39-byte conversion: its sole V1 prefix is
replaced by Header::SIZE and zero type padding. A compile-time alignment invariant
rejects model/target layouts that would silently change this geometry. This records
the current supported layout, not broad hardware qualification. Private instruction
frames and signed V1 wire remain separate measurements under the unchanged limit. Private leg proofs are capped at
8,388,608 bytes and capsules at 1,048,576 bytes. A bundle permits at most 255 legs.
These Nexus configuration-owned validity limits still have the contract's F.4 defects.

The existing private fixtures distinguish structural 255-leg carrier/codec tests from
genuine N=3 proving and the N=2/3/4/8/16 real-process release matrix. The matched
workload owner explicitly refuses N=255 because its required reimbursement would
exceed the public control's 255 movements. No current genuine maximum private proof
asset or protocol-valid exactly-4-MiB private carrier was established by this review.
Filling a proof or audit capsule with arbitrary bytes would not close that gap. Actual
maximum private proving, boundary refusal, verification, transport and cold recovery
remain required under the unchanged proof/carrier/resource contract.
