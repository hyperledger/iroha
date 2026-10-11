# Development vote-membership fixture (not election qualification)

The depth-8 native relation in `xtask/src/vote_tally/native.rs`
is a development fixture. It proves a boolean commitment and eight
fixed left-branch compression steps. It does not prove credential ownership,
election/choice binding, ciphertext correctness, aggregate conservation, a
sound tally, or successful completion despite dropout.

The closed production native registry rejects
`pipa-r/pasta/dev-vote-membership-v1`. Neither a raw valid IPA proof, a
registry-shaped record, nor a synthetic host verification latch admits that
relation as a ballot or tally. No deployment key or election should be created
from these artifacts. Ballot and tally construction/qualification remain open
in `specs/zk_audit_matrix.md` and `specs/privacy_first_release_closure.md`.

## Exact fixture relation

Over Pasta Fp, `C(a,b) = 2(a+7)^5 + 3(b+13)^5`. The witness uses vote `1`,
rho `12345`, commitment `C(1,12345)`, and siblings `20..27`. Each root step is
`C(previous, sibling)`. The native public instance is one column with two rows:
commitment, then root. The test helper verifies the actual raw PIPA-R proof;
commitment, root, transcript mutation and transcript truncation are negative
controls. These checks do not establish a production election relation.

## Single developer fixture owner

`xtask/src/vote_tally.rs` owns deterministic development artifact generation.
The obsolete duplicate Core example and production-sounding public command
have been removed; there is no compatibility alias.

```sh
cargo run -p xtask --bin xtask --features dev-tools,dev-vote-fixture -- zk-dev-vote-fixture \
  --out target/dev-vote-membership --print-hashes \
  --summary-json target/dev-vote-membership/summary.json \
  --attestation target/dev-vote-membership/artifacts.json
cargo run -p xtask --bin xtask --features dev-tools,dev-vote-fixture -- zk-dev-vote-fixture \
  --out target/dev-vote-membership --verify \
  --attestation target/dev-vote-membership/artifacts.json
```

The generator raw-verifies before writing and separately requires rejection by
production dispatch. Metadata says `production_admissible: false`. The public
input digest identifies concrete fixture values; it is not a production schema
commitment. The key digest uses Core's canonical `hash_vk`. The deterministic
`fixture_id` is an identifier, not a timestamp. The artifact manifest checks
exact bytes/digests and contains no security-review signature or promotion claim.
The two binary artifacts use canonical Norito (`.norito`): the key contains its
compiled descriptor and processed key, and the proof contains an
`OpenVerifyEnvelope` with one native public column. Deterministic recovery
randomness is derived from the public fixed-witness context only in this
development tool; it provides no witness secrecy. Production proof builders
use hedged entropy.

## Controls and limits

- `zk_vote_tally_audit.rs`: raw proof/instance/transcript controls; production
  dispatch, key registration, and `VerifyProof` rejection, including corrupted
  retained registry state and altered public-input/schema fields.
- `gov_zk_ballot.rs`: pre-proof input admission and invalid retained-key rejection.
  Former toy-proof acceptance/deduplication claims are replaced by no-mutation
  controls, including repeated submissions and hint variants. Real ballot
  acceptance, credential-linked nullifier derivation and deduplication remain open.
- `zk_verify_vendor_e2e.rs`: missing-latch rejection and rejection of the retired
  relation even when a test-only latch is forced. This is not a successful ballot.
- `gov_zk_ballot_real_vk.rs`, `gov_zk_ballot_lock_verified.rs`, and
  `gov_finalize_real_vk.rs`: existing closed-registry/retained-state adversaries.

The Core test-only Halo2 arithmetic helpers still require their separate native
migration before the shared vendor dependency can be deleted. They have no
production registry admission.

Native tests and regenerated artifacts must be run against the reviewed candidate;
source inspection and independent arithmetic alone are not proof qualification.
