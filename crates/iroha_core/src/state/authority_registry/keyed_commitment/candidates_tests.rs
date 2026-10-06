//! State commitment candidates of ZK delivery plan task G.2 behind the keyed
//! State contract. Development only.
//!
//! The candidates live in `fastpq_prover::state_commitment_prototypes`, beside
//! the in-circuit relations that verify their witnesses. This file holds no
//! construction logic: [`Candidate`] maps the contract's statements onto a
//! prototype engine and its errors back, so `conformance::check_contract`
//! (rules K1..K12 of `specs/sumeragi.md` §16.4) runs on exactly the code that
//! is measured. Nothing here is consensus code, and the module is compiled
//! only into unit tests built with the `state-commitment-prototypes` feature:
//!
//! ```text
//! cargo test -p iroha_core --lib --features state-commitment-prototypes \
//!     keyed_commitment::candidates_tests
//! ```
//!
//! TODO(G.3): delete this file with the prototypes when the selected
//! construction is bound to the State publication owner.

use std::collections::BTreeSet;

use fastpq_prover::state_commitment_prototypes::{
    Engine, KeyedMap, PrototypeSchema, Reject,
    btree::MerkleBTree,
    chain::SortedHashChain,
    hash::{
        Blake2bProfile, ByteHash, ByteProfile, Digest384Comparator, HashProfile, Poseidon2Profile,
        RescuePrimeProfile,
    },
    keyed::{StatementFault, VerifyError},
    linked::LinkedLeafMap,
    radix::RadixTree,
    workload::descriptor_from_inventory,
};

use super::{
    CELL_KEY, Change, Entry, KeyRange, KeyedStateCommitment, KeyedStateRoot, ProveError, Rejection,
    StateSchema, StatementError, TableShape, UpdateError, Witness,
    conformance::{Violation, check_contract},
};
use crate::state::authority_registry::STATE_FIELDS;

/// Raw BLAKE3-256, supplied here because this crate owns a `blake3` dependency
/// and the proof crate does not. The framing is `ByteProfile`'s.
struct Blake3Raw;

impl ByteHash for Blake3Raw {
    const NAME: &'static str = "blake3-256-raw";

    fn digest(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for part in parts {
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
    }
}

type Blake3Profile = ByteProfile<Blake3Raw>;

/// One prototype engine behind the keyed State contract.
struct Candidate<E: Engine> {
    schema: StateSchema,
    map: KeyedMap<E>,
}

/// The prototype's view of a contract schema: the same canonical descriptor bytes.
fn prototype_schema(schema: &StateSchema) -> PrototypeSchema {
    PrototypeSchema::from_descriptor(&schema.canonical_bytes())
        .expect("a validated State schema has a canonical descriptor")
}

fn position(index: usize) -> u32 {
    u32::try_from(index).expect("a State schema has fewer than 2^32 tables")
}

fn statement(fault: StatementFault) -> StatementError {
    match fault {
        StatementFault::UnknownTable => StatementError::UnknownTable,
        StatementFault::CellKey => StatementError::CellKey,
        StatementFault::EmptyRange => StatementError::EmptyRange,
        StatementFault::EntryOutsideRange => StatementError::EntryOutsideRange,
        StatementFault::EntryOrder => StatementError::EntryOrder,
        StatementFault::DuplicateChange => {
            unreachable!("only a change set can name one position twice")
        }
    }
}

fn rejection(error: VerifyError) -> Rejection {
    match error {
        VerifyError::Statement(fault) => Rejection::Statement(statement(fault)),
        VerifyError::Witness(Reject::Malformed) => Rejection::Malformed,
        VerifyError::Witness(Reject::NotProven) => Rejection::NotProven,
    }
}

impl<E: Engine> KeyedStateCommitment for Candidate<E> {
    const CONSTRUCTION: &'static str = E::CONSTRUCTION;

    fn empty(schema: &StateSchema) -> Self {
        Self {
            schema: schema.clone(),
            map: KeyedMap::empty(prototype_schema(schema)),
        }
    }

    fn apply(&mut self, changes: &[Change<'_>]) -> Result<(), UpdateError> {
        // Statements are checked by the contract's own schema, in change order.
        let mut seen = BTreeSet::new();
        let mut positioned = Vec::with_capacity(changes.len());
        for change in changes {
            let table = position(self.schema.check_key(change.table, change.key)?);
            if !seen.insert((table, change.key)) {
                return Err(UpdateError::DuplicateChange);
            }
            positioned.push((table, change.key, change.value));
        }
        self.map.apply(&positioned).map_err(|fault| match fault {
            StatementFault::DuplicateChange => UpdateError::DuplicateChange,
            other => UpdateError::Statement(statement(other)),
        })
    }

    fn root(&self) -> KeyedStateRoot {
        KeyedStateRoot(self.map.root())
    }

    fn entries(&self) -> u64 {
        self.map.entries()
    }

    fn prove_inclusion(&self, table: &str, key: &[u8]) -> Result<Witness, ProveError> {
        let table = position(self.schema.check_key(table, key)?);
        self.map
            .prove_inclusion(table, key)
            .map_err(|fault| ProveError::Statement(statement(fault)))?
            .map(Witness::new)
            .ok_or(ProveError::KeyAbsent)
    }

    fn prove_absence(&self, table: &str, key: &[u8]) -> Result<Witness, ProveError> {
        let table = position(self.schema.check_key(table, key)?);
        self.map
            .prove_absence(table, key)
            .map_err(|fault| ProveError::Statement(statement(fault)))?
            .map(Witness::new)
            .ok_or(ProveError::KeyPresent)
    }

    fn prove_range(&self, table: &str, range: KeyRange<'_>) -> Result<Witness, ProveError> {
        let table = position(self.schema.check_range(table, range, &[])?);
        self.map
            .prove_range(table, range.lower, range.upper)
            .map(Witness::new)
            .map_err(|fault| ProveError::Statement(statement(fault)))
    }

    fn verify_inclusion(
        schema: &StateSchema,
        root: &KeyedStateRoot,
        table: &str,
        key: &[u8],
        value: &[u8],
        witness: &Witness,
    ) -> Result<(), Rejection> {
        let table = position(schema.check_key(table, key)?);
        KeyedMap::<E>::verify_inclusion(
            &prototype_schema(schema),
            root.payload(),
            table,
            key,
            value,
            witness.as_bytes(),
        )
        .map_err(rejection)
    }

    fn verify_absence(
        schema: &StateSchema,
        root: &KeyedStateRoot,
        table: &str,
        key: &[u8],
        witness: &Witness,
    ) -> Result<(), Rejection> {
        let table = position(schema.check_key(table, key)?);
        KeyedMap::<E>::verify_absence(
            &prototype_schema(schema),
            root.payload(),
            table,
            key,
            witness.as_bytes(),
        )
        .map_err(rejection)
    }

    fn verify_range(
        schema: &StateSchema,
        root: &KeyedStateRoot,
        table: &str,
        range: KeyRange<'_>,
        entries: &[Entry<'_>],
        witness: &Witness,
    ) -> Result<(), Rejection> {
        let table = position(schema.check_range(table, range, entries)?);
        let claimed: Vec<(&[u8], &[u8])> = entries
            .iter()
            .map(|entry| (entry.key, entry.value))
            .collect();
        KeyedMap::<E>::verify_range(
            &prototype_schema(schema),
            root.payload(),
            table,
            range.lower,
            range.upper,
            &claimed,
            witness.as_bytes(),
        )
        .map_err(rejection)
    }
}

/// Run the complete contract on one construction under one hash profile.
fn conforms<E: Engine>() -> Result<(), Violation> {
    check_contract::<Candidate<E>>()
}

/// The profile every construction is checked with in every run.
macro_rules! conformance_tests {
    ($($name:ident: $engine:ident<$profile:ty>;)*) => {$(
        #[test]
        fn $name() {
            assert_eq!(conforms::<$engine<$profile>>(), Ok(()));
        }
    )*};
}

conformance_tests! {
    radix_tree_over_blake2b_satisfies_the_keyed_state_contract: RadixTree<Blake2bProfile>;
    radix_tree_over_blake3_satisfies_the_keyed_state_contract: RadixTree<Blake3Profile>;
    radix_tree_over_poseidon2_satisfies_the_keyed_state_contract: RadixTree<Poseidon2Profile>;
    radix_tree_over_rescue_prime_satisfies_the_keyed_state_contract: RadixTree<RescuePrimeProfile>;
    merkle_btree_over_blake2b_satisfies_the_keyed_state_contract: MerkleBTree<Blake2bProfile>;
    merkle_btree_over_blake3_satisfies_the_keyed_state_contract: MerkleBTree<Blake3Profile>;
    merkle_btree_over_poseidon2_satisfies_the_keyed_state_contract: MerkleBTree<Poseidon2Profile>;
    merkle_btree_over_rescue_prime_satisfies_the_keyed_state_contract: MerkleBTree<RescuePrimeProfile>;
    linked_leaf_map_over_blake2b_satisfies_the_keyed_state_contract: LinkedLeafMap<Blake2bProfile>;
    linked_leaf_map_over_blake3_satisfies_the_keyed_state_contract: LinkedLeafMap<Blake3Profile>;
    linked_leaf_map_over_poseidon2_satisfies_the_keyed_state_contract: LinkedLeafMap<Poseidon2Profile>;
    linked_leaf_map_over_rescue_prime_satisfies_the_keyed_state_contract: LinkedLeafMap<RescuePrimeProfile>;
    sorted_hash_chain_over_blake2b_satisfies_the_keyed_state_contract: SortedHashChain<Blake2bProfile>;
    sorted_hash_chain_over_blake3_satisfies_the_keyed_state_contract: SortedHashChain<Blake3Profile>;
    sorted_hash_chain_over_poseidon2_satisfies_the_keyed_state_contract: SortedHashChain<Poseidon2Profile>;
    sorted_hash_chain_over_rescue_prime_satisfies_the_keyed_state_contract: SortedHashChain<RescuePrimeProfile>;
    radix_tree_over_the_in_repo_digest_satisfies_the_keyed_state_contract: RadixTree<Digest384Comparator>;
    merkle_btree_over_the_in_repo_digest_satisfies_the_keyed_state_contract: MerkleBTree<Digest384Comparator>;
    linked_leaf_map_over_the_in_repo_digest_satisfies_the_keyed_state_contract: LinkedLeafMap<Digest384Comparator>;
    sorted_hash_chain_over_the_in_repo_digest_satisfies_the_keyed_state_contract: SortedHashChain<Digest384Comparator>;
}

/// The four constructions are distinct and every profile is named.
#[test]
fn candidates_are_four_distinct_constructions_over_named_profiles() {
    let constructions: BTreeSet<&str> = [
        <Candidate<RadixTree<Blake2bProfile>> as KeyedStateCommitment>::CONSTRUCTION,
        <Candidate<MerkleBTree<Blake2bProfile>> as KeyedStateCommitment>::CONSTRUCTION,
        <Candidate<LinkedLeafMap<Blake2bProfile>> as KeyedStateCommitment>::CONSTRUCTION,
        <Candidate<SortedHashChain<Blake2bProfile>> as KeyedStateCommitment>::CONSTRUCTION,
    ]
    .into_iter()
    .collect();
    assert_eq!(constructions.len(), 4);
    assert!(constructions.iter().all(|name| name.ends_with("/v0")));
    let profiles: BTreeSet<&str> = [
        Blake2bProfile::NAME,
        Blake3Profile::NAME,
        Poseidon2Profile::NAME,
        RescuePrimeProfile::NAME,
        Digest384Comparator::NAME,
    ]
    .into_iter()
    .collect();
    assert_eq!(profiles.len(), 5);
    assert!(!Blake2bProfile::ALGEBRAIC && !Blake3Profile::ALGEBRAIC);
    assert!(Poseidon2Profile::ALGEBRAIC && RescuePrimeProfile::ALGEBRAIC);
    // Raw byte digests are not marker-bearing `iroha_crypto::Hash` values.
    assert_eq!(Blake2bProfile::NAME, "blake2b-256-raw");
    let digest = Blake3Raw::digest(&[b"abc"]);
    assert_eq!(digest, *blake3::hash(b"abc").as_bytes());
}

/// The measured schema is the schema of the actual State: the descriptor that
/// the measurement run derives from the tracked inventory equals the registry's,
/// and the prototype reads it back table by table.
#[test]
fn measured_schema_is_the_registry_schema_of_the_actual_state() {
    let schema = StateSchema::from_registry(STATE_FIELDS).expect("the registry has a V1 schema");
    let inventory = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../specs/state_table_inventory.json"),
    )
    .expect("read specs/state_table_inventory.json");
    assert_eq!(
        descriptor_from_inventory(&inventory).as_deref(),
        Some(schema.canonical_bytes().as_slice()),
        "the tracked State inventory and the authority registry declare different schemas"
    );
    let prototype = prototype_schema(&schema);
    assert_eq!(prototype.tables() as usize, schema.tables().len());
    for (index, table) in schema.tables().iter().enumerate() {
        let index = position(index);
        assert_eq!(prototype.identity(index), Some(table.id()));
        assert_eq!(prototype.position(table.id()), Some(index));
        assert_eq!(
            prototype.is_cell(index),
            Some(table.shape() == TableShape::Cell)
        );
    }
}

/// Entries of several real tables and a cell under the registry schema: every
/// construction commits them, proves the three statement kinds and binds the
/// schema descriptor.
#[test]
fn every_construction_commits_entries_of_the_registry_schema() {
    fn check<E: Engine>() {
        let schema = StateSchema::from_registry(STATE_FIELDS).unwrap();
        let mut candidate = Candidate::<E>::empty(&schema);
        let empty_root = candidate.root();
        let rows: [(&str, &[u8], &[u8]); 5] = [
            ("world.accounts", b"alice", b"details-a"),
            ("world.accounts", b"bob", b""),
            ("world.assets", b"alice", b"100"),
            ("state.transactions.current", b"hash", b"7"),
            ("world.parameters", CELL_KEY, b"parameters"),
        ];
        let changes: Vec<Change<'_>> = rows
            .iter()
            .map(|(table, key, value)| Change {
                table,
                key,
                value: Some(value),
            })
            .collect();
        candidate.apply(&changes).unwrap();
        assert_eq!(candidate.entries(), 5);
        let root = candidate.root();
        assert_ne!(root, empty_root);
        for (table, key, value) in rows {
            let witness = candidate.prove_inclusion(table, key).unwrap();
            assert_eq!(
                Candidate::<E>::verify_inclusion(&schema, &root, table, key, value, &witness),
                Ok(())
            );
        }
        // The same key in another table is a different position.
        let absent = candidate.prove_absence("world.assets", b"bob").unwrap();
        assert_eq!(
            Candidate::<E>::verify_absence(&schema, &root, "world.assets", b"bob", &absent),
            Ok(())
        );
        assert!(
            Candidate::<E>::verify_absence(&schema, &root, "world.accounts", b"bob", &absent)
                .is_err()
        );
        let accounts = [
            Entry {
                key: b"alice",
                value: b"details-a",
            },
            Entry {
                key: b"bob",
                value: b"",
            },
        ];
        let complete = candidate
            .prove_range("world.accounts", KeyRange::FULL)
            .unwrap();
        assert_eq!(
            Candidate::<E>::verify_range(
                &schema,
                &root,
                "world.accounts",
                KeyRange::FULL,
                &accounts,
                &complete
            ),
            Ok(())
        );
        // A witness whose encoding depends on the number of claimed entries
        // reports an omission as malformed; either way it is rejected.
        assert!(
            matches!(
                Candidate::<E>::verify_range(
                    &schema,
                    &root,
                    "world.accounts",
                    KeyRange::FULL,
                    &accounts[..1],
                    &complete
                ),
                Err(Rejection::NotProven | Rejection::Malformed)
            ),
            "an omitted account"
        );
        assert_eq!(
            candidate.prove_inclusion("world.parameters", b"not-the-cell-key"),
            Err(ProveError::Statement(StatementError::CellKey))
        );
        assert_eq!(
            candidate.prove_inclusion("world.domains_by_owner", b"k"),
            Err(ProveError::Statement(StatementError::UnknownTable)),
            "a derived index is not a committed table"
        );
    }
    check::<RadixTree<Blake2bProfile>>();
    check::<MerkleBTree<Blake2bProfile>>();
    check::<LinkedLeafMap<Blake2bProfile>>();
    check::<SortedHashChain<Blake2bProfile>>();
    check::<RadixTree<Poseidon2Profile>>();
}
