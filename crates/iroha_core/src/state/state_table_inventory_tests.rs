//! Inventory of every State and World field, the roots each one currently affects and
//! every commitment over State content that exists in the tree.
//!
//! `specs/state_table_inventory.json` is generated here from the source:
//!
//! - the exhaustive authority registry (`STATE_FIELDS`, which destructures `State`,
//!   `WorldData`, the trigger set and the canonical runtime without `..`) and the
//!   exhaustive destructure of `TransactionsStorage`;
//! - the World state accumulator's field index, the production World pass and the exact
//!   table catalog;
//! - a scan of every non-test Rust source of `iroha_core` and `iroha_data_model` (the
//!   drift test of `specs/sumeragi.md` §16.8): it discovers domain literals by their
//!   form, independently of the listed commitments, pins the sources and occurrence
//!   counts of every listed literal, and counts the uses of commitment constructions in
//!   code;
//! - a signature scan of every non-test source of `iroha_core`: the functions and methods
//!   with a State or World receiver or reader argument and a hash-bearing return value
//!   (`state_table_inventory_functions.rs`). A reader is `State`, `World` or the owner of
//!   another registry field with its handles and reader traits, or a table or cell
//!   handle; a method belongs to a reader when the whole header of its `impl` or `trait`
//!   block names one. A record of the peer handshake or of a lane block that the carrier
//!   walk reads is matched as a return type whatever its name;
//! - the declarations of the consensus-carried types and their nested records: the block
//!   header, the block payload and block result, the signed genesis consensus parameters,
//!   the execution result, every Sumeragi wire message (`crates/iroha_sumeragi`), the lane
//!   batch and lane result, the peer handshake (`crates/iroha_p2p`: the hello record with
//!   its four metadata records and wire digest, the identity binding that its signature
//!   covers, and the consensus, confidential and crypto capabilities) and the node's
//!   network envelope;
//! - the execution-witness key tags of the data model, the SCCP write-set encoder, the
//!   World accessors of the functions that derive witness values and the fields of the
//!   witness value types.
//!
//! The tracked file is compared byte for byte with a fresh generation, so it fails when
//!
//! - the registry gains, loses or reclassifies a field,
//! - a field starts or stops affecting the certified World state root or an
//!   execution-witness family,
//! - a domain literal appears that is not listed exactly: under a commitment of `ROOTS`,
//!   under an application accumulator, or with its reviewed use in
//!   `state_table_inventory_domains.rs`. No listing matches a prefix, so a new literal
//!   under a known prefix fails as well,
//! - a listed domain literal appears in another source, or a source changes its number
//!   of occurrences: every use of a listed literal is reviewed again,
//! - a source starts to use a Merkle, sparse-Merkle, multiset or accumulator
//!   construction, or an approved source changes its number of uses,
//! - a function that reads State and returns a hash-bearing value appears, moves or is
//!   renamed without an exact listing,
//! - a hash-bearing field, or a nested named type, appears in a listed consensus-carried
//!   type or execution-witness value type without a classification,
//! - any field, whatever its type, appears in a carrier type whose every field is
//!   classified: the block, its payload and its result, the header, `R`, the lane batch and
//!   lane result, the genesis context parameters, the epoch identity, every record of the
//!   peer handshake and the network envelope,
//! - a function that derives a witness value reads another World accessor,
//! - an expected-open defect changes (for example a State-level canonical field becomes
//!   committed), or
//! - cited source evidence disappears or is duplicated.
//!
//! What the scan does not do: it detects carrier, signature, literal and construction
//! drift, not arbitrary State dataflow. A digest of State content is not detected when
//! its domain literal does not have the form of `DOMAIN_LITERAL_RULE`, it uses none of
//! the listed constructions, it enters no listed witness value type and no listed
//! consensus-carried type, and no function with a State or World reader in its signature
//! returns it ([`HASH_RETURN_RULE`]). A digest held in a type that the hash rules do not
//! match, for example an integer, is not detected either: such fields are listed by review
//! (`Carrier::reviewed`). The signature scan reads literal `impl` and `trait` blocks, also
//! in macro bodies, and does not expand macros. The commitments that only a review found
//! are listed under [`REVIEW_ONLY_ROOTS`]. Witness values that are State records copied
//! as written are rows; their own fields are not walked.
//!
//! Cited line numbers are locators: they are refreshed by regeneration and not compared,
//! so unrelated edits above a cited line do not fail the check.
//!
//! Regenerate after an intended change with
//! `cargo test -p iroha_core --lib regenerate_state_table_inventory -- --ignored`
//! and review the difference. The tracked file describes the shipping `node` feature set,
//! whose `State` has the `state.telemetry` field.
//!
//! The contract these facts are measured against is `specs/sumeragi.md` §16. The tests
//! below also pin the as-built premises of its §16.5 and §16.6, and they are the evidence
//! for "every table mutation affects the appropriate root": each inventoried field is
//! driven through the production accumulator under its registry identity, and the result
//! must agree with the inventory.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    path::{Path, PathBuf},
};

use super::*;
use crate::state::{
    World,
    authority_registry::{
        DerivationCheck, STATE_FIELDS, catalog_table_ids, keyed_commitment::codec_identity,
    },
    block_field::BlockField,
    storage_transactions::{MembershipFieldRole, TRANSACTIONS_STORAGE_FIELDS},
};
use mv::storage::Storage;

#[path = "state_table_inventory_domains.rs"]
mod domains;
use domains::{OTHER_DOMAINS, Use};

#[path = "state_table_inventory_functions.rs"]
mod functions;
use functions::STATE_HASH_FUNCTIONS;

const INVENTORY_PATH: &str = "specs/state_table_inventory.json";

/// The normative contract of the keyed State commitment and its typed interface.
const CONTRACT: &str = "specs/sumeragi.md §16";
const CONTRACT_PATH: &str = "specs/sumeragi.md";
const INTERFACE: &str = "crates/iroha_core/src/state/authority_registry/keyed_commitment.rs";

/// How a field relates to the certified roots today.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Commitment {
    /// A nested owner: its children are classified, it holds no row itself.
    Owner,
    /// Canonical and bound by the certified World state root.
    Certified,
    /// Canonical but bound by no certified State root (open defect G1-D2).
    Uncommitted,
    /// Secondary state: excluded as independent authority, rebuilt from its sources.
    Derived,
    /// Authenticated history: bound by the header chain and results, by no State root.
    History,
    /// Node-local machinery that must affect no root.
    Local,
}

impl Commitment {
    const fn name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Certified => "certified",
            Self::Uncommitted => "uncommitted",
            Self::Derived => "derived",
            Self::History => "history",
            Self::Local => "local",
        }
    }
}

struct Row {
    field: &'static Field,
    /// Registry kind of a canonical field, physical shape of any other World field.
    shape: Option<u8>,
    commitment: Commitment,
}

/// Records which fields the production World pass visits, and in which shape.
#[derive(Default)]
struct ShapeRecorder(Vec<(&'static str, u8)>);

impl WorldProjection for ShapeRecorder {
    type Error = String;

    fn append_storage_with<K: Key + Encode, V: Value, M: mv::storage::StorageMode<K, V>>(
        &mut self,
        name: &'static str,
        _storage: &StorageField<'_, K, V, M>,
        _encode: impl Fn(&V) -> Result<Hash, String>,
    ) -> Result<(), Self::Error> {
        self.0.push((name, TABLE));
        Ok(())
    }

    fn append_cell_with<V: Value, C: Send + Sync + 'static>(
        &mut self,
        name: &'static str,
        _cell: &CellField<'_, V, C>,
        _encode: impl Fn(&V) -> Result<Hash, String>,
    ) -> Result<(), Self::Error> {
        self.0.push((name, CELL));
        Ok(())
    }
}

/// The name under which the production World pass projects a registry field, if it does:
/// World fields use their bare name, trigger stores keep their identity.
fn pass_name(id: &'static str) -> Option<&'static str> {
    match id.strip_prefix("world.") {
        Some(name) => Some(name),
        None => id.starts_with("triggers.").then_some(id),
    }
}

/// Every field the production pass visits over the actual World overlay, with its shape.
fn pass_shapes() -> BTreeMap<&'static str, u8> {
    let world = World::default();
    let block = world.block();
    let mut recorder = ShapeRecorder::default();
    block
        .project_world(&mut recorder)
        .expect("the production World pass completes");
    let mut shapes = BTreeMap::new();
    for (name, shape) in recorder.0 {
        assert!(
            shapes.insert(name, shape).is_none(),
            "the World pass visits {name} twice"
        );
    }
    shapes
}

fn rows() -> Vec<Row> {
    let index = field_index().as_ref().expect("complete World registry");
    let shapes = pass_shapes();
    let mut fields = Vec::new();
    flatten(STATE_FIELDS, &mut fields);
    fields
        .into_iter()
        .map(|field| {
            let name = pass_name(field.id);
            let slot = name.and_then(|name| index.by_name.get(name).copied());
            let declared = match field.role {
                Role::Canonical(Canonical::Table { .. }) => Some(TABLE),
                Role::Canonical(Canonical::Cell(_)) => Some(CELL),
                _ => None,
            };
            let commitment = match (field.role, slot) {
                (Role::Canonical(Canonical::Owner(_)), None) => Commitment::Owner,
                (Role::Canonical(_), Some(Classified::Canonical { kind, .. })) => {
                    assert_eq!(Some(kind), declared, "{}", field.id);
                    Commitment::Certified
                }
                (Role::Canonical(_), None) => {
                    assert!(
                        name.is_none(),
                        "canonical World field {} has no accumulator slot",
                        field.id
                    );
                    Commitment::Uncommitted
                }
                (Role::Derived { .. }, Some(Classified::Excluded) | None) => Commitment::Derived,
                (Role::Local(_), Some(Classified::Excluded) | None) => Commitment::Local,
                (Role::History { .. }, None) => Commitment::History,
                _ => panic!("{} has an inconsistent accumulator slot", field.id),
            };
            let visited = name.and_then(|name| shapes.get(name).copied());
            if commitment == Commitment::Certified {
                assert_eq!(visited, declared, "{} is not visited as declared", field.id);
            }
            Row {
                field,
                shape: declared.or(visited),
                commitment,
            }
        })
        .collect()
}

/// The uncommitted canonical and historical bases that a derived field rests on.
fn unbound_bases(
    rows: &BTreeMap<&'static str, &Row>,
    sources: &'static [&'static str],
    seen: &mut BTreeSet<&'static str>,
    out: &mut BTreeSet<&'static str>,
) {
    for &source in sources {
        if !seen.insert(source) {
            continue;
        }
        let row = rows
            .get(source)
            .unwrap_or_else(|| panic!("unclassified derivation source {source}"));
        match row.commitment {
            Commitment::Uncommitted | Commitment::History => {
                out.insert(source);
            }
            Commitment::Derived => {
                if let Role::Derived { sources, .. } = row.field.role {
                    unbound_bases(rows, sources, seen, out);
                }
            }
            Commitment::Certified | Commitment::Owner => {}
            Commitment::Local => panic!("derivation depends on node-local {source}"),
        }
    }
}

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    std::fs::read_to_string(repository().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if u32::from(control) < 0x20 => {
                write!(out, "\\u{:04x}", u32::from(control)).expect("write to a String");
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn list<S: AsRef<str>>(items: impl IntoIterator<Item = S>) -> String {
    let items: Vec<String> = items
        .into_iter()
        .map(|item| string(item.as_ref()))
        .collect();
    format!("[{}]", items.join(","))
}

/// One cited source line: its path, first line number, number of matching lines and text.
/// The check pins the path, the text and the number of matching lines, so vanished or
/// duplicated evidence fails; the line number is a locator refreshed by regeneration.
fn evidence(path: &str, text: &str) -> String {
    let source = source(path);
    let lines: Vec<usize> = source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(text))
        .map(|(index, _)| index + 1)
        .collect();
    assert!(
        !lines.is_empty(),
        "cited evidence is gone from {path}: {text}"
    );
    format!(
        "{{\"path\":{},\"line\":{},\"occurrences\":{},\"text\":{}}}",
        string(path),
        lines[0],
        lines.len(),
        string(text)
    )
}

fn evidence_list(items: &[(&str, &str)]) -> String {
    let items: Vec<String> = items
        .iter()
        .map(|(path, text)| evidence(path, text))
        .collect();
    format!("[{}]", items.join(","))
}

/// State-level canonical cells whose Rust owner is a node configuration value, read from
/// the registry declaration itself.
fn node_configuration_cells() -> Vec<String> {
    const REGISTRY: &str = "crates/iroha_core/src/state/authority_registry/state.rs";
    source(REGISTRY)
        .lines()
        .filter(|line| line.contains("iroha_config::parameters::actual::"))
        .map(|line| {
            let (_, rest) = line
                .split_once("=> (\"")
                .unwrap_or_else(|| panic!("registry declaration without an identity: {line}"));
            rest.split_once('"')
                .expect("registry identity is a string literal")
                .0
                .to_owned()
        })
        .collect()
}

/// What a listed commitment is. The class fixes how its disposition is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootClass {
    /// A root that the execution result certifies today and that authenticates canonical
    /// State entries: the complete World state root, or a per-table State root.
    CertifiedStateRoot,
    /// A per-block witness root of the execution result.
    CertifiedWitnessRoot,
    /// A value committed by a per-block witness root and proven in the result.
    CertifiedWitnessValue,
    /// A flat digest or composite summary of State content carried for comparison in a
    /// header, the block result, signed genesis or the peer handshake, with no witness form.
    ProtocolFingerprint,
    /// Digests or embedded records that bind consensus authority, scheduling and finalized
    /// beacon inputs in their specified roles (`specs/sumeragi.md` §§3, 4.1 and 10). They
    /// authenticate no State read.
    ConsensusBinding,
    /// A root over State content that nothing publishes, certifies or admits.
    UncertifiedDraft,
    /// A node-local binding commitment of a local artifact, cache or comparison. It
    /// authenticates no State read.
    LocalBindingDigest,
}

impl RootClass {
    const fn name(self) -> &'static str {
        match self {
            Self::CertifiedStateRoot => "certified_state_root",
            Self::CertifiedWitnessRoot => "certified_witness_root",
            Self::CertifiedWitnessValue => "certified_witness_value",
            Self::ProtocolFingerprint => "protocol_fingerprint",
            Self::ConsensusBinding => "consensus_binding",
            Self::UncertifiedDraft => "uncertified_draft",
            Self::LocalBindingDigest => "local_binding_digest",
        }
    }

    /// Whether the execution result certifies the commitment today. A consensus binding
    /// is bound by every vote and certificate (the epoch context) or embedded in the
    /// result preimage (the schedule and the beacon pulse).
    const fn certified(self) -> bool {
        matches!(
            self,
            Self::CertifiedStateRoot
                | Self::CertifiedWitnessRoot
                | Self::CertifiedWitnessValue
                | Self::ConsensusBinding
        )
    }

    /// Whether the commitment stays in its role under contract rule P1.
    const fn kept(self) -> bool {
        matches!(
            self,
            Self::CertifiedWitnessRoot
                | Self::CertifiedWitnessValue
                | Self::ConsensusBinding
                | Self::LocalBindingDigest
        )
    }
}

struct Root {
    id: &'static str,
    class: RootClass,
    carrier: &'static str,
    keyed: bool,
    scope: &'static str,
    construction: &'static str,
    witnesses: &'static str,
    /// The task or owner that decides the commitment's fate, and what happens to it.
    owner: &'static str,
    disposition: &'static str,
    /// The open defect that tracks a disposition which changes the tree.
    defect: Option<&'static str>,
    /// The exact domain literals of the scanned sources that belong to it, as written and
    /// in ascending order. Its construction users are listed in [`CONSTRUCTION_USES`].
    domains: &'static [&'static str],
    evidence: &'static [(&'static str, &'static str)],
}

/// Every commitment over State content that exists in the tree today: a digest or root
/// that node code computes from the content of State fields and that the execution result
/// certifies, a protocol object carries, a node holds outside State, or a draft builds.
/// Application accumulators are listed under [`APPLICATION_ACCUMULATORS`]. The source scan
/// below fails when a domain literal or a construction use belongs to none of them and is
/// not listed exactly under [`OTHER_DOMAINS`] or [`CONSTRUCTION_USES`], when a hash-bearing
/// field of a consensus-carried type is not classified under [`CARRIERS`], and when a
/// function that reads State and returns a hash-bearing value is not listed under
/// [`STATE_HASH_FUNCTIONS`].
const ROOTS: &[Root] = &[
    Root {
        id: "world_state_root",
        class: RootClass::CertifiedStateRoot,
        carrier: "ExecutionCommitment.parent_world_state_root, ExecutionCommitment.world_state_root",
        keyed: false,
        scope: "every canonical World table and cell, trigger stores included",
        construction: "LtHash16 multiset hash over field, key and value hashes",
        witnesses: "none: a multiset hash has no inclusion, absence or range witness",
        owner: "G.3",
        disposition: "replaced in place by parent_keyed_state_root and keyed_state_root; the accumulator, its World cell and the World-element snapshot format are deleted",
        defect: Some("G1-D1"),
        domains: &[
            r"iroha 2026-09-30 world-state lthash16 element v1",
            r"iroha.sumeragi.world-state-snapshot.v1",
            r"iroha:world-net-delta:value:bare-v1\0",
            r"iroha:world-state:path:v1\0",
            r"iroha:world-state:root:v1\0",
            r"iroha:world-state:schema:field:v1\0",
            r"iroha:world-state:schema:no-key:v1\0",
            r"iroha:world-state:schema:start:v1\0",
            r"iroha:world-state:schema:value:v1\0",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/state/world_state_accumulator.rs",
                "pub(crate) struct WorldStateAccumulator {",
            ),
            (
                "crates/iroha_data_model/src/sumeragi_finality/commitment.rs",
                "pub parent_world_state_root: Hash,",
            ),
            (
                "crates/iroha_data_model/src/sumeragi_finality/commitment.rs",
                "pub world_state_root: Hash,",
            ),
            (
                "specs/sumeragi.md",
                "| E51 | Application `R` (node integration, §4.1) |",
            ),
        ],
    },
    Root {
        id: "execution_witness_roots",
        class: RootClass::CertifiedWitnessRoot,
        carrier: "ExecutionCommitment.parent_state_root, post_state_root, ordinary_writes_root",
        keyed: true,
        scope: "the reserved witness families one block's execution recorded (listed under witness_families). No table is committed row by row and untouched rows are not committed; a family value may digest a complete table or cell, and each such digest is a commitment listed here (the digests of every family)",
        construction: "sparse Merkle tree over execution-witness key hashes, rebuilt per block",
        witnesses: "per-key write proofs of one block; not a State root",
        owner: "A.1",
        disposition: "kept in its E51 role as per-block witness roots; ordinary_writes_root stays the new_root of ordinary effects",
        defect: None,
        domains: &[r"iroha:sumeragi:invalid-exec-witness"],
        evidence: &[
            (
                "crates/iroha_data_model/src/sumeragi_finality/commitment.rs",
                "pub post_state_root: Hash,",
            ),
            (
                "crates/iroha_data_model/src/sumeragi_finality/commitment.rs",
                "pub ordinary_writes_root: Hash,",
            ),
            (
                "crates/iroha_core/src/exec_witness/roots.rs",
                "//! Execution-witness state roots.",
            ),
        ],
    },
    Root {
        id: "native_lane_state_commitment",
        class: RootClass::CertifiedWitnessValue,
        carrier: "ExecutionResultCommitment.native_lanes: one fixed-key write under ordinary_writes_root",
        keyed: false,
        scope: "the complete value of the world.sumeragi_lanes cell at one height",
        construction: "flat hash of the canonical lane state, bound to the network and carrier height",
        witnesses: "the fixed-key sparse Merkle path of the block's ordinary-write root",
        owner: "G.3",
        disposition: "kept in its E51 role as a witnessed value of the block; the cell itself also becomes an entry of the keyed State root",
        defect: None,
        domains: &[
            r"iroha:sumeragi:lane-state-value:v1\0",
            r"iroha:sumeragi:lane-state:v1",
        ],
        evidence: &[
            (
                "crates/iroha_data_model/src/sumeragi_finality/lane_state_commitment.rs",
                "const DOMAIN: &[u8] = b\"iroha:sumeragi:lane-state-value:v1\\0\";",
            ),
            (
                "crates/iroha_data_model/src/sumeragi_finality/native_lanes.rs",
                "pub const SUMERAGI_LANE_STATE_WITNESS_KEY: &[u8] = b\"iroha:sumeragi:lane-state:v1\";",
            ),
            (
                "crates/iroha_core/src/state/native_lane_state.rs",
                "key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),",
            ),
        ],
    },
    Root {
        id: "execution_policy_digest",
        class: RootClass::ProtocolFingerprint,
        carrier: "signed genesis consensus parameters (execution_policy_hash), the peer handshake (execution_policy_hash and nexus_policy_digest of the consensus capabilities) and the local publication comparison surface",
        keyed: false,
        scope: "the canonical policy cells that are installed from node configuration. The Nexus policy digest also incorporates `state.lane_manifests` and `state.lane_compliance` through their policy digests",
        construction: "flat SHA-256 digest of the policy fields, with the ZK, SCCP and Nexus policy digests as inputs; the Nexus policy digest is also carried on its own in the peer handshake",
        witnesses: "none",
        owner: "G.3",
        disposition: "made a function of the committed policy entries or removed, together with those cells' move into committed protocol State (F.4); it authenticates no State read",
        defect: Some("G1-D3"),
        domains: &[
            r"iroha:nexus:consensus-policy:v1\0",
            r"iroha:nexus:lane-compliance-policy-set:v1\0",
            r"iroha:nexus:lane-manifest-policy-set:v1\0",
            r"iroha:nexus:lane-manifest-source-set:v1\0",
            r"iroha:sccp:policy:v1",
            r"iroha:zk:consensus-policy:v1",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/state.rs",
                "fn compute_execution_policy_digest_v1(",
            ),
            (
                "crates/iroha_core/src/sumeragi/genesis_meta.rs",
                "staged.execution_policy_digest_v1().map(Hash::prehashed)",
            ),
            (
                "crates/iroha_data_model/src/block/consensus.rs",
                "pub execution_policy_hash: [u8; 32],",
            ),
            (
                "crates/iroha_p2p/src/lib.rs",
                "pub nexus_policy_digest: [u8; 32],",
            ),
        ],
    },
    Root {
        id: "confidential_feature_digest",
        class: RootClass::ProtocolFingerprint,
        carrier: "BlockHeader.confidential_features of every block, and the confidential capabilities of the peer handshake",
        keyed: false,
        scope: "the effective verifying-key projection, selected parameter identifiers and their registry-effectiveness checks, ZK policy, and the SCCP light-client profile versions and hashes active at the block height. Source fields: world.verifying_keys, world.poseidon_params, world.pedersen_params, world.sccp_light_client_profiles and state.zk",
        construction: "composite summary: an undomained flat hash of the sorted effective entries of the complete verifying-key table, the Poseidon and Pedersen parameter identifiers that state.zk selects while their registry rows are effective, the confidential rules version, and a SHA-256 digest of the ZK consensus policy combined with the SCCP policy hash of the active profile selection; absent profile activations select the compiled version-1 genesis profiles",
        witnesses: "none",
        owner: "G.3",
        disposition: "Removed, or retained solely as an inventoried comparison value recomputed at the specified height from committed registry entries and committed policy. All canonical source entries are committed under the keyed State root. It authenticates no State read; consumers requiring State reads use keyed State witnesses. Policy hashes, parameter selectors and transition limits follow G1-D3/F.4",
        defect: Some("G1-D10"),
        domains: &[r"iroha:confidential-policy:v1"],
        evidence: &[
            (
                "crates/iroha_core/src/state.rs",
                "fn compute_vk_set_hash_from_statuses_at_height(",
            ),
            (
                "crates/iroha_core/src/state.rs",
                "pub fn compute_confidential_feature_digest(",
            ),
            (
                "crates/iroha_data_model/src/block/header.rs",
                "pub confidential_features: Option<ConfidentialFeatureDigest>,",
            ),
            (
                "crates/iroha_core/src/sumeragi/payload.rs",
                "let confidential = compute_confidential_feature_digest(view.world(), view.zk(), height);",
            ),
            (
                "crates/iroha_core/src/block.rs",
                "ensure_confidential_features_match(expected_digest, actual_digest)?;",
            ),
            (
                "crates/iroha_p2p/src/peer.rs",
                "pub(super) struct HandshakeConfidentialDigest {",
            ),
        ],
    },
    Root {
        id: "nexus_amx_context_digest",
        class: RootClass::ProtocolFingerprint,
        carrier: "SumeragiGenesisContextParameters.nexus_amx_context_hash of the signed genesis consensus parameters and of the handshake metadata signed into genesis",
        keyed: false,
        scope: "the node-configured cells state.nexus and state.pipeline, the rows of world.public_lane_validators that are election-eligible at height one, and the cell runtime.lane_incarnation_lineage, as staged by genesis execution",
        construction: "flat hash of tagged, length-framed canonical projections; the hashing is in crates/iroha_config, under the domain sumeragi:nexus-amx-context",
        witnesses: "none",
        owner: "G.3",
        disposition: "Removed, or retained solely as a genesis comparison value recomputed from canonical entries staged from the signed genesis. All canonical source entries are committed under the keyed State root, with node-configured validity policy moved into protocol State under F.4. It authenticates no State read",
        defect: Some("G1-D3"),
        domains: &[],
        evidence: &[
            (
                "crates/iroha_core/src/sumeragi/genesis_meta.rs",
                "pub fn staged_genesis_nexus_amx_context_hash(staged: &StateBlock<'_>) -> Hash {",
            ),
            (
                "crates/iroha_config/src/parameters/actual.rs",
                "let mut preimage = NexusAmxContextWriterV1::new();",
            ),
            (
                "crates/iroha_data_model/src/block/consensus.rs",
                "pub nexus_amx_context_hash: [u8; 32],",
            ),
            (
                "crates/iroha_core/src/block/native_genesis_policy.rs",
                "let actual_nexus = crate::sumeragi::staged_genesis_nexus_amx_context_hash(state);",
            ),
        ],
    },
    Root {
        id: "da_proof_policy_bundle_hash",
        class: RootClass::ProtocolFingerprint,
        carrier: "BlockHeader.da_proof_policies_hash of every block, with the bundle itself carried in the block payload",
        keyed: false,
        scope: "the DA proof policies that the node-configured cell state.nexus gives for the block height",
        construction: "typed hash of the canonical DA proof-policy bundle; validation derives the bundle from State and compares both the header hash and the carried bundle",
        witnesses: "none",
        owner: "G.3",
        disposition: "Removed, or retained as the hash of the carried DA policy bundle that every validator derives at the block height from committed `state.nexus` policy, checking both the header hash and the carried bundle against that derivation. It authenticates no State read; the source policy follows G1-D3/F.4",
        defect: Some("G1-D3"),
        domains: &[],
        evidence: &[
            (
                "crates/iroha_data_model/src/block/header.rs",
                "pub da_proof_policies_hash: Option<HashOf<DaProofPolicyBundle>>,",
            ),
            (
                "crates/iroha_core/src/block.rs",
                "crate::da::active_proof_policy_bundle_at_height(nexus, block_height);",
            ),
            (
                "crates/iroha_core/src/block.rs",
                "if block.da_proof_policies() != Some(&expected_policy_bundle) {",
            ),
        ],
    },
    Root {
        id: "axt_policy_snapshot",
        class: RootClass::ProtocolFingerprint,
        carrier: "BlockResult.axt_policy_snapshot in the result of every block, with the 64-bit AxtPolicySnapshot.version beside its entries; R binds the result-bearing block wire through ExecutionCommitment.executed_block_wire_hash",
        keyed: false,
        scope: "the AXT policy projection at the post-execution cut: the rows of the derived table world.axt_policies whose target lane serves their dataspace at the block height, or, when none remains, the policies derived from the active manifests of world.space_directory_manifests and the bindings of world.uaid_dataspaces; each row carries the manifest root of the dataspace's active Space Directory manifest, the current slot, and the next handle counter and authorization generation of the canonical table world.axt_handle_counters. Registered sources of the derived table: world.space_directory_manifests, world.axt_handle_counters, runtime.lanes, runtime.lane_incarnation_lineage, state.nexus and state.block_hashes. Block-header context: the block height and the header creation time, which the slot length of state.nexus turns into the current slot",
        construction: "composite summary: the projection itself as bindings in ascending dataspace order, and a 64-bit version, the first eight bytes of an undomained hash of the encoded bindings (zero for no binding). Validation requires the version to equal that hash and compares the whole carried record with the validator's own projection",
        witnesses: "none",
        owner: "G.3",
        disposition: "Removed, or retained solely as an inventoried comparison value: every validator independently derives the complete AXT policy projection at the specified post-execution cut from its registered sources and inventoried block-header context, compares the entire carried snapshot with it, and rejects any difference. Canonical source entries are committed under the keyed State root; historical inputs remain authenticated under §§16.1 and 16.7. Node-configured Nexus policy follows G1-D3/F.4. The apply path rebuilds `world.axt_policies` from those sources or installs the carried copy only after that independent equality check at the applicable source cut; changes to the sources before publication require rederivation. The carried copy never authenticates a State read; consumers requiring State reads use keyed State witnesses. The 64-bit `version` is a telemetry identifier, not a binding digest",
        defect: Some("G1-D11"),
        domains: &[],
        evidence: &[
            (
                "crates/iroha_data_model/src/block/payload.rs",
                "pub axt_policy_snapshot: crate::nexus::AxtPolicySnapshot,",
            ),
            (
                "crates/iroha_data_model/src/nexus/axt.rs",
                "pub fn compute_version(entries: &[AxtPolicyBinding]) -> u64 {",
            ),
            (
                "crates/iroha_core/src/smartcontracts/ivm/host.rs",
                "pub fn axt_policy_snapshot_from_state(state: &impl StateReadOnly) -> Option<AxtPolicySnapshot> {",
            ),
            (
                "crates/iroha_core/src/state.rs",
                "pub(crate) fn project_axt_handle_counters(",
            ),
            (
                "crates/iroha_core/src/block/post_execution_tail.rs",
                "Self::validate_advertised_axt_post_state(advertised_policy, &policy)?;",
            ),
            (
                "crates/iroha_core/src/state/carrier_metadata_preparation.rs",
                "self.replace_axt_policy_projection(snapshot);",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/world.rs",
                "axt_policies: Storage<DataSpaceId, AxtPolicyEntry> => (\"world.axt_policies\",",
            ),
        ],
    },
    Root {
        id: "consensus_authority_binding",
        class: RootClass::ConsensusBinding,
        carrier: "EpochId.context in every Sumeragi core header, vote, QC, timeout vote and timeout certificate; ExecutionResultCommitment.schedule and ExecutionResultCommitment.beacon in the preimage of R; the epoch context identifiers inside the schedule and the beacon pulse; the current and successor ordered-key committee roots of the fixed native X header",
        keyed: false,
        scope: "four members. (1) The epoch context and its exact validator-generation and scheduling-authorization identities: the complete ordered BLS roster, scalar generation, epoch bounds, beacon binding and predecessor. (2) The schedule of R: the current epoch context, the boundary with its immutable E+2 preparation and the two successor slots, embedded as records; the preparation identity binds every frozen election input. (3) The finalized beacon pulse of R, embedded as a record. (4) The fixed native X current and successor committee roots: C3/C4 bind them to the exact ordered keys of the same current/boundary epoch graph. Canonical State sources: world.consensus_schedule for (1) and (2), world.validator_committee_transitions for the frozen preparation, world.global_beacon_pulses for (3); (4) projects those authenticated epoch keys and retains the SCCP generation in world.sccp_committee_generations",
        construction: "(1) domain-separated identities of the canonical context, exact ordered BLS generation and scheduling authorization; (2) the complete frozen preparation has its own domain-separated identity, while the schedule and (3) pulse records are part of the body that R hashes; (4) SCCP committee_root over the original ordered key bytes, checked against that same schedule before the native result can be accepted",
        witnesses: "none over State: votes and certificates bind the epoch context, and R binds the schedule and the pulse. Authority follows signed genesis and authenticated predecessor transitions; it does not depend on a State opening authenticated by the certificate being verified",
        owner: "Sumeragi (specs/sumeragi.md §§3, 4.1, 10)",
        disposition: "kept in its specified role under §§3, 4.1 and 10: the binding authenticates no State read, and its canonical State source entries are also committed by the keyed State root",
        defect: None,
        domains: &[
            r"iroha:native-validator-epoch:v1",
            r"iroha:validator-committee-preparation:v1",
            r"iroha:validator-epoch-authorization:v1",
            r"iroha:validator-generation:v1",
        ],
        evidence: &[
            (
                "crates/iroha_data_model/src/sumeragi/epoch.rs",
                "const EPOCH_DOMAIN: &[u8] = b\"iroha:native-validator-epoch:v1\";",
            ),
            (
                "crates/iroha_data_model/src/sumeragi/epoch/generation.rs",
                "const GENERATION_DOMAIN_V1: &[u8] = b\"iroha:validator-generation:v1\";",
            ),
            (
                "crates/iroha_data_model/src/sumeragi/epoch/authorization.rs",
                "const AUTHORIZATION_DOMAIN_V1: &[u8] = b\"iroha:validator-epoch-authorization:v1\";",
            ),
            (
                "crates/iroha_data_model/src/nexus/committee.rs",
                "let mut bytes = b\"iroha:validator-committee-preparation:v1\".to_vec();",
            ),
            (
                "crates/iroha_data_model/src/sumeragi_finality/certified_result.rs",
                "pub fn context_committee_root(",
            ),
            ("crates/iroha_sumeragi/src/types.rs", "pub context: Hash32,"),
            (
                "crates/iroha_data_model/src/sumeragi_finality/commitment.rs",
                "pub schedule: ScheduleOutcome,",
            ),
            (
                "crates/iroha_data_model/src/sumeragi_finality/commitment.rs",
                "pub beacon: Option<FinalizedGlobalThresholdBeaconPulseV1>,",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/world.rs",
                "consensus_schedule: Cell<crate::sumeragi::schedule::RetainedConsensusSchedule> => (\"world.consensus_schedule\",",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/world.rs",
                "validator_committee_transitions: Storage<u64, iroha_data_model::nexus::ValidatorCommitteeTransitionV1> => (\"world.validator_committee_transitions\",",
            ),
        ],
    },
    Root {
        id: "lane_authority_binding",
        class: RootClass::ConsensusBinding,
        carrier: "LaneResult.next_committee_digest and LaneResult.next_params in the result of every lane block, which lane votes and certificates bind; the genesis hash and the genesis result of every lane incarnation, from which its consensus instance and first result derive",
        keyed: false,
        scope: "the record of one lane incarnation in the world.sumeragi_lanes cell: its pinned committee, chain parameters, DA layout, incarnation and activation",
        construction: "flat domain-separated hashes: the committee digest of the Sumeragi core over the pinned committee keys, and the genesis hash and genesis result of the incarnation over the fields fixed at its creation; the pinned parameters are embedded in the lane result as a record",
        witnesses: "none over State: lane votes and certificates bind the lane result. Lane authority follows the lane record that the global chain committed and the authenticated predecessor results of the lane; it does not depend on a State opening authenticated by the certificate being verified",
        owner: "Sumeragi lanes (specs/sumeragi_lanes.md §§2.3, 3.2)",
        disposition: "kept in its specified role as the authority binding of a lane instance (specs/sumeragi.md §3, specs/sumeragi_lanes.md): the binding authenticates no State read, and its canonical State source, the lane cell, is also committed by the keyed State root",
        defect: None,
        domains: &[
            r"iroha/sumeragi/lane/genesis-result/v1",
            r"iroha/sumeragi/lane/genesis/v1",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/sumeragi/lanes/mod.rs",
                "pub next_committee_digest: [u8; 32],",
            ),
            (
                "crates/iroha_core/src/sumeragi/lanes/mod.rs",
                "next_committee_digest: chain_hash(&committee_digest_preimage(&config.committee)).0,",
            ),
            (
                "crates/iroha_core/src/sumeragi/lanes/mod.rs",
                "pub fn lane_genesis_result(record: &SumeragiLaneRecord) -> Hash32 {",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/world.rs",
                "sumeragi_lanes: Cell<iroha_data_model::sumeragi_lanes::SumeragiLaneState> => (\"world.sumeragi_lanes\",",
            ),
        ],
    },
    Root {
        id: "state_table_substrate",
        class: RootClass::UncertifiedDraft,
        carrier: "none: not published, certified or admitted",
        keyed: true,
        scope: "caller-selected canonical tables read through the exact table catalog",
        construction: "MerkleMap lookup tree paired with an ordered raw-Norito-key digest tree",
        witnesses: "lookup, hashed-key range and raw-key range over scoped rows",
        owner: "G.3",
        disposition: "measured by G.2 as one candidate behind KeyedStateCommitment; deleted unless G.3 selects it as the construction",
        defect: Some("G1-D4"),
        domains: &[
            r"iroha:state-table-substrate:key-payload:v1\0",
            r"iroha:state-table-substrate:paired-root:v1\0",
            r"iroha:state-table-substrate:path:v1\0",
            r"iroha:state-table-substrate:root:v1\0",
            r"iroha:state-table-substrate:schema:field:v1\0",
            r"iroha:state-table-substrate:schema:start:v1\0",
            r"iroha:state-table-substrate:value-payload:v1\0",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/state/authority_registry/leaf.rs",
                "const PAIRED_ROOT: &[u8] = b\"iroha:state-table-substrate:paired-root:v1\\0\";",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/complete/table_capture.rs",
                "const TABLE_MATERIALIZERS: &[TableMaterializer] = &[",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/complete/transaction_membership.rs",
                "//! Same-original-writer capture of both declared membership tables and frontier.",
            ),
        ],
    },
    Root {
        id: "state_canonical_composition_draft",
        class: RootClass::UncertifiedDraft,
        carrier: "none: not published, certified or admitted",
        keyed: false,
        scope: "caller-supplied leaf digests of the canonical fields in declaration order",
        construction: "linear hash fold bound to the registry descriptor",
        witnesses: "none",
        owner: "G.3",
        disposition: "deleted: the keyed commitment binds its own schema descriptor and entries",
        defect: Some("G1-D4"),
        domains: &[
            r"iroha:state-canonical-composition-draft:descriptor-field:v1\0",
            r"iroha:state-canonical-composition-draft:descriptor-finish:v1\0",
            r"iroha:state-canonical-composition-draft:descriptor-start:v1\0",
            r"iroha:state-canonical-composition-draft:field:v1\0",
            r"iroha:state-canonical-composition-draft:finish:v1\0",
            r"iroha:state-canonical-composition-draft:schema:v1\0",
            r"iroha:state-canonical-composition-draft:start:v1\0",
            r"iroha:state-canonical-composition-draft:text:v1\0",
        ],
        evidence: &[(
            "crates/iroha_core/src/state/authority_registry/complete/composition.rs",
            "const START: &[u8] = b\"iroha:state-canonical-composition-draft:start:v1\\0\";",
        )],
    },
    Root {
        id: "state_cell_digest_slice",
        class: RootClass::UncertifiedDraft,
        carrier: "none: a diagnostic capture",
        keyed: false,
        scope: "four native-Norito State cells under one publication counter",
        construction: "one flat domain-separated digest per cell; no aggregate root",
        witnesses: "none",
        owner: "G.3",
        disposition: "deleted: the cells become entries of the keyed State root",
        defect: Some("G1-D4"),
        domains: &[r"iroha:state-cell-slice:bare-v1\0"],
        evidence: &[
            (
                "crates/iroha_core/src/state/authority_registry/cell_snapshot.rs",
                "//! Bounded, non-authorizing capture of four native-Norito State cells.",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/cell_snapshot.rs",
                "const CELL_DOMAIN: &[u8] = b\"iroha:state-cell-slice:bare-v1\\0\";",
            ),
        ],
    },
    Root {
        id: "transaction_membership_root",
        class: RootClass::UncertifiedDraft,
        carrier: "none: compiled for tests only, not published, certified or admitted",
        keyed: true,
        scope: "state.transactions.current and its rollback cut, bound to the committed frontier",
        construction: "MerkleMap over transaction hashes and height digests, with a domain-separated commitment of the current root, the predecessor root and the height",
        witnesses: "authenticated membership and non-membership reads against one cut",
        owner: "G.3",
        disposition: "G.3 commits state.transactions.frontier, current and rollback through the one keyed commitment; this specialized root survives only as an internal component of the selected construction, never as an independently authoritative root, and is deleted otherwise",
        defect: Some("G1-D4"),
        domains: &[
            r"iroha:transaction-membership:height:v1\0",
            r"iroha:transaction-membership:key:v1\0",
            r"iroha:transaction-membership:root:v1\0",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/state/storage_transactions/block/membership_root.rs",
                "const ROOT_DOMAIN: &[u8] = b\"iroha:transaction-membership:root:v1\\0\";",
            ),
            (
                "crates/iroha_core/src/state/storage_transactions.rs",
                "reason = \"TODO: retain authenticated membership roots in the complete State publisher\"",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/complete/transaction_membership.rs",
                "//! its frontier, original surface and both roots together. Those roots cannot",
            ),
        ],
    },
    Root {
        id: "retail_contract_state_map_root",
        class: RootClass::UncertifiedDraft,
        carrier: "none: derived locally for one retail policy query",
        keyed: true,
        scope: "world.smart_contract_state",
        construction: "MerkleMap over physical state paths",
        witnesses: "inclusion only",
        owner: "G.3",
        disposition: "deleted or kept only as a test differential: contract-state value proofs are witnesses against the keyed State root",
        defect: Some("G1-D7"),
        domains: &[
            r"iroha:contract-state:key:v1\0",
            r"iroha:contract-state:value:v1\0",
        ],
        evidence: &[(
            "crates/iroha_core/src/state/retail_contract_state_snapshot.rs",
            "//! generation. Its locally derived map root is not a consensus commitment and",
        )],
    },
    Root {
        id: "world_net_delta_fold",
        class: RootClass::LocalBindingDigest,
        carrier: "none: held in memory by the execution-output owner and the publication comparison surface of one block",
        keyed: false,
        scope: "the before and after values of one block's World changes (the net delta) and its undo journal (the publication delta)",
        construction: "linear hash fold over field identities and value hashes; it shares the bare-value hash domain of the World state root",
        witnesses: "none",
        owner: "State publication owner",
        disposition: "kept as a node-local binding digest: it is never persisted, certified or served and decides no transaction validity; a mismatch is a local publication failure",
        defect: None,
        domains: &[
            r"iroha:world-net-delta:end-field:v1\0",
            r"iroha:world-net-delta:entry:v1\0",
            r"iroha:world-net-delta:executor:v1\0",
            r"iroha:world-net-delta:field:v1\0",
            r"iroha:world-net-delta:finish:v1\0",
            r"iroha:world-net-delta:start:v1\0",
            r"iroha:world-publication-journal:start:v1\0",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/state/world_projection.rs",
                "const FINISH_DOMAIN: &[u8] = b\"iroha:world-net-delta:finish:v1\\0\";",
            ),
            (
                "crates/iroha_core/src/state/output_producer.rs",
                "world_delta: crate::state::world_projection::WorldNetDelta,",
            ),
            (
                "crates/iroha_core/src/state/output_publication.rs",
                "world: block.world.publication_state_delta()?,",
            ),
        ],
    },
    Root {
        id: "lane_incarnation_lineage_digest",
        class: RootClass::LocalBindingDigest,
        carrier: "none outside the node: stored only in Kura's lane-geometry binding records, where it composes into the local geometry transition identity",
        keyed: false,
        scope: "the canonical runtime.lane_incarnation_lineage cell and the network identity",
        construction: "flat hash of the canonical encoding (named a root, it has no tree)",
        witnesses: "none",
        owner: "State lane lifecycle and Kura",
        disposition: "kept as a node-local binding digest of lane storage; the lineage cell itself becomes an entry of the keyed State root; a mismatch is a local storage failure",
        defect: None,
        domains: &[r"iroha:nexus:lane-incarnation-lineage-root:v1\0"],
        evidence: &[
            (
                "crates/iroha_core/src/state/lane_lifecycle_support.rs",
                "pub(crate) fn lane_incarnation_lineage_root(",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/runtime.rs",
                "(\"runtime.lane_incarnation_lineage\",",
            ),
        ],
    },
    Root {
        id: "fastpq_permission_table_root",
        class: RootClass::CertifiedWitnessValue,
        carrier: "perm_root of every FastpqOrdinarySourceStatementLeafV1 under statement_root of the D7 manifest (one fixed-key write under ordinary_writes_root), and perm_root of the FASTPQ public inputs",
        keyed: false,
        scope: "the role, permission and permission-epoch projection of the complete world.roles table (not every byte of a role)",
        construction: "flat BLAKE2b-256 digest of the sorted (role, permission, epoch) entries and their count; zero for an empty table",
        witnesses: "none: contextual public input; the transfer relation establishes no permission membership from it",
        owner: "A.1",
        disposition: "Retained as a certified per-block witness value, not as State-read authority; all canonical source State entries are also committed under the keyed State root, and consumers requiring State reads use keyed State witnesses. A.1 decides whether perm_root remains contextual public input or is replaced by authenticated role reads",
        defect: None,
        domains: &[
            r"fastpq:v1:permission-table:blake2b-256",
            r"iroha:fastpq:permission-context-retention:v1\0",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/fastpq/mod.rs",
                "const PERMISSION_TABLE_ROOT_DOMAIN: &[u8] = b\"fastpq:v1:permission-table:blake2b-256\";",
            ),
            (
                "crates/iroha_core/src/state/fastpq_quantity_capture/commitment_journal/finalized_source.rs",
                "|| block.world.roles.iter(),",
            ),
            (
                "crates/iroha_core/src/state/fastpq_quantity_capture/commitment_journal/finalized_source.rs",
                "perm_root: permission_root,",
            ),
            (
                "crates/iroha_core/src/state.rs",
                ".then(|| crate::fastpq::permission_table_root(state.world.roles.iter()));",
            ),
            (
                "crates/iroha_data_model/src/fastpq/source_statement.rs",
                "pub perm_root: [u8; 32],",
            ),
        ],
    },
    Root {
        id: "validation_fee_policy_snapshot",
        class: RootClass::CertifiedWitnessValue,
        carrier: "ValidationFeePolicySnapshotCommitmentV1: one fixed-key write under ordinary_writes_root",
        keyed: false,
        scope: "the validation-fee policy registry, one custom parameter of the world.parameters cell",
        construction: "flat hashes of the canonical registry and of its head, scheduled and effective policies, or of an invalid registry payload",
        witnesses: "the fixed-key sparse Merkle path of the block's ordinary-write root",
        owner: "G.3",
        disposition: "Retained as a certified per-block witness value, not as State-read authority; all canonical source State entries are also committed under the keyed State root, and consumers requiring State reads use keyed State witnesses",
        defect: None,
        domains: &[r"iroha.validation_fee.registry.snapshot.v1"],
        evidence: &[
            (
                "crates/iroha_core/src/state.rs",
                "iroha_data_model::validation_fee::ValidationFeePolicySnapshotCommitmentV1::from_custom_parameter_state(",
            ),
            (
                "crates/iroha_data_model/src/validation_fee.rs",
                "pub registry_hash: [u8; 32],",
            ),
        ],
    },
    Root {
        id: "parliament_casting_snapshot_root",
        class: RootClass::CertifiedWitnessValue,
        carrier: "ParliamentTimedOvnCastingSnapshotCommitmentV1: one fixed-key write under ordinary_writes_root",
        keyed: false,
        scope: "the authorized timed-OVN casting contexts at one height, derived from world.parliament_attempts, world.timed_ovn_evidence, world.tle_key_sessions and the casting-candidate index",
        construction: "application Merkle root over the ballot-ordered context bindings, with their count",
        witnesses: "membership of one casting context under the snapshot root, served with the fixed-key path of the ordinary-write root: an application statement, not a State read",
        owner: "G.3",
        disposition: "Retained as a certified per-block witness value, not as State-read authority; all canonical source State entries are also committed under the keyed State root, and consumers requiring State reads use keyed State witnesses",
        defect: None,
        domains: &[r"iroha:parliament:timed-ovn:casting-contexts:empty:v1\0"],
        evidence: &[
            (
                "crates/iroha_core/src/tle_release/casting.rs",
                "pub(crate) fn derive_parliament_timed_ovn_casting_snapshot_v1(",
            ),
            (
                "crates/iroha_data_model/src/parliament_casting.rs",
                "/// Canonical application-Merkle root, or the fixed empty-set root when `count` is zero.",
            ),
        ],
    },
    Root {
        id: "sccp_block_message_root",
        class: RootClass::CertifiedWitnessRoot,
        carrier: "the original fixed X carried with the canonical result body and bound by every native commit certificate",
        keyed: false,
        scope: "the ordered transfer/control leaves of this block from world.sccp_block_leaves",
        construction: "canonical SCCP v1 leaf Merkle tree",
        witnesses: "SCCP ordered leaf path under the original sealed X.sccp_root",
        owner: "SCCP native finality",
        disposition: "Retained in its protocol role; it does not authenticate a complete State snapshot or a general State read",
        defect: None,
        domains: &[],
        evidence: &[(
            "crates/iroha_core/src/smartcontracts/isi/sccp/commitment.rs",
            "pub fn commit_block(",
        )],
    },
    Root {
        id: "sccp_certified_history_root",
        class: RootClass::CertifiedWitnessRoot,
        carrier: "the original fixed X carried with the canonical result body and bound by every native commit certificate",
        keyed: false,
        scope: "the exact SCCP history accumulator in world.sccp_history, binding completed block commitments and history size",
        construction: "canonical SCCP v1 history accumulator root",
        witnesses: "SCCP history path plus its block leaf path under original sealed X.history_root",
        owner: "SCCP native finality",
        disposition: "Retained in its protocol role; it does not authenticate a complete State snapshot or a general State read",
        defect: None,
        domains: &[],
        evidence: &[(
            "crates/iroha_core/src/smartcontracts/isi/sccp/commitment.rs",
            "pub fn history_root_and_size(",
        )],
    },
    Root {
        id: "sccp_generation_committee_root",
        class: RootClass::ConsensusBinding,
        carrier: "the original fixed X carried with the canonical result body and bound by every native commit certificate",
        keyed: false,
        scope: "the original authenticated committee keys of world.sccp_committee_generations; the outgoing and optional successor generation at this native height",
        construction: "canonical sorted BLS-normal committee key root under SCCP/COMMITTEE/V1",
        witnesses: "none over State; the original X and authenticated native schedule bind committee authority",
        owner: "SCCP native finality",
        disposition: "Retained in its protocol role; it does not authenticate a complete State snapshot or a general State read",
        defect: None,
        domains: &[],
        evidence: &[(
            "crates/iroha_data_model/src/sumeragi_finality/certified_result.rs",
            "pub fn committee_root(keys:",
        )],
    },
    Root {
        id: "sccp_state_delta_digest",
        class: RootClass::CertifiedWitnessValue,
        carrier: "the height and digest of the SCCP state delta: one fixed-key write under ordinary_writes_root, present when the block changed an SCCP field",
        keyed: false,
        scope: "the block's write set over the world.sccp_* fields: every written key in canonical order with its new value or its deletion",
        construction: "flat hash of the canonical delta bytes",
        witnesses: "the fixed-key sparse Merkle path of the block's ordinary-write root",
        owner: "G.3",
        disposition: "Retained as a certified per-block witness value, not as State-read authority; all canonical source State entries are also committed under the keyed State root, and consumers requiring State reads use keyed State witnesses",
        defect: None,
        domains: &[],
        evidence: &[
            (
                "crates/iroha_core/src/smartcontracts/isi/sccp/witness.rs",
                "pub const SCCP_STATE_DELTA_WITNESS_KEY_V1: &[u8] = b\"\\xd8iroha:sccp:state-delta:v1\";",
            ),
            (
                "crates/iroha_core/src/smartcontracts/isi/sccp/witness.rs",
                "let digest: [u8; 32] = Hash::new(delta).into();",
            ),
        ],
    },
    Root {
        id: "fee_evidence_record_root",
        class: RootClass::CertifiedWitnessValue,
        carrier: "FeeEvidenceSnapshotV1.root with the record count: one fixed-key write under ordinary_writes_root; each record is also a witnessed write",
        keyed: false,
        scope: "the block's fee-evidence records: the reward custody snapshot (custody balances from world.assets, the reward state rows and the fee policy registry) and the fee rows of world.smart_contract_state that the block changed",
        construction: "Merkle root over the hashes of the block's records; a fixed empty value without records",
        witnesses: "membership of one record of the block under the snapshot root",
        owner: "G.3",
        disposition: "Retained as a certified per-block witness value, not as State-read authority; all canonical source State entries are also committed under the keyed State root, and consumers requiring State reads use keyed State witnesses",
        defect: None,
        domains: &[r"iroha.fee_evidence.empty.v1"],
        evidence: &[
            (
                "crates/iroha_core/src/validation_fee_rewards.rs",
                "let mut snapshot = FeeEvidenceSnapshotV1::from_records(height, &records)?;",
            ),
            (
                "crates/iroha_data_model/src/fee_evidence.rs",
                "pub struct FeeEvidenceSnapshotV1 {",
            ),
        ],
    },
    Root {
        id: "retail_fee_receipt_head_root",
        class: RootClass::CertifiedStateRoot,
        carrier: "FeeEvidenceSnapshotV1.account_heads_root: certified through the fee-evidence write under ordinary_writes_root; its tree nodes are rows of world.smart_contract_state",
        keyed: true,
        scope: "the retail fee receipt-head rows of world.smart_contract_state only: the current canonical head of every wallet",
        construction: "compressed sparse Merkle tree of depth 256 over wallet paths, maintained incrementally by execution",
        witnesses: "membership of one wallet's current head: it authenticates an exact canonical head key and value at a checkpoint",
        owner: "G.3",
        disposition: "Replace receipt-head membership proofs with keyed State inclusion witnesses over the canonical head rows in `world.smart_contract_state`, and remove the specialized root and obsolete tree",
        defect: Some("G1-D9"),
        domains: &[r"retail_fee_head_tree_v1/"],
        evidence: &[
            (
                "crates/iroha_core/src/validation_fee_rewards/head_tree.rs",
                "//! Incremental compressed sparse commitment to all current canonical wallet heads.",
            ),
            (
                "crates/iroha_core/src/validation_fee_rewards.rs",
                "snapshot.account_heads_root = head_tree::receipt_head_root(&block.world)?;",
            ),
            (
                "crates/iroha_core/src/validation_fee_rewards/head_tree.rs",
                "pub fn receipt_head_membership(",
            ),
        ],
    },
    Root {
        id: "confidential_spentness_checkpoint_root",
        class: RootClass::UncertifiedDraft,
        carrier: "none: data-model types and a verifier only; no node code computes the root",
        keyed: true,
        scope: "the spent or unspent status of one privacy nullifier per confidential asset",
        construction: "depth-256 sparse Poseidon tree over nullifiers, with checkpoint digests chained to finalized block hashes",
        witnesses: "point proof for one nullifier",
        owner: "G.3",
        disposition: "deleted or replaced by keyed State inclusion and absence witnesses over the nullifier entries: a commitment that independently authenticates canonical State entries is a per-table State root (rule P1); no producer exists today",
        defect: Some("G1-D4"),
        domains: &[
            r"confidential-asset-spentness-v1",
            r"poseidon-x7-goldilocks-digest384-sparse-depth256-v1",
        ],
        evidence: &[
            (
                "crates/iroha_data_model/src/confidential/spentness.rs",
                "//! Permanent sparse spentness checkpoints for confidential assets.",
            ),
            (
                "crates/iroha_data_model/src/confidential/spentness.rs",
                "const CONFIDENTIAL_SPENTNESS_PROTOCOL_ID_V1: &[u8] = b\"confidential-asset-spentness-v1\";",
            ),
        ],
    },
    Root {
        id: "pipeline_durable_state_fingerprint",
        class: RootClass::LocalBindingDigest,
        carrier: "none: held in memory by the pipeline overlay cache",
        keyed: false,
        scope: "all rows of world.smart_contract_state, or the rows under the prefixes that one overlay read",
        construction: "flat SHA-256 digest of length-framed paths and values",
        witnesses: "none",
        owner: "IVM pipeline overlay cache",
        disposition: "kept as a node-local cache-validity digest: a cached overlay is reused only while the fingerprint of the rows it read is unchanged; it is never stored, carried or certified",
        defect: None,
        domains: &[r"iroha:durable-state-read-snapshot:v1"],
        evidence: &[(
            "crates/iroha_core/src/pipeline/overlay.rs",
            "fn durable_state_prefix_fingerprint<R>(prefixes: Option<&[StatePath]>, state_ro: &R) -> [u8; 32]",
        )],
    },
    Root {
        id: "state_snapshot_chunk_root",
        class: RootClass::LocalBindingDigest,
        carrier: "the Merkle metadata and the node-signed bundle digest stored beside a local State snapshot file",
        keyed: false,
        scope: "the bytes of one serialized State snapshot file",
        construction: "SHA-256 Merkle tree over fixed-size file chunks",
        witnesses: "none for State: chunk proofs authenticate bytes of the local snapshot file",
        owner: "Snapshot service",
        disposition: "kept as node-local file integrity of a snapshot artifact: chunk proofs authenticate snapshot file bytes, never a State read, and the root enters no protocol-authenticated root or State witness",
        defect: None,
        domains: &[r"iroha:snapshot-bundle:v1\0"],
        evidence: &[
            (
                "crates/iroha_core/src/snapshot.rs",
                "/// Hex-encoded Merkle root over the chunk digests.",
            ),
            (
                "crates/iroha_core/src/snapshot.rs",
                "const SNAPSHOT_BUNDLE_SIGNATURE_DOMAIN: &[u8] = b\"iroha:snapshot-bundle:v1\\0\";",
            ),
        ],
    },
    Root {
        id: "sorafs_reputation_archive_digest",
        class: RootClass::LocalBindingDigest,
        carrier: "records of the node-local durable SoraFS reputation archive",
        keyed: false,
        scope: "the finalized SoraFS reputation projection of State at one anchor: the reserve-provider state, the journal, proof, repair, order-book and reserve feeds and the authority policies",
        construction: "flat domain-separated digests of canonical projection records and feed prefixes, chained through the anchor manifests",
        witnesses: "none",
        owner: "SoraFS reputation query archive",
        disposition: "kept as node-local archive binding: the archive is a projection store and no finality authority; a mismatch is a local archive failure",
        defect: None,
        domains: &[
            r"iroha.sorafs.reputation.finalized-anchor-delta.v1\0",
            r"iroha.sorafs.reputation.finalized-anchor-manifest.v1\0",
            r"iroha.sorafs.reputation.finalized-anchor-prefix.v1\0",
            r"iroha.sorafs.reputation.finalized-anchor-record.v1\0",
            r"iroha.sorafs.reputation.finalized-archive-key.v1\0",
            r"iroha.sorafs.reputation.finalized-checkpoint-validation.v1\0",
            r"iroha.sorafs.reputation.finalized-journal-prefix-source-head-root.v1\0",
            r"iroha.sorafs.reputation.finalized-journal-prefix.v1\0",
            r"iroha.sorafs.reputation.finalized-orderbook-prefix.v1\0",
            r"iroha.sorafs.reputation.finalized-policy-history.v1\0",
            r"iroha.sorafs.reputation.finalized-policy-record.v1\0",
            r"iroha.sorafs.reputation.finalized-proof-prefix.v1\0",
            r"iroha.sorafs.reputation.finalized-provider-state-root.v1\0",
            r"iroha.sorafs.reputation.finalized-repair-prefix.v1\0",
            r"iroha.sorafs.reputation.finalized-reserve-prefix.v1\0",
            r"iroha.sorafs.reputation.finalized-retention-approval.v1\0",
            r"iroha.sorafs.reputation.finalized-retention-checkpoint-bytes.v1\0",
            r"iroha.sorafs.reputation.finalized-retention-proposal.v1\0",
            r"iroha.sorafs.reputation.finalized-virtual-base-checkpoint.v1\0",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/query/reputation_finalized.rs",
                "//! Durable exact-anchor archive for finalized SoraFS reputation projections.",
            ),
            (
                "crates/iroha_core/src/query/reputation_finalized.rs",
                "fn reserve_provider_state_root(",
            ),
        ],
    },
    Root {
        id: "sorafs_provider_ingest_archive_digest",
        class: RootClass::LocalBindingDigest,
        carrier: "records of the node-local durable SoraFS provider-ingest archive",
        keyed: false,
        scope: "the finalized provider-indexed replication-order projection of State at one height",
        construction: "flat domain-separated digests of canonical projection records, each linking the preceding height and committing the complete provider-indexed state",
        witnesses: "none",
        owner: "SoraFS provider-ingest query archive",
        disposition: "kept as node-local archive binding: the archive is a committed projection and never a source of finality or mutation authority; a mismatch is a local archive failure",
        defect: None,
        domains: &[
            r"iroha.sorafs.provider-ingest.finalized-archive-checkpoint.v1\0",
            r"iroha.sorafs.provider-ingest.finalized-archive-key.v1\0",
            r"iroha.sorafs.provider-ingest.finalized-archive-prefix.v1\0",
            r"iroha.sorafs.provider-ingest.finalized-archive-record.v1\0",
            r"iroha.sorafs.provider-ingest.finalized-archive-retention-approval.v1\0",
            r"iroha.sorafs.provider-ingest.finalized-archive-retention-checkpoint-bytes.v1\0",
            r"iroha.sorafs.provider-ingest.finalized-archive-retention-proposal.v1\0",
            r"iroha.sorafs.provider-ingest.finalized-provider-state.first-release.v1\0",
            r"iroha.sorafs.provider-ingest.finalized-provider-state.v1\0",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/query/provider_ingest_finalized.rs",
                "//! Durable provider-indexed archive for finalized SoraFS replication orders.",
            ),
            (
                "crates/iroha_core/src/query/provider_ingest_finalized.rs",
                "const STATE_ROOT_DOMAIN_V1: &[u8] =",
            ),
        ],
    },
    Root {
        id: "kura_lane_geometry_binding",
        class: RootClass::LocalBindingDigest,
        carrier: "none outside the node: Kura's lane-geometry journal and binding records",
        keyed: false,
        scope: "Kura's lane geometry bindings, which follow the lane catalog and the lane incarnations of the canonical runtime (runtime.lanes), composed with the lineage digest into the geometry transition identity",
        construction: "flat hash of the canonical binding list, and a flat transition identity over the catalog and lineage digests",
        witnesses: "none",
        owner: "Kura lane geometry",
        disposition: "kept as a node-local catalog binding of lane storage; the lane catalog itself becomes an entry of the keyed State root; a mismatch is a local storage failure",
        defect: None,
        domains: &[
            r"iroha:kura:lane-geometry-catalog:v1\0",
            r"iroha:kura:lane-geometry-transition:v4\0",
            r"iroha:kura:lane-geometry-unscoped-lineage:v1\0",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/kura/lane_geometry.rs",
                "const CATALOG_DOMAIN: &[u8] = b\"iroha:kura:lane-geometry-catalog:v1\\0\";",
            ),
            (
                "crates/iroha_core/src/kura/lane_geometry/catalog_validation.rs",
                "Hash::new_from_chunks(&[CATALOG_DOMAIN, encoded.as_slice()])",
            ),
        ],
    },
    Root {
        id: "tiered_backend_row_hashes",
        class: RootClass::LocalBindingDigest,
        carrier: "TieredManifestEntry.key_hash_hex and value_hash_hex in the snapshot manifests of the tiered State backend",
        keyed: false,
        scope: "the encoded key and the encoded value of each World row that the tiered backend snapshots: two separate hashes per row, no aggregate over a table",
        construction: "separate undomained SHA-256 hashes of one row's key bytes and of its value bytes",
        witnesses: "none",
        owner: "Tiered State backend",
        disposition: "kept as node-local per-row change detection and spill-file integrity of the tiered backend: the hashes authenticate only local artifacts, never State reads or transaction validity; a mismatch is a local storage failure",
        defect: None,
        domains: &[],
        evidence: &[
            (
                "crates/iroha_core/src/state/tiered.rs",
                "pub struct TieredManifestEntry {",
            ),
            (
                "crates/iroha_core/src/state/tiered.rs",
                "key_hash_hex: String,",
            ),
            (
                "crates/iroha_core/src/state/tiered.rs",
                "value_hash_hex: String,",
            ),
            (
                "crates/iroha_core/src/state/tiered.rs",
                "out.copy_from_slice(&Sha256::digest(bytes));",
            ),
        ],
    },
    Root {
        id: "query_projection_payload_hash",
        class: RootClass::LocalBindingDigest,
        carrier: "QueryProjectionShardArchive.payload_hash, the payload hash of its DA upload and the shard references (blob_hash) of the query-projection checkpoint in the node-local checkpoint journal",
        keyed: false,
        scope: "the rowset of one query-projection partition at one indexed height, and the compressed archive that carries it",
        construction: "undomained BLAKE3 hash of the rowset bytes, and undomained BLAKE3 hash of the compressed archive (the DA blob)",
        witnesses: "none",
        owner: "Query projection store",
        disposition: "kept as node-local integrity of projection archives: the hashes authenticate only local artifacts, never State reads or transaction validity. The projection worker that would produce the archives is still pending",
        defect: None,
        domains: &[],
        evidence: &[
            (
                "crates/iroha_core/src/query/projection_shard.rs",
                "//! The projection worker itself is still pending, but the shard payload shape, deterministic blob",
            ),
            (
                "crates/iroha_core/src/query/projection_shard.rs",
                "payload_hash: BlobDigest::from_hash(blake3::hash(&payload)),",
            ),
            (
                "crates/iroha_core/src/query/projection_checkpoint.rs",
                "let computed_payload_hash = BlobDigest::from_hash(blake3::hash(&archive.payload));",
            ),
            (
                "crates/iroha_core/src/query/projection_checkpoint.rs",
                "pub blob_hash: BlobDigest,",
            ),
        ],
    },
    Root {
        id: "private_settlement_test_network_evidence",
        class: RootClass::LocalBindingDigest,
        carrier: "PrivateSettlementLedgerEvidenceV1.commitment and PrivateSettlementReplicatedStagedLockEvidenceV1.commitment, returned to a test-network observer",
        keyed: false,
        scope: "two commitments: the seven-table ledger evidence over world.private_settlement_governance, pools, roots, nullifiers, outputs, receipts and aborts with their counts, and the replicated staged-lock evidence over world.private_settlement_staged_locks with its count",
        construction: "flat domain-separated hashes of the canonical encodings of the complete tables and their counts",
        witnesses: "none",
        owner: "private-settlement test-network evidence (non-shipping feature)",
        disposition: "kept as a test observation compiled only under cfg(any(test, feature = \"test-network-private-settlement-evidence\")): shipping builds do not compile it; it authenticates only test observations, never State reads or transaction validity",
        defect: None,
        domains: &[
            r"iroha:test-network:private-settlement:ledger-evidence:v1\0",
            r"iroha:test-network:private-settlement:replicated-staged-lock-evidence:v1\0",
        ],
        evidence: &[
            (
                "crates/iroha_core/src/state.rs",
                "fn private_settlement_ledger_evidence_commitment_v1(",
            ),
            (
                "crates/iroha_core/src/state.rs",
                "fn private_settlement_replicated_staged_lock_commitment_v1(",
            ),
            (
                "crates/iroha_core/src/state.rs",
                "#[cfg(any(test, feature = \"test-network-private-settlement-evidence\"))]",
            ),
        ],
    },
];

/// Listed commitments that no detector of the scan reports: each has no domain literal
/// of the recognized form, no counted construction, no listed carrier or witness value
/// type, and no function with a State or World reader in its signature returns it. A
/// review found them; a new digest of this kind is not detected.
const REVIEW_ONLY_ROOTS: &[(&str, &str)] = &[(
    "tiered_backend_row_hashes",
    "undomained SHA-256 of row bytes inside the tiered backend, which reads storage rows and takes no State or World reader",
)];

/// Sources that the scan reads: every Rust source of the two crates. Test sources
/// ([`is_test_source`]) are skipped: they define no production commitment.
const SCAN_SCOPE: &[&str] = &["crates/iroha_core/src", "crates/iroha_data_model/src"];

/// This file and its table of exact literals quote domain literals, so the scan skips them.
const SELF_PATHS: &[&str] = &[
    "crates/iroha_core/src/state/state_table_inventory_tests.rs",
    "crates/iroha_core/src/state/state_table_inventory_domains.rs",
];

/// Identifiers that mark a use of a Merkle, sparse-Merkle, multiset or accumulator
/// construction. They are counted in code only: comments and string literals do not count.
const CONSTRUCTIONS: &[&str] = &[
    "MerkleMap",
    "MerkleTree",
    "WORLD_STATE_ACCUMULATOR_LANES",
    "smt::",
    "ConfidentialTree",
    "HistoryAccumulator",
    "anchor_node",
];

/// File-name endings of path literals, which are not domain literals.
const PATH_ENDINGS: &[&str] = &[".json", ".to", ".bin", ".md", ".rs", ".toml", ".ko", ".txt"];

/// The rule that decides which string literals the scan treats as domain literals.
const DOMAIN_LITERAL_RULE: &str = "a string or byte-string literal outside comments, read as written, that (a) starts with iroha: or iroha/, or (b) starts with 'iroha ' and has a version segment, or (c) has a version segment (v or V followed by digits, delimited by non-alphanumeric characters) and one of the separators : / . | - ; literals with whitespace (except b), with any of {}<>()[]=!?,;'\" or with ::, and path literals (leading . or /, or a file-name ending) are not domain literals";

/// The exclusion rule of application accumulators (`specs/sumeragi.md` §16.8).
const ACCUMULATOR_RULE: &str = "An application accumulator is maintained by deterministic execution over application records; its authoritative root and canonical persisted data are committed as State values by the keyed State root, and its proofs establish application statements without substituting for keyed State inclusion, absence or complete-range witnesses.";

/// An accumulator that execution maintains over application records and stores in State.
struct ApplicationAccumulator {
    id: &'static str,
    /// The State fields that hold its root and its persisted data.
    fields: &'static [&'static str],
    /// The application statement that its proofs establish.
    statement: &'static str,
    /// The exact domain literals of the scanned sources that belong to it, as written.
    domains: &'static [&'static str],
    evidence: &'static [(&'static str, &'static str)],
}

/// Every application accumulator that the scan detects by a domain literal, by a
/// construction use or by a function that reads State and returns its root. They are
/// excluded from [`ROOTS`] under [`ACCUMULATOR_RULE`]; a
/// commitment that independently authenticates canonical State entries is not one of them
/// (rule P1) and is listed under [`ROOTS`] instead, as `retail_fee_receipt_head_root` is.
const APPLICATION_ACCUMULATORS: &[ApplicationAccumulator] = &[
    ApplicationAccumulator {
        id: "confidential_note_tree",
        fields: &["world.zk_assets"],
        statement: "membership of a note commitment under a retained root of one confidential asset, proved inside confidential transfer and unshield proofs",
        domains: &[],
        evidence: &[
            (
                "crates/iroha_core/src/state/zk_asset_state.rs",
                "/// Current root authenticated by the incremental frontier and retained history.",
            ),
            (
                "crates/iroha_core/src/state.rs",
                "pub enum ConfidentialTreeProfile {",
            ),
        ],
    },
    // Canonical model hashing, original Core publication and borrowed anchor lookup share
    // one accumulator. Its primitive domains and construction are both inside the scan.
    ApplicationAccumulator {
        id: "sccp_anchor_accumulator",
        fields: &["world.sccp_anchor_open", "world.sccp_anchor_chunks"],
        statement: "membership of one nonzero height's original consensus core hash and certified result in a retained complete 4096-anchor chunk, checked against its State-committed chunk root; neither a supplied witness nor the accumulator authenticates arbitrary State entries",
        domains: &[r"sccp/anchor-leaf/v1", r"sccp/anchor-node/v1"],
        evidence: &[
            (
                "crates/iroha_core/src/smartcontracts/isi/sccp/hook.rs",
                "fn prepare_anchor<'a>(",
            ),
            (
                "crates/iroha_data_model/src/sccp/generation.rs",
                "pub fn anchor_chunk_root_v1(",
            ),
            (
                "crates/iroha_core/src/smartcontracts/isi/sccp/anchors.rs",
                "pub fn lookup_anchor(",
            ),
            (
                "crates/iroha_core/src/smartcontracts/isi/sccp/hook.rs",
                ".try_insert_admitted(chunk, root)",
            ),
        ],
    },
    ApplicationAccumulator {
        id: "sccp_message_accumulator",
        fields: &[
            "world.sccp_block_leaves",
            "world.sccp_block_commitments",
            "world.sccp_history",
            "world.sccp_history_leaves",
        ],
        statement: "inclusion of an SCCP message leaf in its block root and of that block root in the history accumulator; these roots are the native finality X fields, with certified-result production and reader binding required separately",
        domains: &[],
        evidence: &[(
            "crates/iroha_core/src/smartcontracts/isi/sccp/commitment.rs",
            "//! Block commitment and history accumulator (`specs/sccp.md` §3.4, §3.5, §4.5 step 1).",
        )],
    },
    ApplicationAccumulator {
        id: "kaigi_roster_root",
        fields: &["world.domains"],
        statement: "membership of a participant commitment in the roster of one Kaigi call, whose record is domain metadata, proved inside Kaigi roster proofs",
        domains: &[
            r"iroha:kaigi:roster:empty:v1\x00",
            r"iroha:kaigi:roster:leaf:v1\x00",
        ],
        evidence: &[(
            "crates/iroha_data_model/src/kaigi.rs",
            "fn compute_roster_root_from(commitments: &[KaigiParticipantCommitment]) -> Hash {",
        )],
    },
    ApplicationAccumulator {
        id: "privacy_roots",
        fields: &["world.privacy_roots", "world.privacy_root_heads"],
        statement: "membership of a privacy commitment or account state under a published privacy root, proved inside privacy-engine proofs",
        domains: &[
            r"iroha.privacy.monero-fcmp-plus-plus.root-commitment.v1",
            r"iroha:privacy:pgc-account-state-root:v1",
            r"iroha:privacy:root-publication:v1",
        ],
        evidence: &[(
            "crates/iroha_data_model/src/privacy.rs",
            "/// Domain separator for core's deterministic PGC account-state root derivation.",
        )],
    },
    ApplicationAccumulator {
        id: "private_settlement_pool_roots",
        fields: &[
            "world.private_settlement_pools",
            "world.private_settlement_roots",
        ],
        statement: "membership of a private-settlement note commitment under a retained root of one settlement pool, proved inside private-settlement proofs",
        domains: &[],
        evidence: &[
            (
                "crates/iroha_core/src/private_settlement/state.rs",
                "pub(crate) struct PrivateSettlementPoolStateV1 {",
            ),
            (
                "crates/iroha_core/src/private_settlement/state.rs",
                "let frontier = build_proof_managed_frontier_v1(namespace, initial_commitments)",
            ),
            (
                "crates/iroha_core/src/state.rs",
                "pub fn private_settlement_pool_head_v1(",
            ),
        ],
    },
];

/// What owns the construction uses of one source.
#[derive(Clone, Copy, Debug)]
enum UseOwner {
    /// Listed commitments.
    Roots(&'static [&'static str]),
    /// A listed application accumulator.
    Accumulator(&'static str),
    /// Another use, with the reason it is not a commitment over State content.
    Other(Use, &'static str),
}

/// The construction uses of one source: the exact number of occurrences of each
/// construction identifier in its code, and their owner. A changed count fails the check,
/// so a construction added to an approved source is reviewed again.
struct ConstructionUse {
    path: &'static str,
    uses: &'static [(&'static str, usize)],
    owner: UseOwner,
}

/// Every non-test source of the two crates that uses a commitment construction.
const CONSTRUCTION_USES: &[ConstructionUse] = &[
    ConstructionUse {
        path: "crates/iroha_core/src/block.rs",
        uses: &[("MerkleTree", 7)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle trees of a block's transaction entrypoints and results: block content bound by the header and by R's input and output commitments",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/block/valid/admission_batching.rs",
        uses: &[("MerkleTree", 1)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle trees of a block's transaction entrypoints and results: block content bound by the header and by R's input and output commitments",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/exec_witness.rs",
        uses: &[("smt::", 1)],
        owner: UseOwner::Roots(&["execution_witness_roots"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/exec_witness/roots.rs",
        uses: &[("smt::", 1)],
        owner: UseOwner::Roots(&["execution_witness_roots"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/kagemusha_wallet_v1/event_evidence.rs",
        uses: &[("MerkleTree", 7)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Counted Merkle paths of the original pre-seal block event stream, retained by receipt identity and authenticated against R's event commitment; not a State-content root or independent finality authority",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/pipeline/zk_lane.rs",
        uses: &[("MerkleTree", 1)],
        owner: UseOwner::Other(Use::Test, "Root-typed fixture of the inline ZK-lane tests"),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/query/native_receipts.rs",
        uses: &[("MerkleTree", 2)],
        owner: UseOwner::Roots(&["parliament_casting_snapshot_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/receiver_snapshot.rs",
        uses: &[("MerkleTree", 2), ("smt::", 5)],
        owner: UseOwner::Roots(&["execution_witness_roots"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/smartcontracts/isi/sccp/commitment.rs",
        uses: &[("HistoryAccumulator", 3)],
        owner: UseOwner::Accumulator("sccp_message_accumulator"),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/smartcontracts/isi/sccp/hook.rs",
        uses: &[("HistoryAccumulator", 2)],
        owner: UseOwner::Roots(&["sccp_certified_history_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/smartcontracts/isi/sccp/read/history/funded.rs",
        uses: &[("HistoryAccumulator", 2)],
        owner: UseOwner::Accumulator("sccp_message_accumulator"),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/smartcontracts/isi/sccp/witness.rs",
        uses: &[("smt::", 1)],
        owner: UseOwner::Roots(&["sccp_state_delta_digest"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/smartcontracts/isi/tx.rs",
        uses: &[("MerkleTree", 2)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle trees of a block's transaction entrypoints and results: block content bound by the header and by R's input and output commitments",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/smartcontracts/isi/world.rs",
        uses: &[("ConfidentialTree", 2)],
        owner: UseOwner::Accumulator("confidential_note_tree"),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/smartcontracts/ivm/host.rs",
        uses: &[("ConfidentialTree", 2)],
        owner: UseOwner::Accumulator("confidential_note_tree"),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/snapshot.rs",
        uses: &[("MerkleTree", 7)],
        owner: UseOwner::Roots(&["state_snapshot_chunk_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state.rs",
        uses: &[("ConfidentialTree", 3)],
        owner: UseOwner::Accumulator("confidential_note_tree"),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/authority_registry/leaf.rs",
        uses: &[("MerkleMap", 20)],
        owner: UseOwner::Roots(&["state_table_substrate"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/output_capacity.rs",
        uses: &[("MerkleTree", 2)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle commitment of a block's execution outputs: block content bound by R's output commitment, not State content",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/output_producer.rs",
        uses: &[("MerkleTree", 2)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle commitment of a block's network inputs: block content bound by R's input commitment, not State content",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/output_seal.rs",
        uses: &[("MerkleTree", 1)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle commitment of a block's network inputs: block content bound by R's input commitment, not State content",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/output_source.rs",
        uses: &[("MerkleTree", 1)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle commitment of a block's network inputs: block content bound by R's input commitment, not State content",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/retail_contract_state_snapshot.rs",
        uses: &[("MerkleMap", 3)],
        owner: UseOwner::Roots(&["retail_contract_state_map_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/storage_transactions/block/membership_append.rs",
        uses: &[("MerkleMap", 13)],
        owner: UseOwner::Roots(&["transaction_membership_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/storage_transactions/block/membership_record.rs",
        uses: &[("MerkleMap", 11)],
        owner: UseOwner::Roots(&["transaction_membership_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/storage_transactions/block/membership_root.rs",
        uses: &[("MerkleMap", 24)],
        owner: UseOwner::Roots(&["transaction_membership_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/tiered.rs",
        uses: &[("ConfidentialTree", 2), ("MerkleTree", 3)],
        owner: UseOwner::Other(
            Use::LocalArtifact,
            "Byte accounting of stored Merkle and confidential-tree values in the tiered backend: these uses build no tree. The per-row SHA-256 hashes that the same source persists are listed as tiered_backend_row_hashes",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/state/zk_asset_state.rs",
        uses: &[("ConfidentialTree", 7)],
        owner: UseOwner::Accumulator("confidential_note_tree"),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/sumeragi/commitment.rs",
        uses: &[("MerkleTree", 7), ("smt::", 1)],
        owner: UseOwner::Roots(&["execution_witness_roots"]),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/telemetry.rs",
        uses: &[("ConfidentialTree", 5)],
        owner: UseOwner::Accumulator("confidential_note_tree"),
    },
    ConstructionUse {
        path: "crates/iroha_core/src/validation_fee_rewards/head_tree.rs",
        uses: &[("smt::", 2)],
        owner: UseOwner::Roots(&["retail_fee_receipt_head_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/block/builder.rs",
        uses: &[("MerkleTree", 3)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle trees of a block's transaction entrypoints and results: block content bound by the header and by R's input and output commitments",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/block/header.rs",
        uses: &[("MerkleTree", 13)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle trees of a block's transaction entrypoints and results: block content bound by the header and by R's input and output commitments",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/block/mod.rs",
        uses: &[("MerkleTree", 3)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle trees of a block's transaction entrypoints and results: block content bound by the header and by R's input and output commitments",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/block/native_results.rs",
        uses: &[("MerkleTree", 2)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle trees of a block's transaction entrypoints and results: block content bound by the header and by R's input and output commitments",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/block/payload.rs",
        uses: &[("MerkleTree", 7)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle trees of a block's transaction entrypoints and results: block content bound by the header and by R's input and output commitments",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/block/proofs.rs",
        uses: &[("MerkleTree", 36)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle trees of a block's transaction entrypoints and results: block content bound by the header and by R's input and output commitments",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/block/proposal.rs",
        uses: &[("MerkleTree", 1)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle trees of a block's transaction entrypoints and results: block content bound by the header and by R's input and output commitments",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/bridge.rs",
        uses: &[("MerkleTree", 3)],
        owner: UseOwner::Other(Use::Test, "Fixtures of the inline bridge-proof tests"),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/contract_state_proof.rs",
        uses: &[("MerkleMap", 15)],
        owner: UseOwner::Roots(&["retail_contract_state_map_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/fastpq/source_statement.rs",
        uses: &[("MerkleTree", 15)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle root of the block's source-statement leaves (the D7 manifest); each leaf carries perm_root, which is listed as fastpq_permission_table_root",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/fee_evidence.rs",
        uses: &[("MerkleTree", 5)],
        owner: UseOwner::Roots(&["fee_evidence_record_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/kagemusha/kagemusha_wallet_v1/load_finality.rs",
        uses: &[("MerkleTree", 1)],
        owner: UseOwner::Other(
            Use::Test,
            "Shape-only native Load finality roundtrip fixture; its single event tree supplies a test proof and grants no State or finality authority",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/kaigi.rs",
        uses: &[("MerkleTree", 2)],
        owner: UseOwner::Accumulator("kaigi_roster_root"),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/lib.rs",
        uses: &[("MerkleTree", 1)],
        owner: UseOwner::Other(Use::Name, "Prelude re-export of the Merkle tree type"),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/nexus/privacy.rs",
        uses: &[("MerkleTree", 2)],
        owner: UseOwner::Other(Use::Test, "Fixtures of the inline lane-privacy tests"),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/parliament_casting.rs",
        uses: &[("MerkleTree", 7)],
        owner: UseOwner::Roots(&["parliament_casting_snapshot_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/sccp/generation.rs",
        uses: &[("anchor_node", 4)],
        owner: UseOwner::Accumulator("sccp_anchor_accumulator"),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/sumeragi_finality.rs",
        uses: &[("WORLD_STATE_ACCUMULATOR_LANES", 1)],
        owner: UseOwner::Roots(&["world_state_root"]),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/sumeragi_finality/commitment.rs",
        uses: &[("MerkleTree", 6)],
        owner: UseOwner::Other(
            Use::BlockContent,
            "Merkle commitments of the block's events, network inputs and typed outputs carried in R",
        ),
    },
    ConstructionUse {
        path: "crates/iroha_data_model/src/sumeragi_finality/world_state.rs",
        uses: &[("WORLD_STATE_ACCUMULATOR_LANES", 6)],
        owner: UseOwner::Roots(&["world_state_root"]),
    },
];

/// Repository-relative paths of every Rust source under `scope`, sorted.
fn rust_sources(scope: &[&str]) -> Vec<String> {
    fn walk(root: &Path, relative: &str, out: &mut Vec<String>) {
        let path = root.join(relative);
        if path.is_file() {
            if relative.ends_with(".rs") {
                out.push(relative.to_owned());
            }
            return;
        }
        let entries =
            std::fs::read_dir(&path).unwrap_or_else(|error| panic!("read {relative}: {error}"));
        for entry in entries {
            let name = entry.expect("a directory entry").file_name();
            let name = name.to_str().expect("source names are UTF-8");
            walk(root, &format!("{relative}/{name}"), out);
        }
    }
    let root = repository();
    let mut out = Vec::new();
    for entry in scope {
        walk(&root, entry, &mut out);
    }
    out.sort();
    out.dedup();
    out
}

/// Whether a source holds only test code.
fn is_test_source(path: &str) -> bool {
    path.ends_with("_tests.rs")
        || path.ends_with("/tests.rs")
        || path.contains("/tests/")
        || path.ends_with("/test_fixtures.rs")
}

/// Split a Rust source into its string and byte-string literals, as written (escapes are
/// not interpreted), and its code without comments and without literal contents.
fn split_source(text: &str) -> (Vec<&str>, String) {
    let bytes = text.as_bytes();
    let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut literals = Vec::new();
    let mut code = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let rest = &bytes[at..];
        if rest.starts_with(b"//") {
            at += rest
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(rest.len());
            continue;
        }
        if rest.starts_with(b"/*") {
            let mut depth = 1_usize;
            at += 2;
            while at < bytes.len() && depth > 0 {
                if bytes[at..].starts_with(b"/*") {
                    depth += 1;
                    at += 2;
                } else if bytes[at..].starts_with(b"*/") {
                    depth -= 1;
                    at += 2;
                } else {
                    at += 1;
                }
            }
            continue;
        }
        match bytes[at] {
            b'\'' => {
                if bytes.get(at + 1) == Some(&b'\\') {
                    // An escaped character literal: its closing quote follows the escape.
                    let from = (at + 3).min(bytes.len());
                    at = bytes[from..]
                        .iter()
                        .position(|byte| *byte == b'\'')
                        .map_or(bytes.len(), |found| from + found + 1);
                    continue;
                }
                let width = text[at + 1..].chars().next().map_or(1, char::len_utf8);
                if bytes.get(at + 1 + width) == Some(&b'\'') {
                    // A character literal.
                    at += width + 2;
                    continue;
                }
                // A lifetime.
                code.push(b'\'');
                at += 1;
            }
            b'r' if at == 0
                || !is_identifier(bytes[at - 1])
                || (bytes[at - 1] == b'b' && (at < 2 || !is_identifier(bytes[at - 2]))) =>
            {
                let hashes = bytes[at + 1..]
                    .iter()
                    .take_while(|byte| **byte == b'#')
                    .count();
                let open = at + 1 + hashes;
                if bytes.get(open) != Some(&b'"') {
                    code.push(b'r');
                    at += 1;
                    continue;
                }
                let body = open + 1;
                let mut end = body;
                let closed = loop {
                    match bytes[end..].iter().position(|byte| *byte == b'"') {
                        None => break None,
                        Some(found) => {
                            let quote = end + found;
                            let tail = &bytes[quote + 1..];
                            if tail.len() >= hashes && tail[..hashes].iter().all(|b| *b == b'#') {
                                break Some(quote);
                            }
                            end = quote + 1;
                        }
                    }
                };
                match closed {
                    Some(quote) => {
                        literals.push(&text[body..quote]);
                        at = quote + 1 + hashes;
                    }
                    None => at = bytes.len(),
                }
            }
            b'"' => {
                let body = at + 1;
                let mut end = body;
                while end < bytes.len() && bytes[end] != b'"' {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                let end = end.min(bytes.len());
                literals.push(&text[body..end]);
                at = end + 1;
            }
            other => {
                code.push(other);
                at += 1;
            }
        }
    }
    (
        literals,
        String::from_utf8(code).expect("code between ASCII delimiters is UTF-8"),
    )
}

/// The alphanumeric segments of a literal.
fn segments(literal: &str) -> impl Iterator<Item = &str> {
    literal
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|segment| !segment.is_empty())
}

/// Whether a literal has a version segment: `v` or `V` followed by digits only.
fn has_version_segment(literal: &str) -> bool {
    segments(literal).any(|segment| {
        segment.len() > 1
            && (segment.starts_with('v') || segment.starts_with('V'))
            && segment[1..].bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// Whether the scan treats a literal as a domain literal ([`DOMAIN_LITERAL_RULE`]).
fn is_domain_literal(literal: &str) -> bool {
    if literal.contains("::") {
        return false;
    }
    if literal.contains(char::is_whitespace) {
        return literal.starts_with("iroha ") && has_version_segment(literal);
    }
    if literal.contains(|character: char| "{}<>()[]=!?,;'\"".contains(character)) {
        return false;
    }
    if literal.starts_with("iroha:") || literal.starts_with("iroha/") {
        return true;
    }
    if literal.starts_with('.')
        || literal.starts_with('/')
        || PATH_ENDINGS.iter().any(|ending| literal.ends_with(ending))
    {
        return false;
    }
    has_version_segment(literal) && literal.contains(|character: char| ":/.|-".contains(character))
}

/// What owns one exact domain literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DomainOwner {
    Root(&'static str),
    Accumulator(&'static str),
    Other(Use),
}

/// The owner of every listed domain literal. Each literal is listed exactly once and no
/// entry is a prefix rule: a literal that is not in this map is unclassified.
fn domain_owners() -> BTreeMap<&'static str, DomainOwner> {
    let roots = ROOTS.iter().flat_map(|root| {
        root.domains
            .iter()
            .map(|literal| (*literal, DomainOwner::Root(root.id)))
    });
    let accumulators = APPLICATION_ACCUMULATORS.iter().flat_map(|accumulator| {
        accumulator
            .domains
            .iter()
            .map(|literal| (*literal, DomainOwner::Accumulator(accumulator.id)))
    });
    let others = OTHER_DOMAINS.iter().flat_map(|group| {
        group
            .literals
            .iter()
            .map(|literal| (*literal, DomainOwner::Other(group.usage)))
    });
    let mut owners = BTreeMap::new();
    for (literal, owner) in roots.chain(accumulators).chain(others) {
        assert!(
            is_domain_literal(literal),
            "{literal} is listed but is not a domain literal"
        );
        assert!(
            owners.insert(literal, owner).is_none(),
            "domain literal {literal} is listed twice"
        );
    }
    owners
}

/// What the scan found that the inventory does not list, and what it lists without a source.
#[derive(Default)]
struct SourceScan {
    /// Number of distinct domain literals in the scanned sources.
    literals: usize,
    /// Domain literals that nothing lists, with one source that holds each.
    unlisted_domains: BTreeSet<String>,
    /// Listed literals that no scanned source holds.
    stale_domains: BTreeSet<&'static str>,
    /// Construction uses whose source or count is not listed.
    unlisted_uses: BTreeSet<String>,
    /// Listed construction uses that the sources do not have.
    stale_uses: BTreeSet<String>,
    /// Every use of a listed domain literal: its sources and the number of occurrences
    /// in each. The generated inventory pins them, so a new use is reviewed again.
    literal_uses: BTreeMap<&'static str, BTreeMap<String, usize>>,
    /// Functions that read State and return a hash-bearing value, by source and name, with
    /// the number of matching functions (`iroha_core` sources only).
    state_hash_functions: BTreeMap<(String, String), usize>,
    /// Such functions that are not listed, or listed with another count.
    unlisted_functions: BTreeSet<String>,
    /// Listed functions that the sources do not have.
    stale_functions: BTreeSet<String>,
}

impl SourceScan {
    /// Panic with every unlisted or stale item: the completeness check of the inventory.
    fn require_complete(&self) {
        assert!(
            self.unlisted_domains.is_empty()
                && self.unlisted_uses.is_empty()
                && self.stale_domains.is_empty()
                && self.stale_uses.is_empty()
                && self.unlisted_functions.is_empty()
                && self.stale_functions.is_empty(),
            "State inventory source discrepancies (review every category):\n\
             Unclassified domains: {:?}\n\
             Unlisted or changed construction uses: {:?}\n\
             Stale domains: {:?}\n\
             Stale construction uses: {:?}\n\
             Unlisted or changed State-reading hash functions: {:?}\n\
             Stale State-reading hash functions: {:?}\n\
             Classify exact domains under ROOTS, an application accumulator or OTHER_DOMAINS; \
             review construction uses in CONSTRUCTION_USES and State-reading hash functions \
             in STATE_HASH_FUNCTIONS. Remove entries only after confirming their source retired.",
            self.unlisted_domains,
            self.unlisted_uses,
            self.stale_domains,
            self.stale_uses,
            self.unlisted_functions,
            self.stale_functions,
        );
    }
}

#[test]
fn source_scan_reports_all_discrepancies_and_refuses_each_category() {
    let mut combined = SourceScan::default();
    for category in 0..6 {
        let mut isolated = SourceScan::default();
        for scan in [&mut combined, &mut isolated] {
            match category {
                0 => {
                    scan.unlisted_domains.insert("unlisted-domain".into());
                }
                1 => {
                    scan.unlisted_uses.insert("unlisted-construction".into());
                }
                2 => {
                    scan.stale_domains.insert("stale-domain");
                }
                3 => {
                    scan.stale_uses.insert("stale-construction".into());
                }
                4 => {
                    scan.unlisted_functions.insert("unlisted-function".into());
                }
                5 => {
                    scan.stale_functions.insert("stale-function".into());
                }
                _ => unreachable!(),
            }
        }
        assert!(std::panic::catch_unwind(|| isolated.require_complete()).is_err());
    }
    let error = std::panic::catch_unwind(|| combined.require_complete()).unwrap_err();
    let message = error
        .downcast_ref::<String>()
        .expect("formatted inventory diagnostic");
    for item in [
        "unlisted-domain",
        "unlisted-construction",
        "stale-domain",
        "stale-construction",
        "unlisted-function",
        "stale-function",
    ] {
        assert!(message.contains(item), "missing {item}: {message}");
    }
    SourceScan::default().require_complete();
}

/// Classify the domain literals and construction uses of `sources` (path and text).
fn scan_sources<'a>(sources: impl IntoIterator<Item = (&'a str, &'a str)>) -> SourceScan {
    let owners = domain_owners();
    let listed_uses: BTreeMap<&'static str, &ConstructionUse> = CONSTRUCTION_USES
        .iter()
        .map(|listed| (listed.path, listed))
        .collect();
    assert_eq!(
        listed_uses.len(),
        CONSTRUCTION_USES.len(),
        "a construction user is listed twice"
    );
    let listed_functions: BTreeMap<(&'static str, &'static str), usize> = STATE_HASH_FUNCTIONS
        .iter()
        .map(|listed| ((listed.path, listed.name), listed.count))
        .collect();
    assert_eq!(
        listed_functions.len(),
        STATE_HASH_FUNCTIONS.len(),
        "a State-reading hash function is listed twice"
    );
    let mut scan = SourceScan::default();
    let mut found = BTreeSet::new();
    let mut matched = BTreeSet::new();
    let mut seen_users = BTreeSet::new();
    for (path, text) in sources {
        if is_test_source(path) {
            continue;
        }
        let (literals, code) = split_source(text);
        for literal in literals {
            if !is_domain_literal(literal) {
                continue;
            }
            found.insert(literal.to_owned());
            match owners.get_key_value(literal) {
                Some((listed, _)) => {
                    matched.insert(*listed);
                    *scan
                        .literal_uses
                        .entry(*listed)
                        .or_default()
                        .entry(path.to_owned())
                        .or_default() += 1;
                }
                None => {
                    scan.unlisted_domains.insert(format!("{literal} in {path}"));
                }
            }
        }
        if path.starts_with(FUNCTION_SCAN_SCOPE) {
            for signature in fn_signatures(&code) {
                if signature.reads_state && signature.returns_hash {
                    *scan
                        .state_hash_functions
                        .entry((path.to_owned(), signature.name))
                        .or_default() += 1;
                }
            }
        }
        let mut uses: Vec<(&'static str, usize)> = CONSTRUCTIONS
            .iter()
            .map(|token| (*token, code.matches(token).count()))
            .filter(|(_, count)| *count > 0)
            .collect();
        uses.sort_unstable();
        if uses.is_empty() {
            continue;
        }
        match listed_uses.get_key_value(path) {
            Some((listed_path, listed)) => {
                seen_users.insert(*listed_path);
                if listed.uses != uses.as_slice() {
                    scan.unlisted_uses
                        .insert(format!("{path}: found {uses:?}, listed {:?}", listed.uses));
                }
            }
            None => {
                scan.unlisted_uses.insert(format!("{path}: found {uses:?}"));
            }
        }
    }
    scan.literals = found.len();
    scan.stale_domains = owners
        .keys()
        .copied()
        .filter(|literal| !matched.contains(literal))
        .collect();
    scan.stale_uses = CONSTRUCTION_USES
        .iter()
        .filter(|listed| !seen_users.contains(listed.path))
        .map(|listed| listed.path.to_owned())
        .collect();
    for ((path, name), count) in &scan.state_hash_functions {
        match listed_functions.get(&(path.as_str(), name.as_str())) {
            Some(listed) if listed == count => {}
            Some(listed) => {
                scan.unlisted_functions
                    .insert(format!("{path}: {name}: found {count}, listed {listed}"));
            }
            None => {
                scan.unlisted_functions
                    .insert(format!("{path}: {name}: found {count}"));
            }
        }
    }
    scan.stale_functions = listed_functions
        .keys()
        .filter(|(path, name)| {
            !scan
                .state_hash_functions
                .contains_key(&((*path).to_owned(), (*name).to_owned()))
        })
        .map(|(path, name)| format!("{path}: {name}"))
        .collect();
    scan
}

/// The sources whose functions the signature scan reads: only `iroha_core` holds State.
const FUNCTION_SCAN_SCOPE: &str = "crates/iroha_core/src/";

/// Type names that mark a State or World reader: in a function signature, or in the
/// header of the `impl` or `trait` block that a method with a `self` receiver belongs to.
/// They are the owners of the registry fields (`State`, `World`, the transaction storage,
/// the block-hash journal, the trigger set and the canonical runtime) with their reader
/// traits and their block, transaction, view, prepared, detached and published handles,
/// every other type that implements a reader trait, and the table and cell handles that
/// State is built from. In ascending order. The list is by name: the scan test requires
/// every type that implements a reader trait in a literal `impl` block to be listed; a
/// further handle type is added by hand.
const STATE_READER_TYPES: &[&str] = &[
    "BlockHashRange",
    "BlockHashRead",
    "BlockHashes",
    "BlockHashesBlock",
    "BlockHashesTransaction",
    "BlockHashesView",
    "BorrowedHistorySource",
    "CanonicalRuntimeProjection",
    "Cell",
    "CellBlock",
    "CellTransaction",
    "CellView",
    "CommittedLoadReceipts",
    "DetachedBlockHashes",
    "DetachedSet",
    "DetachedStateTransactionDelta",
    "DetachedTransactionsBlock",
    "DetachedWorld",
    "HistoryDraft",
    "PreparedBlockHashes",
    "PreparedDetachedTransactionsBlock",
    "PreparedSet",
    "PreparedTransactionsBlock",
    "PreparedWorld",
    "PreparedWorldCommit",
    "PublishedBlockHashes",
    "PublishedSet",
    "PublishedTransactions",
    "SccpHistoryNodeCache",
    "Set",
    "SetBlock",
    "SetBlockFields",
    "SetReadOnly",
    "SetTransaction",
    "SetView",
    "SnapshotNexusRuntime",
    "State",
    "StateBlock",
    "StateBlockFields",
    "StateQueryView",
    "StateReadOnly",
    "StateReadOnlyWithTransactions",
    "StateTransaction",
    "StateView",
    "Storage",
    "StorageBlock",
    "StorageReadOnly",
    "StorageTransaction",
    "StorageView",
    "TransactionsBlock",
    "TransactionsBlockField",
    "TransactionsReadOnly",
    "TransactionsStorage",
    "TransactionsView",
    "World",
    "WorldBlock",
    "WorldBlockFields",
    "WorldData",
    "WorldHistory",
    "WorldReadOnly",
    "WorldStateSnapshot",
    "WorldTransaction",
    "WorldView",
    "WsvLedger",
];

/// Endings of a type name (before an optional `V<digits>` version) that mark a
/// hash-bearing return type: wrappers, aliases and records named for what they carry.
const HASH_TYPE_ENDINGS: &[&str] = &[
    "Commitment",
    "Digest",
    "Fingerprint",
    "Hash",
    "Proof",
    "ProofBundle",
    "Proofs",
    "Root",
];

/// Records that carry a root or digest of State content under another name.
const ROOT_BEARING_RECORDS: &[&str] = &[
    "AxtPolicySnapshot",
    "CanonicalTablePairedSnapshot",
    "CapturedCanonicalTables",
    "CapturedMembershipTables",
    "CapturedSnapshotIdentity",
    "LocalRetailContractStateSnapshotV1",
    "NativeExecutionTipRecord",
    "PredecessorWorldReceipt",
    "QueryProjectionCheckpoint",
    "RetainedSccpHistoryPath",
    "RetainedSccpHistoryView",
    "StateCellDigestSliceV1",
    "WorldNetDelta",
    "WorldPublicationDelta",
    "WorldStateAccumulator",
    "WorldStateTransition",
];

/// The carriers whose walked records the signature scan also matches as return types: the
/// records of the peer handshake and of a lane block. Most of them have no name that the
/// hash rules match, so a State reader that fills one from State content would otherwise
/// be seen by no detector.
const RECORD_RETURN_CARRIERS: &[&str] = &["lane_result", "peer_handshake"];

/// The names of the records that the carriers of [`RECORD_RETURN_CARRIERS`] walk, in
/// ascending order: the handshake hello with its metadata records, the identity binding,
/// the handshake capabilities, and the lane batch and lane result.
fn carried_records() -> Vec<&'static str> {
    let mut records: Vec<&'static str> = CARRIERS
        .iter()
        .filter(|carrier| RECORD_RETURN_CARRIERS.contains(&carrier.id))
        .flat_map(|carrier| carrier.types.iter())
        .map(|(_, declaration)| declared_name(declaration))
        .collect();
    records.sort_unstable();
    records.dedup();
    records
}

/// The rule that decides which functions the signature scan matches.
const STATE_READER_RULE: &str = "a function or method of a non-test iroha_core source, outside items under #[cfg(test)] or #[test], whose generics, parameters or where clause name a State reader type, or that has a self receiver inside an impl or trait block whose header names one anywhere between the keyword and the opening brace: in the generics, the implemented trait, the implementing type, the supertraits or the where clause. A blanket implementation for all readers, an extension trait of a reader trait, an implementation of a reader trait for a type with another name and an impl block in a macro body are therefore matched. The State reader types (state_reader_types) are the owners of the registry fields (State, World, the transaction storage, the block-hash journal, the trigger set and the canonical runtime) with their reader traits and their block, transaction, view, prepared, detached and published handles, every other type that implements a reader trait in a literal impl block, and the table and cell handles that State is built from";

/// The rule that decides which return types are hash-bearing.
const HASH_RETURN_RULE: &str = "a return type is hash-bearing when it names Hash, HashOf or Hash32; or a raw digest array [u8; 32], [u8; Hash::LENGTH] or [u8; blake3::OUT_LEN]; or a type whose name, before an optional V<digits> version, ends in Commitment, Digest, Fingerprint, Hash, Proof, ProofBundle, Proofs or Root (wrappers, aliases and records named for what they carry); or one of the listed records that carry a root or digest of State content under another name (root_bearing_records); or one of the records of the peer handshake and of a lane block that the carrier walk reads (carried_records), whatever its name; Self in a return type stands for the implementing type of the enclosing impl block (an associated type Self::Name does not)";

/// The identifiers of a code text.
fn identifiers(code: &str) -> impl Iterator<Item = &str> {
    code.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|name| !name.is_empty())
}

/// The name of a type without its `V<digits>` version suffix.
fn unversioned(name: &str) -> &str {
    let stem = name.trim_end_matches(|character: char| character.is_ascii_digit());
    match stem.strip_suffix('V') {
        Some(base) if stem.len() < name.len() => base,
        _ => name,
    }
}

/// Whether a type name says that the type carries a hash ([`HASH_TYPE_ENDINGS`]).
fn is_hash_named(name: &str) -> bool {
    HASH_TYPE_ENDINGS
        .iter()
        .any(|ending| unversioned(name).ends_with(ending))
}

/// Whether a return type is hash-bearing ([`HASH_RETURN_RULE`]).
fn returns_hash(output: &str) -> bool {
    let compact: String = output
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    compact.contains("[u8;32]")
        || compact.contains("OUT_LEN]")
        || identifiers(output).any(|name| {
            matches!(name, "Hash" | "HashOf" | "Hash32")
                || ROOT_BEARING_RECORDS.contains(&name)
                || is_hash_named(name)
                || CARRIERS.iter().any(|carrier| {
                    RECORD_RETURN_CARRIERS.contains(&carrier.id)
                        && carrier
                            .types
                            .iter()
                            .any(|(_, declaration)| declared_name(declaration) == name)
                })
        })
}

/// Whether a code text names a State or World reader type.
fn names_state_reader(code: &str) -> bool {
    identifiers(code).any(|name| STATE_READER_TYPES.contains(&name))
}

/// Whether the keyword `word` starts at `at` in `code`, as a whole identifier.
fn keyword_at(code: &[u8], at: usize, word: &[u8]) -> bool {
    let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    code[at..].starts_with(word)
        && (at == 0 || !is_identifier(code[at - 1]))
        && code
            .get(at + word.len())
            .is_none_or(|byte| !is_identifier(*byte))
}

/// The index just past the bracket that closes the one at `open`. Angle brackets skip
/// the arrow of a return type; an unclosed bracket ends at the end of the text.
fn closing(code: &[u8], open: usize) -> usize {
    let (left, right) = match code[open] {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        b'{' => (b'{', b'}'),
        _ => (b'<', b'>'),
    };
    let mut depth = 0_usize;
    let mut at = open;
    while at < code.len() {
        let byte = code[at];
        if byte == left {
            depth += 1;
        } else if byte == right && !(right == b'>' && at > 0 && code[at - 1] == b'-') {
            depth -= 1;
            if depth == 0 {
                return at + 1;
            }
        }
        at += 1;
    }
    code.len()
}

/// The index of the first `{` or `;` at or after `from` that is outside parentheses and
/// square brackets: the end of an item header.
fn header_end(code: &[u8], from: usize) -> usize {
    let mut at = from;
    while at < code.len() {
        match code[at] {
            b'(' | b'[' => at = closing(code, at),
            b'{' | b';' => return at,
            _ => at += 1,
        }
    }
    code.len()
}

/// The index just past the item whose header starts at `from`: its body, or its `;`.
fn item_end(code: &[u8], from: usize) -> usize {
    let end = header_end(code, from);
    match code.get(end) {
        Some(b'{') => closing(code, end),
        Some(_) => end + 1,
        None => end,
    }
}

/// The end of a literal braced control expression, including the original `else` chain.
/// Balanced call/index groups belong to its header. A header operand that is itself a
/// block is consumed before the final body, rather than mistaken for that body.
fn test_only_control_end(code: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    // Labels on loops are part of the attributed expression, not its enclosing owner.
    if code.get(at) == Some(&b'\'') {
        at += 1;
        while at < code.len()
            && (code[at].is_ascii_alphanumeric() || code[at] == b'_' || !code[at].is_ascii())
        {
            at += 1;
        }
        if code.get(at) != Some(&b':') {
            return None;
        }
        at += 1;
        while at < code.len() && code[at].is_ascii_whitespace() {
            at += 1;
        }
        if code.get(at) == Some(&b'{') {
            return Some(closing(code, at));
        }
    }
    let word = [b"if".as_slice(), b"while", b"for", b"match", b"loop"]
        .into_iter()
        .find(|word| keyword_at(code, at, word))?;
    let has_else = word == b"if";
    let loop_body = word == b"loop";
    let for_header = word == b"for";
    at += word.len();
    loop {
        let mut operand_block_seen = false;
        let body_end = loop {
            let open = header_end(code, at);
            if code.get(open) != Some(&b'{') {
                return Some(open);
            }
            let header = &code[at..open];
            let last = header.iter().rposition(|byte| !byte.is_ascii_whitespace());
            let needs_operand = last.is_some_and(|index| {
                matches!(
                    header[index],
                    b'=' | b'!'
                        | b'&'
                        | b'|'
                        | b'+'
                        | b'-'
                        | b'*'
                        | b'/'
                        | b'%'
                        | b'^'
                        | b'<'
                        | b'>'
                ) || (for_header
                    && index >= 1
                    && keyword_at(header, index - 1, b"in")
                    && index.checked_sub(2).and_then(|before| header.get(before)) != Some(&b'#'))
            });
            let end = closing(code, open);
            if !loop_body && ((!operand_block_seen && last.is_none()) || needs_operand) {
                // The condition/iterator/matched value owns this block; the control
                // expression still requires its own body after it.
                operand_block_seen = true;
                at = end;
            } else {
                break end;
            }
        };
        at = body_end;
        while at < code.len() && code[at].is_ascii_whitespace() {
            at += 1;
        }
        if !has_else || !keyword_at(code, at, b"else") {
            return Some(body_end);
        }
        at += 4;
        while at < code.len() && code[at].is_ascii_whitespace() {
            at += 1;
        }
        if keyword_at(code, at, b"if") {
            at += 2;
        } else {
            return Some(if code.get(at) == Some(&b'{') {
                closing(code, at)
            } else {
                body_end
            });
        }
    }
}

/// The end of an attributed item, argument, field, statement or expression. Only a
/// literal item keyword uses the item-header scan: non-items stop at their own separator
/// or enclosing close, so an attribute on a call argument cannot consume a later item.
fn test_only_target_end(code: &[u8], from: usize) -> usize {
    let mut at = from;
    loop {
        while at < code.len() && code[at].is_ascii_whitespace() {
            at += 1;
        }
        if keyword_at(code, at, b"pub") {
            at += 3;
            while at < code.len() && code[at].is_ascii_whitespace() {
                at += 1;
            }
            if code.get(at) == Some(&b'(') {
                at = closing(code, at);
            }
        } else if let Some(modifier) = [b"async".as_slice(), b"unsafe", b"default", b"move"]
            .into_iter()
            .find(|word| keyword_at(code, at, word))
        {
            at += modifier.len();
        } else {
            break;
        }
    }
    if [
        b"fn".as_slice(),
        b"mod",
        b"impl",
        b"trait",
        b"struct",
        b"enum",
        b"union",
        b"type",
        b"const",
        b"static",
        b"use",
        b"extern",
        b"macro_rules",
    ]
    .into_iter()
    .any(|word| keyword_at(code, at, word))
    {
        return item_end(code, from);
    }
    if let Some(end) = test_only_control_end(code, at) {
        return end;
    }
    // A bare, async or unsafe block is itself the attributed expression/statement;
    // Rust permits a following local item without a semicolon after this block.
    if code.get(at) == Some(&b'{') {
        return closing(code, at);
    }
    // Keep nested groups inside the same target. At this level a close belongs to its
    // enclosing owner; it must never be crossed in search of the next item's body.
    at = from;
    while at < code.len() {
        match code[at] {
            b'(' | b'[' | b'{' => at = closing(code, at),
            b',' | b';' => return at + 1,
            b')' | b']' | b'}' => return at,
            _ => at += 1,
        }
    }
    at
}

/// The ranges compiled for tests only under `#[cfg(test)]` or `#[test]`,
/// including attributed local targets without crossing into later items.
fn test_only_ranges(code: &str) -> Vec<(usize, usize)> {
    let bytes = code.as_bytes();
    let mut ranges = Vec::new();
    for marker in ["#[cfg(test)]", "#[test]"] {
        let mut from = 0;
        while let Some(found) = code[from..].find(marker) {
            let start = from + found;
            let mut at = start + marker.len();
            loop {
                while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                    at += 1;
                }
                if bytes[at..].starts_with(b"#[") {
                    at = closing(bytes, at + 1);
                } else {
                    break;
                }
            }
            ranges.push((start, test_only_target_end(bytes, at)));
            from = start + marker.len();
        }
    }
    ranges
}

/// The `impl` and `trait` blocks of a code text: their range and their whole header, from
/// the keyword up to the opening brace. The header of an `impl` block holds its generics, the
/// implemented trait, the implementing type and the where clause; the header of a `trait`
/// block holds its name, generics, supertraits and where clause. A method inside the block
/// belongs to a State or World reader when any of them names one: an inherent method of a
/// reader, a method of a reader trait implemented for another type (also inside a macro
/// body, where the type is a metavariable), and a method of a blanket implementation or
/// an extension trait for all readers.
fn type_blocks(code: &str) -> Vec<(usize, usize, String)> {
    let bytes = code.as_bytes();
    let mut blocks = Vec::new();
    for at in 0..bytes.len() {
        let word: &[u8] = if keyword_at(bytes, at, b"impl") {
            b"impl"
        } else if keyword_at(bytes, at, b"trait") {
            b"trait"
        } else {
            continue;
        };
        // An item, not `impl Trait` in a type: it follows the end of another item, an
        // attribute, a visibility, the start of its module or the opening of a macro
        // repetition (`$(`), which holds the first item of a repeated macro body.
        let before = code[..at].trim_end();
        let item = before.is_empty()
            || before.ends_with(['}', ';', '{', ']', ')'])
            || before.ends_with("$(")
            || ["pub", "unsafe"].iter().any(|keyword| {
                before.ends_with(keyword)
                    && keyword_at(bytes, before.len() - keyword.len(), keyword.as_bytes())
            });
        if !item {
            continue;
        }
        let open = header_end(bytes, at + word.len());
        if bytes.get(open) != Some(&b'{') {
            continue;
        }
        let header: Vec<&str> = code[at..open].split_whitespace().collect();
        blocks.push((at, closing(bytes, open), header.join(" ")));
    }
    blocks
}

/// The implementing type of an `impl` block header ([`type_blocks`]): the text after
/// ` for ` when the block implements a trait, otherwise the header after the keyword and
/// its generics; the where clause is not part of it. `Self` in a signature of the block
/// stands for this type. A `trait` block has no implementing type.
fn implementing_type(header: &str) -> Option<&str> {
    let rest = header.strip_prefix("impl")?.trim_start();
    let rest = if rest.starts_with('<') {
        rest[closing(rest.as_bytes(), 0)..].trim_start()
    } else {
        rest
    };
    let target = rest.split_once(" for ").map_or(rest, |(_, target)| target);
    Some(target.split(" where ").next().unwrap_or(target))
}

/// The reader traits among [`STATE_READER_TYPES`]: a type that implements one is a reader.
const STATE_READER_TRAITS: &[&str] = &[
    "BlockHashRead",
    "BorrowedHistorySource",
    "SetReadOnly",
    "StateReadOnly",
    "StateReadOnlyWithTransactions",
    "TransactionsReadOnly",
    "WorldReadOnly",
    "WorldStateSnapshot",
];

/// The named types for which a code text implements a reader trait in a literal `impl`
/// block: the first identifier of the implementing type, unless it is a type parameter
/// of the block, a macro metavariable or a standard container of block hashes. Each is a
/// reader and belongs in [`STATE_READER_TYPES`].
fn reader_trait_implementors(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (_, _, header) in type_blocks(code) {
        let Some(target) = implementing_type(&header) else {
            continue;
        };
        let Some((implemented, _)) = header.rsplit_once(" for ") else {
            continue;
        };
        let rest = implemented["impl".len()..].trim_start();
        let (parameters, implemented) = if rest.starts_with('<') {
            rest.split_at(closing(rest.as_bytes(), 0))
        } else {
            ("", rest)
        };
        if !identifiers(implemented).any(|name| STATE_READER_TRAITS.contains(&name)) {
            continue;
        }
        let named = identifiers(target).next().filter(|name| {
            name.starts_with(|character: char| character.is_ascii_uppercase())
                && !["HashOf", "Vec"].contains(name)
                && !identifiers(parameters).any(|parameter| parameter == *name)
                && !target.trim_start().starts_with('$')
        });
        out.extend(named.map(str::to_owned));
    }
    out
}

/// Whether a type text names `Self` as a type of its own. `Self::Name` is an associated
/// type of the implementing type, not the type itself.
fn names_own_type(kind: &str) -> bool {
    let bytes = kind.as_bytes();
    (0..bytes.len())
        .any(|at| keyword_at(bytes, at, b"Self") && !kind[at + 4..].trim_start().starts_with("::"))
}

/// One function of a source: its name, and what its signature says.
#[derive(Debug, PartialEq, Eq)]
struct FnSignature {
    name: String,
    /// The signature takes a State or World reader, or the function is a method of one
    /// ([`STATE_READER_RULE`]).
    reads_state: bool,
    /// The return type is hash-bearing ([`HASH_RETURN_RULE`]).
    returns_hash: bool,
}

/// Every function declared in a code text outside test-only items, with what its
/// signature says. `code` is a source without comments and literals ([`split_source`]).
fn fn_signatures(code: &str) -> Vec<FnSignature> {
    let bytes = code.as_bytes();
    let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let tests = test_only_ranges(code);
    let blocks = type_blocks(code);
    let mut out = Vec::new();
    for at in 0..bytes.len() {
        if !keyword_at(bytes, at, b"fn")
            || tests
                .iter()
                .any(|(start, end)| (*start..*end).contains(&at))
        {
            continue;
        }
        let mut cursor = at + 2;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let name_start = cursor;
        while cursor < bytes.len() && is_identifier(bytes[cursor]) {
            cursor += 1;
        }
        if cursor == name_start {
            // A function pointer type.
            continue;
        }
        let name = &code[name_start..cursor];
        let generics_start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'<') {
            cursor = closing(bytes, cursor);
        }
        let generics = &code[generics_start..cursor];
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'(') {
            continue;
        }
        let parameters_end = closing(bytes, cursor);
        let parameters = &code[cursor..parameters_end];
        let tail = &code[parameters_end..header_end(bytes, parameters_end)];
        let (output, bounds) = match tail.trim_start().strip_prefix("->") {
            Some(rest) => {
                let split = (0..rest.len())
                    .find(|at| keyword_at(rest.as_bytes(), *at, b"where"))
                    .unwrap_or(rest.len());
                rest.split_at(split)
            }
            None => ("", tail),
        };
        // The innermost `impl` or `trait` block that holds the function.
        let enclosing = blocks
            .iter()
            .filter(|(start, end, _)| (*start..*end).contains(&at))
            .min_by_key(|(start, end, _)| end - start)
            .map(|(_, _, header)| header.as_str());
        let method_of_reader = identifiers(parameters).any(|word| word == "self")
            && enclosing.is_some_and(names_state_reader);
        // `Self` in the return type is the implementing type of that block.
        let returns_own_hash = names_own_type(output)
            && enclosing
                .and_then(implementing_type)
                .is_some_and(returns_hash);
        out.push(FnSignature {
            name: name.to_owned(),
            reads_state: method_of_reader
                || names_state_reader(generics)
                || names_state_reader(parameters)
                || names_state_reader(bounds),
            returns_hash: returns_hash(output) || returns_own_hash,
        });
    }
    out
}

/// Scan the actual sources of [`SCAN_SCOPE`].
fn source_scan() -> SourceScan {
    let texts: Vec<(String, String)> = rust_sources(SCAN_SCOPE)
        .into_iter()
        .filter(|path| !SELF_PATHS.contains(&path.as_str()))
        .map(|path| {
            let text = source(&path);
            (path, text)
        })
        .collect();
    scan_sources(
        texts
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str())),
    )
}

/// The construction users of one commitment, from [`CONSTRUCTION_USES`].
fn construction_users(root: &str) -> Vec<&'static str> {
    CONSTRUCTION_USES
        .iter()
        .filter(|listed| matches!(listed.owner, UseOwner::Roots(roots) if roots.contains(&root)))
        .map(|listed| listed.path)
        .collect()
}

/// What one World accessor read by a deriving function contributes to a witness value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    /// The content of this registry field enters the value.
    Field(&'static str),
    /// The accessor is read but no content of the field enters the value.
    NoContent(&'static str),
}

/// What a hash-typed field of a witness value type commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HashUse {
    /// A digest of State content: the listed commitment with this identity.
    State(&'static str),
    /// A digest of the block's or a transaction's own content, or an identifier.
    Block(&'static str),
}

/// One family of keys that production execution writes into the execution witness, and
/// with it into `post_state_root` and `ordinary_writes_root`.
struct WitnessFamily {
    id: &'static str,
    /// `ExecutionWitnessKeyTagV1` variants of the family's keys; empty for a fixed key
    /// that the data model declares outside the tag enum.
    tags: &'static [&'static str],
    key: &'static str,
    value: &'static str,
    /// Whether the family also records pre-values, which enter `parent_state_root`.
    reads: bool,
    /// Registry fields whose content the value carries or digests, when no deriving
    /// function is listed (the SCCP family reads them from its encoder).
    fields: &'static [&'static str],
    /// What else the value is derived from.
    source: &'static str,
    /// The functions that derive the value from World, as source and signature line. The
    /// check reads their direct `world.` accessors; helpers they call are listed as well.
    derivation: &'static [(&'static str, &'static str)],
    /// Every World accessor those functions read, and what it contributes.
    accessors: &'static [(&'static str, Access)],
    /// The listed commitments over State content that the value embeds.
    digests: &'static [&'static str],
    /// The types that the capture path builds for the value, as source and declaration,
    /// nested types and types committed through a root in the value included. A record
    /// that is copied as written is a row and is not listed.
    value_types: &'static [(&'static str, &'static str)],
    /// Every hash-typed field of those types, as `Type.field`, and what it commits.
    hashes: &'static [(&'static str, HashUse)],
    /// Named types in fields of those types that are not walked, with the reason.
    opaque: &'static [(&'static str, &'static str)],
    evidence: &'static [(&'static str, &'static str)],
}

/// The family whose registry fields are read from the SCCP write-set encoder.
const SCCP_FAMILY: &str = "sccp_state_delta";

const FEE_REWARDS: &str = "crates/iroha_core/src/validation_fee_rewards.rs";
const REWARD_EXPOSURE: &str = "crates/iroha_core/src/validation_fee_rewards/exposure.rs";
const REWARD_EXPOSURE_MODEL: &str = "crates/iroha_data_model/src/validation_fee_rewards.rs";
const CASTING: &str = "crates/iroha_core/src/tle_release/casting.rs";
const FINALIZED_SOURCE: &str =
    "crates/iroha_core/src/state/fastpq_quantity_capture/commitment_journal/finalized_source.rs";
const SOURCE_STATEMENT: &str = "crates/iroha_data_model/src/fastpq/source_statement.rs";
const VALIDATION_FEE_MODEL: &str = "crates/iroha_data_model/src/validation_fee.rs";

/// Every production writer of the execution witness. The witnessed roots commit these
/// reserved families and nothing else: no table is committed row by row. A family whose
/// value digests State content names the listed commitment under `digests`.
const WITNESS_FAMILIES: &[WitnessFamily] = &[
    WitnessFamily {
        id: "validation_fee_policy",
        tags: &["ValidationFeePolicy"],
        key: "fixed key of the tag",
        value: "snapshot commitment of the validation-fee custom parameter at the block's height and time",
        reads: false,
        fields: &["world.parameters"],
        source: "",
        derivation: &[],
        accessors: &[],
        digests: &["validation_fee_policy_snapshot"],
        value_types: &[
            (
                VALIDATION_FEE_MODEL,
                "pub struct ValidationFeePolicySnapshotCommitmentV1 {",
            ),
            (
                VALIDATION_FEE_MODEL,
                "pub enum ValidationFeePolicySnapshotStatusV1 {",
            ),
            (
                VALIDATION_FEE_MODEL,
                "pub struct ValidationFeePolicySnapshotAvailableV1 {",
            ),
        ],
        hashes: &[
            (
                "ValidationFeePolicySnapshotStatusV1.Invalid",
                HashUse::State("validation_fee_policy_snapshot"),
            ),
            (
                "ValidationFeePolicySnapshotAvailableV1.registry_hash",
                HashUse::State("validation_fee_policy_snapshot"),
            ),
            (
                "ValidationFeePolicySnapshotAvailableV1.head_policy_hash",
                HashUse::State("validation_fee_policy_snapshot"),
            ),
            (
                "ValidationFeePolicySnapshotAvailableV1.scheduled_policy_hash",
                HashUse::State("validation_fee_policy_snapshot"),
            ),
            (
                "ValidationFeePolicySnapshotAvailableV1.effective_policy_hash",
                HashUse::State("validation_fee_policy_snapshot"),
            ),
        ],
        opaque: &[],
        evidence: &[(
            "crates/iroha_core/src/state.rs",
            "iroha_data_model::validation_fee::VALIDATION_FEE_POLICY_WITNESS_KEY_V1;",
        )],
    },
    WitnessFamily {
        id: "parliament_timed_ovn_casting",
        tags: &["ParliamentTimedOvnCasting"],
        key: "fixed key of the tag",
        value: "snapshot commitment of the authorized timed-OVN casting contexts",
        reads: false,
        fields: &[],
        source: "",
        derivation: &[
            (
                CASTING,
                "pub(crate) fn derive_parliament_timed_ovn_casting_snapshot_v1(",
            ),
            (CASTING, "fn compact_binding_from_world_v1("),
        ],
        accessors: &[
            (
                "parliament_timed_ovn_casting_candidates",
                Access::Field("world.parliament_timed_ovn_casting_candidates"),
            ),
            (
                "timed_ovn_evidence",
                Access::Field("world.timed_ovn_evidence"),
            ),
            (
                "parliament_attempts",
                Access::Field("world.parliament_attempts"),
            ),
            ("tle_key_sessions", Access::Field("world.tle_key_sessions")),
        ],
        digests: &["parliament_casting_snapshot_root"],
        value_types: &[(
            "crates/iroha_data_model/src/parliament_casting.rs",
            "pub struct ParliamentTimedOvnCastingSnapshotCommitmentV1 {",
        )],
        hashes: &[(
            "ParliamentTimedOvnCastingSnapshotCommitmentV1.root",
            HashUse::State("parliament_casting_snapshot_root"),
        )],
        opaque: &[],
        evidence: &[(
            "crates/iroha_core/src/state.rs",
            "iroha_data_model::parliament_casting::PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1;",
        )],
    },
    WitnessFamily {
        id: "fastpq_ordinary_source_statements",
        tags: &["FastpqOrdinarySourceStatements"],
        key: "fixed key of the tag",
        value: "ordinary FASTPQ source-statement manifest (D7) derived by validator execution; every statement leaf carries perm_root",
        reads: false,
        fields: &[],
        source: "the block's source inventory and ordered quantity effects (block execution, not one State table), and the permission-table root of the complete world.roles table in every statement leaf",
        derivation: &[(
            FINALIZED_SOURCE,
            "fn prepare(block: &StateBlock<'_>) -> SourceResult<ChargedShared<Self>> {",
        )],
        accessors: &[
            ("roles", Access::Field("world.roles")),
            (
                "assets",
                Access::NoContent(
                    "write observation that detects a stale source; no balance enters the value",
                ),
            ),
            (
                "asset_definitions",
                Access::NoContent(
                    "write observation that detects a stale source; no supply enters the value",
                ),
            ),
        ],
        digests: &["fastpq_permission_table_root"],
        value_types: &[
            (
                SOURCE_STATEMENT,
                "pub struct FastpqOrdinarySourceStatementManifestV1 {",
            ),
            (
                SOURCE_STATEMENT,
                "pub struct FastpqOrdinarySourceStatementLeafV1 {",
            ),
            (
                SOURCE_STATEMENT,
                "pub struct FastpqSourceStatementContextV1 {",
            ),
            (SOURCE_STATEMENT, "pub enum FastpqSourceRouteV1 {"),
            (SOURCE_STATEMENT, "pub struct FastpqSourceLaneV1 {"),
        ],
        hashes: &[
            (
                "FastpqOrdinarySourceStatementManifestV1.source_entries_digest",
                HashUse::Block("digest of the block's executed source entries"),
            ),
            (
                "FastpqOrdinarySourceStatementManifestV1.statement_root",
                HashUse::Block("Merkle root of the block's statement leaves"),
            ),
            (
                "FastpqOrdinarySourceStatementLeafV1.entry_hash",
                HashUse::Block("hash of the executed entrypoint"),
            ),
            (
                "FastpqOrdinarySourceStatementLeafV1.effects_digest",
                HashUse::Block("digest of the entry's ordered quantity effects"),
            ),
            (
                "FastpqOrdinarySourceStatementLeafV1.perm_root",
                HashUse::State("fastpq_permission_table_root"),
            ),
            (
                "FastpqOrdinarySourceStatementLeafV1.tx_set_hash",
                HashUse::Block("commitment of the block's ordered transaction wire set"),
            ),
            (
                "FastpqSourceLaneV1.lane_incarnation",
                HashUse::Block("identifier of the lane incarnation that routed the entry"),
            ),
        ],
        opaque: &[
            ("NetworkId", "network identity fixed at genesis"),
            ("DataSpaceId", "dataspace identifier of the entry"),
            (
                "FastpqSourceEffectCoverageV1",
                "enumeration without a payload",
            ),
            (
                "FastpqSourceExecutionKindV1",
                "enumeration without a payload",
            ),
            ("LaneId", "lane identifier of the route"),
        ],
        evidence: &[
            (
                "crates/iroha_core/src/state.rs",
                "let witness = state.retain_quantity_source_witness(witness)?;",
            ),
            (FINALIZED_SOURCE, "perm_root: permission_root,"),
        ],
    },
    WitnessFamily {
        id: SCCP_FAMILY,
        tags: &["SccpStateDelta"],
        key: "fixed key of the tag",
        value: "the height and the digest of the block's SCCP write set; absent when the block changed no SCCP field",
        reads: false,
        fields: &[],
        source: "",
        derivation: &[],
        accessors: &[],
        digests: &["sccp_state_delta_digest"],
        value_types: &[],
        hashes: &[],
        opaque: &[],
        evidence: &[
            (
                "crates/iroha_core/src/state.rs",
                "crate::smartcontracts::isi::sccp::witness::SCCP_STATE_DELTA_WITNESS_KEY_V1;",
            ),
            (
                "crates/iroha_core/src/state.rs",
                "pub(crate) fn sccp_execution_write_set_bytes(&self) -> Vec<u8> {",
            ),
        ],
    },
    WitnessFamily {
        id: "amx_record",
        tags: &["AmxRecord"],
        key: "tag byte, record kind and transaction identifier",
        value: "canonical AMX record of the block that creates it",
        reads: false,
        fields: &["world.sumeragi_amx"],
        source: "",
        derivation: &[],
        accessors: &[],
        digests: &[],
        value_types: &[],
        hashes: &[],
        opaque: &[],
        evidence: &[
            (
                "crates/iroha_core/src/exec_witness.rs",
                "pub(crate) fn record_write_amx_record(",
            ),
            (
                "crates/iroha_core/src/sumeragi/amx/mod.rs",
                "crate::exec_witness::record_write_amx_record(record)",
            ),
        ],
    },
    WitnessFamily {
        id: "fee_evidence",
        tags: &["FeeSnapshot", "FeeRecord"],
        key: "fixed snapshot key, and the record tag with the hash of each record key",
        value: "post-block retail fee evidence snapshot (record root, record count and receipt-head root) and each retained fee record as written",
        reads: false,
        fields: &[],
        source: "",
        derivation: &[
            (FEE_REWARDS, "pub(crate) fn capture_fee_evidence("),
            (FEE_REWARDS, "fn pending_fee_evidence_records("),
            (FEE_REWARDS, "fn collect_pending_fee_evidence_records("),
            (
                "crates/iroha_core/src/validation_fee_rewards/head_tree.rs",
                "fn read_root(world: &impl WorldReadOnly) -> Result<Option<NodeRef>, ExecutionAttemptError<String>> {",
            ),
            (
                "crates/iroha_core/src/validation_fee.rs",
                "fn validated_policy_registry_in_world<W: WorldReadOnly + ?Sized>(",
            ),
        ],
        accessors: &[
            ("assets", Access::Field("world.assets")),
            ("asset_definition", Access::Field("world.asset_definitions")),
            ("parameters", Access::Field("world.parameters")),
            (
                "smart_contract_state",
                Access::Field("world.smart_contract_state"),
            ),
        ],
        digests: &["fee_evidence_record_root", "retail_fee_receipt_head_root"],
        value_types: &[(
            "crates/iroha_data_model/src/fee_evidence.rs",
            "pub struct FeeEvidenceSnapshotV1 {",
        )],
        hashes: &[
            (
                "FeeEvidenceSnapshotV1.root",
                HashUse::State("fee_evidence_record_root"),
            ),
            (
                "FeeEvidenceSnapshotV1.account_heads_root",
                HashUse::State("retail_fee_receipt_head_root"),
            ),
        ],
        opaque: &[],
        evidence: &[
            (
                "crates/iroha_core/src/state.rs",
                "crate::validation_fee_rewards::capture_fee_evidence(state, &mut witness)?;",
            ),
            (
                FEE_REWARDS,
                "let mut key = vec![FEE_EVIDENCE_RECORD_TAG_V1];",
            ),
        ],
    },
    WitnessFamily {
        id: "reward_exposure_archive",
        tags: &["RewardExposureArchive"],
        key: "tag byte 0xDC followed by the hash of the protected ExposureArchive StatePath UTF-8 bytes",
        value: "canonical ValidationFeeExposureArchive row as written, including the chronological stake page and its predecessor reference",
        reads: false,
        fields: &[],
        source: "changed resident reward tails, excluding deleted rows; the reference archive_hash hashes the entire canonical wrapper including its predecessor, and cold reads authenticate the original ordinary_writes_root before following that content hash; no independent table root",
        derivation: &[(REWARD_EXPOSURE, "pub(super) fn capture_archive(")],
        accessors: &[(
            "smart_contract_state",
            Access::Field("world.smart_contract_state"),
        )],
        digests: &[],
        // Capture copies an existing protected row verbatim. As for AMX and
        // fee records, its nested row fields are not separately walked here.
        value_types: &[],
        hashes: &[],
        opaque: &[],
        evidence: &[
            (FEE_REWARDS, "exposure::capture_archive(block, witness)?;"),
            (
                REWARD_EXPOSURE_MODEL,
                "witness[1..].copy_from_slice(Hash::new(key.as_ref().as_bytes()).as_ref());",
            ),
            (
                REWARD_EXPOSURE,
                "Some(bytes) if Hash::new(bytes) == reference.archive_hash => {",
            ),
            (
                "crates/iroha_core/src/query/native_receipts/reward_history.rs",
                "if value.len() > MAX_REWARD_EXPOSURE_ARCHIVE_BYTES || Hash::new(value) != expected_hash {",
            ),
        ],
    },
    WitnessFamily {
        id: "sumeragi_lane_state",
        tags: &[],
        key: "the fixed key SUMERAGI_LANE_STATE_WITNESS_KEY",
        value: "SumeragiLaneStateCommitment of the complete lane state",
        reads: false,
        fields: &["world.sumeragi_lanes"],
        source: "",
        derivation: &[],
        accessors: &[],
        digests: &["native_lane_state_commitment"],
        value_types: &[(
            "crates/iroha_data_model/src/sumeragi_finality/lane_state_commitment.rs",
            "pub struct SumeragiLaneStateCommitment {",
        )],
        hashes: &[(
            "SumeragiLaneStateCommitment.state_hash",
            HashUse::State("native_lane_state_commitment"),
        )],
        opaque: &[("NetworkId", "network identity fixed at genesis")],
        evidence: &[
            (
                "crates/iroha_core/src/state.rs",
                "state.capture_sumeragi_lane_state(&mut witness)?;",
            ),
            (
                "crates/iroha_core/src/state/native_lane_state.rs",
                "key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),",
            ),
        ],
    },
    WitnessFamily {
        id: "private_dataspace_record",
        tags: &[],
        key: "the domain-separated witness key of the record",
        value: "canonical PrivateDataspaceRecord after a registration or anchor",
        reads: false,
        fields: &["world.private_dataspaces"],
        source: "",
        derivation: &[],
        accessors: &[],
        digests: &[],
        value_types: &[],
        hashes: &[],
        opaque: &[],
        evidence: &[
            (
                "crates/iroha_core/src/exec_witness.rs",
                "pub(crate) fn record_write_private_dataspace(",
            ),
            (
                "crates/iroha_core/src/sumeragi/private_dataspace.rs",
                "crate::exec_witness::record_write_private_dataspace(record).map_err(invalid)",
            ),
        ],
    },
];

const WITNESS_RECORDER: &str = "crates/iroha_core/src/exec_witness.rs";
const WITNESS_TAGS: &str = "crates/iroha_data_model/src/execution_witness.rs";

/// Witness key tags that only `#[cfg(test)]` recorders write, with the signature of the
/// recorder or key builder that uses the tag. No production block commits these keys.
const TEST_ONLY_WITNESS_TAGS: &[(&str, &str)] = &[
    (
        "AccountMetadata",
        "fn key_account_kv(id: &AccountId, key: &Name) -> Vec<u8> {",
    ),
    (
        "DomainMetadata",
        "fn key_domain_kv(id: &DomainId, key: &Name) -> Vec<u8> {",
    ),
    (
        "NftMetadata",
        "fn key_nft_kv(id: &NftId, key: &Name) -> Vec<u8> {",
    ),
    (
        "AssetDefinitionMetadata",
        "fn key_asset_def_kv(id: &AssetDefinitionId, key: &Name) -> Vec<u8> {",
    ),
    (
        "AssetBalance",
        "fn key_asset_balance(id: &AssetId) -> Vec<u8> {",
    ),
    (
        "AssetDefinitionTotalSupply",
        "fn key_asset_def_total(id: &AssetDefinitionId) -> Vec<u8> {",
    ),
    (
        "AccountRoleBinding",
        "pub fn record_read_from_access_key(state_block: &StateBlock<'_>, access_key: &str) {",
    ),
    (
        "Role",
        "pub fn record_read_from_access_key(state_block: &StateBlock<'_>, access_key: &str) {",
    ),
    (
        "AccountPermission",
        "pub fn record_read_from_access_key(state_block: &StateBlock<'_>, access_key: &str) {",
    ),
    (
        "RolePermission",
        "pub fn record_read_from_access_key(state_block: &StateBlock<'_>, access_key: &str) {",
    ),
];

/// The variants of `ExecutionWitnessKeyTagV1`, read from the data-model source.
fn witness_key_tags() -> Vec<String> {
    let text = source(WITNESS_TAGS);
    let (_, body) = text
        .split_once("pub enum ExecutionWitnessKeyTagV1 {")
        .expect("the data model declares the witness key tags");
    let (body, _) = body.split_once("\n}").expect("the tag enum ends");
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .map(|line| {
            line.split_once(" = 0x")
                .unwrap_or_else(|| panic!("a witness key tag without a value: {line}"))
                .0
                .to_owned()
        })
        .collect()
}

/// The registry fields that the SCCP write-set encoder covers, read from its source.
fn sccp_write_set_fields() -> Vec<String> {
    let text = source("crates/iroha_core/src/state.rs");
    let (_, body) = text
        .split_once("pub(crate) fn write_sccp_execution_delta<W: std::io::Write>(")
        .expect("State has the SCCP write-set encoder");
    let (body, _) = body
        .split_once("\n        Ok(())\n    }")
        .expect("the SCCP write-set encoder completes its exact stream");
    let fields: Vec<String> = ["cell!(", "storage!("]
        .into_iter()
        .flat_map(|invocation| {
            let (_, fields) = body
                .split_once(invocation)
                .expect("the SCCP encoder names its cell and storage fields");
            let (fields, _) = fields
                .split_once(");")
                .expect("the SCCP field invocation is complete");
            fields
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
        })
        .map(|name| {
            assert!(name.starts_with("sccp_"), "unexpected SCCP field: {name}");
            format!("world.{name}")
        })
        .collect();
    assert!(!fields.is_empty(), "the SCCP write set names no field");
    fields
}

/// Whether the item whose signature line contains `signature` carries `#[cfg(test)]`.
fn is_cfg_test_item(path: &str, signature: &str) -> bool {
    let text = source(path);
    let lines: Vec<&str> = text.lines().collect();
    let found: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains(signature))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(found.len(), 1, "{path} must hold exactly one: {signature}");
    lines[..found[0]]
        .iter()
        .rev()
        .map(|line| line.trim())
        .take_while(|line| line.starts_with("///") || line.starts_with("#["))
        .any(|line| line == "#[cfg(test)]")
}

/// The text of the item whose signature line contains `signature`, up to the line that
/// closes it at the same indentation.
fn item_body(path: &str, signature: &str) -> String {
    let text = source(path);
    let lines: Vec<&str> = text.lines().collect();
    let found: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains(signature))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(found.len(), 1, "{path} must hold exactly one: {signature}");
    let start = found[0];
    let indentation = &lines[start][..lines[start].len() - lines[start].trim_start().len()];
    let closing = format!("{indentation}}}");
    let length = lines[start..]
        .iter()
        .position(|line| *line == closing)
        .unwrap_or_else(|| panic!("{path}: the item {signature} does not close"));
    lines[start..=start + length].join("\n")
}

/// The identifiers that follow `world.` in a source text, with whitespace ignored.
fn world_accessors(text: &str) -> BTreeSet<String> {
    const MARKER: &str = "world.";
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let mut out = BTreeSet::new();
    let mut rest = compact.as_str();
    while let Some(at) = rest.find(MARKER) {
        rest = &rest[at + MARKER.len()..];
        let name: String = rest
            .chars()
            .take_while(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || *character == '_'
            })
            .collect();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

/// The canonical fields behind a registry field: the field itself, or the canonical
/// sources of a derived field.
fn canonical_sources(id: &str, out: &mut BTreeSet<&'static str>) {
    let mut fields = Vec::new();
    flatten(STATE_FIELDS, &mut fields);
    let field = fields
        .iter()
        .find(|field| field.id == id)
        .unwrap_or_else(|| panic!("unknown registry field {id}"));
    match field.role {
        Role::Derived { sources, .. } => {
            for source in sources {
                canonical_sources(source, out);
            }
        }
        _ => {
            out.insert(field.id);
        }
    }
}

/// The registry fields of one witness family. For a family with listed deriving
/// functions they are read from the source: the functions' World accessors must be
/// exactly the listed ones, and derived fields resolve to their canonical sources.
fn family_fields(family: &WitnessFamily) -> Vec<String> {
    if family.id == SCCP_FAMILY {
        return sccp_write_set_fields();
    }
    if family.derivation.is_empty() {
        return family
            .fields
            .iter()
            .map(|field| (*field).to_owned())
            .collect();
    }
    assert!(
        family.fields.is_empty(),
        "witness family {} lists fields and deriving functions",
        family.id
    );
    let mut read = BTreeSet::new();
    for (path, signature) in family.derivation {
        read.extend(world_accessors(&item_body(path, signature)));
    }
    let listed: BTreeSet<String> = family
        .accessors
        .iter()
        .map(|(accessor, _)| (*accessor).to_owned())
        .collect();
    assert_eq!(
        read, listed,
        "the deriving functions of witness family {} read other World accessors than listed",
        family.id
    );
    let mut fields = BTreeSet::new();
    for (_, access) in family.accessors {
        match access {
            Access::Field(id) => canonical_sources(id, &mut fields),
            Access::NoContent(reason) => assert!(!reason.is_empty(), "{}", family.id),
        }
    }
    fields.into_iter().map(str::to_owned).collect()
}

/// The fields of a struct, or the variants of an enum, declared at `declaration` in a
/// source text, as name and type text. A variant without a payload has an empty type; the
/// fields of a variant with named fields follow it as fields of the type. The declaration
/// occurs exactly once and ends at the closing line of its own indentation, so a type
/// declared inside a module is read as well.
fn declared_fields(text: &str, declaration: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let found: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains(declaration))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "the declaration must occur exactly once: {declaration}"
    );
    let start = found[0];
    let indentation = &lines[start][..lines[start].len() - lines[start].trim_start().len()];
    let closing = format!("{indentation}}}");
    let length = lines[start + 1..]
        .iter()
        .position(|line| *line == closing)
        .unwrap_or_else(|| panic!("the declaration does not end: {declaration}"));
    let mut out = Vec::new();
    let mut attribute = false;
    for line in lines[start + 1..=start + length]
        .iter()
        .map(|line| line.trim())
    {
        if attribute {
            attribute = !line.ends_with(']');
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if line.starts_with("#[") {
            attribute = !line.ends_with(']');
            continue;
        }
        let line = line.trim_end_matches(',');
        if line == "}" {
            // The end of a variant with named fields.
            continue;
        }
        let line = line.strip_suffix(" {").unwrap_or(line);
        let line = match line.strip_prefix("pub") {
            Some(rest) if rest.starts_with('(') => {
                rest.split_once(") ").map_or(line, |(_, declared)| declared)
            }
            Some(rest) if rest.starts_with(' ') => rest.trim_start(),
            _ => line,
        };
        if let Some((name, kind)) = line.split_once(": ") {
            out.push((name.to_owned(), kind.to_owned()));
        } else if let Some((name, kind)) = line.split_once('(') {
            out.push((name.to_owned(), kind.trim_end_matches(')').to_owned()));
        } else {
            out.push((line.to_owned(), String::new()));
        }
    }
    out
}

/// The name that a `pub struct X {` or `pub enum X {` declaration declares.
fn declared_name(declaration: &str) -> &str {
    declaration
        .trim_end_matches('{')
        .trim()
        .rsplit(' ')
        .next()
        .expect("a declaration names a type")
}

/// Whether a struct name of `crates/iroha_p2p` says that it is a record of the peer
/// handshake: a capability record (`..HandshakeCaps`, `ConsensusConfigCaps`), or a
/// `Handshake..` hello, metadata, digest or binding record. A trailing layout version
/// (`V1`, `V2`, ..) is not part of the role, so a later version of a walked record is a
/// handshake record as well.
fn is_handshake_record_name(name: &str) -> bool {
    let digits = name.trim_end_matches(|character: char| character.is_ascii_digit());
    let role = match digits.strip_suffix('V') {
        Some(unversioned) if digits.len() < name.len() => unversioned,
        _ => name,
    };
    role.ends_with("HandshakeCaps")
        || role == "ConsensusConfigCaps"
        || (role.starts_with("Handshake")
            && ["Hello", "Meta", "Digest", "Binding"]
                .iter()
                .any(|ending| role.ends_with(ending)))
}

#[test]
fn handshake_record_names_are_recognised_at_every_layout_version() {
    for name in [
        "ConsensusHandshakeCaps",
        "ConfidentialHandshakeCaps",
        "CryptoHandshakeCaps",
        "CryptoHandshakeCapsV2",
        "ConsensusConfigCaps",
        "ConsensusConfigCapsV3",
        "HandshakeHello",
        "HandshakeHelloV2",
        "HandshakeConsensusMeta",
        "HandshakeTrustMetaV12",
        "HandshakeConfidentialDigest",
        "HandshakeIdentityBindingV1",
        "HandshakeIdentityBindingV2",
        "HandshakeIdentityBinding",
    ] {
        assert!(is_handshake_record_name(name), "{name}");
    }
    for name in [
        "HandshakeError",
        "HandshakeBindingContext",
        "HandshakeState",
        "PeerBinding",
        "ConsensusCaps",
        "HandshakeV",
        "HandshakeHelloVersion",
        "V1",
    ] {
        assert!(!is_handshake_record_name(name), "{name}");
    }
}

/// Whether a field type carries a 32-byte hash, or a Merkle tree of such hashes.
fn is_hash_type(kind: &str) -> bool {
    kind.contains("Hash") || kind.contains("[u8; 32]") || kind.contains("MerkleTree")
}

/// Named types of a type text that are hashes themselves or hold no value of their own:
/// hashes, containers and primitive wrappers.
const PLAIN_TYPES: &[&str] = &[
    "Hash",
    "HashOf",
    "Hash32",
    "MerkleTree",
    "MerkleTreeCommitment",
    "Option",
    "Vec",
    "BTreeMap",
    "BTreeSet",
    "String",
    "Box",
    "Arc",
    "NonZeroU64",
];

/// Typed hashes: their type parameter names what is hashed and holds no value.
const TYPED_HASHES: &[&str] = &["HashOf", "MerkleTree", "MerkleTreeCommitment"];

/// Whether an identifier of a type text is a constant and not a type: a name in upper
/// snake case, as the array length in `[u8; Hash::LENGTH]`. A name of two or more characters
/// without a lowercase letter is a constant when it has an underscore or no digit; `T` and
/// `H256` are types.
fn is_constant_name(name: &str) -> bool {
    name.len() > 1
        && !name.chars().any(|character| character.is_ascii_lowercase())
        && (name.contains('_') || !name.chars().any(|character| character.is_ascii_digit()))
}

/// The named types in a type text. The type parameters of a typed hash are not values of
/// the field and are not named, and neither is a constant ([`is_constant_name`]).
fn named_types(kind: &str) -> Vec<&str> {
    let bytes = kind.as_bytes();
    let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if !is_identifier(bytes[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < bytes.len() && is_identifier(bytes[at]) {
            at += 1;
        }
        let name = &kind[start..at];
        if name.starts_with(|character: char| character.is_ascii_uppercase())
            && !is_constant_name(name)
        {
            out.push(name);
        }
        if TYPED_HASHES.contains(&name) && bytes.get(at) == Some(&b'<') {
            at = closing(bytes, at);
        }
    }
    out
}

/// What the value types of a witness family or of a protocol carrier hold that the
/// listing does not classify: hash-bearing fields that are not listed, named field types
/// that are neither walked nor declared opaque, and listed hash fields that the types no
/// longer have. A field is hash-bearing when its type carries a 32-byte hash
/// ([`is_hash_type`]) or names a type that is not walked and whose name says that it
/// carries one ([`HASH_TYPE_ENDINGS`]).
fn unclassified_value_fields(
    types: &[(&str, Vec<(String, String)>)],
    hashes: &[(&str, HashUse)],
    opaque: &[(&str, &str)],
) -> Vec<String> {
    let walked: BTreeSet<&str> = types.iter().map(|(name, _)| *name).collect();
    let mut found = BTreeSet::new();
    let mut out = Vec::new();
    for (name, fields) in types {
        for (field, kind) in fields {
            let id = format!("{name}.{field}");
            let named = named_types(kind);
            if is_hash_type(kind)
                || named
                    .iter()
                    .any(|named| !walked.contains(named) && is_hash_named(named))
            {
                if !hashes.iter().any(|(listed, _)| *listed == id) {
                    out.push(format!("unclassified hash field {id}: {kind}"));
                }
                found.insert(id.clone());
            }
            for named in named {
                if PLAIN_TYPES.contains(&named)
                    || walked.contains(named)
                    || is_hash_named(named)
                    || opaque.iter().any(|(listed, _)| *listed == named)
                {
                    continue;
                }
                out.push(format!("unclassified nested type {named} in {id}"));
            }
        }
    }
    for (listed, _) in hashes {
        if !found.contains(*listed) {
            out.push(format!("listed hash field {listed} is gone"));
        }
    }
    out
}

/// The value types of one witness family, read from their sources.
fn family_value_types(family: &WitnessFamily) -> Vec<(&'static str, Vec<(String, String)>)> {
    family
        .value_types
        .iter()
        .map(|(path, declaration)| {
            (
                declared_name(declaration),
                declared_fields(&source(path), declaration),
            )
        })
        .collect()
}

/// Check the witness families against the tag enum, their deriving functions and their
/// value types, and return, per registry field, the families that carry its content.
fn witnessed_fields() -> BTreeMap<String, Vec<&'static str>> {
    let tags = witness_key_tags();
    let mut owners: BTreeMap<&str, &str> = BTreeMap::new();
    for family in WITNESS_FAMILIES {
        for tag in family.tags {
            assert!(
                owners.insert(*tag, family.id).is_none(),
                "witness key tag {tag} is listed twice"
            );
        }
    }
    for (tag, signature) in TEST_ONLY_WITNESS_TAGS {
        assert!(
            owners.insert(*tag, "test only").is_none(),
            "witness key tag {tag} is listed twice"
        );
        assert!(
            is_cfg_test_item(WITNESS_RECORDER, signature),
            "the recorder of witness key tag {tag} is no longer test only: list its family"
        );
    }
    for tag in &tags {
        assert!(
            owners.contains_key(tag.as_str()),
            "witness key tag {tag} has no listed family: add it to WITNESS_FAMILIES or, if \
             only tests write it, to TEST_ONLY_WITNESS_TAGS"
        );
    }
    assert_eq!(owners.len(), tags.len(), "a listed witness key tag is gone");
    let mut witnessed: BTreeMap<String, Vec<&'static str>> = BTreeMap::new();
    let mut digests: BTreeMap<&str, &str> = BTreeMap::new();
    for family in WITNESS_FAMILIES {
        let fields = family_fields(family);
        assert!(
            !fields.is_empty() || !family.source.is_empty(),
            "witness family {} names neither its registry fields nor its source",
            family.id
        );
        for field in fields {
            witnessed.entry(field).or_default().push(family.id);
        }
        let unclassified =
            unclassified_value_fields(&family_value_types(family), family.hashes, family.opaque);
        assert!(
            unclassified.is_empty(),
            "witness family {} has unclassified value fields. Classify each hash-typed field \
             (a State digest with its ROOTS entry, or block content) and each nested type:\n{}",
            family.id,
            unclassified.join("\n")
        );
        let embedded: BTreeSet<&str> = family
            .hashes
            .iter()
            .filter_map(|(_, hash)| match hash {
                HashUse::State(root) => Some(*root),
                HashUse::Block(reason) => {
                    assert!(!reason.is_empty(), "{}", family.id);
                    None
                }
            })
            .collect();
        let listed: BTreeSet<&str> = family.digests.iter().copied().collect();
        assert!(
            embedded.is_subset(&listed) && (family.value_types.is_empty() || embedded == listed),
            "witness family {} lists other State digests than its value types hold",
            family.id
        );
        for digest in family.digests {
            let root = ROOTS
                .iter()
                .find(|root| root.id == *digest)
                .unwrap_or_else(|| panic!("{} embeds unlisted commitment {digest}", family.id));
            assert!(
                root.class.certified(),
                "{digest} is certified through {}",
                family.id
            );
            assert!(
                digests.insert(*digest, family.id).is_none(),
                "{digest} is embedded by two witness families"
            );
        }
    }
    for root in ROOTS {
        assert_eq!(
            root.class == RootClass::CertifiedWitnessValue,
            digests.contains_key(root.id) && root.class != RootClass::CertifiedStateRoot,
            "{}: a certified witness value is embedded by exactly one witness family",
            root.id
        );
    }
    witnessed
}

/// One protocol object that consensus, signed genesis or the peer handshake carries.
struct Carrier {
    id: &'static str,
    /// What the object is and who authenticates it.
    object: &'static str,
    /// The types of the object and their declared nested records, as source and
    /// declaration. Sources outside the two scanned crates are read as well.
    types: &'static [(&'static str, &'static str)],
    /// Every hash-bearing field of those types, as `Type.field`, and what it commits.
    hashes: &'static [(&'static str, HashUse)],
    /// Fields that embed a record of State content as a whole, with the listed commitment
    /// that owns the binding.
    embeds: &'static [(&'static str, &'static str)],
    /// Fields that carry a digest, or another value derived from State for comparison, in a
    /// type that the hash rules do not match (an integer), and what the value commits. A
    /// review found them: the hash-type rule cannot.
    reviewed: &'static [(&'static str, HashUse)],
    /// Fields without a hash-bearing type, each with what it carries and why it is no
    /// commitment over State content.
    content: &'static [(&'static str, &'static str)],
    /// Types whose every field is classified: under `hashes`, `embeds`, `reviewed` or
    /// `content`. A field added to one of them fails the check whatever its type.
    exhaustive: &'static [&'static str],
    /// Named types in fields of those types that are not walked, with the reason.
    opaque: &'static [(&'static str, &'static str)],
}

const HEADER_MODEL: &str = "crates/iroha_data_model/src/block/header.rs";
const CONSENSUS_MODEL: &str = "crates/iroha_data_model/src/block/consensus.rs";
const RESULT_MODEL: &str = "crates/iroha_data_model/src/sumeragi_finality/commitment.rs";
const CERTIFIED_RESULT_MODEL: &str =
    "crates/iroha_data_model/src/sumeragi_finality/certified_result.rs";
const EPOCH_GRAPH_MODEL: &str = "crates/iroha_data_model/src/sumeragi_finality/epoch_graph.rs";
const EPOCH_MODEL: &str = "crates/iroha_data_model/src/sumeragi/epoch.rs";
const BEACON_MODEL: &str = "crates/iroha_data_model/src/consensus.rs";
const CORE_MESSAGES: &str = "crates/iroha_sumeragi/src/message.rs";
const HANDSHAKE_CAPS: &str = "crates/iroha_p2p/src/lib.rs";
const HANDSHAKE_WIRE: &str = "crates/iroha_p2p/src/peer.rs";
const LANE_CORE: &str = "crates/iroha_core/src/sumeragi/lanes/mod.rs";
const BLOCK_MODEL: &str = "crates/iroha_data_model/src/block/mod.rs";
const PAYLOAD_MODEL: &str = "crates/iroha_data_model/src/block/payload.rs";
const DA_COMMITMENT_MODEL: &str = "crates/iroha_data_model/src/da/commitment.rs";
const DA_BUNDLE_MODEL: &str = "crates/iroha_data_model/src/da/commitment/commitment_bundle.rs";
const DA_POLICY_MODEL: &str = "crates/iroha_data_model/src/da/commitment/proof_policy.rs";
const DA_PIN_MODEL: &str = "crates/iroha_data_model/src/da/pin_intent.rs";
const CONTEXT_MODEL: &str = "crates/iroha_data_model/src/block/execution_context.rs";
const LANE_MODEL: &str = "crates/iroha_data_model/src/sumeragi_lanes.rs";
const AXT_MODEL: &str = "crates/iroha_data_model/src/nexus/axt.rs";
const FASTPQ_MODEL: &str = "crates/iroha_data_model/src/fastpq.rs";
const OUTPUT_MODEL: &str = "crates/iroha_data_model/src/block/execution_output.rs";

/// Why the three roots of a transfer SMT witness commit no State table.
const TRANSCRIPT_LOCAL_TREE: &str = "the FASTPQ transfer relation builds this tree from the balances of the transcript itself (crates/fastpq_prover); execution records the witness empty. It commits transcript-local balances and no State table";

/// Every consensus-carried type whose hash-bearing fields the drift test classifies: the
/// block header, the block payload and block result, the signed genesis consensus
/// parameters, the execution result `R`, every Sumeragi wire message, the lane batch and
/// lane result, the records of the peer handshake and the node's network envelope. A field
/// that carries a digest of State content names its [`ROOTS`] entry; every other
/// hash-bearing field says what content it commits.
const CARRIERS: &[Carrier] = &[
    Carrier {
        id: "block_header",
        object: "the header of every block (iroha_data_model BlockHeader), which the block hash and with it every vote and certificate bind",
        types: &[
            (HEADER_MODEL, "pub struct BlockHeader {"),
            (
                "crates/iroha_data_model/src/confidential.rs",
                "pub struct ConfidentialFeatureDigest {",
            ),
        ],
        hashes: &[
            (
                "BlockHeader.prev_block_hash",
                HashUse::Block("hash of the previous block header: the chain link"),
            ),
            (
                "BlockHeader.merkle_root",
                HashUse::Block("Merkle root of the block's transaction entrypoints"),
            ),
            (
                "BlockHeader.da_proof_policies_hash",
                HashUse::State("da_proof_policy_bundle_hash"),
            ),
            (
                "BlockHeader.da_commitments_hash",
                HashUse::Block(
                    "commitment of the DA commitment bundle carried in the block payload",
                ),
            ),
            (
                "BlockHeader.da_pin_intents_hash",
                HashUse::Block(
                    "commitment of the DA pin-intent bundle carried in the block payload",
                ),
            ),
            (
                "BlockHeader.npos_effects_hash",
                HashUse::Block("hash of the NPoS consensus effects carried in the block payload"),
            ),
            (
                "BlockHeader.execution_context_hash",
                HashUse::Block(
                    "hash of the execution context bundle carried in the block payload: per-transaction routing plans and the lane merge section",
                ),
            ),
            (
                "BlockHeader.global_beacon_pulse_hash",
                HashUse::Block(
                    "hash of a beacon pulse in the payload; native validation requires it to be absent",
                ),
            ),
            (
                "ConfidentialFeatureDigest.vk_set_hash",
                HashUse::State("confidential_feature_digest"),
            ),
            (
                "ConfidentialFeatureDigest.zk_policy_hash",
                HashUse::State("confidential_feature_digest"),
            ),
        ],
        embeds: &[(
            "BlockHeader.confidential_features",
            "confidential_feature_digest",
        )],
        reviewed: &[
            (
                "ConfidentialFeatureDigest.poseidon_params_id",
                HashUse::State("confidential_feature_digest"),
            ),
            (
                "ConfidentialFeatureDigest.pedersen_params_id",
                HashUse::State("confidential_feature_digest"),
            ),
        ],
        content: &[
            ("BlockHeader.height", "height of the block"),
            (
                "BlockHeader.creation_time_ms",
                "creation time of the block: the authenticated ledger time",
            ),
            (
                "BlockHeader.view_change_index",
                "view change index of the block",
            ),
            (
                "ConfidentialFeatureDigest.conf_rules_version",
                "version of the confidential rules compiled into the binary: a constant, no State content",
            ),
        ],
        exhaustive: &["BlockHeader", "ConfidentialFeatureDigest"],
        opaque: &[],
    },
    Carrier {
        id: "block_payload_and_result",
        object: "the body of every block (iroha_data_model SignedBlock): the payload, whose bundles the header hashes, and the result of execution, which R binds through the hash of the result-bearing block wire",
        types: &[
            (BLOCK_MODEL, "pub struct SignedBlock {"),
            (PAYLOAD_MODEL, "pub(crate) struct BlockPayload {"),
            (PAYLOAD_MODEL, "pub struct BlockResult {"),
            (DA_POLICY_MODEL, "pub struct DaProofPolicyBundle {"),
            (DA_POLICY_MODEL, "enum Storage {"),
            (DA_POLICY_MODEL, "struct CanonicalParts {"),
            (DA_COMMITMENT_MODEL, "pub struct DaProofPolicy {"),
            (DA_PIN_MODEL, "pub struct DaPinIntentBundle {"),
            (DA_PIN_MODEL, "pub struct DaPinIntent {"),
            (BEACON_MODEL, "pub struct NposConsensusEffects {"),
            (CONTEXT_MODEL, "pub struct BlockExecutionContextBundle {"),
            (CONTEXT_MODEL, "pub struct ExternalExecutionContext {"),
            (CONTEXT_MODEL, "pub struct ExternalExecutionRouteLeg {"),
            (LANE_MODEL, "pub struct SumeragiLaneMergeSection {"),
            (LANE_MODEL, "pub struct SumeragiLaneMerge {"),
            (AXT_MODEL, "pub struct AxtEnvelopeRecord {"),
            (AXT_MODEL, "pub struct AxtPolicySnapshot {"),
            (AXT_MODEL, "pub struct AxtPolicyBinding {"),
            (AXT_MODEL, "pub struct AxtPolicyEntry {"),
            (FASTPQ_MODEL, "pub struct TransferTranscript {"),
            (FASTPQ_MODEL, "pub struct TransferDeltaTranscript {"),
            (FASTPQ_MODEL, "pub struct TransferSmtWitness {"),
            (OUTPUT_MODEL, "pub enum ExecutionOutputV1 {"),
            (OUTPUT_MODEL, "pub struct NetworkExecutionOutputV1 {"),
            (OUTPUT_MODEL, "pub struct PipelineExecutionOutputV1 {"),
            (OUTPUT_MODEL, "pub struct TimeExecutionOutputV1 {"),
            // The name ends in `Root`: the root cause of a trigger failure, not a hash.
            (OUTPUT_MODEL, "pub enum TriggerFailureRootV1 {"),
        ],
        hashes: &[
            (
                "BlockResult.output_merkle",
                HashUse::Block(
                    "checked Merkle tree over the hashes of the block's typed outputs; its root and count are transaction_output_commitment of R",
                ),
            ),
            (
                "BlockResult.fastpq_transcripts",
                HashUse::Block(
                    "key of each transcript group: the execution-call hash of the call that emitted the transcripts",
                ),
            ),
            (
                "CanonicalParts.policy_hash",
                HashUse::State("da_proof_policy_bundle_hash"),
            ),
            (
                "DaPinIntent.manifest_hash",
                HashUse::Block("digest of the DA manifest that the pin intent registers"),
            ),
            (
                "ExternalExecutionContext.entrypoint_hash",
                HashUse::Block(
                    "hash of the external entrypoint that the routing context belongs to",
                ),
            ),
            (
                "ExternalExecutionContext.routing_plan_digest",
                HashUse::Block(
                    "digest of the routing plan of one input: its lane and dataspace identifiers, or its native AMX plan. Validators re-derive each input's route from the State routing inputs and reject on a difference: a per-input decision, not a summary of a State table",
                ),
            ),
            (
                "SumeragiLaneMerge.incarnation",
                HashUse::Block(
                    "incarnation identifier of the merged lane, validated against the lane cell",
                ),
            ),
            (
                "SumeragiLaneMerge.tip_hash",
                HashUse::Block(
                    "core block hash of the last merged lane block: a reference to a certified lane block",
                ),
            ),
            (
                "SumeragiLaneMerge.tip_result",
                HashUse::Block(
                    "certified result R of the last merged lane block, whose fields the lane_result carrier classifies",
                ),
            ),
            (
                "AxtPolicyEntry.manifest_root",
                HashUse::State("axt_policy_snapshot"),
            ),
            (
                "TransferTranscript.batch_hash",
                HashUse::Block(
                    "execution-call or native protocol-purpose hash of the call that emitted the transcript",
                ),
            ),
            (
                "TransferTranscript.authority_digest",
                HashUse::Block("digest of the account identifier of the authority of the call"),
            ),
            (
                "TransferTranscript.poseidon_preimage_digest",
                HashUse::Block(
                    "Poseidon digest of the transfer's own preimage: accounts, asset, amount and batch hash",
                ),
            ),
            (
                "TransferSmtWitness.root_before",
                HashUse::Block(TRANSCRIPT_LOCAL_TREE),
            ),
            (
                "TransferSmtWitness.root_after",
                HashUse::Block(TRANSCRIPT_LOCAL_TREE),
            ),
            (
                "TransferSmtWitness.siblings",
                HashUse::Block(TRANSCRIPT_LOCAL_TREE),
            ),
        ],
        embeds: &[
            (
                "BlockPayload.da_proof_policies",
                "da_proof_policy_bundle_hash",
            ),
            (
                "BlockPayload.global_beacon_pulse",
                "consensus_authority_binding",
            ),
            ("BlockResult.axt_policy_snapshot", "axt_policy_snapshot"),
        ],
        reviewed: &[(
            "AxtPolicySnapshot.version",
            HashUse::State("axt_policy_snapshot"),
        )],
        content: &[
            (
                "SignedBlock.signatures",
                "validator signatures over the block header",
            ),
            (
                "SignedBlock.payload",
                "the block payload: walked as BlockPayload",
            ),
            (
                "SignedBlock.result",
                "the result of execution: walked as BlockResult. Proposals carry none",
            ),
            (
                "SignedBlock.commit_certificate",
                "the finality artifacts of a committed block as canonical bytes: the core header and CommitQC (carrier consensus_messages), the preimage of R (carrier execution_result) and the availability signatures. The block hash, the proposal wire and the executed block wire hash do not cover it",
            ),
            (
                "BlockPayload.header",
                "the block header: walked under the block_header carrier",
            ),
            (
                "BlockPayload.external_entrypoints",
                "the network inputs of the block as their authors signed them; BlockHeader.merkle_root commits their hashes",
            ),
            (
                "BlockPayload.da_commitments",
                "proposal input: DA commitment records, committed by BlockHeader.da_commitments_hash",
            ),
            (
                "BlockPayload.da_pin_intents",
                "proposal input: signed DA pin intents, committed by BlockHeader.da_pin_intents_hash",
            ),
            (
                "BlockPayload.npos_consensus_effects",
                "proposal input: the parent service CommitQC, admitted evidence and penalty actions, hashed by BlockHeader.npos_effects_hash. Execution applies it; the block overlay keeps the hash of what it applied and the apply path compares the two",
            ),
            (
                "BlockPayload.execution_context",
                "the routing context of every input and the lane merge section, hashed by BlockHeader.execution_context_hash. Validators re-derive each input's route from the State routing inputs and reject on a difference: per-input decisions, not a summary of a State table",
            ),
            (
                "BlockExecutionContextBundle.lane_merge",
                "the lane blocks that the global block merges: references to certified lane blocks, validated against the lane cell",
            ),
            (
                "BlockResult.outputs",
                "one typed output per executed input or internal invocation: execution results, whose hashes are the leaves of output_merkle",
            ),
            (
                "BlockResult.committed_fragment_count",
                "number of successful execution fragments: an execution result that validators compare with their own count",
            ),
            (
                "BlockResult.axt_envelopes",
                "the AXT envelopes that execution completed: execution results, which the apply path replays into the AXT replay ledger",
            ),
            (
                "BlockResult.axt_transitioned_dataspaces",
                "the dataspaces whose AXT authorization changed during the block. Validators compare it with the executor's block-scoped set, which is no State field, and the apply path installs it into that block-scoped set",
            ),
        ],
        exhaustive: &["SignedBlock", "BlockPayload", "BlockResult"],
        opaque: &[
            (
                "BlockHeader",
                "the block header: walked under the block_header carrier",
            ),
            (
                "DaCommitmentBundle",
                "the immutable DA commitment bundle: its exact custody wrapper, canonical contents and record hashes are walked under the da_commitment_bundle carrier",
            ),
            (
                "BlockSignatures",
                "validator signatures over the block header",
            ),
            (
                "CommitCertificate",
                "finality artifacts as canonical bytes: the core header and CommitQC are walked under consensus_messages and the preimage of R under execution_result; the availability signatures sign the payload frame",
            ),
            (
                "TransactionEntrypoint",
                "network inputs as their authors signed them: transactions, sealed commitments and reveals. A State value that a transaction names is an expected-value precondition (other_domains and state_hash_functions, use precondition)",
            ),
            (
                "FinalizedGlobalThresholdBeaconPulseV1",
                "the finalized beacon pulse: walked under the execution_result carrier, where R embeds it",
            ),
            (
                "ChargedShared",
                "allocation custody wrapper of the admitted bundle: it holds exactly the canonical parts",
            ),
            (
                "RetainedPayload",
                "allocation custody wrapper of the admitted bundle: it holds exactly the canonical parts",
            ),
            ("LaneId", "lane identifier"),
            ("DataSpaceId", "dataspace identifier"),
            ("DaProofScheme", "enumeration without a hash payload"),
            (
                "StorageTicketId",
                "identifier of the storage ticket of the blob",
            ),
            (
                "DaIngestAuthorizationV1",
                "account authorization and quota charge identity of the DA ingest, signed by the account: proposal input",
            ),
            (
                "DaPinScopeAuthorizationV1",
                "producer signatures over the ticket, manifest and alias scope of the pin intent: proposal input",
            ),
            (
                "Evidence",
                "consensus evidence as admitted: the signed messages of the offence. Proposal input",
            ),
            (
                "NposPenaltyAction",
                "penalty or marker action that the block applies: proposal input, validated by execution",
            ),
            (
                "ExternalExecutionRouteRole",
                "enumeration without a hash payload",
            ),
            (
                "AxtBinding",
                "identifier of the AXT: the hash of its descriptor",
            ),
            (
                "AxtDescriptor",
                "the AXT descriptor as its transaction declared it: dataspaces and touch specifications",
            ),
            (
                "AxtTouchFragment",
                "touch manifest of one dataspace: the keys the AXT read and wrote",
            ),
            (
                "AxtProofFragment",
                "proof blob of one dataspace as its transaction carried it",
            ),
            (
                "AxtAnchoredSpendV1",
                "issuer-signed source-anchored spend as its transaction carried it: the handle, the intent, the proof, the claimed source receipt and occurrence and the finalized source anchor. Execution resolves the anchor against finalized State; the binding is the subject of A.1 and is no digest that this block computes over State",
            ),
            ("AccountId", "account identifier"),
            ("AssetDefinitionId", "asset definition identifier"),
            ("Quantity", "amount or balance of the transfer"),
            (
                "TransactionResult",
                "result of one executed input or invocation: its data trigger sequence or its rejection reason",
            ),
            (
                "InvocationCompletionV1",
                "completion of one callback of an invocation: the trigger identifier and the outcome",
            ),
            (
                "PipelineInvocationV1",
                "the internal invocation that produced the output: its trigger, event and source",
            ),
            (
                "TimeInvocationV1",
                "the time invocation that produced the output: its trigger and event",
            ),
            (
                "ExecutionStep",
                "one instruction or call of a failed trigger, named as the root cause of the failure",
            ),
        ],
    },
    Carrier {
        id: "signed_genesis_consensus_parameters",
        object: "the consensus parameters and the handshake metadata signed into genesis",
        types: &[
            (CONSENSUS_MODEL, "pub struct ConsensusGenesisParams {"),
            (CONSENSUS_MODEL, "pub enum ConsensusGenesisModeParams {"),
            (CONSENSUS_MODEL, "pub struct NposGenesisParams {"),
            (
                CONSENSUS_MODEL,
                "pub struct SumeragiGenesisContextParameters {",
            ),
            (
                "crates/iroha_data_model/src/parameter/system.rs",
                "pub struct ConsensusHandshakeMetadata {",
            ),
        ],
        hashes: &[
            (
                "NposGenesisParams.epoch_seed",
                HashUse::Block("signed initial seed of leader and validator selection"),
            ),
            (
                "SumeragiGenesisContextParameters.nexus_amx_context_hash",
                HashUse::State("nexus_amx_context_digest"),
            ),
            (
                "SumeragiGenesisContextParameters.execution_policy_hash",
                HashUse::State("execution_policy_digest"),
            ),
            (
                "ConsensusHandshakeMetadata.consensus_fingerprint",
                HashUse::Block(
                    "fingerprint of the signed genesis consensus parameters themselves, which include the two State digests above",
                ),
            ),
        ],
        embeds: &[],
        reviewed: &[],
        content: &[
            (
                "SumeragiGenesisContextParameters.root_scope",
                "execution scope and kind of the root instance, selected by signed genesis",
            ),
            (
                "SumeragiGenesisContextParameters.da_layout",
                "payload availability geometry: numbers",
            ),
        ],
        exhaustive: &["SumeragiGenesisContextParameters"],
        opaque: &[
            ("Quantity", "bond amount"),
            (
                "SumeragiRootScope",
                "scope of the root instance; a dataspace scope names the parent network by its genesis hash",
            ),
            (
                "DataAvailabilityLayout",
                "payload availability geometry: numbers",
            ),
            (
                "SumeragiConsensusMode",
                "enumeration without a hash payload",
            ),
        ],
    },
    Carrier {
        id: "execution_result",
        object: "R = raw SHA-256(RESULT_TAG ‖ original fixed X ‖ H_iroha(RESULT_BODY_TAG ‖ canonical Norito body)); stored preimage is X ‖ body, and every commit vote and certificate binds this complete result",
        types: &[
            (CERTIFIED_RESULT_MODEL, "pub struct CertifiedResultV1 {"),
            (
                CERTIFIED_RESULT_MODEL,
                "pub struct SccpFinalityHeaderFieldsV1 {",
            ),
            (RESULT_MODEL, "pub struct ExecutionResultCommitment {"),
            (RESULT_MODEL, "pub struct ExecutionCommitment {"),
            (EPOCH_GRAPH_MODEL, "pub struct ScheduleOutcome {"),
            (EPOCH_GRAPH_MODEL, "pub enum ScheduledSlot {"),
            (EPOCH_GRAPH_MODEL, "pub struct ScheduledConfig {"),
            (EPOCH_MODEL, "pub struct ValidatorEpochContextV1 {"),
            (EPOCH_MODEL, "pub struct ValidatorEpochBoundaryV1 {"),
            (EPOCH_MODEL, "pub struct ValidatorCommitteeMemberV1 {"),
            (
                "crates/iroha_data_model/src/sumeragi/epoch/authorization.rs",
                "pub struct ValidatorEpochAuthorizationV1 {",
            ),
            (
                "crates/iroha_data_model/src/sumeragi/epoch/authorization.rs",
                "pub enum BeaconEpochBindingV1 {",
            ),
            (
                "crates/iroha_data_model/src/sumeragi/epoch/authorization.rs",
                "pub struct InstalledBeaconEpochBindingV1 {",
            ),
            (
                "crates/iroha_data_model/src/nexus/committee.rs",
                "pub struct ValidatorCommitteePreparationV1 {",
            ),
            (
                "crates/iroha_data_model/src/nexus/committee.rs",
                "pub struct ValidatorElectionPolicyV1 {",
            ),
            (
                BEACON_MODEL,
                "pub struct FinalizedGlobalThresholdBeaconPulseV1 {",
            ),
            (
                BEACON_MODEL,
                "pub struct GlobalThresholdBeaconPulseContextV1 {",
            ),
            (
                BEACON_MODEL,
                "pub struct GlobalThresholdBeaconChainAnchorV1 {",
            ),
            (
                "crates/iroha_data_model/src/sumeragi_finality/native_lanes.rs",
                "pub struct NativeLaneStateProof {",
            ),
            (
                "crates/iroha_data_model/src/sumeragi_finality/lane_state_commitment.rs",
                "pub struct SumeragiLaneStateCommitment {",
            ),
        ],
        hashes: &[
            (
                "SccpFinalityHeaderFieldsV1.network_id",
                HashUse::Block("original signed-genesis network identity"),
            ),
            (
                "SccpFinalityHeaderFieldsV1.sccp_root",
                HashUse::State("sccp_block_message_root"),
            ),
            (
                "SccpFinalityHeaderFieldsV1.history_root",
                HashUse::State("sccp_certified_history_root"),
            ),
            (
                "SccpFinalityHeaderFieldsV1.committee_root",
                HashUse::State("sccp_generation_committee_root"),
            ),
            (
                "SccpFinalityHeaderFieldsV1.next_committee_root",
                HashUse::State("sccp_generation_committee_root"),
            ),
            (
                "ExecutionCommitment.parent_state_root",
                HashUse::State("execution_witness_roots"),
            ),
            (
                "ExecutionCommitment.post_state_root",
                HashUse::State("execution_witness_roots"),
            ),
            (
                "ExecutionCommitment.ordinary_writes_root",
                HashUse::State("execution_witness_roots"),
            ),
            (
                "ExecutionCommitment.parent_world_state_root",
                HashUse::State("world_state_root"),
            ),
            (
                "ExecutionCommitment.world_state_root",
                HashUse::State("world_state_root"),
            ),
            (
                "ExecutionCommitment.event_commitment",
                HashUse::Block("Merkle root and count of the events the block emitted"),
            ),
            (
                "ExecutionCommitment.executed_block_wire_hash",
                HashUse::Block("hash of the result-bearing block wire"),
            ),
            (
                "ExecutionCommitment.transaction_input_commitment",
                HashUse::Block("Merkle commitment of the block's network inputs"),
            ),
            (
                "ExecutionCommitment.transaction_output_commitment",
                HashUse::Block("Merkle commitment of the block's typed outputs"),
            ),
            (
                "ScheduledSlot.predecessor_context_id",
                HashUse::State("consensus_authority_binding"),
            ),
            (
                "ValidatorEpochAuthorizationV1.authority_id",
                HashUse::State("consensus_authority_binding"),
            ),
            (
                "ValidatorEpochAuthorizationV1.previous_authorization_id",
                HashUse::State("consensus_authority_binding"),
            ),
            (
                "ValidatorEpochAuthorizationV1.transition_id",
                HashUse::State("consensus_authority_binding"),
            ),
            (
                "InstalledBeaconEpochBindingV1.session_id",
                HashUse::Block("identifier of the exact installed threshold-beacon session"),
            ),
            (
                "InstalledBeaconEpochBindingV1.transcript_hash",
                HashUse::Block("commitment to the complete original target DKG transcript"),
            ),
            (
                "ValidatorCommitteePreparationV1.selection_anchor",
                HashUse::Block(
                    "hash of the committed parent that supplied the frozen election inputs",
                ),
            ),
            (
                "ValidatorCommitteePreparationV1.preparing_authorization_id",
                HashUse::State("consensus_authority_binding"),
            ),
            (
                "ValidatorCommitteePreparationV1.election_seed",
                HashUse::Block("election randomness derived from the authenticated boundary pulse"),
            ),
            (
                "ValidatorEpochContextV1.leader_seed",
                HashUse::Block(
                    "leader-selection seed of the epoch, a field of the embedded epoch context",
                ),
            ),
            (
                "ValidatorEpochBoundaryV1.predecessor_context_id",
                HashUse::State("consensus_authority_binding"),
            ),
            (
                "ValidatorEpochBoundaryV1.selection_anchor",
                HashUse::Block("hash of the block that anchors the committee selection"),
            ),
            (
                "FinalizedGlobalThresholdBeaconPulseV1.session_id",
                HashUse::Block("identifier of the beacon key session"),
            ),
            (
                "FinalizedGlobalThresholdBeaconPulseV1.roster_hash",
                HashUse::Block(
                    "hash of the roster of the beacon key session: a field of the session record",
                ),
            ),
            (
                "FinalizedGlobalThresholdBeaconPulseV1.transcript_hash",
                HashUse::Block("hash of the DKG transcript of the beacon key session"),
            ),
            (
                "FinalizedGlobalThresholdBeaconPulseV1.seed",
                HashUse::Block("the pulse output"),
            ),
            (
                "FinalizedGlobalThresholdBeaconPulseV1.pulse_id",
                HashUse::Block("identifier of the pulse"),
            ),
            (
                "GlobalThresholdBeaconPulseContextV1.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "GlobalThresholdBeaconPulseContextV1.epoch_context_id",
                HashUse::State("consensus_authority_binding"),
            ),
            (
                "GlobalThresholdBeaconPulseContextV1.parent_consensus_hash",
                HashUse::Block("hash of the parent consensus header"),
            ),
            (
                "GlobalThresholdBeaconPulseContextV1.parent_result",
                HashUse::Block("R of the parent block"),
            ),
            (
                "GlobalThresholdBeaconChainAnchorV1.block_hash",
                HashUse::Block("hash of the finalized block that anchors the pulse"),
            ),
            (
                "NativeLaneStateProof.siblings",
                HashUse::Block("sibling hashes of the fixed-key path under ordinary_writes_root"),
            ),
            (
                "SumeragiLaneStateCommitment.state_hash",
                HashUse::State("native_lane_state_commitment"),
            ),
        ],
        embeds: &[
            (
                "ExecutionResultCommitment.schedule",
                "consensus_authority_binding",
            ),
            (
                "ExecutionResultCommitment.beacon",
                "consensus_authority_binding",
            ),
            (
                "ExecutionResultCommitment.native_lanes",
                "native_lane_state_commitment",
            ),
        ],
        reviewed: &[],
        content: &[
            (
                "CertifiedResultV1.header",
                "original fixed 221-byte X; every decoded field is walked as SccpFinalityHeaderFieldsV1",
            ),
            (
                "CertifiedResultV1.commitment",
                "canonical Norito body; every field is walked as ExecutionResultCommitment",
            ),
            (
                "SccpFinalityHeaderFieldsV1.height",
                "same carrier native height",
            ),
            (
                "SccpFinalityHeaderFieldsV1.timestamp_ms",
                "same carrier signed creation time",
            ),
            (
                "SccpFinalityHeaderFieldsV1.flags",
                "active/rotation bits; no other bit is admitted",
            ),
            (
                "SccpFinalityHeaderFieldsV1.message_count",
                "number of ordered SCCP leaves at this height",
            ),
            (
                "SccpFinalityHeaderFieldsV1.history_size",
                "size of the certified append-only history",
            ),
            (
                "SccpFinalityHeaderFieldsV1.generation",
                "outgoing committee generation identifier",
            ),
            (
                "SccpFinalityHeaderFieldsV1.validity_ms",
                "successor trust duration only on a rotation",
            ),
            ("ExecutionResultCommitment.height", "height of the block"),
            (
                "ExecutionResultCommitment.execution",
                "the execution commitment: walked as ExecutionCommitment",
            ),
            (
                "ExecutionCommitment.executed_block_wire_len",
                "byte length of the result-bearing block wire",
            ),
            (
                "ValidatorCommitteeMemberV1.validator",
                "exact canonical BLS-normal peer identity",
            ),
            (
                "ValidatorCommitteeMemberV1.proof_of_possession",
                "original BLS proof of possession for this exact peer",
            ),
            (
                "ValidatorEpochAuthorizationV1.version",
                "sole first-release authorization layout version",
            ),
            (
                "ValidatorEpochAuthorizationV1.network_id",
                "genesis-derived network of the authorized generation",
            ),
            (
                "ValidatorEpochAuthorizationV1.epoch",
                "monotonic scheduling epoch",
            ),
            (
                "ValidatorEpochAuthorizationV1.first_height",
                "inclusive first height of this authorization",
            ),
            (
                "ValidatorEpochAuthorizationV1.last_height",
                "inclusive last height of this authorization",
            ),
            (
                "ValidatorEpochAuthorizationV1.authority_generation",
                "scalar generation of the exact ordered BLS committee",
            ),
            (
                "ValidatorEpochAuthorizationV1.beacon",
                "exact beacon authority, walked as BeaconEpochBindingV1",
            ),
            (
                "ValidatorEpochAuthorizationV1.decision",
                "incumbent-certified scheduling disposition",
            ),
            (
                "BeaconEpochBindingV1.Bootstrap",
                "explicit signed-genesis bootstrap state",
            ),
            (
                "BeaconEpochBindingV1.Installed",
                "exact installed beacon binding, walked as InstalledBeaconEpochBindingV1",
            ),
            (
                "ValidatorCommitteePreparationV1.version",
                "sole first-release preparation layout version",
            ),
            (
                "ValidatorCommitteePreparationV1.network_id",
                "genesis-derived network of the frozen election",
            ),
            (
                "ValidatorCommitteePreparationV1.selection_epoch",
                "epoch whose final prestate supplied the election",
            ),
            (
                "ValidatorCommitteePreparationV1.selection_height",
                "boundary height whose incumbent quorum froze the election",
            ),
            (
                "ValidatorCommitteePreparationV1.target_epoch",
                "immutable target scheduling epoch",
            ),
            (
                "ValidatorCommitteePreparationV1.first_height",
                "inclusive target activation height",
            ),
            (
                "ValidatorCommitteePreparationV1.last_height",
                "inclusive end of the target scheduling interval",
            ),
            (
                "ValidatorCommitteePreparationV1.authority_generation",
                "successor scalar generation for the exact frozen committee",
            ),
            (
                "ValidatorCommitteePreparationV1.eligibility",
                "exact signed eligibility policy, walked as ValidatorElectionPolicyV1",
            ),
            (
                "ValidatorCommitteePreparationV1.committee",
                "complete ordered target BLS roster and original proofs of possession",
            ),
            (
                "ValidatorElectionPolicyV1.xor_asset_definition_id",
                "canonical XOR asset identity authenticated by the selecting network",
            ),
            (
                "ValidatorElectionPolicyV1.asset_scope",
                "frozen global custody bucket",
            ),
            (
                "ValidatorElectionPolicyV1.asset_scale",
                "frozen canonical XOR precision",
            ),
            (
                "ValidatorElectionPolicyV1.min_self_bond",
                "exact frozen minimum self-bond quantity",
            ),
            (
                "ValidatorElectionPolicyV1.min_nomination_bond",
                "exact frozen minimum nomination quantity",
            ),
            (
                "ValidatorElectionPolicyV1.max_validators",
                "bounded equal-vote committee selection ceiling",
            ),
            (
                "ValidatorElectionPolicyV1.epoch_length_blocks",
                "complete target scheduling interval length",
            ),
        ],
        exhaustive: &[
            "CertifiedResultV1",
            "SccpFinalityHeaderFieldsV1",
            "ExecutionResultCommitment",
            "ExecutionCommitment",
            "ValidatorCommitteeMemberV1",
            "ValidatorEpochAuthorizationV1",
            "BeaconEpochBindingV1",
            "InstalledBeaconEpochBindingV1",
            "ValidatorCommitteePreparationV1",
            "ValidatorElectionPolicyV1",
        ],
        opaque: &[
            (
                "SccpFinalityHeaderV1",
                "validated inline fixed X bytes; its complete field layout is exhaustively walked through SccpFinalityHeaderFieldsV1 and bound by the release wire identity",
            ),
            ("ChainParamsRecord", "chain parameters: numbers"),
            ("NetworkId", "network identity fixed at genesis"),
            ("ConsensusMode", "enumeration without a hash payload"),
            (
                "PeerId",
                "exact BLS public-key identity of one ordered validator seat",
            ),
            (
                "ValidatorEpochDecisionV1",
                "closed scalar scheduling-disposition enumeration without a hash payload",
            ),
            (
                "AssetDefinitionId",
                "canonical identity of the frozen XOR definition, not a State digest",
            ),
            (
                "AssetBalanceScope",
                "global or dataspace custody identifier, not a State digest",
            ),
            ("Quantity", "canonical fixed-scale stake quantity"),
            (
                "DataAvailabilityLayout",
                "payload availability geometry: numbers",
            ),
        ],
    },
    Carrier {
        id: "consensus_messages",
        object: "every message that travels between consensus nodes (crates/iroha_sumeragi WireMessage): the core header, proposal, vote, QC, timeout vote and timeout certificate, the status, synchronization and payload messages and the application control partial",
        types: &[
            (CORE_MESSAGES, "pub struct BlockHeader {"),
            ("crates/iroha_sumeragi/src/types.rs", "pub struct EpochId {"),
            (CORE_MESSAGES, "pub struct Vote {"),
            (CORE_MESSAGES, "pub struct Qc {"),
            (CORE_MESSAGES, "pub struct TimeoutVote {"),
            (CORE_MESSAGES, "pub struct TimeoutCert {"),
            (CORE_MESSAGES, "pub struct TcEntry {"),
            // Everything that travels between consensus nodes: the walk starts at the
            // enumeration of the wire messages, so a new message is walked or declared.
            (CORE_MESSAGES, "pub enum WireMessage {"),
            (CORE_MESSAGES, "pub struct ProposalMessage {"),
            (CORE_MESSAGES, "pub struct Proposal {"),
            (CORE_MESSAGES, "pub struct PayloadManifest {"),
            (CORE_MESSAGES, "pub struct Status {"),
            (CORE_MESSAGES, "pub struct Echo {"),
            (CORE_MESSAGES, "pub struct SyncRequest {"),
            (CORE_MESSAGES, "pub struct SyncEntry {"),
            (CORE_MESSAGES, "pub struct SyncResponse {"),
            (CORE_MESSAGES, "pub struct PayloadRequest {"),
            (CORE_MESSAGES, "pub struct PayloadChunk {"),
            (CORE_MESSAGES, "pub struct ApplicationControl {"),
            (
                "crates/iroha_sumeragi/src/api.rs",
                "pub struct ApplicationControlContext {",
            ),
        ],
        hashes: &[
            (
                "BlockHeader.instance",
                HashUse::Block(
                    "consensus instance identifier, derived from the signed genesis scope, the network identity and the chain identity",
                ),
            ),
            (
                "BlockHeader.parent_hash",
                HashUse::Block("hash of the parent consensus header"),
            ),
            (
                "BlockHeader.parent_result",
                HashUse::Block(
                    "R of the parent block, which binds the fields of the execution_result carrier",
                ),
            ),
            (
                "BlockHeader.payload_hash",
                HashUse::Block("hash of the block payload"),
            ),
            (
                "BlockHeader.availability_digest",
                HashUse::Block("digest of the payload availability frame"),
            ),
            (
                "EpochId.context",
                HashUse::State("consensus_authority_binding"),
            ),
            (
                "Vote.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "Vote.block_hash",
                HashUse::Block("hash of the consensus header voted on"),
            ),
            ("Vote.result", HashUse::Block("R of the block voted on")),
            (
                "Qc.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "Qc.block_hash",
                HashUse::Block("hash of the certified consensus header"),
            ),
            ("Qc.result", HashUse::Block("R of the certified block")),
            (
                "TimeoutVote.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "TimeoutCert.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "Proposal.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "Status.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "Status.proposal_hash",
                HashUse::Block("hash of the consensus header that the sender holds or wants"),
            ),
            (
                "SyncRequest.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "SyncResponse.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "PayloadRequest.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "PayloadRequest.block_hash",
                HashUse::Block("hash of the consensus header whose payload is requested"),
            ),
            (
                "PayloadChunk.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "PayloadChunk.block_hash",
                HashUse::Block("hash of the consensus header that the payload row belongs to"),
            ),
            (
                "ApplicationControlContext.instance",
                HashUse::Block("consensus instance identifier"),
            ),
            (
                "ApplicationControlContext.parent_hash",
                HashUse::Block("hash of the applied parent consensus header"),
            ),
            (
                "ApplicationControlContext.parent_result",
                HashUse::Block("R of the applied parent block"),
            ),
        ],
        embeds: &[],
        reviewed: &[],
        content: &[("EpochId.epoch", "number of the scheduling epoch")],
        exhaustive: &["EpochId"],
        opaque: &[
            ("ValidatorIndex", "index of a validator in the committee"),
            ("PublicKey", "validator public key"),
            (
                "ControlWitness",
                "opaque application control bytes of the header: the beacon pulse that execution verifies and that R then binds",
            ),
            ("VoteKind", "enumeration without a hash payload"),
            ("Signature", "signature"),
            ("Bitmap", "signer bitmap"),
            ("AggregateSignature", "aggregate signature"),
            (
                "AvailabilityFrame",
                "signed availability metadata of the payload rows; the header binds it through availability_digest",
            ),
            ("RowBytes", "bytes of one payload row"),
        ],
    },
    Carrier {
        id: "lane_result",
        object: "the payload and the result of every lane block: the transaction batch whose canonical bytes are the block payload that the lane header's payload hash binds (LaneBatch), and R = H(LANE_RESULT_TAG ‖ norito(LaneResult)), which the votes and certificates of the lane instance bind",
        types: &[
            (LANE_CORE, "pub struct LaneBatch {"),
            (LANE_CORE, "pub struct LaneResult {"),
        ],
        hashes: &[
            (
                "LaneBatch.anchor_hash",
                HashUse::Block("hash of the global block that anchors the lane batch"),
            ),
            (
                "LaneResult.anchor_hash",
                HashUse::Block("hash of the global block that anchors the lane block"),
            ),
            (
                "LaneResult.tx_hashes",
                HashUse::Block("entrypoint hashes of the admitted transactions"),
            ),
            (
                "LaneResult.next_committee_digest",
                HashUse::State("lane_authority_binding"),
            ),
        ],
        embeds: &[("LaneResult.next_params", "lane_authority_binding")],
        reviewed: &[],
        content: &[
            (
                "LaneBatch.anchor_height",
                "height of the global block that anchors the lane batch",
            ),
            (
                "LaneBatch.transactions",
                "the signed transactions of the lane block, in lane order: block content that admission checks and the global merge executes",
            ),
            (
                "LaneResult.anchor_height",
                "height of the global block that anchors the lane block",
            ),
            (
                "LaneResult.payload_bytes",
                "payload length of the lane block",
            ),
        ],
        exhaustive: &["LaneBatch", "LaneResult"],
        opaque: &[
            (
                "SignedTransaction",
                "a network input as its author signed it, as the transaction entrypoints of the block_payload_and_result carrier. A State value that a transaction names is an expected-value precondition (other_domains and state_hash_functions, use precondition)",
            ),
            ("ChainParamsRecord", "chain parameters: numbers"),
        ],
    },
    Carrier {
        id: "peer_handshake",
        object: "the hello record that peers exchange in the handshake (crates/iroha_p2p) with its consensus, confidential, crypto and trust metadata and its wire digest, the identity binding that the hello signature covers, and the consensus, confidential and crypto capabilities that a node is configured with and compares the metadata against. The SoraNet transport delegation that authenticates the transport keys before the hello is not part of it",
        types: &[
            (HANDSHAKE_CAPS, "pub struct ConsensusHandshakeCaps {"),
            (HANDSHAKE_CAPS, "pub struct ConsensusConfigCaps {"),
            (HANDSHAKE_CAPS, "pub struct ConfidentialHandshakeCaps {"),
            (HANDSHAKE_CAPS, "pub struct CryptoHandshakeCaps {"),
            (HANDSHAKE_WIRE, "pub(super) struct HandshakeHello {"),
            (HANDSHAKE_WIRE, "pub(super) struct HandshakeConsensusMeta {"),
            (
                HANDSHAKE_WIRE,
                "pub(super) struct HandshakeConfidentialMeta {",
            ),
            (HANDSHAKE_WIRE, "pub(super) struct HandshakeCryptoMeta {"),
            (HANDSHAKE_WIRE, "pub(super) struct HandshakeTrustMeta {"),
            (
                HANDSHAKE_WIRE,
                "pub(super) struct HandshakeConfidentialDigest {",
            ),
            (HANDSHAKE_WIRE, "struct HandshakeIdentityBindingV1 {"),
        ],
        hashes: &[
            (
                "ConsensusHandshakeCaps.consensus_fingerprint",
                HashUse::Block("fingerprint of the signed genesis consensus parameters"),
            ),
            (
                "ConsensusConfigCaps.execution_policy_hash",
                HashUse::State("execution_policy_digest"),
            ),
            (
                "ConsensusConfigCaps.nexus_policy_digest",
                HashUse::State("execution_policy_digest"),
            ),
            (
                "ConsensusConfigCaps.native_config_fingerprint",
                HashUse::Block("fingerprint of the signed genesis native consensus configuration"),
            ),
            (
                "ConsensusConfigCaps.ivm_gas_schedule_hash",
                HashUse::Block("digest of the IVM gas schedule compiled into the binary"),
            ),
            (
                "ConfidentialHandshakeCaps.features",
                HashUse::State("confidential_feature_digest"),
            ),
            (
                "HandshakeConsensusMeta.consensus_fingerprint",
                HashUse::Block("fingerprint of the signed genesis consensus parameters"),
            ),
            (
                "HandshakeConfidentialDigest.vk_set_hash",
                HashUse::State("confidential_feature_digest"),
            ),
            (
                "HandshakeConfidentialDigest.zk_policy_hash",
                HashUse::State("confidential_feature_digest"),
            ),
            (
                "HandshakeIdentityBindingV1.session_binding",
                HashUse::Block(
                    "domain-separated hash of the session key of the encrypted connection: binds the identity signature to the session",
                ),
            ),
            (
                "HandshakeIdentityBindingV1.soranet_transport_binding",
                HashUse::Block(
                    "domain-separated hash of the signed SoraNet transport delegation frame of the connection",
                ),
            ),
            (
                "HandshakeIdentityBindingV1.transport_binding",
                HashUse::Block(
                    "binding of the authenticated transport session (TLS or QUIC), when the transport provides one",
                ),
            ),
        ],
        embeds: &[],
        reviewed: &[
            (
                "HandshakeConfidentialDigest.poseidon_params_id",
                HashUse::State("confidential_feature_digest"),
            ),
            (
                "HandshakeConfidentialDigest.pedersen_params_id",
                HashUse::State("confidential_feature_digest"),
            ),
        ],
        content: &[
            ("ConsensusHandshakeCaps.mode", "consensus mode"),
            (
                "ConsensusHandshakeCaps.proto_version",
                "wire protocol version of consensus messages",
            ),
            (
                "ConsensusHandshakeCaps.config",
                "the shared configuration capabilities: walked as ConsensusConfigCaps",
            ),
            (
                "ConfidentialHandshakeCaps.enabled",
                "whether the node enforces confidential verification: node configuration",
            ),
            (
                "ConfidentialHandshakeCaps.assume_valid",
                "whether the node accepts confidential blocks without verifying them: node configuration",
            ),
            (
                "ConfidentialHandshakeCaps.verifier_backend",
                "name of the configured verifier backend: node configuration",
            ),
            (
                "CryptoHandshakeCaps.sm_enabled",
                "whether the SM helpers are enabled: node configuration",
            ),
            (
                "CryptoHandshakeCaps.sm_openssl_preview",
                "whether the OpenSSL preview provider is enabled: node configuration",
            ),
            (
                "CryptoHandshakeCaps.require_sm_handshake_match",
                "whether a peer must advertise the same SM helper availability: node configuration",
            ),
            (
                "CryptoHandshakeCaps.require_sm_openssl_preview_match",
                "whether a peer must advertise the same OpenSSL preview setting: node configuration",
            ),
            (
                "HandshakeHello.network_id",
                "identity of the network, fixed at genesis",
            ),
            ("HandshakeHello.public_key", "public key bytes of the peer"),
            (
                "HandshakeHello.signature",
                "signature of the peer over the identity binding (HandshakeIdentityBindingV1)",
            ),
            ("HandshakeHello.addr", "advertised address of the peer"),
            ("HandshakeHello.relay", "relay role of the peer"),
            (
                "HandshakeHello.consensus",
                "consensus metadata: walked as HandshakeConsensusMeta",
            ),
            (
                "HandshakeHello.confidential",
                "confidential metadata: walked as HandshakeConfidentialMeta",
            ),
            (
                "HandshakeHello.crypto",
                "crypto metadata: walked as HandshakeCryptoMeta",
            ),
            (
                "HandshakeHello.trust",
                "trust metadata: walked as HandshakeTrustMeta",
            ),
            ("HandshakeConsensusMeta.mode", "consensus mode"),
            (
                "HandshakeConsensusMeta.proto_version",
                "wire protocol version of consensus messages",
            ),
            (
                "HandshakeConsensusMeta.config",
                "the shared configuration capabilities: walked as ConsensusConfigCaps",
            ),
            (
                "HandshakeConfidentialMeta.enabled",
                "whether the peer enforces confidential verification: node configuration",
            ),
            (
                "HandshakeConfidentialMeta.assume_valid",
                "whether the peer accepts confidential blocks without verifying them: node configuration",
            ),
            (
                "HandshakeConfidentialMeta.verifier_backend",
                "name of the peer's verifier backend: node configuration",
            ),
            (
                "HandshakeConfidentialMeta.features",
                "the confidential feature digest on the wire: walked as HandshakeConfidentialDigest",
            ),
            (
                "HandshakeCryptoMeta.sm_enabled",
                "whether the peer has the SM helpers enabled: node configuration",
            ),
            (
                "HandshakeCryptoMeta.sm_openssl_preview",
                "whether the peer has the OpenSSL preview provider enabled: node configuration",
            ),
            (
                "HandshakeTrustMeta.trust_gossip",
                "whether the peer takes part in trust gossip: node configuration",
            ),
            (
                "HandshakeTrustMeta.scion_supported",
                "whether the peer supports the SCION transport: node configuration",
            ),
            (
                "HandshakeConfidentialDigest.conf_rules_version",
                "version of the confidential rules compiled into the binary: a constant, no State content",
            ),
            (
                "HandshakeIdentityBindingV1.network_id",
                "identity of the network, fixed at genesis",
            ),
            (
                "HandshakeIdentityBindingV1.public_key",
                "public key bytes of the peer",
            ),
            (
                "HandshakeIdentityBindingV1.advertised_addr",
                "advertised address of the peer",
            ),
            ("HandshakeIdentityBindingV1.relay", "relay role of the peer"),
            (
                "HandshakeIdentityBindingV1.consensus",
                "consensus metadata: walked as HandshakeConsensusMeta",
            ),
            (
                "HandshakeIdentityBindingV1.confidential",
                "confidential metadata: walked as HandshakeConfidentialMeta",
            ),
            (
                "HandshakeIdentityBindingV1.crypto",
                "crypto metadata: walked as HandshakeCryptoMeta",
            ),
            (
                "HandshakeIdentityBindingV1.trust",
                "trust metadata: walked as HandshakeTrustMeta",
            ),
        ],
        exhaustive: &[
            "ConsensusHandshakeCaps",
            "ConsensusConfigCaps",
            "ConfidentialHandshakeCaps",
            "CryptoHandshakeCaps",
            "HandshakeHello",
            "HandshakeConsensusMeta",
            "HandshakeConfidentialMeta",
            "HandshakeCryptoMeta",
            "HandshakeTrustMeta",
            "HandshakeConfidentialDigest",
            "HandshakeIdentityBindingV1",
        ],
        opaque: &[
            ("ConsensusMode", "enumeration without a hash payload"),
            ("NetworkId", "network identity fixed at genesis"),
            ("SocketAddr", "network address of a peer"),
            ("RelayRole", "enumeration without a hash payload"),
        ],
    },
    Carrier {
        id: "node_network_envelope",
        object: "the envelope of everything that nodes exchange (iroha_core NetworkMessage). Only its Sumeragi frame carries consensus objects; the walk classifies every variant, so a new kind of network message is reviewed",
        types: &[
            ("crates/iroha_core/src/lib.rs", "pub enum NetworkMessage {"),
            (
                "crates/iroha_core/src/sumeragi/net.rs",
                "pub struct SumeragiFrame {",
            ),
        ],
        hashes: &[(
            "SumeragiFrame.instance",
            HashUse::Block("consensus instance identifier of the frame"),
        )],
        embeds: &[],
        reviewed: &[],
        content: &[
            (
                "NetworkMessage.TransactionGossiper",
                "gossiped transactions with their routes and routing plans: admission input, no consensus object",
            ),
            (
                "NetworkMessage.PeersGossiper",
                "peer addresses and transport capabilities",
            ),
            (
                "NetworkMessage.PeerTrustGossip",
                "signed peer trust records",
            ),
            ("NetworkMessage.Health", "health check without a payload"),
            ("NetworkMessage.TimePing", "network time synchronization"),
            ("NetworkMessage.TimePong", "network time synchronization"),
            (
                "NetworkMessage.Connect",
                "Iroha Connect control message between a wallet session and an application session",
            ),
            (
                "NetworkMessage.ToriiProxyRequest",
                "Torii API request routed to another node",
            ),
            (
                "NetworkMessage.ToriiProxyResponse",
                "Torii API response returned to the ingress node: the bytes an endpoint serves to a client, never a consensus input",
            ),
            (
                "NetworkMessage.StreamingControl",
                "Norito Streaming control-plane frame",
            ),
            (
                "NetworkMessage.Sumeragi",
                "one Sumeragi consensus frame: walked as SumeragiFrame",
            ),
            (
                "SumeragiFrame.frame",
                "the encoding of one core WireMessage: walked under the consensus_messages carrier",
            ),
        ],
        exhaustive: &["NetworkMessage", "SumeragiFrame"],
        opaque: &[
            (
                "TransactionGossip",
                "gossiped transactions with their routes and routing plans",
            ),
            ("PeersGossip", "peer addresses and transport capabilities"),
            ("PeerTrustGossip", "signed peer trust records"),
            ("TimePing", "network time synchronization ping"),
            ("TimePong", "network time synchronization pong"),
            ("ConnectP2pMessage", "Iroha Connect control message"),
            ("ToriiProxyRequestV1", "proxied Torii API request"),
            ("ToriiProxyResponseV1", "proxied Torii API response"),
            ("ControlFrame", "Norito Streaming control-plane frame"),
        ],
    },
    Carrier {
        id: "da_commitment_bundle",
        object: "the immutable DA commitment bundle in BlockPayload.da_commitments, committed by BlockHeader.da_commitments_hash. Only its version and ordered commitment records are serialized; its storage variants retain local allocation custody",
        types: &[
            (DA_BUNDLE_MODEL, "pub struct DaCommitmentBundle {"),
            (DA_BUNDLE_MODEL, "enum Storage {"),
            (DA_BUNDLE_MODEL, "struct CanonicalParts {"),
            (DA_COMMITMENT_MODEL, "pub struct DaCommitmentRecord {"),
        ],
        hashes: &[
            (
                "DaCommitmentRecord.client_blob_id",
                HashUse::Block("client-declared identifier of the DA blob"),
            ),
            (
                "DaCommitmentRecord.manifest_hash",
                HashUse::Block("digest of the DA manifest of the blob"),
            ),
            (
                "DaCommitmentRecord.chunk_root",
                HashUse::Block("Merkle root over the chunk digests of the blob"),
            ),
            (
                "DaCommitmentRecord.proof_digest",
                HashUse::Block("digest of the proof scheduling metadata of the blob"),
            ),
        ],
        embeds: &[],
        reviewed: &[],
        content: &[
            (
                "DaCommitmentBundle.storage",
                "the immutable canonical parts and their local custody: walked as Storage",
            ),
            (
                "Storage.Untrusted",
                "untrusted transport canonical parts: walked as CanonicalParts",
            ),
            (
                "Storage.Admitted",
                "the same original canonical parts retained with their allocation custody: walked as CanonicalParts",
            ),
            (
                "CanonicalParts.version",
                "sole first-release bundle version",
            ),
            (
                "CanonicalParts.commitments",
                "ordered original commitment records whose Merkle commitment the block header binds: walked as DaCommitmentRecord",
            ),
            ("DaCommitmentRecord.lane_id", "lane of the DA blob"),
            (
                "DaCommitmentRecord.epoch",
                "scheduling epoch of the DA blob",
            ),
            (
                "DaCommitmentRecord.sequence",
                "monotonic sequence within the lane and epoch",
            ),
            (
                "DaCommitmentRecord.proof_scheme",
                "proof scheme required for the target lane",
            ),
            (
                "DaCommitmentRecord.retention_class",
                "retention policy of the DA blob",
            ),
            (
                "DaCommitmentRecord.storage_ticket",
                "storage ticket binding the DA blob to replication state",
            ),
            (
                "DaCommitmentRecord.acknowledgement_sig",
                "signature of the Torii DA service over its commitment acknowledgement",
            ),
        ],
        exhaustive: &[
            "DaCommitmentBundle",
            "Storage",
            "CanonicalParts",
            "DaCommitmentRecord",
        ],
        opaque: &[
            (
                "ChargedShared",
                "shared immutable allocation custody of the original canonical parts",
            ),
            (
                "RetainedPayload",
                "the original canonical parts and their allocation ledger",
            ),
            ("LaneId", "lane identifier"),
            ("DaProofScheme", "enumeration without a hash payload"),
            ("RetentionClass", "retention policy without a hash payload"),
            ("StorageTicketId", "storage ticket identifier"),
            ("Signature", "signature"),
        ],
    },
];

/// The types of one carrier, read from their sources.
fn carrier_types(carrier: &Carrier) -> Vec<(&'static str, Vec<(String, String)>)> {
    carrier
        .types
        .iter()
        .map(|(path, declaration)| {
            (
                declared_name(declaration),
                declared_fields(&source(path), declaration),
            )
        })
        .collect()
}

/// What the field listings of a carrier do not match in the declarations of its types:
/// a field of an exhaustive type that no listing classifies, a listed `embeds`, `reviewed`
/// or `content` field that the types no longer have, and a `reviewed` field that the hash
/// rules now match (it then belongs under `hashes`).
fn unlisted_carrier_fields(
    carrier: &Carrier,
    types: &[(&str, Vec<(String, String)>)],
) -> Vec<String> {
    let declared: BTreeMap<String, &str> = types
        .iter()
        .flat_map(|(name, fields)| {
            fields
                .iter()
                .map(move |(field, kind)| (format!("{name}.{field}"), kind.as_str()))
        })
        .collect();
    let listed: BTreeSet<&str> = carrier
        .hashes
        .iter()
        .map(|(field, _)| *field)
        .chain(carrier.embeds.iter().map(|(field, _)| *field))
        .chain(carrier.reviewed.iter().map(|(field, _)| *field))
        .chain(carrier.content.iter().map(|(field, _)| *field))
        .collect();
    let mut out = Vec::new();
    for exhaustive in carrier.exhaustive {
        match types.iter().find(|(name, _)| name == exhaustive) {
            None => out.push(format!("exhaustive type {exhaustive} is not walked")),
            Some((name, fields)) => {
                for (field, kind) in fields {
                    let id = format!("{name}.{field}");
                    if !listed.contains(id.as_str()) {
                        out.push(format!("unclassified field {id}: {kind}"));
                    }
                }
            }
        }
    }
    let gone = carrier
        .embeds
        .iter()
        .map(|(field, _)| ("embedded", *field))
        .chain(
            carrier
                .reviewed
                .iter()
                .map(|(field, _)| ("reviewed", *field)),
        )
        .chain(carrier.content.iter().map(|(field, _)| ("content", *field)));
    for (listing, field) in gone {
        if !declared.contains_key(field) {
            out.push(format!("{listing} field {field} is gone"));
        }
    }
    let walked: BTreeSet<&str> = types.iter().map(|(name, _)| *name).collect();
    for (field, _) in carrier.reviewed {
        if declared.get(*field).is_some_and(|kind| {
            is_hash_type(kind)
                || named_types(kind)
                    .iter()
                    .any(|named| !walked.contains(named) && is_hash_named(named))
        }) {
            out.push(format!(
                "reviewed field {field} has a hash-bearing type: list it under hashes"
            ));
        }
    }
    let named: BTreeSet<&str> = declared
        .values()
        .flat_map(|kind| named_types(kind))
        .collect();
    for (opaque, _) in carrier.opaque {
        if !named.contains(opaque) {
            out.push(format!("not-walked type {opaque} is in no field"));
        }
    }
    out
}

/// Check every carrier against the declarations of its types: each hash-bearing field
/// and each nested type is classified, every field of an exhaustive type is classified,
/// every State digest names a listed commitment and every listed field exists.
fn check_carriers() {
    let mut ids = BTreeSet::new();
    for carrier in CARRIERS {
        assert!(ids.insert(carrier.id), "{} is listed twice", carrier.id);
        assert!(!carrier.object.is_empty(), "{}", carrier.id);
        let types = carrier_types(carrier);
        let mut type_names = BTreeSet::new();
        for (name, _) in &types {
            assert!(
                type_names.insert(*name),
                "protocol carrier {} walks duplicate type name {name}: give identically named \
                 declarations from different modules their own carriers",
                carrier.id
            );
        }
        let unclassified = unclassified_value_fields(&types, carrier.hashes, carrier.opaque);
        assert!(
            unclassified.is_empty(),
            "protocol carrier {} has unclassified fields. Classify each hash-bearing field (a \
             digest of State content with its ROOTS entry, or the content it commits) and \
             each nested type:\n{}",
            carrier.id,
            unclassified.join("\n")
        );
        let unlisted = unlisted_carrier_fields(carrier, &types);
        assert!(
            unlisted.is_empty(),
            "protocol carrier {} does not match its declarations. Classify each field of an \
             exhaustive type (hashes, embeds, reviewed or content) and remove listings of \
             fields that are gone:\n{}",
            carrier.id,
            unlisted.join("\n")
        );
        let mut fields = BTreeSet::new();
        for field in carrier
            .hashes
            .iter()
            .map(|(field, _)| *field)
            .chain(carrier.embeds.iter().map(|(field, _)| *field))
            .chain(carrier.reviewed.iter().map(|(field, _)| *field))
            .chain(carrier.content.iter().map(|(field, _)| *field))
        {
            assert!(fields.insert(field), "{field} is classified twice");
        }
        for (field, hash) in carrier.reviewed {
            match hash {
                HashUse::State(root) => assert!(
                    ROOTS.iter().any(|known| known.id == *root),
                    "{field} names unlisted commitment {root}"
                ),
                HashUse::Block(reason) => assert!(!reason.is_empty(), "{field}"),
            }
        }
        for (field, reason) in carrier.content {
            assert!(!reason.is_empty(), "{field}");
        }
        for (field, hash) in carrier.hashes {
            match hash {
                HashUse::State(root) => assert!(
                    ROOTS.iter().any(|known| known.id == *root),
                    "{field} names unlisted commitment {root}"
                ),
                HashUse::Block(reason) => assert!(!reason.is_empty(), "{field}"),
            }
        }
        for (field, root) in carrier.embeds {
            assert!(
                ROOTS.iter().any(|known| known.id == *root),
                "{field} names unlisted commitment {root}"
            );
        }
        for (named, reason) in carrier.opaque {
            assert!(!reason.is_empty(), "{named}");
        }
    }
}

/// The detectors of the scan that report a listed commitment: removing its listing fails
/// the check through each of them. A commitment that only a review found has the single
/// anchor `review` and is listed under [`REVIEW_ONLY_ROOTS`].
fn root_anchors(root: &Root) -> Vec<&'static str> {
    let mut anchors = Vec::new();
    if !root.domains.is_empty() {
        anchors.push("domain_literal");
    }
    if !construction_users(root.id).is_empty() {
        anchors.push("construction_use");
    }
    if WITNESS_FAMILIES
        .iter()
        .any(|family| family.digests.contains(&root.id))
    {
        anchors.push("witness_value_type");
    }
    if CARRIERS.iter().any(|carrier| {
        carrier
            .hashes
            .iter()
            .any(|(_, hash)| *hash == HashUse::State(root.id))
            || carrier.embeds.iter().any(|(_, listed)| *listed == root.id)
    }) {
        anchors.push("protocol_carrier");
    }
    if STATE_HASH_FUNCTIONS
        .iter()
        .any(|listed| matches!(listed.owner, UseOwner::Roots(roots) if roots.contains(&root.id)))
    {
        anchors.push("state_hash_function");
    }
    let review_only = REVIEW_ONLY_ROOTS.iter().any(|(id, _)| *id == root.id);
    assert_eq!(
        anchors.is_empty(),
        review_only,
        "{}: a commitment is reported by a detector of the scan, or it is listed under \
         REVIEW_ONLY_ROOTS with the reason no detector reports it",
        root.id
    );
    if review_only {
        anchors.push("review");
    }
    anchors
}

/// One as-built fact that the contract's publication and layout rules rest on.
struct Premise {
    /// The contract rule (`specs/sumeragi.md` §16.5, §16.6) that rests on the fact.
    rule: &'static str,
    statement: &'static str,
    evidence: &'static [(&'static str, &'static str)],
}

/// As-built premises of the contract, pinned to their source. The tests below check the
/// two that are not single lines: the result layout and the single production caller.
const PREMISES: &[Premise] = &[
    Premise {
        rule: "P1",
        statement: "The State publication owner is the only production caller that advances the certified State commitment, once per block after the last deterministic World write",
        evidence: &[
            (
                "crates/iroha_core/src/state/publication.rs",
                ".advance_state_accumulator(_curr_block.is_genesis())",
            ),
            (
                "crates/iroha_core/src/state/world_state_accumulator.rs",
                "pub(in crate::state) fn advance_state_accumulator(",
            ),
        ],
    },
    Premise {
        rule: "P3",
        statement: "The result binds the State before and after execution; both roots come from the State commitment of the executing State alone",
        evidence: &[
            (
                "crates/iroha_core/src/state/world_state_accumulator.rs",
                "parent_world_state_root: parent.root()?,",
            ),
            (
                "crates/iroha_core/src/state/world_state_accumulator.rs",
                "world_state_root: post.root()?,",
            ),
            (
                "crates/iroha_core/src/sumeragi/commitment.rs",
                "world_state_root: transition.world_state_root,",
            ),
        ],
    },
    Premise {
        rule: "P5",
        statement: "A certified-root mismatch at apply, a block that does not replay at restart and lost local publication are three distinct outcomes",
        evidence: &[
            (
                "crates/iroha_core/src/sumeragi/driver/exec.rs",
                "self.halted = Some(HaltReason::ApplyDiverged {",
            ),
            ("crates/iroha_core/src/sumeragi/node.rs", "    Replay {"),
            (
                "crates/iroha_core/src/state/publication.rs",
                "return Err(TransactionsBlockError::PublicationRecoveryRequired);",
            ),
        ],
    },
    Premise {
        rule: "N1",
        statement: "A block header binds its parent's result and not its own",
        evidence: &[
            (
                "crates/iroha_sumeragi/src/message.rs",
                "pub parent_result: Hash32,",
            ),
            (
                "specs/sumeragi.md",
                "The block's *own* result `R` is **not** in its header; it is bound by the votes and certificates",
            ),
        ],
    },
    Premise {
        rule: "layout",
        statement: "ExecutionCommitment has the field order of section 16.6, with the two World state roots in the positions of the keyed State roots",
        evidence: &[
            (
                "crates/iroha_data_model/src/sumeragi_finality/commitment.rs",
                "pub struct ExecutionCommitment {",
            ),
            (
                "specs/sumeragi.md",
                "    parent_keyed_state_root,        // replaces parent_world_state_root: root(P_{h−1})",
            ),
            (
                "specs/sumeragi.md",
                "    keyed_state_root,               // replaces world_state_root: root(X_h)",
            ),
        ],
    },
];

struct Defect {
    id: &'static str,
    title: &'static str,
    assigned: &'static str,
    related: &'static [&'static str],
    required: &'static str,
    evidence: &'static [(&'static str, &'static str)],
}

/// Expected-open defects. Each is assigned to the task that must close it; closing one
/// changes the generated inventory and therefore fails the tracked-file check.
const DEFECTS: &[Defect] = &[
    Defect {
        id: "G1-D1",
        title: "The certified World state root is an unkeyed multiset hash",
        assigned: "G.3",
        related: &["G.2", "G.4", "G.5"],
        required: "Replace parent_world_state_root and world_state_root by the selected keyed commitment in one cutover and delete the LtHash16 accumulator and the World-element snapshot format. A second calculation may exist only as a test differential.",
        evidence: &[
            (
                "crates/iroha_core/src/state/world_state_accumulator.rs",
                "pub(crate) struct WorldStateAccumulator {",
            ),
            (
                "crates/iroha_data_model/src/sumeragi_finality/world_state.rs",
                "pub fn world_state_root_from_accumulator_v1",
            ),
            (
                "crates/iroha_data_model/src/sumeragi_finality/world_state.rs",
                "//! Bounded complete World-element snapshots authenticated against certified execution.",
            ),
        ],
    },
    Defect {
        id: "G1-D2",
        title: "Canonical State-level tables and cells affect no certified root",
        assigned: "G.3",
        related: &["G.4"],
        required: "Commit every listed field in the keyed State root: transaction membership, commit topologies, the canonical runtime, chain and network identity, lane manifests and compliance, and the policy cells.",
        evidence: &[
            (
                "crates/iroha_core/src/state/world_projection.rs",
                "//! TODO(S9): State-level canonical fields outside World (transaction membership,",
            ),
            (
                "crates/iroha_core/src/state/authority_registry.rs",
                "//! result `R` binds its root. TODO(S9): supply every required semantic",
            ),
            (
                "crates/iroha_core/src/state/native_execution_tip/finalized_world.rs",
                "//! This is a World-only receipt. State-owned runtime, membership and semantic",
            ),
        ],
    },
    Defect {
        id: "G1-D3",
        title: "Canonical policy cells are installed from node configuration and bound only by flat protocol fingerprints",
        assigned: "G.3",
        related: &["F.4"],
        required: "Commit the declared semantic projection of each listed cell. Task F.4 moves the validity-affecting values into committed protocol State so that node configuration cannot change a root or an accepted effect. The protocol fingerprints of these cells become functions of the committed canonical entries or are removed: the execution-policy digest in the signed genesis parameters and the peer handshake (with the Nexus policy digest that the handshake also carries on its own), the Nexus/AMX context hash in signed genesis, the DA proof-policy bundle hash in every block header, and the configured inputs of the confidential feature digest (the ZK policy hash, the parameter selectors and the registry transition limits; its registry half is G1-D10). None authenticates a State read.",
        evidence: &[
            (
                "crates/iroha_core/src/state/authority_registry/state.rs",
                "pipeline: iroha_config::parameters::actual::Pipeline => (\"state.pipeline\",",
            ),
            (
                "crates/iroha_core/src/state.rs",
                "fn compute_execution_policy_digest_v1(",
            ),
            (
                "crates/iroha_data_model/src/block/consensus.rs",
                "pub execution_policy_hash: [u8; 32],",
            ),
            (
                "crates/iroha_data_model/src/block/consensus.rs",
                "pub nexus_amx_context_hash: [u8; 32],",
            ),
            (
                "crates/iroha_core/src/block/native_genesis_policy.rs",
                "if expected_execution != actual_execution || expected_nexus != actual_nexus {",
            ),
            (
                "crates/iroha_core/src/block.rs",
                "if block.header().da_proof_policies_hash() != Some(expected_policy_hash) {",
            ),
            (
                "crates/iroha_core/src/state.rs",
                "zk_config.registry_max_delta_per_block,",
            ),
        ],
    },
    Defect {
        id: "G1-D4",
        title: "Uncertified table-leaf, membership, cell and composition drafts define their own root domains",
        assigned: "G.3",
        related: &["G.2"],
        required: "G.2 may measure the table-leaf substrate and the membership tree as candidates behind KeyedStateCommitment. G.3 folds the selected construction into the single State-owned commitment and deletes every draft that is not it. A draft survives only as an internal component of the selected construction, without an independently authoritative root; none is published as a second root. The data-model spentness checkpoint root, which no node code produces, is deleted or replaced by keyed State inclusion and absence witnesses over the nullifier entries.",
        evidence: &[
            (
                "crates/iroha_core/src/state/authority_registry/leaf.rs",
                "const PAIRED_ROOT: &[u8] = b\"iroha:state-table-substrate:paired-root:v1\\0\";",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/complete/composition.rs",
                "const START: &[u8] = b\"iroha:state-canonical-composition-draft:start:v1\\0\";",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/complete/table_capture/aggregate.rs",
                "pub(super) fn capture_tables_once",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/cell_snapshot.rs",
                "//! Bounded, non-authorizing capture of four native-Norito State cells.",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/complete/transaction_membership.rs",
                "//! Same-original-writer capture of both declared membership tables and frontier.",
            ),
            (
                "crates/iroha_core/src/state/storage_transactions/block/membership_root.rs",
                "const ROOT_DOMAIN: &[u8] = b\"iroha:transaction-membership:root:v1\\0\";",
            ),
            (
                "crates/iroha_data_model/src/confidential/spentness.rs",
                "//! Permanent sparse spentness checkpoints for confidential assets.",
            ),
        ],
    },
    Defect {
        id: "G1-D5",
        title: "The accumulator lanes are persisted as a derived World cell",
        assigned: "G.3",
        related: &[],
        required: "Removed with G1-D1: the keyed commitment retains its nodes through the State publication owner, not through a World row that every snapshot carries.",
        evidence: &[(
            "crates/iroha_core/src/state/authority_registry/world.rs",
            "state_accumulator: Cell<crate::state::world_projection::WorldStateAccumulator> => (\"world.state_accumulator\",",
        )],
    },
    Defect {
        id: "G1-D6",
        title: "Authenticated history is outside every State root and no committed root history exists",
        assigned: "G.3",
        related: &["G.4"],
        required: "Define the committed root-history table of the keyed State (sumeragi.md section 16.7) so that G.4 validates carried witnesses against replicated State alone. The listed history fields stay authenticated by the header chain and certified results.",
        evidence: &[(
            "crates/iroha_core/src/state/authority_registry/state.rs",
            "block_hashes: BlockHashes => (\"state.block_hashes\",",
        )],
    },
    Defect {
        id: "G1-D7",
        title: "A local contract-state map root duplicates one table of the keyed State",
        assigned: "G.3",
        related: &["G.5"],
        required: "Serve contract-state value proofs from the keyed State root over world.smart_contract_state (contract_state_value_proof_v1.md). No separate result field is added; the local map is deleted or kept only as a test differential.",
        evidence: &[
            (
                "crates/iroha_core/src/state/retail_contract_state_snapshot.rs",
                "//! generation. Its locally derived map root is not a consensus commitment and",
            ),
            (
                "specs/contract_state_value_proof_v1.md",
                "`world.smart_contract_state`. No separate `contract_state_root` field is added",
            ),
        ],
    },
    Defect {
        id: "G1-D8",
        title: "Root-valued canonical World cells have no writer",
        assigned: "G.3",
        related: &[],
        required: "Either give world.merge_hint_roots and world.merge_global_state_root a committed writer and a defined relation to the keyed State root, or remove the cells. Their unused writer was removed; without a committed writer they remain permanently default root-named values in the keyed schema.",
        evidence: &[
            (
                "crates/iroha_core/src/state/authority_registry/world.rs",
                "merge_global_state_root: Cell<Option<Hash>> => (\"world.merge_global_state_root\",",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/world.rs",
                "merge_hint_roots: Cell<Vec<Hash>> => (\"world.merge_hint_roots\",",
            ),
        ],
    },
    Defect {
        id: "G1-D9",
        title: "A certified per-table root authenticates the retail fee receipt heads",
        assigned: "G.3",
        related: &["G.5"],
        required: "Replace receipt-head membership proofs with keyed State inclusion witnesses over the canonical head rows in world.smart_contract_state, and remove the specialized root and the obsolete head tree. The root is certified through the fee-evidence witness value; under rule P1 a commitment that independently authenticates canonical State entries is a per-table State root regardless of its carrier. Task G.5 covers consumer conformance.",
        evidence: &[
            (
                "crates/iroha_core/src/validation_fee_rewards/head_tree.rs",
                "//! Incremental compressed sparse commitment to all current canonical wallet heads.",
            ),
            (
                "crates/iroha_core/src/validation_fee_rewards.rs",
                "snapshot.account_heads_root = head_tree::receipt_head_root(&block.world)?;",
            ),
            (
                "crates/iroha_core/src/validation_fee_rewards/head_tree.rs",
                "/// The caller must match the returned root to immutable finality before responding.",
            ),
        ],
    },
    Defect {
        id: "G1-D10",
        title: "Confidential-feature registry comparisons are not backed by the keyed State commitment",
        assigned: "G.3",
        related: &["F.4", "G1-D3"],
        required: "Every block header carries a confidential-feature summary of the effective verifying-key registry, selected parameter identifiers, ZK policy, and SCCP light-client profile versions and hashes active at its height; block validation rejects a summary that differs from the value recomputed from State. Remove the summary, or retain it solely as an inventoried comparison value recomputed at the specified height from committed registry entries and committed policy. The registry rows, including active SCCP profile activations, are committed under the keyed State root, the summary authenticates no State read, and consumers requiring State reads use keyed State witnesses. Node-configured policy hashes, parameter selectors and transition limits that enter the summary follow G1-D3 and F.4.",
        evidence: &[
            (
                "crates/iroha_core/src/state.rs",
                "fn compute_vk_set_hash_from_statuses_at_height(",
            ),
            (
                "crates/iroha_core/src/state.rs",
                "Some(iroha_crypto::Hash::new(&buf).into())",
            ),
            (
                "crates/iroha_data_model/src/block/header.rs",
                "pub confidential_features: Option<ConfidentialFeatureDigest>,",
            ),
            (
                "crates/iroha_core/src/block.rs",
                "Err(BlockValidationError::ConfidentialFeaturesMismatch { expected, actual })",
            ),
        ],
    },
    Defect {
        id: "G1-D11",
        title: "The block result carries an AXT policy projection that validators compare with State and that the apply path installs without independently rebuilding it from its registered sources",
        assigned: "G.3",
        related: &["A.1", "G1-D2", "G1-D3"],
        required: "Every block result carries the AXT policy projection of the derived table `world.axt_policies`, with a 64-bit version that is a truncated undomained hash of its entries. Validation compares the whole carried record with the projection it reads from State after execution, and the apply path replaces the rows of the derived table with the carried entries, checking only their counters and generations against `world.axt_handle_counters`. Certification through `R` does not remove the defect. Remove the carried snapshot, or retain it solely as an inventoried comparison value: every validator independently derives the complete projection at the post-execution cut from the registered sources of the table and the inventoried block-header context, and the apply path rebuilds the table from those sources or installs the carried copy only after that equality check. Four of the six registered sources are bound by no certified root today (G1-D2, G1-D3); the canonical sources are committed under the keyed State root and the node-configured Nexus policy follows F.4. A.1 owns the current-policy checks at the destination, which read State and not the carried copy.",
        evidence: &[
            (
                "crates/iroha_data_model/src/block/payload.rs",
                "pub axt_policy_snapshot: crate::nexus::AxtPolicySnapshot,",
            ),
            (
                "crates/iroha_core/src/block.rs",
                "message: \"advertised AXT post-state policy snapshot does not match deterministic execution\"",
            ),
            (
                "crates/iroha_core/src/state/carrier_metadata_preparation.rs",
                "self.replace_axt_policy_projection(snapshot);",
            ),
            (
                "crates/iroha_core/src/state/carrier_metadata_preparation.rs",
                "self.install_axt_policy_snapshot(snapshot)",
            ),
            (
                "crates/iroha_core/src/state/authority_registry/world.rs",
                "Role::Derived { sources: &[\"world.space_directory_manifests\", \"world.axt_handle_counters\", \"runtime.lanes\", \"runtime.lane_incarnation_lineage\", \"state.nexus\", \"state.block_hashes\"], check: DerivationCheck::Rebuild(\"World::rebuild_axt_policies_from_space_directory; exact authenticated slot and lane policy\") }), release = axt_policies;",
            ),
        ],
    },
];

/// The fields each defect names.
fn defect_fields(id: &str, rows: &[Row]) -> Vec<String> {
    let with = |commitment| -> Vec<String> {
        rows.iter()
            .filter(|row| row.commitment == commitment)
            .map(|row| row.field.id.to_owned())
            .collect()
    };
    let named = |ids: &[&str]| -> Vec<String> { ids.iter().map(|id| (*id).to_owned()).collect() };
    match id {
        // Every certified field: listed by selector, not by name.
        "G1-D1" => Vec::new(),
        "G1-D2" => with(Commitment::Uncommitted),
        "G1-D3" => node_configuration_cells(),
        "G1-D4" => named(&[
            "state.transactions.frontier",
            "state.transactions.current",
            "state.transactions.rollback",
        ]),
        "G1-D5" => named(&["world.state_accumulator"]),
        "G1-D6" => with(Commitment::History),
        "G1-D7" => named(&["world.smart_contract_state"]),
        "G1-D8" => named(&["world.merge_hint_roots", "world.merge_global_state_root"]),
        "G1-D9" => named(&["world.smart_contract_state"]),
        "G1-D10" => named(&[
            "world.verifying_keys",
            "world.poseidon_params",
            "world.pedersen_params",
            "world.sccp_light_client_profiles",
        ]),
        "G1-D11" => named(&["world.axt_policies", "world.axt_handle_counters"]),
        other => panic!("defect {other} has no field rule"),
    }
}

fn shape_name(shape: Option<u8>) -> &'static str {
    match shape {
        Some(TABLE) => "\"table\"",
        Some(CELL) => "\"cell\"",
        _ => "null",
    }
}

/// The physical fields of the `state.transactions` owner and what each holds.
fn physical_fields() -> String {
    let fields: Vec<String> = TRANSACTIONS_STORAGE_FIELDS
        .iter()
        .map(|(name, role)| match role {
            MembershipFieldRole::Canonical(ids) => format!(
                "{{\"name\":{},\"holds\":{}}}",
                string(name),
                list(ids.iter().copied())
            ),
            MembershipFieldRole::Local(reason) => {
                format!("{{\"name\":{},\"local\":{}}}", string(name), string(reason))
            }
        })
        .collect();
    format!("[{}]", fields.join(","))
}

fn field_line(
    row: &Row,
    by_id: &BTreeMap<&'static str, &Row>,
    readers: &BTreeSet<&str>,
    witnessed: &BTreeMap<String, Vec<&'static str>>,
) -> String {
    let id = row.field.id;
    let mut line = format!("{{\"id\":{}", string(id));
    let role = match row.field.role {
        Role::Canonical(Canonical::Owner(_)) => "owner",
        Role::Canonical(_) => "canonical",
        Role::Derived { .. } => "derived",
        Role::History { .. } => "history",
        Role::Local(_) => "local",
    };
    write!(line, ",\"role\":\"{role}\"").expect("write to a String");
    if !matches!(row.commitment, Commitment::Owner) {
        write!(line, ",\"shape\":{}", shape_name(row.shape)).expect("write to a String");
    }
    let codec = |schema| codec_identity(id, schema).expect("the registry is complete");
    match row.field.role {
        Role::Canonical(Canonical::Table { key, value }) => {
            write!(
                line,
                ",\"key\":{},\"value\":{},\"table_reader\":{}",
                string(&codec(key)),
                string(&codec(value)),
                readers.contains(id)
            )
            .expect("write to a String");
        }
        Role::Canonical(Canonical::Cell(value)) => {
            write!(line, ",\"value\":{}", string(&codec(value))).expect("write to a String");
        }
        Role::Derived { sources, check } => {
            let check = match check {
                DerivationCheck::Rebuild(_) => "rebuild",
                DerivationCheck::Commitment(_) => "commitment",
            };
            write!(
                line,
                ",\"sources\":{},\"check\":\"{check}\"",
                list(sources.iter().copied())
            )
            .expect("write to a String");
            let mut unbound = BTreeSet::new();
            unbound_bases(by_id, sources, &mut BTreeSet::new(), &mut unbound);
            if !unbound.is_empty() {
                write!(line, ",\"unbound_bases\":{}", list(unbound)).expect("write to a String");
            }
        }
        Role::Canonical(Canonical::Owner(_)) => {
            if id == "state.transactions" {
                write!(line, ",\"physical_fields\":{}", physical_fields())
                    .expect("write to a String");
            }
        }
        Role::History { .. } | Role::Local(_) => {}
    }
    let root = match row.commitment {
        Commitment::Certified => "\"world_state_root\"",
        _ => "null",
    };
    write!(line, ",\"current_root\":{root}").expect("write to a String");
    if let Some(families) = witnessed.get(id) {
        write!(
            line,
            ",\"witness_families\":{}",
            list(families.iter().copied())
        )
        .expect("write to a String");
    }
    write!(line, ",\"commitment\":\"{}\"}}", row.commitment.name()).expect("write to a String");
    line
}

/// Join rendered JSON objects, one per line, at the given indentation.
fn put_lines(out: &mut String, indent: &str, lines: &[String]) {
    for (index, line) in lines.iter().enumerate() {
        out.push_str(indent);
        out.push_str(line);
        if index + 1 != lines.len() {
            out.push(',');
        }
        out.push('\n');
    }
}

/// Append one line of the inventory text.
fn put(out: &mut String, text: &str) {
    out.push_str(text);
    out.push('\n');
}

/// The owner of a construction use or of a State-reading hash function, as JSON members.
fn owner_json(owner: UseOwner) -> String {
    match owner {
        UseOwner::Roots(roots) => format!("\"roots\":{}", list(roots.iter().copied())),
        UseOwner::Accumulator(id) => format!("\"application_accumulator\":{}", string(id)),
        UseOwner::Other(usage, reason) => format!(
            "\"use\":{},\"reason\":{}",
            string(usage.name()),
            string(reason)
        ),
    }
}

/// One line per listed domain literal that the sources hold: its owner, and every source
/// with the number of occurrences. A new use of a listed literal changes its line.
fn literal_use_lines(scan: &SourceScan) -> Vec<String> {
    let owners = domain_owners();
    scan.literal_uses
        .iter()
        .map(|(literal, sources)| {
            let owner = match owners[literal] {
                DomainOwner::Root(id) => format!("root:{id}"),
                DomainOwner::Accumulator(id) => format!("application_accumulator:{id}"),
                DomainOwner::Other(usage) => format!("use:{}", usage.name()),
            };
            let sources: Vec<String> = sources
                .iter()
                .map(|(path, count)| format!("{}:{count}", string(path)))
                .collect();
            format!(
                "{{\"literal\":{},\"owner\":{},\"sources\":{{{}}}}}",
                string(literal),
                string(&owner),
                sources.join(",")
            )
        })
        .collect()
}

/// One line per protocol carrier: its types, its classified hash-bearing fields, the
/// records it embeds, the digests a review found in other types, the classified fields
/// without a hash, the types whose every field is classified and the nested types it does
/// not walk.
fn carrier_lines() -> Vec<String> {
    let classified = |listing: &[(&str, HashUse)]| -> Vec<String> {
        listing
            .iter()
            .map(|(field, hash)| match hash {
                HashUse::State(root) => format!(
                    "{{\"field\":{},\"commits\":\"state\",\"root\":{}}}",
                    string(field),
                    string(root)
                ),
                HashUse::Block(reason) => format!(
                    "{{\"field\":{},\"commits\":\"content\",\"reason\":{}}}",
                    string(field),
                    string(reason)
                ),
            })
            .collect()
    };
    CARRIERS
        .iter()
        .map(|carrier| {
            let hashes = classified(carrier.hashes);
            let reviewed = classified(carrier.reviewed);
            let content: Vec<String> = carrier
                .content
                .iter()
                .map(|(field, reason)| {
                    format!(
                        "{{\"field\":{},\"reason\":{}}}",
                        string(field),
                        string(reason)
                    )
                })
                .collect();
            let embeds: Vec<String> = carrier
                .embeds
                .iter()
                .map(|(field, root)| {
                    format!(
                        "{{\"field\":{},\"root\":{}}}",
                        string(field),
                        string(root)
                    )
                })
                .collect();
            let opaque: Vec<String> = carrier
                .opaque
                .iter()
                .map(|(named, reason)| {
                    format!(
                        "{{\"type\":{},\"reason\":{}}}",
                        string(named),
                        string(reason)
                    )
                })
                .collect();
            format!(
                "{{\"id\":{},\"object\":{},\"types\":{},\"hashes\":[{}],\"embeds\":[{}],\"found_by_review\":[{}],\"fields_without_hash\":[{}],\"every_field_classified\":{},\"not_walked\":[{}]}}",
                string(carrier.id),
                string(carrier.object),
                evidence_list(carrier.types),
                hashes.join(","),
                embeds.join(","),
                reviewed.join(","),
                content.join(","),
                list(carrier.exhaustive.iter().copied()),
                opaque.join(","),
            )
        })
        .collect()
}

/// The complete inventory as canonical JSON text: one line per root, family, premise,
/// defect and field.
fn generate() -> String {
    let rows = rows();
    let by_id: BTreeMap<&'static str, &Row> = rows.iter().map(|row| (row.field.id, row)).collect();
    assert_eq!(by_id.len(), rows.len(), "registry identities are unique");
    let catalog = catalog_table_ids();
    let readers: BTreeSet<&str> = catalog.iter().copied().collect();
    assert_eq!(
        readers.len(),
        catalog.len(),
        "table catalog repeats a table"
    );
    let scan = source_scan();
    scan.require_complete();
    check_carriers();
    let witnessed = witnessed_fields();
    for (field, families) in &witnessed {
        let row = by_id
            .get(field.as_str())
            .unwrap_or_else(|| panic!("witness families {families:?} name unknown {field}"));
        assert!(
            matches!(row.field.role, Role::Canonical(_)) && row.commitment != Commitment::Owner,
            "witness families {families:?} name {field}, which is not a canonical table or cell"
        );
    }
    let count = |commitment| {
        rows.iter()
            .filter(|row| row.commitment == commitment)
            .count()
    };
    let shaped = |shape| {
        rows.iter()
            .filter(|row| matches!(row.field.role, Role::Canonical(_)) && row.shape == Some(shape))
            .count()
    };
    let mut out = String::new();
    put(&mut out, "{");
    put(
        &mut out,
        "  \"schema\": \"iroha:state-table-inventory:v1\",",
    );
    put(&mut out, &format!("  \"contract\": {},", string(CONTRACT)));
    put(
        &mut out,
        &format!("  \"interface\": {},", string(INTERFACE)),
    );
    put(
        &mut out,
        "  \"registry\": \"crates/iroha_core/src/state/authority_registry.rs\",",
    );
    put(
        &mut out,
        "  \"checked_by\": \"crates/iroha_core/src/state/state_table_inventory_tests.rs\",",
    );
    put(
        &mut out,
        "  \"regenerate\": \"cargo test -p iroha_core --lib regenerate_state_table_inventory -- --ignored\",",
    );
    put(&mut out, "  \"summary\": {");
    put(&mut out, &format!("    \"fields\": {},", rows.len()));
    put(
        &mut out,
        &format!("    \"owners\": {},", count(Commitment::Owner)),
    );
    put(
        &mut out,
        &format!("    \"canonical_tables\": {},", shaped(TABLE)),
    );
    put(
        &mut out,
        &format!("    \"canonical_cells\": {},", shaped(CELL)),
    );
    put(
        &mut out,
        &format!(
            "    \"certified_by_world_state_root\": {},",
            count(Commitment::Certified)
        ),
    );
    put(
        &mut out,
        &format!(
            "    \"canonical_without_certified_root\": {},",
            count(Commitment::Uncommitted)
        ),
    );
    put(
        &mut out,
        &format!("    \"carried_by_a_witness_family\": {},", witnessed.len()),
    );
    put(
        &mut out,
        &format!("    \"derived\": {},", count(Commitment::Derived)),
    );
    put(
        &mut out,
        &format!("    \"history\": {},", count(Commitment::History)),
    );
    put(
        &mut out,
        &format!("    \"local\": {},", count(Commitment::Local)),
    );
    put(
        &mut out,
        &format!("    \"table_catalog_readers\": {},", catalog.len()),
    );
    put(&mut out, &format!("    \"commitments\": {},", ROOTS.len()));
    put(
        &mut out,
        &format!(
            "    \"application_accumulators\": {},",
            APPLICATION_ACCUMULATORS.len()
        ),
    );
    put(
        &mut out,
        &format!("    \"classified_domain_literals\": {},", scan.literals),
    );
    put(
        &mut out,
        &format!("    \"construction_users\": {},", CONSTRUCTION_USES.len()),
    );
    put(
        &mut out,
        &format!(
            "    \"state_hash_functions\": {},",
            STATE_HASH_FUNCTIONS.len()
        ),
    );
    put(
        &mut out,
        &format!("    \"protocol_carriers\": {},", CARRIERS.len()),
    );
    put(
        &mut out,
        &format!("    \"witness_families\": {},", WITNESS_FAMILIES.len()),
    );
    put(
        &mut out,
        &format!("    \"open_defects\": {}", DEFECTS.len()),
    );
    put(&mut out, "  },");
    put(&mut out, "  \"roots\": [");
    let roots: Vec<String> = ROOTS
        .iter()
        .map(|root| {
            format!(
                "{{\"id\":{},\"class\":{},\"certified\":{},\"keyed\":{},\"carrier\":{},\"scope\":{},\"construction\":{},\"witnesses\":{},\"owner\":{},\"disposition\":{},\"defect\":{},\"detected_by\":{},\"domains\":{},\"construction_users\":{},\"evidence\":{}}}",
                string(root.id),
                string(root.class.name()),
                root.class.certified(),
                root.keyed,
                string(root.carrier),
                string(root.scope),
                string(root.construction),
                string(root.witnesses),
                string(root.owner),
                string(root.disposition),
                root.defect.map_or_else(|| "null".to_owned(), string),
                list(root_anchors(root)),
                list(root.domains.iter().copied()),
                list(construction_users(root.id)),
                evidence_list(root.evidence),
            )
        })
        .collect();
    put_lines(&mut out, "    ", &roots);
    put(&mut out, "  ],");
    put(&mut out, "  \"application_accumulator\": [");
    let accumulators: Vec<String> = APPLICATION_ACCUMULATORS
        .iter()
        .map(|accumulator| {
            for field in accumulator.fields {
                assert!(
                    by_id.contains_key(field),
                    "{} names unknown {field}",
                    accumulator.id
                );
            }
            let users: Vec<&str> = CONSTRUCTION_USES
                .iter()
                .filter(
                    |listed| matches!(listed.owner, UseOwner::Accumulator(id) if id == accumulator.id),
                )
                .map(|listed| listed.path)
                .collect();
            let functions: Vec<String> = STATE_HASH_FUNCTIONS
                .iter()
                .filter(
                    |listed| matches!(listed.owner, UseOwner::Accumulator(id) if id == accumulator.id),
                )
                .map(|listed| format!("{}: {}", listed.path, listed.name))
                .collect();
            format!(
                "{{\"id\":{},\"fields\":{},\"statement\":{},\"domains\":{},\"construction_users\":{},\"state_hash_functions\":{},\"evidence\":{}}}",
                string(accumulator.id),
                list(accumulator.fields.iter().copied()),
                string(accumulator.statement),
                list(accumulator.domains.iter().copied()),
                list(users),
                list(functions),
                evidence_list(accumulator.evidence),
            )
        })
        .collect();
    put_lines(&mut out, "    ", &accumulators);
    put(&mut out, "  ],");
    put(&mut out, "  \"source_scan\": {");
    put(
        &mut out,
        &format!("    \"scope\": {},", list(SCAN_SCOPE.iter().copied())),
    );
    put(
        &mut out,
        &format!(
            "    \"not_read\": {},",
            list([
                "test sources: *_tests.rs, tests.rs, tests/ and test_fixtures.rs",
                SELF_PATHS[0],
                SELF_PATHS[1],
            ])
        ),
    );
    put(
        &mut out,
        &format!(
            "    \"domain_literal_rule\": {},",
            string(DOMAIN_LITERAL_RULE)
        ),
    );
    put(
        &mut out,
        &format!(
            "    \"application_accumulator_rule\": {},",
            string(ACCUMULATOR_RULE)
        ),
    );
    put(
        &mut out,
        &format!("    \"state_reader_rule\": {},", string(STATE_READER_RULE)),
    );
    put(
        &mut out,
        &format!(
            "    \"state_reader_types\": {},",
            list(STATE_READER_TYPES.iter().copied())
        ),
    );
    put(
        &mut out,
        &format!("    \"hash_return_rule\": {},", string(HASH_RETURN_RULE)),
    );
    put(
        &mut out,
        &format!(
            "    \"root_bearing_records\": {},",
            list(ROOT_BEARING_RECORDS.iter().copied())
        ),
    );
    put(
        &mut out,
        &format!("    \"carried_records\": {},", list(carried_records())),
    );
    put(
        &mut out,
        "    \"not_detected\": \"a digest of State content whose domain literal does not have the form of domain_literal_rule, that uses none of the construction tokens, that enters no listed execution-witness value type and no listed protocol carrier, and that no function matched by state_reader_rule returns in a hash-bearing type; for example an undomained hash of State rows that a function computes from an iterator or from row bytes instead of a reader type (state_reader_types) and that a node keeps in a local artifact. Also not detected: a digest held in a type that the hash rules do not match, for example an integer; such a field is listed by review (protocol_carriers[*].found_by_review, which also lists identifiers that validation derives from State for comparison). Inside a type listed under every_field_classified a new field fails the check whatever its type; in the other walked types a new field without a hash-bearing or unclassified nested type does not. The signature scan reads literal impl and trait blocks, also inside macro bodies; it does not expand macros, so a method that a macro generates from a fragment is not matched. It reads iroha_core only: the node binary (crates/irohad) fills the handshake capabilities, and a function of another crate that reads State and returns a hash or a carried record is not matched. The peer_handshake carrier walks the hello record, its metadata records, its identity binding and the capability records; the SoraNet transport delegation records of crates/iroha_p2p, which authenticate transport keys before the hello and carry no capability, are not walked. The State reader types are listed by name: a new handle type of a State owner is matched once it is listed, which the scan test requires for every type that implements a reader trait in a literal impl block. The checks detect carrier, signature, literal and construction drift; they do not establish arbitrary State-dataflow completeness\",",
    );
    put(&mut out, "    \"found_by_review\": [");
    let review_only: Vec<String> = REVIEW_ONLY_ROOTS
        .iter()
        .map(|(id, reason)| {
            assert!(
                ROOTS.iter().any(|root| root.id == *id) && !reason.is_empty(),
                "{id}"
            );
            format!("{{\"root\":{},\"reason\":{}}}", string(id), string(reason))
        })
        .collect();
    put_lines(&mut out, "      ", &review_only);
    put(&mut out, "    ],");
    put(
        &mut out,
        &format!(
            "    \"construction_tokens\": {},",
            list(CONSTRUCTIONS.iter().copied())
        ),
    );
    put(&mut out, "    \"construction_uses\": [");
    let construction_uses: Vec<String> = CONSTRUCTION_USES
        .iter()
        .map(|listed| {
            let uses: Vec<String> = listed
                .uses
                .iter()
                .map(|(token, count)| format!("{}:{count}", string(token)))
                .collect();
            format!(
                "{{\"path\":{},\"uses\":{{{}}},{}}}",
                string(listed.path),
                uses.join(","),
                owner_json(listed.owner)
            )
        })
        .collect();
    put_lines(&mut out, "      ", &construction_uses);
    put(&mut out, "    ],");
    put(&mut out, "    \"state_hash_functions\": [");
    let state_hash_functions: Vec<String> = STATE_HASH_FUNCTIONS
        .iter()
        .map(|listed| {
            format!(
                "{{\"path\":{},\"function\":{},\"count\":{},{}}}",
                string(listed.path),
                string(listed.name),
                listed.count,
                owner_json(listed.owner)
            )
        })
        .collect();
    put_lines(&mut out, "      ", &state_hash_functions);
    put(&mut out, "    ],");
    put(&mut out, "    \"literal_uses\": [");
    put_lines(&mut out, "      ", &literal_use_lines(&scan));
    put(&mut out, "    ],");
    put(&mut out, "    \"other_domains\": [");
    for (index, group) in OTHER_DOMAINS.iter().enumerate() {
        put(
            &mut out,
            &format!(
                "      {{\"use\":{},\"reason\":{},\"literals\":[",
                string(group.usage.name()),
                string(group.reason)
            ),
        );
        let literals: Vec<String> = group
            .literals
            .iter()
            .map(|literal| string(literal))
            .collect();
        put_lines(&mut out, "        ", &literals);
        put(
            &mut out,
            if index + 1 == OTHER_DOMAINS.len() {
                "      ]}"
            } else {
                "      ]},"
            },
        );
    }
    put(&mut out, "    ]");
    put(&mut out, "  },");
    put(&mut out, "  \"protocol_carriers\": [");
    put_lines(&mut out, "    ", &carrier_lines());
    put(&mut out, "  ],");
    put(&mut out, "  \"witness_families\": [");
    let families: Vec<String> = WITNESS_FAMILIES
        .iter()
        .map(|family| {
            let roots = if family.reads {
                "[\"parent_state_root\",\"post_state_root\",\"ordinary_writes_root\"]"
            } else {
                "[\"post_state_root\",\"ordinary_writes_root\"]"
            };
            let fields = family_fields(family);
            let derivation: Vec<(&str, &str)> = family.derivation.to_vec();
            let hashes: Vec<String> = family
                .hashes
                .iter()
                .map(|(field, hash)| match hash {
                    HashUse::State(root) => format!(
                        "{{\"field\":{},\"commits\":\"state\",\"root\":{}}}",
                        string(field),
                        string(root)
                    ),
                    HashUse::Block(reason) => format!(
                        "{{\"field\":{},\"commits\":\"block\",\"reason\":{}}}",
                        string(field),
                        string(reason)
                    ),
                })
                .collect();
            let unread: Vec<String> = family
                .accessors
                .iter()
                .filter_map(|(accessor, access)| match access {
                    Access::Field(_) => None,
                    Access::NoContent(reason) => Some(format!(
                        "{{\"accessor\":{},\"reason\":{}}}",
                        string(accessor),
                        string(reason)
                    )),
                })
                .collect();
            format!(
                "{{\"id\":{},\"tags\":{},\"key\":{},\"value\":{},\"roots\":{roots},\"fields\":{},\"source\":{},\"digests\":{},\"derived_by\":{},\"read_without_content\":[{}],\"value_types\":{},\"hashes\":[{}],\"evidence\":{}}}",
                string(family.id),
                list(family.tags.iter().copied()),
                string(family.key),
                string(family.value),
                list(fields.iter().map(String::as_str)),
                if family.source.is_empty() {
                    "null".to_owned()
                } else {
                    string(family.source)
                },
                list(family.digests.iter().copied()),
                evidence_list(&derivation),
                unread.join(","),
                list(family
                    .value_types
                    .iter()
                    .map(|(_, declaration)| declared_name(declaration))),
                hashes.join(","),
                evidence_list(family.evidence),
            )
        })
        .collect();
    put_lines(&mut out, "    ", &families);
    put(&mut out, "  ],");
    put(
        &mut out,
        &format!(
            "  \"witness_tags_with_test_recorders_only\": {},",
            list(TEST_ONLY_WITNESS_TAGS.iter().map(|(tag, _)| *tag))
        ),
    );
    put(&mut out, "  \"contract_premises\": [");
    let premises: Vec<String> = PREMISES
        .iter()
        .map(|premise| {
            format!(
                "{{\"rule\":{},\"statement\":{},\"evidence\":{}}}",
                string(premise.rule),
                string(premise.statement),
                evidence_list(premise.evidence),
            )
        })
        .collect();
    put_lines(&mut out, "    ", &premises);
    put(&mut out, "  ],");
    put(&mut out, "  \"open_defects\": [");
    let defects: Vec<String> = DEFECTS
        .iter()
        .map(|defect| {
            let fields = defect_fields(defect.id, &rows);
            for field in &fields {
                assert!(
                    by_id.contains_key(field.as_str()),
                    "{} names unknown {field}",
                    defect.id
                );
            }
            let selector = if defect.id == "G1-D1" {
                ",\"applies_to_commitment\":\"certified\""
            } else {
                ""
            };
            let roots: Vec<&str> = ROOTS
                .iter()
                .filter(|root| root.defect == Some(defect.id))
                .map(|root| root.id)
                .collect();
            format!(
                "{{\"id\":{},\"status\":\"open\",\"assigned\":{},\"related\":{},\"title\":{},\"required\":{},\"roots\":{},\"fields\":{}{selector},\"evidence\":{}}}",
                string(defect.id),
                string(defect.assigned),
                list(defect.related.iter().copied()),
                string(defect.title),
                string(defect.required),
                list(roots),
                list(fields.iter().map(String::as_str)),
                evidence_list(defect.evidence),
            )
        })
        .collect();
    put_lines(&mut out, "    ", &defects);
    put(&mut out, "  ],");
    put(&mut out, "  \"fields\": [");
    let fields: Vec<String> = rows
        .iter()
        .map(|row| field_line(row, &by_id, &readers, &witnessed))
        .collect();
    put_lines(&mut out, "    ", &fields);
    out.push_str("  ]\n}\n");
    out
}

/// The inventory text with every cited line number cleared.
fn without_line_numbers(text: &str) -> String {
    const FIELD: &str = "\"line\":";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(FIELD) {
        let (head, tail) = rest.split_at(at + FIELD.len());
        out.push_str(head);
        out.push('0');
        rest = tail.trim_start_matches(|character: char| character.is_ascii_digit());
    }
    out.push_str(rest);
    out
}

#[test]
#[cfg_attr(
    not(feature = "telemetry"),
    ignore = "the tracked inventory describes the node feature set, which has state.telemetry"
)]
fn tracked_inventory_matches_the_source() {
    let generated = generate();
    let parsed = norito::json::from_str::<norito::json::Value>(&generated)
        .expect("the generated inventory is JSON");
    let fields = parsed
        .get("fields")
        .and_then(norito::json::Value::as_array)
        .expect("the inventory lists its fields");
    assert_eq!(fields.len(), rows().len());
    let tracked = source(INVENTORY_PATH);
    let (tracked, generated) = (
        without_line_numbers(&tracked),
        without_line_numbers(&generated),
    );
    if tracked != generated {
        let line = tracked
            .lines()
            .zip(generated.lines())
            .position(|(tracked, generated)| tracked != generated)
            .map_or_else(
                || tracked.lines().count().min(generated.lines().count()) + 1,
                |index| index + 1,
            );
        panic!(
            "{INVENTORY_PATH} differs from the source at line {line}.\n\
             tracked:   {}\n\
             generated: {}\n\
             A State/World field, its root coverage, an open defect or cited evidence changed. \
             Review the change, then regenerate with\n\
             cargo test -p iroha_core --lib regenerate_state_table_inventory -- --ignored",
            tracked.lines().nth(line - 1).unwrap_or("<end of file>"),
            generated.lines().nth(line - 1).unwrap_or("<end of file>"),
        );
    }
}

#[test]
#[ignore = "writes specs/state_table_inventory.json; run it to accept an intended change"]
fn regenerate_state_table_inventory() {
    assert!(
        cfg!(feature = "telemetry"),
        "regenerate with the node feature set: the tracked inventory lists state.telemetry"
    );
    let path = repository().join(INVENTORY_PATH);
    let generated = generate();
    // A canonical no-op must preserve the fixture timestamp and Cargo's input
    // identity; only an actual inventory change needs to rewrite the fixture.
    if std::fs::read(&path).ok().as_deref() != Some(generated.as_bytes()) {
        std::fs::write(path, generated).expect("write the tracked inventory");
    }
}

/// The registry is the completeness guard: it destructures every owner without `..`, so a
/// new persisted field cannot compile unclassified, and a classified field cannot be left
/// out of the inventory.
#[test]
fn inventory_lists_every_registry_field_and_every_catalog_table() {
    let rows = rows();
    let mut registry = Vec::new();
    flatten(STATE_FIELDS, &mut registry);
    assert_eq!(
        rows.iter().map(|row| row.field.id).collect::<Vec<_>>(),
        registry.iter().map(|field| field.id).collect::<Vec<_>>()
    );
    let tables: BTreeSet<&str> = rows
        .iter()
        .filter(|row| matches!(row.field.role, Role::Canonical(Canonical::Table { .. })))
        .map(|row| row.field.id)
        .collect();
    let catalog: BTreeSet<&str> = catalog_table_ids().into_iter().collect();
    assert_eq!(
        tables, catalog,
        "the table catalog and the registry disagree on the canonical tables"
    );
    // Every World and trigger field is visited by the production pass exactly once,
    // under its registry identity; nothing else is.
    let shapes = pass_shapes();
    let visited: BTreeSet<&str> = shapes.keys().copied().collect();
    let expected: BTreeSet<&str> = rows
        .iter()
        .filter(|row| row.commitment != Commitment::Owner)
        .filter_map(|row| pass_name(row.field.id))
        .filter(|name| shapes.contains_key(name) || is_canonical_slot(name))
        .collect();
    assert_eq!(visited, expected);
    for row in &rows {
        if let Some(name) = pass_name(row.field.id) {
            assert_eq!(
                shapes.contains_key(name),
                row.commitment != Commitment::Owner && row.field.id != "world.external_event_buf",
                "World pass coverage of {}",
                row.field.id
            );
        }
    }
    // The committed schema of the contract is exactly the canonical tables and cells.
    let schema = crate::state::authority_registry::keyed_commitment::StateSchema::from_registry(
        STATE_FIELDS,
    )
    .unwrap();
    let canonical: BTreeSet<&str> = rows
        .iter()
        .filter(|row| {
            matches!(
                row.commitment,
                Commitment::Certified | Commitment::Uncommitted
            )
        })
        .map(|row| row.field.id)
        .collect();
    assert_eq!(
        schema
            .tables()
            .iter()
            .map(|table| table.id())
            .collect::<BTreeSet<_>>(),
        canonical
    );
}

fn is_canonical_slot(name: &str) -> bool {
    matches!(
        field_index().as_ref().unwrap().by_name.get(name),
        Some(Classified::Canonical { .. })
    )
}

fn builder(
    index: &'static FieldIndex,
    accumulator: WorldStateAccumulator,
    direction: Direction,
) -> Builder<'static> {
    Builder {
        index,
        accumulator,
        direction,
        visited: vec![false; index.canonical],
        snapshot: None,
        snapshot_field: None,
    }
}

/// Drive one table slot of the production accumulator: the roots of the committed row, of
/// the block's incremental change and of a cold capture of the changed table.
fn table_slot(
    name: &'static str,
    mutate: impl Fn(&mut StorageField<'_, u64, Vec<u8>>),
) -> Result<[Hash; 3], String> {
    let index = field_index().as_ref().map_err(Clone::clone)?;
    let storage: Storage<u64, Vec<u8>> = [(7_u64, vec![1_u8])].into_iter().collect();
    let mut committed = builder(index, WorldStateAccumulator::empty(), Direction::Capture);
    committed.append_storage_with(name, &BlockField::new(storage.block()), hash_value)?;
    let base = committed.accumulator;
    let mut block = BlockField::new(storage.block());
    mutate(&mut block);
    let mut incremental = builder(index, base.clone(), Direction::Forward);
    incremental.append_storage_with(name, &block, hash_value)?;
    let mut cold = builder(index, WorldStateAccumulator::empty(), Direction::Capture);
    cold.append_storage_with(name, &block, hash_value)?;
    Ok([
        base.root()?,
        incremental.accumulator.root()?,
        cold.accumulator.root()?,
    ])
}

/// The same for a cell slot whose value changes.
fn cell_slot(name: &'static str) -> Result<[Hash; 3], String> {
    let index = field_index().as_ref().map_err(Clone::clone)?;
    let cell = mv::cell::Cell::new(vec![1_u8]);
    let mut committed = builder(index, WorldStateAccumulator::empty(), Direction::Capture);
    committed.append_cell_with(name, &BlockField::new(cell.block()), hash_value)?;
    let base = committed.accumulator;
    let mut block = BlockField::new(cell.block());
    *block.get_mut() = vec![2_u8];
    let mut incremental = builder(index, base.clone(), Direction::Forward);
    incremental.append_cell_with(name, &block, hash_value)?;
    let mut cold = builder(index, WorldStateAccumulator::empty(), Direction::Capture);
    cold.append_cell_with(name, &block, hash_value)?;
    Ok([
        base.root()?,
        incremental.accumulator.root()?,
        cold.accumulator.root()?,
    ])
}

/// For every inventoried field: a row insertion, replacement and removal (or a cell
/// change) under the field's registry identity changes the certified World state root
/// exactly when the inventory says the field is certified, and never otherwise.
#[test]
fn every_inventoried_field_mutation_reaches_exactly_its_declared_root() {
    let index = field_index().as_ref().unwrap();
    let empty = WorldStateAccumulator::empty().root().unwrap();
    let mut certified_inserts = BTreeSet::new();
    let mut checked = BTreeMap::new();
    for row in rows() {
        let id = row.field.id;
        *checked.entry(row.commitment.name()).or_insert(0_usize) += 1;
        let Some(name) = pass_name(id) else {
            // A State-level field has no slot: the World pass rejects it by identity and
            // by bare name, so no mutation of it can reach the World state root.
            let bare = id.rsplit('.').next().unwrap();
            for candidate in [id, bare] {
                let mut probe = builder(index, WorldStateAccumulator::empty(), Direction::Forward);
                for kind in [TABLE, CELL] {
                    let refused = probe.field(candidate, kind);
                    assert!(
                        !index.by_name.contains_key(candidate) && refused.is_err(),
                        "{id} unexpectedly has a World accumulator slot"
                    );
                }
            }
            assert!(
                !matches!(row.commitment, Commitment::Certified),
                "{id} is outside the World pass but inventoried as certified"
            );
            continue;
        };
        match (row.commitment, row.shape) {
            (Commitment::Owner, _) => {
                assert!(!index.by_name.contains_key(name), "{id}");
            }
            (Commitment::Certified, Some(TABLE)) => {
                let inserted = table_slot(name, |block| {
                    block.insert(9, vec![2]);
                })
                .unwrap();
                let replaced = table_slot(name, |block| {
                    block.insert(7, vec![3]);
                })
                .unwrap();
                let removed = table_slot(name, |block| {
                    block.remove(7);
                })
                .unwrap();
                let untouched = table_slot(name, |_| {}).unwrap();
                assert_eq!(untouched[0], untouched[1], "{id}: no change");
                for (mutation, [base, incremental, cold]) in [
                    ("insert", inserted),
                    ("replace", replaced),
                    ("remove", removed),
                ] {
                    assert_ne!(base, incremental, "{id}: {mutation} must change the root");
                    assert_eq!(incremental, cold, "{id}: {mutation} incremental == cold");
                    assert_ne!(base, empty, "{id}: the committed row is bound");
                }
                assert_eq!(
                    removed[1], empty,
                    "{id}: the emptied table is the empty World"
                );
                assert_ne!(inserted[1], replaced[1], "{id}: key and value are bound");
                assert!(
                    certified_inserts.insert(inserted[1]),
                    "{id}: the table identity is not bound into its entries"
                );
                assert!(
                    cell_slot(name).is_err(),
                    "{id}: a table cannot be projected as a cell"
                );
            }
            (Commitment::Certified, Some(CELL)) => {
                let [base, incremental, cold] = cell_slot(name).unwrap();
                assert_ne!(
                    base, incremental,
                    "{id}: a cell change must change the root"
                );
                assert_eq!(incremental, cold, "{id}: incremental == cold");
                assert!(
                    certified_inserts.insert(incremental),
                    "{id}: the cell identity is not bound into its value"
                );
                assert!(
                    table_slot(name, |_| {}).is_err(),
                    "{id}: a cell cannot be projected as a table"
                );
            }
            (Commitment::Derived | Commitment::Local, shape) => {
                // Excluded fields are visited by the pass and contribute nothing in
                // either shape: they cannot create independent authority.
                assert!(
                    matches!(index.by_name.get(name), Some(Classified::Excluded)),
                    "{id}"
                );
                let table = table_slot(name, |block| {
                    block.insert(9, vec![2]);
                    block.remove(7);
                })
                .unwrap();
                assert_eq!(
                    table, [empty; 3],
                    "{id}: a derived or local table changed the root"
                );
                assert_eq!(
                    cell_slot(name).unwrap(),
                    [empty; 3],
                    "{id}: a derived or local cell changed the root"
                );
                assert!(
                    shape.is_some() || id == "world.external_event_buf",
                    "{id}: the production pass does not visit this field"
                );
            }
            (commitment, shape) => {
                panic!("{id}: unexpected inventory row {commitment:?} {shape:?}")
            }
        }
    }
    // The run covered every class the inventory contains.
    for class in [
        "owner",
        "certified",
        "uncommitted",
        "derived",
        "history",
        "local",
    ] {
        assert!(
            checked.get(class).is_some_and(|count| *count > 0),
            "{class}"
        );
    }
    assert_eq!(certified_inserts.len(), checked["certified"]);
    assert_eq!(checked["certified"], index.canonical);
}

/// Typed end-to-end mutations of actual World fields through the real overlay: the
/// certified root changes on insertion and replacement and returns on removal.
#[test]
fn typed_world_table_mutations_change_the_certified_world_state_root() {
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_data_model::{
        account::{AccountId, rekey::AccountAlias},
        consensus::{ConsensusKeyId, ConsensusKeyRole},
        content::ContentChunk,
        nexus::DomainEndorsement,
        sorafs::capacity::ProviderId,
    };
    use iroha_model_base::{domain::DomainId, state_path::StatePath, topology::DataSpaceId};

    fn account(seed: &[u8]) -> AccountId {
        AccountId::new(
            KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    }
    fn domain() -> DomainId {
        DomainId::try_new("typed", "row").unwrap()
    }
    fn endorsement(seed: &[u8]) -> HashOf<DomainEndorsement> {
        HashOf::from_untyped_unchecked(Hash::new(seed))
    }

    let world = World::default();
    let budget = iroha_allocation::AllocationBudget::new(16 * 1024 * 1024);
    let mut covered = Vec::new();
    macro_rules! put_typed {
        ($block:ident, sccp_anchor_chunks, $key:expr, $value:expr) => {
            $block
                .sccp_anchor_chunks
                .try_insert_admitted($key, $value)
                .unwrap()
        };
        ($block:ident, sccp_committee_generations, $key:expr, $value:expr) => {
            $block
                .sccp_committee_generations
                .try_insert_admitted($key, $value)
                .unwrap()
        };
        ($block:ident, $field:ident, $key:expr, $value:expr) => {
            $block.$field.insert($key, $value)
        };
    }
    macro_rules! remove_typed {
        ($block:ident, sccp_anchor_chunks, $key:expr) => {
            $block.sccp_anchor_chunks.try_remove_admitted($key).unwrap()
        };
        ($block:ident, sccp_committee_generations, $key:expr) => {
            $block
                .sccp_committee_generations
                .try_remove_admitted($key)
                .unwrap()
        };
        ($block:ident, $field:ident, $key:expr) => {
            $block.$field.remove($key)
        };
    }
    macro_rules! typed_table {
        ($field:ident, $key:expr, $value:expr, $changed:expr) => {{
            let mut block = world.block();
            let parent = WorldStateAccumulator::capture(&block).unwrap();
            put_typed!(block, $field, $key, $value);
            let inserted = parent.apply_block(&block).unwrap();
            assert_ne!(
                inserted.root(),
                parent.root(),
                "{}: insert",
                stringify!($field)
            );
            assert_eq!(
                inserted.root(),
                WorldStateAccumulator::capture(&block).unwrap().root(),
                "{}: incremental == cold",
                stringify!($field)
            );
            assert_eq!(inserted.entries(), parent.entries() + 1);
            put_typed!(block, $field, $key, $changed);
            let replaced = parent.apply_block(&block).unwrap();
            assert_ne!(
                replaced.root(),
                inserted.root(),
                "{}: replace",
                stringify!($field)
            );
            assert_ne!(
                replaced.root(),
                parent.root(),
                "{}: replace",
                stringify!($field)
            );
            remove_typed!(block, $field, $key);
            assert_eq!(
                parent.apply_block(&block).unwrap().root(),
                parent.root(),
                "{}: remove",
                stringify!($field)
            );
            covered.push((concat!("world.", stringify!($field)), Commitment::Certified));
        }};
    }
    typed_table!(
        smart_contract_state,
        "typed/row".parse::<StatePath>().unwrap(),
        vec![1_u8],
        vec![2_u8]
    );
    typed_table!(viral_binding_claims, Hash::new(b"claim"), 1_u32, 2_u32);
    typed_table!(viral_bonus_paid, Hash::new(b"bonus"), false, true);
    typed_table!(tx_sequences, account(b"typed-sequence"), 1_u64, 2_u64);
    typed_table!(musubi_domain_ownership_generations, domain(), 1_u64, 2_u64);
    typed_table!(
        soradns_directory_history,
        7_u64,
        [0x23_u8; 32],
        [0x24_u8; 32]
    );
    typed_table!(global_beacon_active_session, 7_u64, [1_u8; 32], [2_u8; 32]);
    typed_table!(
        sccp_history_leaves,
        7_u64,
        (1_u64, [1_u8; 32]),
        (2_u64, [1_u8; 32])
    );
    {
        use crate::state::sccp_forgery_custody::OffenceKey;
        let mut block = world.block();
        let parent = WorldStateAccumulator::capture(&block).unwrap();
        let pool = block.sccp_forgery_offences.allocation_budget().clone();
        let key = OffenceKey::try_copy(
            7,
            iroha_model_base::topology::LaneId::SINGLE,
            &account(b"typed-offence"),
            &pool,
        )
        .unwrap();
        block
            .sccp_forgery_offences
            .try_insert_admitted(key.clone(), [1; 32])
            .unwrap();
        let inserted = parent.apply_block(&block).unwrap();
        assert_ne!(inserted.root(), parent.root());
        assert_eq!(inserted.entries(), parent.entries() + 1);
        assert_eq!(
            inserted.root(),
            WorldStateAccumulator::capture(&block).unwrap().root()
        );
        block
            .sccp_forgery_offences
            .try_insert_admitted(key.clone(), [2; 32])
            .unwrap();
        assert_ne!(parent.apply_block(&block).unwrap().root(), inserted.root());
        block
            .sccp_forgery_offences
            .try_remove_admitted(key)
            .unwrap();
        assert_eq!(parent.apply_block(&block).unwrap().root(), parent.root());
        covered.push(("world.sccp_forgery_offences", Commitment::Certified));
    }

    typed_table!(
        consensus_keys_by_pk,
        "typed-public-key".to_owned(),
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "first")],
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "second")]
    );
    typed_table!(
        domain_endorsements_by_domain,
        domain(),
        vec![endorsement(b"first")],
        vec![endorsement(b"second")]
    );
    typed_table!(
        account_aliases,
        AccountAlias::domainless("typed".parse().unwrap(), DataSpaceId::UNIVERSAL),
        account(b"typed-alias-first"),
        account(b"typed-alias-second")
    );
    typed_table!(
        provider_owners,
        ProviderId::new([0x21; 32]),
        account(b"typed-provider-first"),
        account(b"typed-provider-second")
    );
    typed_table!(
        content_chunks,
        [0x22_u8; 32],
        ContentChunk::new(vec![1, 2, 3, 4]),
        ContentChunk::new(vec![9])
    );

    macro_rules! typed_cell {
        ($field:ident, $value:expr) => {{
            let mut block = world.block();
            let parent = WorldStateAccumulator::capture(&block).unwrap();
            *block.$field.get_mut() = $value;
            let changed = parent.apply_block(&block).unwrap();
            assert_ne!(changed.root(), parent.root(), "{}", stringify!($field));
            assert_eq!(
                changed.root(),
                WorldStateAccumulator::capture(&block).unwrap().root(),
                "{}: incremental == cold",
                stringify!($field)
            );
            assert_eq!(changed.entries(), parent.entries());
            covered.push((concat!("world.", stringify!($field)), Commitment::Certified));
        }};
    }
    typed_cell!(soradns_last_publish_ms, Some(42_u64));
    typed_cell!(soradns_history_len, 5_u64);
    typed_cell!(soradns_directory_latest, Some([3_u8; 32]));
    typed_cell!(soracloud_sequence_watermark, 9_u64);
    typed_cell!(governance_last_unlock_sweep_height, 3_u64);
    typed_cell!(merge_hint_roots, vec![Hash::new(b"hint")]);
    typed_cell!(merge_global_state_root, Some(Hash::new(b"root")));
    typed_cell!(sccp_reset_nonce, Some([1_u8; 32]));
    typed_cell!(sccp_forgery_max_generation, Some(7_u64));
    typed_cell!(sccp_committee_current, 7_u64);
    typed_cell!(sccp_liability_clock, 1_000_u64);
    typed_cell!(sccp_degraded_run, 2_u32);
    typed_cell!(
        sccp_anchor_open,
        crate::smartcontracts::isi::sccp::anchor_record::RetainedSccpAnchors::admit(
            &[iroha_data_model::sccp::generation::SccpAnchorV1 {
                core_hash: [1; 32],
                result: [2; 32]
            }],
            &budget,
        )
        .unwrap()
    );
    typed_table!(sccp_anchor_chunks, 0_u64, [1_u8; 32], [2_u8; 32]);
    let generation = crate::smartcontracts::isi::sccp::test_support::sample_generation(1);
    let mut changed = generation.clone();
    changed.progress_cap_ms -= 1;
    let generation =
        crate::smartcontracts::isi::sccp::generation_record::RetainedSccpGeneration::admit(
            &generation,
            &budget,
        )
        .unwrap();
    let changed =
        crate::smartcontracts::isi::sccp::generation_record::RetainedSccpGeneration::admit(
            &changed, &budget,
        )
        .unwrap();
    typed_table!(sccp_committee_generations, 1_u64, generation, changed);
    {
        use crate::smartcontracts::isi::sccp::{
            pause_record::{
                RetainedSccpFastPause, RetainedSccpFastPauseRound, RetainedSccpPausePanel,
            },
            test_support::{sample_fast_pause, sample_fast_pause_round, sample_pause_panel},
        };
        use iroha_data_model::{bridge::SccpNetworkV1, sccp::fast_pause::SccpPanelRoleV1};
        let network = SccpNetworkV1::EthereumMainnet;
        typed_table!(
            sccp_fast_pauses,
            network,
            RetainedSccpFastPause::admit(&sample_fast_pause(1), &budget).unwrap(),
            RetainedSccpFastPause::admit(&sample_fast_pause(2), &budget).unwrap()
        );
        typed_table!(
            sccp_fast_pause_rounds,
            (network, SccpPanelRoleV1::Primary),
            RetainedSccpFastPauseRound::admit(&sample_fast_pause_round(1), &budget).unwrap(),
            RetainedSccpFastPauseRound::admit(&sample_fast_pause_round(2), &budget).unwrap()
        );
        typed_table!(
            sccp_fast_pause_suspended_until_ms,
            network,
            1_000_u64,
            2_000_u64
        );
        typed_cell!(
            sccp_pause_panel,
            Some(RetainedSccpPausePanel::admit(&sample_pause_panel(1), &budget).unwrap())
        );
    }

    macro_rules! typed_derived {
        ($field:ident, $key:expr, $value:expr) => {{
            let mut block = world.block();
            let parent = WorldStateAccumulator::capture(&block).unwrap();
            put_typed!(block, $field, $key, $value);
            assert_eq!(
                parent.apply_block(&block).unwrap().root(),
                parent.root(),
                "{}: a derived index is not independent authority",
                stringify!($field)
            );
            assert_eq!(
                WorldStateAccumulator::capture(&block).unwrap().root(),
                parent.root(),
                "{}",
                stringify!($field)
            );
            covered.push((concat!("world.", stringify!($field)), Commitment::Derived));
        }};
    }
    typed_derived!(
        domains_by_owner,
        account(b"typed-owner"),
        BTreeSet::from([domain()])
    );
    typed_derived!(sccp_destination_pending_generations, 7_u64, ());
    typed_derived!(rwas_by_frozen, true, BTreeSet::new());
    typed_derived!(confidential_policy_transition_counts, 7_u64, 1_u32);
    typed_derived!(validation_fee_proposal_index, (7_u64, [2_u8; 32]), ());
    typed_derived!(proofs_by_tag, [1_u8; 4], Vec::new());

    // Each typed field is inventoried in the class the typed mutation observed.
    let rows = rows();
    for &(id, expected) in &covered {
        let row = rows
            .iter()
            .find(|row| row.field.id == id)
            .unwrap_or_else(|| panic!("{id} is not inventoried"));
        assert_eq!(row.commitment, expected, "{id}");
    }
    // Pin the exercised owners, not a retired cardinality: dropping an existing
    // table or testing one twice must not hide missing SCCP pause-state coverage.
    let actual: BTreeSet<_> = covered.iter().map(|(field, _)| *field).collect();
    assert_eq!(actual.len(), covered.len(), "typed owners are unique");
    let expected = BTreeSet::from([
        "world.account_aliases",
        "world.confidential_policy_transition_counts",
        "world.consensus_keys_by_pk",
        "world.content_chunks",
        "world.domain_endorsements_by_domain",
        "world.domains_by_owner",
        "world.global_beacon_active_session",
        "world.governance_last_unlock_sweep_height",
        "world.merge_global_state_root",
        "world.merge_hint_roots",
        "world.musubi_domain_ownership_generations",
        "world.proofs_by_tag",
        "world.provider_owners",
        "world.rwas_by_frozen",
        "world.sccp_anchor_chunks",
        "world.sccp_anchor_open",
        "world.sccp_committee_current",
        "world.sccp_committee_generations",
        "world.sccp_degraded_run",
        "world.sccp_destination_pending_generations",
        "world.sccp_fast_pause_rounds",
        "world.sccp_fast_pause_suspended_until_ms",
        "world.sccp_fast_pauses",
        "world.sccp_forgery_offences",
        "world.sccp_forgery_max_generation",
        "world.sccp_history_leaves",
        "world.sccp_liability_clock",
        "world.sccp_pause_panel",
        "world.sccp_reset_nonce",
        "world.smart_contract_state",
        "world.soracloud_sequence_watermark",
        "world.soradns_directory_history",
        "world.soradns_directory_latest",
        "world.soradns_history_len",
        "world.soradns_last_publish_ms",
        "world.tx_sequences",
        "world.validation_fee_proposal_index",
        "world.viral_binding_claims",
        "world.viral_bonus_paid",
    ]);
    assert_eq!(actual, expected, "every required typed owner is exercised");
}

/// Canonical State-level fields reach no certified root: the truth that open defect
/// G1-D2 records.
///
/// The typed part mutates the two commit topologies and compares the World accumulator
/// root, which is the only State root of the result (premise P3 of the inventory). For
/// every other uncommitted field the evidence is structural: it has no accumulator slot
/// (`every_inventoried_field_mutation_reaches_exactly_its_declared_root`) and no
/// execution-witness family carries it.
#[test]
fn state_level_canonical_fields_have_no_accumulator_slot_and_no_witness_family() {
    use crate::{kura::Kura, query::store::LiveQueryStore, state::State};
    use iroha_crypto::Algorithm;
    use iroha_model_base::peer::PeerId;

    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let root = |state: &State| {
        WorldStateAccumulator::capture(&state.world.block())
            .unwrap()
            .root()
            .unwrap()
    };
    let before = root(&state);
    let peer = || {
        PeerId::new(
            crate::state::checked_keypair_with_algorithm(Algorithm::BlsNormal)
                .public_key()
                .clone(),
        )
    };
    {
        let mut topology = state.commit_topology.block();
        topology.get_mut().push(peer());
        topology.commit();
    }
    assert_eq!(state.commit_topology.view().len(), 1);
    assert_eq!(root(&state), before, "state.commit_topology");
    {
        let mut topology = state.prev_commit_topology.block();
        topology.get_mut().push(peer());
        topology.commit();
    }
    assert_eq!(state.prev_commit_topology.view().len(), 1);
    assert_eq!(root(&state), before, "state.prev_commit_topology");

    let rows = rows();
    let uncommitted: Vec<&str> = rows
        .iter()
        .filter(|row| row.commitment == Commitment::Uncommitted)
        .map(|row| row.field.id)
        .collect();
    for id in [
        "state.transactions.frontier",
        "state.transactions.current",
        "state.transactions.rollback",
        "state.commit_topology",
        "state.prev_commit_topology",
        "state.lane_manifests",
        "state.lane_compliance",
        "state.chain_id",
        "state.network_id",
        "runtime.lanes",
    ] {
        assert!(
            uncommitted.contains(&id),
            "{id} is expected to be uncommitted"
        );
    }
    // Every uncommitted canonical field is State-level; every canonical World field is
    // certified. The node-configuration cells are a subset of the uncommitted ones.
    assert!(
        uncommitted
            .iter()
            .all(|id| id.starts_with("state.") || id.starts_with("runtime."))
    );
    let configured = node_configuration_cells();
    assert_eq!(configured.len(), 9);
    for id in &configured {
        assert!(uncommitted.contains(&id.as_str()), "{id}");
    }
    // No execution-witness family carries a State-level field, so the witnessed roots
    // cannot depend on one either.
    let witnessed = witnessed_fields();
    for id in &uncommitted {
        assert!(
            !witnessed.contains_key(*id),
            "{id} is carried by a witness family"
        );
    }
}

/// The drift test of the commitment list (`specs/sumeragi.md` §16.8): the scan discovers
/// domain literals by their form across both crates, independently of `ROOTS`, and rejects
/// every literal, construction use and count that is not listed exactly.
#[test]
fn source_scan_classifies_every_domain_literal_and_construction_use() {
    let scan = source_scan();
    scan.require_complete();
    let owners = domain_owners();
    assert_eq!(scan.literals, owners.len());
    let sources = rust_sources(SCAN_SCOPE);
    assert!(sources.windows(2).all(|pair| pair[0] < pair[1]));
    for path in [
        "crates/iroha_core/src/state.rs",
        "crates/iroha_core/src/fastpq/mod.rs",
        "crates/iroha_core/src/pipeline/overlay.rs",
        "crates/iroha_core/src/kura/lane_geometry.rs",
        "crates/iroha_core/src/smartcontracts/isi/sccp/witness.rs",
        "crates/iroha_data_model/src/sumeragi_finality/commitment.rs",
        "crates/iroha_data_model/src/confidential/spentness.rs",
    ] {
        assert!(sources.iter().any(|source| source == path), "{path}");
    }
    for path in SELF_PATHS {
        assert!(sources.iter().any(|source| source == path), "{path}");
    }

    // The permission-table root is owned, and it is found where it is declared.
    assert_eq!(
        owners.get("fastpq:v1:permission-table:blake2b-256"),
        Some(&DomainOwner::Root("fastpq_permission_table_root"))
    );
    assert!(
        split_source(&source("crates/iroha_core/src/fastpq/mod.rs"))
            .0
            .contains(&"fastpq:v1:permission-table:blake2b-256")
    );

    // The exact prospective-seat statement has a record digest, not a State-opening root.
    // Its sole model producer remains visible to the ordinary occurrence/source inventory.
    assert_eq!(
        owners.get("iroha:validator-seat-readiness:v1"),
        Some(&DomainOwner::Other(Use::Record))
    );
    assert_eq!(
        scan.literal_uses["iroha:validator-seat-readiness:v1"],
        BTreeMap::from([(
            "crates/iroha_data_model/src/nexus/committee.rs".to_owned(),
            1_usize
        )])
    );

    // Negative controls. Each probe is a source text at a path outside the State owner.
    let unlisted = |path: &str, text: &str| -> Vec<String> {
        scan_sources([(path, text)])
            .unlisted_domains
            .into_iter()
            .collect()
    };
    // An unfamiliar prefix.
    assert_eq!(
        unlisted(
            "crates/iroha_core/src/pipeline/probe.rs",
            "const D: &[u8] = b\"zeta:shadow-root:v1\\0\";"
        ),
        ["zeta:shadow-root:v1\\0 in crates/iroha_core/src/pipeline/probe.rs"]
    );
    // An addition under the prefix of a listed commitment, of a listed schema name and of
    // the permission-table root: none is owned by its neighbours.
    for literal in [
        "iroha:world-state:shadow:v1\\0",
        "iroha:state:shadow-codec:v1",
        "iroha:kagemusha:wallet:v1:shadow-record",
        "iroha:validator-seat-readiness:shadow:v1",
        "fastpq:v2:permission-table:blake2b-256",
    ] {
        assert_eq!(
            unlisted(
                "crates/iroha_core/src/state/probe.rs",
                &format!("const D: &[u8] = b\"{literal}\";")
            ),
            [format!("{literal} in crates/iroha_core/src/state/probe.rs")]
        );
    }
    // A domain without any commitment word, far from the State, witness and finality
    // sources, in either crate and in either literal form.
    assert_eq!(
        unlisted(
            "crates/iroha_data_model/src/probe.rs",
            "const A: &str = \"iroha.torii.cache-binding.v1\"; const B: &[u8] = br#\"probe-digest-v2\"#;"
        ),
        [
            "iroha.torii.cache-binding.v1 in crates/iroha_data_model/src/probe.rs",
            "probe-digest-v2 in crates/iroha_data_model/src/probe.rs"
        ]
    );
    // A listed literal in another source is not an unlisted literal, but it is a new use:
    // the scan records the source and the count, and the generated inventory pins both, so
    // the tracked file differs until the use is reviewed. A test source is not read.
    let reused = scan_sources([(
        "crates/iroha_core/src/probe.rs",
        "const D: &[u8] = b\"iroha:world-state:root:v1\\0\"; const E: &[u8] = b\"iroha:world-state:root:v1\\0\";",
    )]);
    assert!(reused.unlisted_domains.is_empty());
    assert_eq!(
        reused.literal_uses["iroha:world-state:root:v1\\0"],
        BTreeMap::from([("crates/iroha_core/src/probe.rs".to_owned(), 2_usize)])
    );
    assert_eq!(
        literal_use_lines(&reused),
        [
            "{\"literal\":\"iroha:world-state:root:v1\\\\0\",\"owner\":\"root:world_state_root\",\"sources\":{\"crates/iroha_core/src/probe.rs\":2}}"
        ]
    );
    let actual_uses = &scan.literal_uses["iroha:world-state:root:v1\\0"];
    assert!(
        !actual_uses.contains_key("crates/iroha_core/src/probe.rs")
            && actual_uses.values().sum::<usize>() > 0,
        "{actual_uses:?}"
    );
    // Every listed literal has at least one pinned use, and a short generic tag is pinned
    // to each of its sources.
    assert_eq!(scan.literal_uses.len(), owners.len());
    assert!(
        scan.literal_uses
            .values()
            .all(|sources| !sources.is_empty() && sources.values().all(|count| *count > 0))
    );
    assert!(
        scan.literal_uses.values().any(|sources| sources.len() > 1),
        "the sources hold no literal with more than one use"
    );
    assert!(
        unlisted(
            "crates/iroha_core/src/probe_tests.rs",
            "const D: &[u8] = b\"zeta:shadow-root:v1\\0\";"
        )
        .is_empty()
    );
    // A construction in a new source, and one more construction inside an approved source.
    let probe = scan_sources([(
        "crates/iroha_core/src/pipeline/probe.rs",
        "use iroha_crypto::MerkleMap; // MerkleTree in a comment does not count",
    )]);
    assert_eq!(
        probe.unlisted_uses.iter().collect::<Vec<_>>(),
        ["crates/iroha_core/src/pipeline/probe.rs: found [(\"MerkleMap\", 1)]"]
    );
    let approved = "crates/iroha_core/src/snapshot.rs";
    let listed = CONSTRUCTION_USES
        .iter()
        .find(|listed| listed.path == approved)
        .expect("the snapshot service is a listed construction user");
    let text = source(approved);
    assert!(
        scan_sources([(approved, text.as_str())])
            .unlisted_uses
            .is_empty()
    );
    let grown = format!("{text}\nfn shadow() -> MerkleTree<[u8; 32]> {{ todo!() }}\n");
    let grown = scan_sources([(approved, grown.as_str())]);
    assert_eq!(grown.unlisted_uses.len(), 1);
    assert!(
        grown
            .unlisted_uses
            .iter()
            .next()
            .is_some_and(|report| report.starts_with(approved)
                && report.contains(&format!("listed {:?}", listed.uses))),
        "{:?}",
        grown.unlisted_uses
    );
    // A listing that no source backs is reported as stale, and the check fails.
    assert!(probe.stale_domains.contains("iroha:world-state:root:v1\\0"));
    assert!(probe.stale_uses.contains(approved));
    assert!(std::panic::catch_unwind(|| probe.require_complete()).is_err());

    // The literal reader: comments, character literals, lifetimes, escapes, raw strings.
    let (literals, code) = split_source(
        "// \"in:a:comment:v1\"\n/* \"in:a:block:v1\" /* nested */ */\n\
         fn f<'a>(x: &'a str) -> char { let q = '\"'; let e = '\\''; let m = 'é';\n\
         g(b\"iroha:x:v1\\0\", \"a \\\"quoted\\\" b\", r#\"raw \"q\" :v1\"#, br\"raw:b:v1\", \"plain\") }",
    );
    assert_eq!(
        literals,
        [
            "iroha:x:v1\\0",
            "a \\\"quoted\\\" b",
            "raw \"q\" :v1",
            "raw:b:v1",
            "plain"
        ]
    );
    assert!(code.contains("fn f<'a>(x: &'a str)") && !code.contains("comment"));
    assert!(!code.contains("plain") && !code.contains("nested"));
    assert_eq!(split_source("let s = \"unterminated").0, ["unterminated"]);

    // The domain-literal rule.
    for literal in [
        "iroha:x",
        "iroha/sumeragi/result/v1",
        "iroha 2026-09-30 world-state lthash16 element v1",
        "iroha.global-threshold-beacon.pulse-id.v1\\0",
        "fastpq:v1:permission-table:blake2b-256",
        "sumeragi:npos-committee-seat:v1\\0",
        "\\xd8iroha:sccp:state-delta:v1",
        "confidential-asset-spentness-v1",
        "retail_fee_head_tree_v1/",
        "fastpq:execution-effects:v1:step|",
    ] {
        assert!(is_domain_literal(literal), "{literal}");
    }
    for literal in [
        "iroha",
        "iroha.toml",
        "iroha.mint",
        "iroha::logger",
        // Norito Rust schema identities name layouts, not scanned hash domains.
        "iroha_core::amx::AmxParentCoordinatesV1",
        "iroha_core::amx::AmxIntentCoordinatesV1",
        "iroha_core::amx::AmxIntentRowV1",
        "plain text v1 here",
        "retail_fee_head_tree_v1",
        "../fixtures/a/b_v1.json",
        "/v1/status",
        "value {x} :v1",
        "lthash16:x",
        "provider:preview",
    ] {
        assert!(!is_domain_literal(literal), "{literal}");
    }
    assert!(
        has_version_segment("a-V12") && !has_version_segment("a-v") && !has_version_segment("avx2")
    );
    assert_eq!(
        segments("a:b/c.d|e-f_g\\0").collect::<Vec<_>>(),
        ["a", "b", "c", "d", "e", "f", "g", "0"]
    );
    assert!(is_test_source("crates/a/src/x_tests.rs"));
    assert!(is_test_source("crates/a/src/x/tests.rs"));
    assert!(is_test_source("crates/a/src/tests/x.rs"));
    assert!(is_test_source("crates/a/src/test_fixtures.rs"));
    assert!(!is_test_source("crates/a/src/attests.rs"));
}

/// The signature scan (`specs/sumeragi.md` §16.8): every function or method of
/// `iroha_core` with a State or World receiver or reader argument and a hash-bearing
/// return value is listed exactly, with the commitment it computes or serves or with its
/// reviewed use.
#[test]
fn state_hash_function_scan_lists_every_state_reader_that_returns_a_hash() {
    let scan = source_scan();
    scan.require_complete();
    assert_eq!(scan.state_hash_functions.len(), STATE_HASH_FUNCTIONS.len());
    // The two digests that the literal scan cannot see are found by their signatures.
    for (path, name) in [
        (
            "crates/iroha_core/src/state.rs",
            "compute_vk_set_hash_from_statuses_at_height",
        ),
        (
            "crates/iroha_core/src/state.rs",
            "compute_confidential_feature_digest",
        ),
        (
            "crates/iroha_core/src/sumeragi/genesis_meta.rs",
            "staged_genesis_nexus_amx_context_hash",
        ),
    ] {
        assert_eq!(
            scan.state_hash_functions
                .get(&(path.to_owned(), name.to_owned())),
            Some(&1),
            "{path}: {name}"
        );
        let listed = STATE_HASH_FUNCTIONS
            .iter()
            .find(|listed| listed.path == path && listed.name == name)
            .unwrap_or_else(|| panic!("{name} is listed"));
        assert!(
            matches!(listed.owner, UseOwner::Roots(roots) if roots.len() == 1
                && ROOTS.iter().any(|root| root.id == roots[0]
                    && root.class == RootClass::ProtocolFingerprint)),
            "{name}"
        );
    }

    // Negative controls: a probe source in iroha_core. Each function below reads State
    // and returns a hash-bearing value in another form.
    let probe = "crates/iroha_core/src/pipeline/probe.rs";
    let report = |text: &str| -> Vec<String> {
        scan_sources([(probe, text)])
            .unlisted_functions
            .into_iter()
            .collect()
    };
    for (text, name) in [
        (
            "fn shadow_root(world: &impl WorldReadOnly) -> Hash { todo!() }",
            "shadow_root",
        ),
        (
            "pub(crate) fn raw_array(state: &State, height: u64) -> Option<[u8; 32]> { todo!() }",
            "raw_array",
        ),
        (
            "fn named_length<S: StateReadOnly>(view: &S) -> [u8; Hash::LENGTH] { todo!() }",
            "named_length",
        ),
        (
            "fn bounded<S>(view: &S) -> Result<Hash32, E> where S: StateReadOnly + ?Sized { todo!() }",
            "bounded",
        ),
        (
            "fn wrapper(block: &StateBlock<'_>) -> Result<BlobDigest, String> { todo!() }",
            "wrapper",
        ),
        (
            "fn composite(world: &impl WorldReadOnly) -> ConfidentialFeatureDigest { todo!() }",
            "composite",
        ),
        (
            "fn versioned(tx: &StateTransaction<'_, '_>) -> ShadowCommitmentV2 { todo!() }",
            "versioned",
        ),
        (
            "fn proof(view: &StateView<'_>) -> Option<ShadowProofV1> { todo!() }",
            "proof",
        ),
        (
            "fn record(world: &WorldBlock<'_>) -> WorldStateTransition { todo!() }",
            "record",
        ),
        (
            "impl StateBlock<'_> { fn method(&self) -> HashOf<Shadow> { todo!() } }",
            "method",
        ),
        (
            "impl<'a> Shadow for StateView<'a> { fn provided(&self) -> Hash { todo!() } }",
            "provided",
        ),
        (
            "pub trait WorldReadOnly { fn default_method(&self) -> Option<[u8; 32]> { None } }",
            "default_method",
        ),
        (
            "impl<V: StateReadOnly> Holder<V> { fn held(&self) -> Hash32 { todo!() } }",
            "held",
        ),
        // The whole header of the block is read: a blanket implementation for all readers,
        // a reader bound on a parameter of the implementing type, a reader trait
        // implemented for a type with another name, a literal impl block in a macro body,
        // an extension trait of a reader trait and a where clause.
        (
            "impl<T: StateReadOnly + ?Sized> ShadowDigests for T { fn shadow_digest(&self, height: u64) -> Option<[u8; 32]> { todo!() } }",
            "shadow_digest",
        ),
        (
            "impl<W: crate::state::WorldReadOnly> Plan for Inputs<'_, W> { fn shadow_root(&self) -> Hash { todo!() } }",
            "shadow_root",
        ),
        (
            "impl WorldReadOnly for Overlay { fn overlay_root(&self) -> Hash { todo!() } }",
            "overlay_root",
        ),
        (
            "macro_rules! views { ($($ident:ty),*) => {$( impl StateReadOnly for $ident { fn shadow_hash(&self) -> Option<Hash> { todo!() } } )*}; }",
            "shadow_hash",
        ),
        (
            "macro_rules! views { ($ident:ty) => { impl Other for $ident {} impl StateReadOnly for $ident { fn later_hash(&self) -> Hash { todo!() } } }; }",
            "later_hash",
        ),
        (
            "pub trait ShadowExt: StateReadOnly { fn extension_root(&self) -> Hash { todo!() } }",
            "extension_root",
        ),
        (
            "impl<T> Shadow for T where T: WorldReadOnly { fn bounded_root(&self) -> Hash32 { todo!() } }",
            "bounded_root",
        ),
        // `Self` in a return type is the implementing type of the block.
        (
            "impl WorldStateTransition { fn capture(world: &impl WorldReadOnly) -> Self { todo!() } }",
            "capture",
        ),
        (
            "impl<'a> From<&'a State> for ShadowDigest { fn from(state: &'a State) -> Self { todo!() } }",
            "from",
        ),
        // A record that carries a digest of State content under another name.
        (
            "fn snapshot(state: &impl StateReadOnly) -> Option<AxtPolicySnapshot> { todo!() }",
            "snapshot",
        ),
        // The owners of the other registry fields and the table and cell handles are
        // readers as well: the transaction storage, the trigger set, the block-hash
        // journal, a query view and the rows of one table.
        (
            "fn membership(storage: &TransactionsStorage) -> CapturedMembershipTables { todo!() }",
            "membership",
        ),
        (
            "impl Set { fn capture_table(&self) -> Result<CanonicalTablePairedSnapshot, E> { todo!() } }",
            "capture_table",
        ),
        (
            "fn journal(hashes: &dyn BlockHashRead) -> Option<[u8; 32]> { todo!() }",
            "journal",
        ),
        (
            "fn query(view: &StateQueryView<'_>) -> Hash { todo!() }",
            "query",
        ),
        (
            "fn rows_digest(rows: &impl StorageReadOnly<Key, Row>) -> Hash { todo!() }",
            "rows_digest",
        ),
        (
            "fn cell_digest(cell: &CellView<'_, Row>) -> ShadowDigest { todo!() }",
            "cell_digest",
        ),
        // A record of the peer handshake or of a lane block that the carrier walk reads:
        // the hello with its four metadata records, the capabilities and the lane batch.
        (
            "fn hello(view: &StateView<'_>) -> Result<HandshakeHello, E> { todo!() }",
            "hello",
        ),
        (
            "fn consensus_meta(world: &impl WorldReadOnly) -> HandshakeConsensusMeta { todo!() }",
            "consensus_meta",
        ),
        (
            "fn confidential_meta<S: StateReadOnly>(state: &S) -> Option<HandshakeConfidentialMeta> { todo!() }",
            "confidential_meta",
        ),
        (
            "fn crypto_meta(state: &State) -> HandshakeCryptoMeta { todo!() }",
            "crypto_meta",
        ),
        (
            "fn trust_meta(block: &StateBlock<'_>) -> HandshakeTrustMeta { todo!() }",
            "trust_meta",
        ),
        (
            "fn confidential_caps(state: &impl StateReadOnly) -> iroha_p2p::ConfidentialHandshakeCaps { todo!() }",
            "confidential_caps",
        ),
        (
            "fn crypto_caps(world: &World) -> CryptoHandshakeCaps { todo!() }",
            "crypto_caps",
        ),
        (
            "fn identity_binding(view: &StateView<'_>) -> HandshakeIdentityBindingV1 { todo!() }",
            "identity_binding",
        ),
        (
            "fn lane_batch(block: &StateBlock<'_>, height: u64) -> Result<LaneBatch, E> { todo!() }",
            "lane_batch",
        ),
        (
            "impl LaneBatch { fn from_state(world: &impl WorldReadOnly) -> Self { todo!() } }",
            "from_state",
        ),
        (
            "impl StateView<'_> { fn lane_result(&self) -> Option<LaneResult> { todo!() } }",
            "lane_result",
        ),
    ] {
        assert_eq!(
            report(text),
            [format!("{probe}: {name}: found 1")],
            "{text}"
        );
    }
    // The carried records are the walked types of the handshake and lane carriers: a type
    // added to either carrier is matched as a return type without a second listing.
    assert_eq!(
        carried_records(),
        [
            "ConfidentialHandshakeCaps",
            "ConsensusConfigCaps",
            "ConsensusHandshakeCaps",
            "CryptoHandshakeCaps",
            "HandshakeConfidentialDigest",
            "HandshakeConfidentialMeta",
            "HandshakeConsensusMeta",
            "HandshakeCryptoMeta",
            "HandshakeHello",
            "HandshakeIdentityBindingV1",
            "HandshakeTrustMeta",
            "LaneBatch",
            "LaneResult",
        ]
    );
    for record in carried_records() {
        assert!(returns_hash(record), "{record}");
        assert!(
            returns_hash(&format!("Result<Option<{record}>, E>")),
            "{record}"
        );
    }
    for id in RECORD_RETURN_CARRIERS {
        assert!(CARRIERS.iter().any(|carrier| carrier.id == *id), "{id}");
    }
    // The retired SCCP subject digest is not a parallel native authority path.
    assert!(
        scan.state_hash_functions
            .keys()
            .all(|(path, _)| path != "crates/iroha_core/src/smartcontracts/isi/sccp/subjects.rs")
    );
    // The functions of the tree that only the whole header matches are listed.
    for (path, name, count) in [
        (
            "crates/iroha_core/src/governance/parliament/planner.rs",
            "verified_pulse",
            1,
        ),
        (
            "crates/iroha_core/src/state/deserialize_world_musubi_source_traits.rs",
            "source_pin_manifests",
            1,
        ),
        (
            "crates/iroha_core/src/state.rs",
            "lane_incarnation_at_height",
            3,
        ),
    ] {
        assert_eq!(
            scan.state_hash_functions
                .get(&(path.to_owned(), name.to_owned())),
            Some(&count),
            "{path}: {name}"
        );
    }
    // Every State reader that returns the AXT policy snapshot belongs to its commitment.
    let snapshot_readers: Vec<&str> = STATE_HASH_FUNCTIONS
        .iter()
        .filter(|listed| {
            matches!(listed.owner, UseOwner::Roots(roots) if roots == ["axt_policy_snapshot"])
        })
        .map(|listed| listed.name)
        .collect();
    assert_eq!(
        snapshot_readers,
        [
            "axt_policy_snapshot_from_state",
            "derive_axt_policy_snapshot_from_directory",
            "axt_execution_policy_snapshot",
            "axt_policy_snapshot",
            "execution_axt_policy_snapshot",
            "rebuild_axt_policies_from_space_directory",
            "rebuild_space_directory_bindings",
            "refresh_axt_policies_from_directory",
        ]
    );
    // A second function of a listed name in a listed source changes its count.
    let listed = "crates/iroha_core/src/sumeragi/genesis_meta.rs";
    let text = source(listed);
    assert!(
        scan_sources([(listed, text.as_str())])
            .unlisted_functions
            .is_empty()
    );
    let grown = format!(
        "{text}\nmod shadow {{ fn staged_genesis_nexus_amx_context_hash(s: &StateBlock<'_>) -> Hash {{ todo!() }} }}\n"
    );
    assert_eq!(
        scan_sources([(listed, grown.as_str())])
            .unlisted_functions
            .into_iter()
            .collect::<Vec<_>>(),
        [format!(
            "{listed}: staged_genesis_nexus_amx_context_hash: found 2, listed 1"
        )]
    );
    // What the rule does not match: no reader, no hash-bearing return, a test-only item,
    // a source outside iroha_core, a test source, `impl Trait` in a type, a method without
    // a `self` receiver in a reader block, a block whose header names no reader (also when
    // a macro implements it for a reader type: the scan does not expand macros), and
    // `Self` of a type that carries no hash.
    for (path, text) in [
        (probe, "fn no_reader(bytes: &[u8]) -> Hash { todo!() }"),
        (probe, "fn no_hash(world: &impl WorldReadOnly) -> u64 { 0 }"),
        (
            probe,
            "fn record_types(state: &State) -> Result<SumeragiRootScope, DaCommitmentRecord> { todo!() }",
        ),
        (
            probe,
            "#[cfg(test)]\nfn test_only(world: &impl WorldReadOnly) -> Hash { todo!() }",
        ),
        (
            probe,
            "#[cfg(test)]\nmod tests { fn inner(world: &World) -> Hash { todo!() } }",
        ),
        (
            probe,
            "#[test]\n#[ignore]\nfn a_test() { fn inner(world: &World) -> Hash { todo!() } }",
        ),
        (
            "crates/iroha_data_model/src/probe.rs",
            "fn outside(world: &impl WorldReadOnly) -> Hash { todo!() }",
        ),
        (
            "crates/iroha_core/src/probe_tests.rs",
            "fn in_tests(world: &impl WorldReadOnly) -> Hash { todo!() }",
        ),
        (
            probe,
            "impl Other { fn other_method(&self) -> Hash { todo!() } }",
        ),
        (
            probe,
            "fn returns_reader(bytes: &[u8]) -> impl WorldReadOnly { todo!() }\nimpl Other { fn after(&self) -> Hash { todo!() } }",
        ),
        (
            probe,
            "impl World { fn associated(rows: &[u8]) -> Hash { todo!() } }",
        ),
        (
            probe,
            "macro_rules! sources { ($($view:ty),*) => {$( impl ContextSource for $view { fn generated(&self) -> Hash { todo!() } } )*}; }\nsources! { StateView<'_> }",
        ),
        (
            probe,
            "impl Other { fn capture(world: &impl WorldReadOnly) -> Self { todo!() } }",
        ),
        (
            probe,
            "pub trait ShadowDigests { fn shadow_digest(&self) -> Hash; }",
        ),
        (
            probe,
            "impl Other { fn tuple(&self, pair: (impl WorldKey, u8)) -> Hash { todo!() } }",
        ),
        (
            probe,
            "impl Acquire for Cell<ShadowDigest> { fn original(&self) -> Result<Self::Acquisition, E> { todo!() } }",
        ),
    ] {
        assert!(
            scan_sources([(path, text)]).unlisted_functions.is_empty(),
            "{text}"
        );
    }
    // A listing that no source backs is stale.
    let empty = scan_sources([(probe, "")]);
    assert_eq!(empty.stale_functions.len(), STATE_HASH_FUNCTIONS.len());
    assert!(std::panic::catch_unwind(|| empty.require_complete()).is_err());

    // The signature reader.
    let signatures = fn_signatures(
        "pub fn a<T: Into<u8>>(x: T) -> u8 { 0 }\n\
         fn b(f: fn(u8) -> Hash, world: &World) { }\n\
         trait T { fn c(&self) -> Hash; }\n\
         impl World { pub(crate) fn d(&mut self, n: [u8; 4]) -> Result<[u8; 32], E> where E: X { todo!() } }",
    );
    assert_eq!(
        signatures,
        [
            FnSignature {
                name: "a".to_owned(),
                reads_state: false,
                returns_hash: false
            },
            FnSignature {
                name: "b".to_owned(),
                reads_state: true,
                returns_hash: false
            },
            FnSignature {
                name: "c".to_owned(),
                reads_state: false,
                returns_hash: true
            },
            FnSignature {
                name: "d".to_owned(),
                reads_state: true,
                returns_hash: true
            },
        ]
    );
    assert_eq!(
        type_blocks("impl<'a> A for B<'a> where B: C { } pub trait D: E { } fn f(x: impl G) { }"),
        [
            (0, 35, "impl<'a> A for B<'a> where B: C".to_owned()),
            (40, 54, "trait D: E".to_owned())
        ]
    );
    for (kind, own) in [
        ("Self", true),
        ("Option<Self>", true),
        ("(Self, Self::Other)", true),
        ("Result<Self::Acquisition, E>", false),
        ("Box<Self :: Out>", false),
        ("Selfish", false),
        ("", false),
    ] {
        assert_eq!(names_own_type(kind), own, "{kind}");
    }
    assert!(
        STATE_READER_TYPES.windows(2).all(|pair| pair[0] < pair[1]),
        "the State reader types are listed once, in ascending order"
    );
    // The reader list is closed: the reader traits are readers, and so is every type for
    // which an iroha_core source implements one in a literal impl block.
    for reader in STATE_READER_TRAITS {
        assert!(STATE_READER_TYPES.contains(reader), "{reader}");
    }
    let mut implementors = BTreeSet::new();
    for path in rust_sources(&[FUNCTION_SCAN_SCOPE.trim_end_matches('/')]) {
        if is_test_source(&path) || SELF_PATHS.contains(&path.as_str()) {
            continue;
        }
        let text = source(&path);
        let (_, code) = split_source(&text);
        for implementor in reader_trait_implementors(&code) {
            assert!(
                STATE_READER_TYPES.contains(&implementor.as_str()),
                "{implementor} implements a State reader trait in {path}: add it to \
                 STATE_READER_TYPES"
            );
            implementors.insert(implementor);
        }
    }
    for expected in [
        "BlockHashRange",
        "DetachedSet",
        "PreparedTransactionsBlock",
        "StateBlock",
        "StateView",
        "TransactionsBlockField",
    ] {
        assert!(implementors.contains(expected), "{expected}");
    }
    assert_eq!(
        reader_trait_implementors(
            "impl<T: BlockHashRead + ?Sized> BlockHashRead for &T { } \
             impl BlockHashRead for Vec<HashOf<BlockHeader>> { } \
             impl BlockHashRead for [HashOf<BlockHeader>] { } \
             impl<A> SetReadOnly for DetachedSet<A> { } \
             impl crate::state::WorldReadOnly for Overlay<'_> { } \
             impl StateReadOnly for $ident { } \
             impl Other for StateView<'_> { } \
             impl Overlay { } trait WorldReadOnly { }"
        ),
        ["DetachedSet", "Overlay"]
    );
    // The roots that are computed from an owner of State fields other than `State` and
    // `World` are found through that owner.
    for (path, name, root) in [
        (
            "crates/iroha_core/src/state/storage_transactions/block/membership_root.rs",
            "capture_committed_root",
            "transaction_membership_root",
        ),
        (
            "crates/iroha_core/src/state/authority_registry/complete/transaction_membership.rs",
            "capture_from_storage",
            "transaction_membership_root",
        ),
        (
            "crates/iroha_core/src/smartcontracts/isi/triggers/set_authority_capture.rs",
            "capture_data_authority_table",
            "state_table_substrate",
        ),
    ] {
        let listed = STATE_HASH_FUNCTIONS
            .iter()
            .find(|listed| listed.path == path && listed.name == name)
            .unwrap_or_else(|| panic!("{name} is listed"));
        assert!(
            matches!(listed.owner, UseOwner::Roots(roots) if roots.contains(&root)),
            "{name}"
        );
    }
    for (header, target) in [
        ("impl<'a> A for B<'a> where B: C", Some("B<'a>")),
        ("impl<T: X<Y>> Holder<T>", Some("Holder<T>")),
        ("impl World", Some("World")),
        ("impl<T> A for T", Some("T")),
        ("trait D: E", None),
    ] {
        assert_eq!(implementing_type(header), target, "{header}");
    }
    assert_eq!(
        test_only_ranges("#[cfg(test)] #[allow(x)] fn t() -> [u8; 2] { {} } fn u() {}"),
        [(0, 49)]
    );
    assert_eq!(
        test_only_ranges("#[cfg(test)]\nmod tests;\nfn u() {}"),
        [(0, 23)]
    );
    assert_eq!(closing(b"<A<B>, fn() -> C>x", 0), 17);
    assert_eq!(closing(b"(a(b)", 0), 5);
    assert_eq!(header_end(b"-> [u8; 32] where T: X { }", 0), 23);
    assert_eq!(item_end(b"fn f() { { } } x", 0), 14);
    assert_eq!(item_end(b"use a::b; x", 0), 9);
    assert!(keyword_at(b"x fn y", 2, b"fn") && !keyword_at(b"x fnord", 2, b"fn"));
    assert!(!keyword_at(b"xfn y", 1, b"fn"));
    assert_eq!(
        identifiers("&'a mut Foo<Bar_1>").collect::<Vec<_>>(),
        ["a", "mut", "Foo", "Bar_1"]
    );
    assert_eq!(unversioned("ShadowRootV12"), "ShadowRoot");
    assert_eq!(unversioned("Shadow12"), "Shadow12");
    assert_eq!(unversioned("V1"), "");
    assert_eq!(unversioned("ShadowV"), "ShadowV");
    assert!(is_hash_named("BlobDigest") && is_hash_named("SccpMessageProofBundleV1"));
    assert!(!is_hash_named("SumeragiRootScope") && !is_hash_named("DaCommitmentRecord"));
    for output in [
        "Hash",
        "Option<HashOf<BlockHeader>>",
        "Result<Hash32, E>",
        "[u8; 32]",
        "[u8 ;\n 32]",
        "[u8; blake3::OUT_LEN]",
        "ConfidentialFeatureDigest",
        "Result<Option<SccpBlockCommitmentV1>, E>",
        "Vec<(u64, QueryProjectionCheckpoint)>",
    ] {
        assert!(returns_hash(output), "{output}");
    }
    for output in [
        "",
        "u64",
        "[u8; 31]",
        "Result<(), HashError>",
        "AccountId",
        "LaneBatchView",
        "HandshakeHelloTimer",
        "RelayRole",
    ] {
        assert!(!returns_hash(output), "{output}");
    }
    assert!(names_state_reader("x: &crate::state::State") && !names_state_reader("LaneState"));
}

/// A test-only argument cannot hide the next original AMX State-reader method.
#[test]
fn state_hash_scan_cfg_arguments_preserve_original_amx_complete() {
    let text = r#"
        impl<V: StateReadOnly> NativeAmxRecordProofReadV1<'_, V> {
            pub fn poll(&mut self) -> Result<NativeAmxRecordProofPollV1, Error> {
                self.source.as_mut().expect("source").poll(
                    #[cfg(test)]
                    &mut self.portable_probe,
                )
            }
            pub fn complete(&mut self) -> Result<Option<AllocatedAmxRecordProofV1>, Error> {
                loop { match self.poll()? { Poll::Pending => {}, Poll::Complete(p) => return Ok(p) } }
            }
        }
    "#;
    let (_, code) = split_source(text);
    assert_eq!(
        fn_signatures(&code),
        [
            FnSignature {
                name: "poll".to_owned(),
                reads_state: true,
                returns_hash: false
            },
            FnSignature {
                name: "complete".to_owned(),
                reads_state: true,
                returns_hash: true
            },
        ],
        "test-only AMX call argument must not hide original complete State-reader"
    );
}

/// Local attributes end at their original field, argument, statement or block boundary.
#[test]
fn state_hash_scan_cfg_nonitems_preserve_later_production_functions() {
    for text in [
        "struct Holder { #[cfg(test)] pub(crate) probe: Option<(A, B)>, other: A } fn visible(s: &State) -> Hash { todo!() }",
        "enum Holder { #[cfg(test)] Probe(A, B), Other } fn visible(s: &State) -> Hash { todo!() }",
        "fn outer() { call(#[cfg(test)] nested([a, b], (c, d)), { fn visible(s: &State) -> Hash { todo!() } }); }",
        "fn outer() { #[cfg(test)] let probe = { fn hidden(s: &State) -> Hash { todo!() } (a, b) }; fn visible(s: &State) -> Hash { todo!() } }",
        "fn outer() { call(#[cfg(test)] { fn hidden(s: &State) -> Hash { todo!() } [a, b] }); fn visible(s: &State) -> Hash { todo!() } }",
        "fn outer() { #[cfg(test)] { fn hidden(s: &State) -> Hash { todo!() } } } fn visible(s: &State) -> Hash { todo!() }",
        "fn outer() { #[cfg(test)] { fn hidden(s: &State) -> Hash { todo!() } } fn visible(s: &State) -> Hash { todo!() } }",
        "fn outer() { #[cfg(test)] async { fn hidden(s: &State) -> Hash { todo!() } } fn visible(s: &State) -> Hash { todo!() } }",
        "fn outer() { #[cfg(test)] unsafe { fn hidden(s: &State) -> Hash { todo!() } } fn visible(s: &State) -> Hash { todo!() } }",
        "fn outer() { #[cfg(test)] if flag { fn hidden(s: &State) -> Hash { todo!() } } else { fn hidden_else(s: &State) -> Hash { todo!() } } fn visible(s: &State) -> Hash { todo!() } }",
        "fn outer() { #[cfg(test)] loop { fn hidden(s: &State) -> Hash { todo!() } } impl World { fn visible(&self) -> Hash { todo!() } } }",
        "struct Holder { #[cfg(test)] callback: fn() -> [u8; { fn hidden(s: &State) -> Hash { todo!() } 1 }], other: [u8; { fn visible(s: &State) -> Hash { todo!() } 1 }] }",
        "struct Holder { #[cfg(test)] probe: [u8; { fn hidden(s: &State) -> Hash { todo!() } 1 }], other: [u8; { fn visible(s: &State) -> Hash { todo!() } 1 }] }",
        "fn outer() { call(#[cfg(test)] (a, [b, c], { fn hidden(s: &State) -> Hash { todo!() } 0 }), { fn visible(s: &State) -> Hash { todo!() } }); }",
    ] {
        let (_, code) = split_source(text);
        let matched: Vec<_> = fn_signatures(&code)
            .into_iter()
            .filter(|signature| signature.reads_state && signature.returns_hash)
            .map(|signature| signature.name)
            .collect();
        assert_eq!(
            matched,
            ["visible"],
            "local cfg target swallowed another owner: {text}"
        );
    }
    assert_eq!(
        test_only_ranges("#[cfg(test)] probe) fn visible() {}"),
        [(0, 18)]
    );
    assert_eq!(
        test_only_ranges("#[cfg(test)] probe] fn visible() {}"),
        [(0, 18)]
    );
    assert_eq!(
        test_only_ranges("#[cfg(test)] probe} fn visible() {}"),
        [(0, 18)]
    );
}

/// Real test-only items remain excluded, including associated items and generic headers.
#[test]
fn state_hash_scan_cfg_items_preserve_exact_item_exclusion() {
    for item in [
        "#[cfg(test)] #[inline] pub(in crate::state) async unsafe fn hidden<T: Trait<A, B>, U>(s: &State, f: fn(A, B)) -> Hash where T: Other<U, A> { fn nested(s: &State) -> Hash { todo!() } todo!() }",
        "#[cfg(test)] pub(crate) const fn hidden(s: &State) -> Hash { todo!() }",
        "#[cfg(test)] pub unsafe extern \"C\" fn hidden(s: &State) -> Hash { todo!() }",
        "#[test] #[ignore] fn hidden() { fn nested(s: &State) -> Hash { todo!() } }",
        "#[cfg(test)] pub mod test_module { fn hidden(s: &State) -> Hash { todo!() } }",
        "#[cfg(test)] unsafe impl<T: Trait<A, B>> WorldReadOnly for Holder<T> { fn hidden(&self) -> Hash { todo!() } }",
        "#[cfg(test)] pub trait TestTrait: StateReadOnly { fn hidden(&self) -> Hash; }",
        "impl World { #[cfg(test)] pub(crate) fn hidden<T: Trait<A, B>>(&self) -> Hash { todo!() } }",
        "impl World { #[cfg(test)] const HIDDEN: Hash = { fn nested(s: &State) -> Hash { todo!() } todo!() }; }",
        "#[cfg(test)] macro_rules! hidden { () => { fn nested(s: &State) -> Hash { todo!() } }; }",
    ] {
        let text = format!("{item}\nfn visible(s: &State) -> Hash {{ todo!() }}");
        let (_, code) = split_source(&text);
        let matched: Vec<_> = fn_signatures(&code)
            .into_iter()
            .filter(|signature| signature.reads_state && signature.returns_hash)
            .map(|signature| signature.name)
            .collect();
        assert_eq!(
            matched,
            ["visible"],
            "test-only item boundary changed: {item}"
        );
    }
    assert_eq!(
        test_only_ranges("#[cfg(test)] mod tests; fn visible() {}"),
        [(0, 23)]
    );
}

/// Existing delimiter and generic signature rules remain unchanged by local cfg ranges.
#[test]
fn state_hash_scan_cfg_boundary_helpers_preserve_existing_rules() {
    assert_eq!(closing(b"<A<B>, fn() -> C>x", 0), 17);
    assert_eq!(closing(b"(a(b)", 0), 5);
    assert_eq!(header_end(b"-> [u8; 32] where T: X { }", 0), 23);
    assert_eq!(item_end(b"fn f() { { } } x", 0), 14);
    assert_eq!(item_end(b"use a::b; x", 0), 9);
    assert_eq!(
        test_only_ranges("#[cfg(test)] #[allow(x)] fn t() -> [u8; 2] { {} } fn u() {}"),
        [(0, 49)]
    );
    assert!(keyword_at(b"x fn y", 2, b"fn") && !keyword_at(b"x fnord", 2, b"fn"));
    assert!(!keyword_at(b"xfn y", 1, b"fn"));
    let signatures = fn_signatures(
        "impl World { pub(crate) fn raw<T: Trait<A, B>>(&self, pair: (A, B)) -> Result<[u8; 32], E> where E: Other<A, B> { todo!() } }",
    );
    assert_eq!(
        signatures,
        [FnSignature {
            name: "raw".to_owned(),
            reads_state: true,
            returns_hash: true
        }]
    );
}

/// The actual AMX source still supplies its exact listed production State-hash method.
#[test]
fn state_hash_scan_actual_amx_complete_keeps_its_original_listing() {
    let path = "crates/iroha_core/src/query/native_receipts/amx_read.rs";
    let text = source(path);
    let (_, code) = split_source(&text);
    let matched: Vec<_> = fn_signatures(&code)
        .into_iter()
        .filter(|signature| {
            signature.name == "complete" && signature.reads_state && signature.returns_hash
        })
        .collect();
    assert_eq!(
        matched.len(),
        1,
        "original AMX complete State-reader must remain scanned"
    );
    let listed: Vec<_> = STATE_HASH_FUNCTIONS
        .iter()
        .filter(|listed| listed.path == path && listed.name == "complete")
        .collect();
    assert_eq!(
        listed.len(),
        1,
        "original AMX complete must retain its exact registry entry"
    );
}

/// Fixture-only hash collection cannot replace the production replay-alias classification.
#[test]
fn state_hash_scan_carrier_fixture_keeps_production_alias_and_visitor_visible() {
    let path = "crates/iroha_core/src/tx.rs";
    let (_, code) = split_source(&source(path));
    let signatures = fn_signatures(&code);
    assert!(
        !signatures
            .iter()
            .any(|entry| entry.name == "canonical_carrier_membership_hashes"),
        "the cfg(test) collection adapter is not a production State reader"
    );
    let visitor: Vec<_> = signatures
        .iter()
        .filter(|entry| entry.name == "for_each_canonical_carrier_membership_hash")
        .collect();
    assert_eq!(visitor.len(), 1);
    assert!(visitor[0].reads_state && !visitor[0].returns_hash);
    let alias: Vec<_> = signatures
        .iter()
        .filter(|entry| entry.name == "authenticated_signed_replay_alias")
        .collect();
    assert_eq!(alias.len(), 1);
    assert!(alias[0].reads_state && alias[0].returns_hash);
    let listed: Vec<_> = STATE_HASH_FUNCTIONS
        .iter()
        .filter(|entry| entry.path == path && entry.name == "authenticated_signed_replay_alias")
        .collect();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].count, 1);
    assert!(matches!(listed[0].owner, UseOwner::Other(Use::Record, _)));
    assert!(!STATE_HASH_FUNCTIONS.iter().any(|entry| {
        entry.path == path && entry.name == "canonical_carrier_membership_hashes"
    }));
}

/// Current execution proofs serve an existing certified identity and result.
#[test]
fn state_hash_scan_current_execution_proof_classifies_certified_identity() {
    let path = "crates/iroha_core/src/sumeragi/finality.rs";
    let (_, code) = split_source(&source(path));
    let name = "current_execution_proof";
    assert_eq!(
        fn_signatures(&code)
            .iter()
            .filter(|entry| entry.name == name && entry.reads_state && entry.returns_hash)
            .count(),
        1,
        "the actual current execution proof producer must remain scanned"
    );
    let listed: Vec<_> = STATE_HASH_FUNCTIONS
        .iter()
        .filter(|entry| entry.path == path && entry.name == name)
        .collect();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].count, 1);
    assert!(matches!(
        listed[0].owner,
        UseOwner::Other(Use::ResultBinding, _)
    ));
}

/// A test-only enum variant cannot hide the production World-root producers after it.
#[test]
fn state_hash_scan_cfg_variant_preserves_world_accumulator_owners() {
    let path = "crates/iroha_core/src/state/world_state_accumulator.rs";
    let (_, code) = split_source(&source(path));
    let signatures = fn_signatures(&code);
    for name in ["apply_block", "capture"] {
        assert_eq!(
            signatures
                .iter()
                .filter(|entry| entry.name == name && entry.reads_state && entry.returns_hash)
                .count(),
            1,
            "test-only Direction variant must not hide World-root producer {name}"
        );
        let listed: Vec<_> = STATE_HASH_FUNCTIONS
            .iter()
            .filter(|entry| entry.path == path && entry.name == name)
            .collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].count, 1);
        assert!(matches!(
            listed[0].owner,
            UseOwner::Roots(["world_state_root"])
        ));
    }
    assert!(
        !signatures
            .iter()
            .any(|entry| entry.name == "capture_predecessor"),
        "the actual test-only reverse capture must remain excluded"
    );
}

/// An attributed control statement cannot consume a following production struct.
#[test]
fn state_hash_scan_cfg_controls_preserve_next_struct() {
    for text in [
        "fn outer() { #[cfg(test)] if flag {} struct Holder { x: [u8; { fn visible(s: &State) -> Hash { todo!() } 1 }] } }",
        "fn outer() { #[cfg(test)] while flag {} struct Holder { x: [u8; { fn visible(s: &State) -> Hash { todo!() } 1 }] } }",
        "fn outer() { #[cfg(test)] match flag { _ => {} } struct Holder { x: [u8; { fn visible(s: &State) -> Hash { todo!() } 1 }] } }",
        "fn outer() { #[cfg(test)] for value in r#in {} struct Holder { x: [u8; { fn visible(s: &State) -> Hash { todo!() } 1 }] } }",
    ] {
        let (_, code) = split_source(text);
        let matched: Vec<_> = fn_signatures(&code)
            .into_iter()
            .filter(|signature| signature.reads_state && signature.returns_hash)
            .map(|signature| signature.name)
            .collect();
        assert_eq!(
            matched,
            ["visible"],
            "cfg control must end before the next production statement: {text}"
        );
    }
}

/// An attributed control statement cannot consume a following production let initializer.
#[test]
fn state_hash_scan_cfg_controls_preserve_next_let() {
    for text in [
        "fn outer() { #[cfg(test)] if flag {} let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
        "fn outer() { #[cfg(test)] for value in values {} let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
        "fn outer() { #[cfg(test)] 'retry: loop {} let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
        "fn outer() { #[cfg(test)] 'rétry: loop {} let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
        "fn outer() { #[cfg(test)] 'local: { fn hidden(s: &State) -> Hash { todo!() } } let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
        "fn outer() { #[cfg(test)] async move { fn hidden(s: &State) -> Hash { todo!() } } let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
    ] {
        let (_, code) = split_source(text);
        let matched: Vec<_> = fn_signatures(&code)
            .into_iter()
            .filter(|signature| signature.reads_state && signature.returns_hash)
            .map(|signature| signature.name)
            .collect();
        assert_eq!(
            matched,
            ["visible"],
            "cfg control must end before the next production let: {text}"
        );
    }
}

/// The original if/else chain is excluded, while the following independent block remains.
#[test]
fn state_hash_scan_cfg_else_chains_end_at_their_original_final_block() {
    for text in [
        "fn outer() { #[cfg(test)] if flag { fn hidden(s: &State) -> Hash { todo!() } } else if other([a, b], (c, d)) { fn hidden_else_if(s: &State) -> Hash { todo!() } } else { fn hidden_else(s: &State) -> Hash { todo!() } } { fn visible(s: &State) -> Hash { todo!() } } }",
        "fn outer() { #[cfg(test)] if flag {} else if other {} else if last {} struct Holder { x: [u8; { fn visible(s: &State) -> Hash { todo!() } 1 }] } }",
        "fn outer() { #[cfg(test)] if flag {} { fn visible(s: &State) -> Hash { todo!() } } }",
        "fn outer() { #[cfg(test)] if flag { if inner {} else {} } else { if inner {} else {} } let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
    ] {
        let (_, code) = split_source(text);
        let matched: Vec<_> = fn_signatures(&code)
            .into_iter()
            .filter(|signature| signature.reads_state && signature.returns_hash)
            .map(|signature| signature.name)
            .collect();
        assert_eq!(
            matched,
            ["visible"],
            "cfg else chain crossed its original final block: {text}"
        );
    }
}

/// Original header operand blocks precede the final body; balanced nested groups stay owned.
#[test]
fn state_hash_scan_cfg_control_headers_keep_original_operand_and_body_blocks() {
    for text in [
        "fn outer() { #[cfg(test)] if { fn hidden_operand(s: &State) -> Hash { todo!() } true } { fn hidden_body(s: &State) -> Hash { todo!() } } else { fn hidden_else(s: &State) -> Hash { todo!() } } let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
        "fn outer() { #[cfg(test)] if flag && { fn hidden_operand(s: &State) -> Hash { todo!() } true } { fn hidden_body(s: &State) -> Hash { todo!() } } struct Holder { x: [u8; { fn visible(s: &State) -> Hash { todo!() } 1 }] } }",
        "fn outer() { #[cfg(test)] if let Some(value) = { fn hidden_operand(s: &State) -> Hash { todo!() } input } { fn hidden_body(s: &State) -> Hash { todo!() } } let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
        "fn outer() { #[cfg(test)] for value in { fn hidden_operand(s: &State) -> Hash { todo!() } values } { fn hidden_body(s: &State) -> Hash { todo!() } } let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
        "fn outer() { #[cfg(test)] match { fn hidden_operand(s: &State) -> Hash { todo!() } value } { _ => { fn hidden_body(s: &State) -> Hash { todo!() } } } let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
        "fn outer() { #[cfg(test)] if ({ fn hidden_operand(s: &State) -> Hash { todo!() } true }) { fn hidden_body(s: &State) -> Hash { todo!() } } else if ({ true }) { fn hidden_else(s: &State) -> Hash { todo!() } } let value = { fn visible(s: &State) -> Hash { todo!() } 1 }; }",
    ] {
        let (_, code) = split_source(text);
        let matched: Vec<_> = fn_signatures(&code)
            .into_iter()
            .filter(|signature| signature.reads_state && signature.returns_hash)
            .map(|signature| signature.name)
            .collect();
        assert_eq!(
            matched,
            ["visible"],
            "cfg header lost its original operand/body boundary: {text}"
        );
    }
}

/// The exact tables are well formed: every exemption has a reviewed reason, every
/// application accumulator names existing canonical State fields, and every construction
/// owner exists.
#[test]
fn domain_and_construction_tables_name_existing_owners() {
    let rows = rows();
    for group in OTHER_DOMAINS {
        assert!(
            !group.reason.is_empty() && !group.literals.is_empty(),
            "{}",
            group.usage.name()
        );
        assert!(
            group.literals.windows(2).all(|pair| pair[0] < pair[1]),
            "{}",
            group.reason
        );
    }
    let uses: BTreeSet<&str> = OTHER_DOMAINS
        .iter()
        .map(|group| group.usage.name())
        .collect();
    assert_eq!(uses.len(), 9, "every use is in use");
    let mut ids = BTreeSet::new();
    for accumulator in APPLICATION_ACCUMULATORS {
        assert!(ids.insert(accumulator.id), "{}", accumulator.id);
        assert!(!accumulator.statement.is_empty() && !accumulator.evidence.is_empty());
        assert!(
            ROOTS.iter().all(|root| root.id != accumulator.id),
            "{} is listed as a commitment and as an accumulator",
            accumulator.id
        );
        for field in accumulator.fields {
            let row = rows
                .iter()
                .find(|row| row.field.id == *field)
                .unwrap_or_else(|| panic!("{} names unknown {field}", accumulator.id));
            assert_eq!(row.commitment, Commitment::Certified, "{field}");
        }
        assert!(
            !accumulator.domains.is_empty()
                || CONSTRUCTION_USES.iter().any(|listed| matches!(
                    listed.owner,
                    UseOwner::Accumulator(id) if id == accumulator.id
                ))
                || STATE_HASH_FUNCTIONS.iter().any(|listed| matches!(
                    listed.owner,
                    UseOwner::Accumulator(id) if id == accumulator.id
                )),
            "{} is detected by no domain literal, construction use or State-reading function",
            accumulator.id
        );
    }
    // The pool roots of private settlement are found only by the function that reads them.
    assert!(
        APPLICATION_ACCUMULATORS
            .iter()
            .any(
                |accumulator| accumulator.id == "private_settlement_pool_roots"
                    && accumulator.domains.is_empty()
            )
    );
    assert!(
        STATE_HASH_FUNCTIONS
            .windows(2)
            .all(|pair| (pair[0].path, pair[0].name) < (pair[1].path, pair[1].name)),
        "the State-reading hash functions are listed in ascending order of source and name"
    );
    for listed in STATE_HASH_FUNCTIONS {
        assert!(
            listed.count > 0 && listed.path.starts_with(FUNCTION_SCAN_SCOPE),
            "{}: {}",
            listed.path,
            listed.name
        );
        match listed.owner {
            UseOwner::Roots(roots) => {
                assert!(!roots.is_empty(), "{}", listed.name);
                for root in roots {
                    assert!(ROOTS.iter().any(|known| known.id == *root), "{root}");
                }
            }
            UseOwner::Accumulator(id) => assert!(ids.contains(id), "{id}"),
            UseOwner::Other(_, reason) => assert!(!reason.is_empty(), "{}", listed.name),
        }
    }
    for listed in CONSTRUCTION_USES {
        assert!(!listed.uses.is_empty(), "{}", listed.path);
        assert!(
            listed.uses.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "{}",
            listed.path
        );
        for (token, count) in listed.uses {
            assert!(
                CONSTRUCTIONS.contains(token) && *count > 0,
                "{}",
                listed.path
            );
        }
        match listed.owner {
            UseOwner::Roots(roots) => {
                assert!(!roots.is_empty(), "{}", listed.path);
                for root in roots {
                    assert!(ROOTS.iter().any(|known| known.id == *root), "{root}");
                }
            }
            UseOwner::Accumulator(id) => assert!(ids.contains(id), "{id}"),
            UseOwner::Other(_, reason) => assert!(!reason.is_empty(), "{}", listed.path),
        }
    }
    assert_eq!(
        construction_users("transaction_membership_root"),
        [
            "crates/iroha_core/src/state/storage_transactions/block/membership_append.rs",
            "crates/iroha_core/src/state/storage_transactions/block/membership_record.rs",
            "crates/iroha_core/src/state/storage_transactions/block/membership_root.rs",
        ]
    );
    assert!(construction_users("execution_policy_digest").is_empty());
    assert_eq!(Use::Precondition.name(), "precondition");
}

/// Every listed commitment has one class, one owner and one disposition: a commitment
/// that changes is tracked by an open defect of its owner task, and a commitment that
/// stays says so. This is the "no unowned shadow root" obligation at inventory level.
#[test]
fn every_listed_commitment_has_one_owner_and_disposition() {
    let defects: BTreeMap<&str, &Defect> =
        DEFECTS.iter().map(|defect| (defect.id, defect)).collect();
    assert_eq!(defects.len(), DEFECTS.len(), "defect identities are unique");
    let mut ids = BTreeSet::new();
    let mut classes = BTreeSet::new();
    for root in ROOTS {
        assert!(ids.insert(root.id), "{} is listed twice", root.id);
        classes.insert(root.class.name());
        assert!(
            !root.owner.is_empty() && !root.disposition.is_empty() && !root.evidence.is_empty(),
            "{}",
            root.id
        );
        if root.class.kept() {
            assert_eq!(root.defect, None, "{}", root.id);
            assert!(
                root.disposition.starts_with("kept ") || root.disposition.starts_with("Retained "),
                "{}",
                root.id
            );
        } else {
            let defect = root
                .defect
                .and_then(|id| defects.get(id))
                .unwrap_or_else(|| panic!("{} changes without an open defect", root.id));
            assert_eq!(defect.assigned, root.owner, "{}", root.id);
        }
        match root.class {
            // A protocol fingerprint, a consensus binding and a node-local binding
            // commitment authenticate no State read: none has a witness form over State.
            RootClass::LocalBindingDigest
            | RootClass::ProtocolFingerprint
            | RootClass::ConsensusBinding => {
                assert!(
                    !root.keyed && root.witnesses.starts_with("none"),
                    "{}",
                    root.id
                );
            }
            _ => {}
        }
        // The result certifies the classes named `certified_`, and the consensus binding,
        // which votes and the result preimage bind.
        assert_eq!(
            root.class.certified(),
            root.class.name().starts_with("certified_")
                || root.class == RootClass::ConsensusBinding,
            "{}",
            root.id
        );
        assert!(
            root.domains.windows(2).all(|pair| pair[0] < pair[1]),
            "{}",
            root.id
        );
        // The scan reports every listed commitment: each is anchored by a domain literal,
        // a construction use, a hash field of a witness value type, a classified field of
        // a protocol carrier or a State-reading hash function, so removing its listing
        // fails the check. The only exceptions are the commitments that a review found,
        // which say so (`root_anchors` checks the two cases against each other).
        let anchors = root_anchors(root);
        assert!(!anchors.is_empty(), "{}", root.id);
        assert_eq!(
            anchors == ["review"],
            REVIEW_ONLY_ROOTS.iter().any(|(id, _)| *id == root.id),
            "{}",
            root.id
        );
        if matches!(
            root.class,
            RootClass::ProtocolFingerprint | RootClass::ConsensusBinding
        ) {
            // A protocol fingerprint and a consensus binding are carried by a listed
            // protocol object: a classified field of a carrier names them.
            assert!(
                anchors.contains(&"protocol_carrier"),
                "{}: {anchors:?}",
                root.id
            );
        }
    }
    // The fingerprints that a State reader computes are also found by their signature;
    // the DA proof-policy hash is derived from the Nexus policy cell without a reader.
    for (id, by_signature) in [
        ("execution_policy_digest", true),
        ("confidential_feature_digest", true),
        ("nexus_amx_context_digest", true),
        ("da_proof_policy_bundle_hash", false),
        ("axt_policy_snapshot", true),
    ] {
        let root = ROOTS
            .iter()
            .find(|root| root.id == id)
            .unwrap_or_else(|| panic!("{id} is listed"));
        assert_eq!(
            root_anchors(root).contains(&"state_hash_function"),
            by_signature,
            "{id}"
        );
    }
    assert_eq!(
        REVIEW_ONLY_ROOTS
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        ["tiered_backend_row_hashes"]
    );
    // The protocol fingerprints and the consensus binding, with the plan author's
    // dispositions.
    let listed = |id: &str| -> &'static Root {
        ROOTS
            .iter()
            .find(|root| root.id == id)
            .unwrap_or_else(|| panic!("{id} is listed"))
    };
    assert_eq!(
        ROOTS
            .iter()
            .filter(|root| root.class == RootClass::ProtocolFingerprint)
            .map(|root| (root.id, root.owner, root.defect))
            .collect::<Vec<_>>(),
        [
            ("execution_policy_digest", "G.3", Some("G1-D3")),
            ("confidential_feature_digest", "G.3", Some("G1-D10")),
            ("nexus_amx_context_digest", "G.3", Some("G1-D3")),
            ("da_proof_policy_bundle_hash", "G.3", Some("G1-D3")),
            ("axt_policy_snapshot", "G.3", Some("G1-D11")),
        ]
    );
    for (id, disposition) in [
        (
            "confidential_feature_digest",
            "Removed, or retained solely as an inventoried comparison value recomputed at the \
             specified height from committed registry entries and committed policy. All \
             canonical source entries are committed under the keyed State root. It \
             authenticates no State read; consumers requiring State reads use keyed State \
             witnesses. Policy hashes, parameter selectors and transition limits follow \
             G1-D3/F.4",
        ),
        (
            "nexus_amx_context_digest",
            "Removed, or retained solely as a genesis comparison value recomputed from \
             canonical entries staged from the signed genesis. All canonical source entries \
             are committed under the keyed State root, with node-configured validity policy \
             moved into protocol State under F.4. It authenticates no State read",
        ),
        (
            "da_proof_policy_bundle_hash",
            "Removed, or retained as the hash of the carried DA policy bundle that every \
             validator derives at the block height from committed `state.nexus` policy, \
             checking both the header hash and the carried bundle against that derivation. It \
             authenticates no State read; the source policy follows G1-D3/F.4",
        ),
        (
            "axt_policy_snapshot",
            "Removed, or retained solely as an inventoried comparison value: every validator \
             independently derives the complete AXT policy projection at the specified \
             post-execution cut from its registered sources and inventoried block-header \
             context, compares the entire carried snapshot with it, and rejects any \
             difference. Canonical source entries are committed under the keyed State root; \
             historical inputs remain authenticated under §§16.1 and 16.7. Node-configured \
             Nexus policy follows G1-D3/F.4. The apply path rebuilds `world.axt_policies` from \
             those sources or installs the carried copy only after that independent equality \
             check at the applicable source cut; changes to the sources before publication \
             require rederivation. The carried copy never authenticates a State read; \
             consumers requiring State reads use keyed State witnesses. The 64-bit `version` \
             is a telemetry identifier, not a binding digest",
        ),
    ] {
        assert_eq!(listed(id).disposition, disposition, "{id}");
    }
    // The AXT policy snapshot: the plan author's defect, and the facts its entry states.
    let snapshot_defect = defects["G1-D11"];
    assert_eq!(
        snapshot_defect.title,
        "The block result carries an AXT policy projection that validators compare with State \
         and that the apply path installs without independently rebuilding it from its \
         registered sources"
    );
    assert_eq!(snapshot_defect.related, ["A.1", "G1-D2", "G1-D3"]);
    let registry = rows();
    let by_id: BTreeMap<&'static str, &Row> =
        registry.iter().map(|row| (row.field.id, row)).collect();
    let policies = by_id["world.axt_policies"];
    let Role::Derived { sources, .. } = policies.field.role else {
        panic!("world.axt_policies is a derived table");
    };
    assert_eq!(policies.commitment, Commitment::Derived);
    for source in sources {
        assert!(
            listed("axt_policy_snapshot").scope.contains(source),
            "the scope names the registered source {source}"
        );
    }
    assert_eq!(sources.len(), 6);
    let mut unbound = BTreeSet::new();
    unbound_bases(&by_id, sources, &mut BTreeSet::new(), &mut unbound);
    assert_eq!(
        unbound.into_iter().collect::<Vec<_>>(),
        [
            "runtime.lane_incarnation_lineage",
            "runtime.lanes",
            "state.block_hashes",
            "state.nexus"
        ]
    );
    assert!(
        snapshot_defect
            .required
            .contains("Four of the six registered sources are bound by no certified root today")
    );
    assert_eq!(
        by_id["world.axt_handle_counters"].commitment,
        Commitment::Certified
    );
    assert_eq!(
        defect_fields("G1-D11", &rows()),
        ["world.axt_policies", "world.axt_handle_counters"]
    );
    assert_eq!(
        listed("confidential_feature_digest").scope,
        "the effective verifying-key projection, selected parameter identifiers and their \
         registry-effectiveness checks, ZK policy, and the SCCP light-client profile versions \
         and hashes active at the block height. Source fields: world.verifying_keys, \
         world.poseidon_params, world.pedersen_params, world.sccp_light_client_profiles and \
         state.zk"
    );
    assert!(listed("execution_policy_digest").scope.ends_with(
        "The Nexus policy digest also incorporates `state.lane_manifests` and \
         `state.lane_compliance` through their policy digests"
    ));
    let binding = listed("consensus_authority_binding");
    assert_eq!(binding.class, RootClass::ConsensusBinding);
    assert_eq!(binding.defect, None);
    assert_eq!(binding.owner, "Sumeragi (specs/sumeragi.md §§3, 4.1, 10)");
    let sccp_binding = listed("sccp_generation_committee_root");
    assert_eq!(sccp_binding.class, RootClass::ConsensusBinding);
    assert_eq!(sccp_binding.owner, "SCCP native finality");
    assert_eq!(sccp_binding.defect, None);
    assert_eq!(
        sccp_binding.witnesses,
        "none over State; the original X and authenticated native schedule bind committee authority"
    );
    // Lane and SCCP committee bindings retain their separate consensus authority.
    assert_eq!(
        ROOTS
            .iter()
            .filter(|root| root.class == RootClass::ConsensusBinding)
            .map(|root| (root.id, root.defect))
            .collect::<Vec<_>>(),
        [
            ("consensus_authority_binding", None),
            ("lane_authority_binding", None),
            ("sccp_generation_committee_root", None)
        ]
    );
    assert_eq!(
        listed("native_lane_state_commitment").class,
        RootClass::CertifiedWitnessValue,
        "the lane state keeps its classification"
    );
    // The node-local bindings that the review added: separate preimages, each with its
    // own owner.
    for (id, owner) in [
        ("tiered_backend_row_hashes", "Tiered State backend"),
        ("query_projection_payload_hash", "Query projection store"),
        (
            "private_settlement_test_network_evidence",
            "private-settlement test-network evidence (non-shipping feature)",
        ),
    ] {
        let root = listed(id);
        assert_eq!(root.class, RootClass::LocalBindingDigest, "{id}");
        assert_eq!(root.owner, owner, "{id}");
        assert!(
            root.disposition
                .contains("never State reads or transaction validity"),
            "{id}"
        );
    }
    assert!(
        listed("private_settlement_test_network_evidence")
            .disposition
            .contains("shipping builds do not compile it")
    );
    assert!(
        listed("query_projection_payload_hash")
            .disposition
            .contains("still pending")
    );
    // Two commitments are certified State roots today: the complete World state root, and
    // the retail fee receipt-head root, a per-table State root that rule P1 forbids and
    // that open defect G1-D9 removes.
    assert_eq!(
        ROOTS
            .iter()
            .filter(|root| root.class == RootClass::CertifiedStateRoot)
            .map(|root| (root.id, root.defect))
            .collect::<Vec<_>>(),
        [
            ("world_state_root", Some("G1-D1")),
            ("retail_fee_receipt_head_root", Some("G1-D9"))
        ]
    );
    assert_eq!(classes.len(), 7);
    // The plan author's disposition of the witnessed State digests, verbatim.
    for id in [
        "fastpq_permission_table_root",
        "validation_fee_policy_snapshot",
        "parliament_casting_snapshot_root",
        "sccp_state_delta_digest",
        "fee_evidence_record_root",
    ] {
        let root = ROOTS
            .iter()
            .find(|root| root.id == id)
            .unwrap_or_else(|| panic!("{id} is listed"));
        assert_eq!(root.class, RootClass::CertifiedWitnessValue, "{id}");
        assert!(
            root.disposition.starts_with(
                "Retained as a certified per-block witness value, not as State-read authority; \
                 all canonical source State entries are also committed under the keyed State \
                 root, and consumers requiring State reads use keyed State witnesses"
            ),
            "{id}"
        );
        assert_eq!(
            root.owner,
            if id == "fastpq_permission_table_root" {
                "A.1"
            } else {
                "G.3"
            },
            "{id}"
        );
    }
}

/// The witnessed roots commit the listed reserved families and nothing else: every
/// witness key tag of the data model is owned by a production family or is written by
/// test recorders only, the registry fields of each family exist, and every hash-typed
/// field of a family's value types is classified.
#[test]
fn witness_families_cover_every_witness_key_tag() {
    let witnessed = witnessed_fields();
    let tags = witness_key_tags();
    for tag in [
        "AmxRecord",
        "AssetBalance",
        "FeeRecord",
        "RewardExposureArchive",
    ] {
        assert!(tags.iter().any(|known| known == tag), "{tag}");
    }
    let rows = rows();
    for (field, families) in &witnessed {
        let row = rows
            .iter()
            .find(|row| row.field.id == field)
            .unwrap_or_else(|| panic!("{families:?} name unknown {field}"));
        assert_eq!(row.commitment, Commitment::Certified, "{field}");
    }
    assert_eq!(witnessed["world.sumeragi_lanes"], ["sumeragi_lane_state"]);
    assert_eq!(witnessed["world.sccp_parameters"], [SCCP_FAMILY]);
    // The table that the permission-table root digests is mapped to its family, and the
    // two families that named only a function now name their fields.
    assert_eq!(
        witnessed["world.roles"],
        ["fastpq_ordinary_source_statements"]
    );
    assert_eq!(
        witnessed["world.parameters"],
        ["validation_fee_policy", "fee_evidence"]
    );
    let fields_of = |id: &str| -> Vec<String> {
        family_fields(
            WITNESS_FAMILIES
                .iter()
                .find(|family| family.id == id)
                .unwrap_or_else(|| panic!("{id} is a witness family")),
        )
    };
    assert_eq!(
        fields_of("parliament_timed_ovn_casting"),
        [
            "world.parliament_attempts",
            "world.timed_ovn_evidence",
            "world.tle_key_sessions"
        ]
    );
    assert_eq!(
        fields_of("fee_evidence"),
        [
            "world.asset_definitions",
            "world.assets",
            "world.parameters",
            "world.smart_contract_state"
        ]
    );
    assert_eq!(
        fields_of("reward_exposure_archive"),
        ["world.smart_contract_state"]
    );
    let sccp = sccp_write_set_fields();
    assert!(sccp.len() > 1 && sccp.iter().all(|field| field.starts_with("world.sccp_")));
    assert_eq!(
        sccp.iter().collect::<BTreeSet<_>>().len(),
        sccp.len(),
        "the SCCP write set names a field twice"
    );
    let mut ids = BTreeSet::new();
    for family in WITNESS_FAMILIES {
        assert!(ids.insert(family.id), "{} is listed twice", family.id);
        assert!(!family.evidence.is_empty(), "{}", family.id);
        assert!(
            !family_fields(family).is_empty() || !family.source.is_empty(),
            "{}",
            family.id
        );
    }
    // The probe that keeps a tag "test only" tells a test recorder from a production one.
    assert!(is_cfg_test_item(
        WITNESS_RECORDER,
        "fn key_asset_balance(id: &AssetId) -> Vec<u8> {"
    ));
    assert!(!is_cfg_test_item(
        WITNESS_RECORDER,
        "pub(crate) fn record_write_amx_record("
    ));

    // Negative controls of the value-type check, on a synthetic declaration: a new hash
    // field, a hash in an enum payload, a hash inside a nested type that is not walked,
    // and a listed field that is gone.
    let outer = "pub struct Outer {\n    /// Height.\n    pub height: u64,\n    \
                 #[norito(\n        default\n    )]\n    pub root: Hash,\n    \
                 pub(crate) inner: Inner,\n    kind: Kind,\n}\n";
    let inner = "pub struct Inner {\n    pub digest: Option<[u8; 32]>,\n}\n";
    let kind = "pub enum Kind {\n    Empty,\n    Invalid(Hash),\n    Named(Other),\n}\n";
    let outer = declared_fields(outer, "pub struct Outer {");
    assert_eq!(
        outer,
        [
            ("height".to_owned(), "u64".to_owned()),
            ("root".to_owned(), "Hash".to_owned()),
            ("inner".to_owned(), "Inner".to_owned()),
            ("kind".to_owned(), "Kind".to_owned())
        ]
    );
    let inner = declared_fields(inner, "pub struct Inner {");
    let kind = declared_fields(kind, "pub enum Kind {");
    assert_eq!(kind[0], ("Empty".to_owned(), String::new()));
    assert_eq!(kind[1], ("Invalid".to_owned(), "Hash".to_owned()));
    let block = HashUse::Block("probe");
    assert_eq!(
        unclassified_value_fields(
            &[("Outer", outer.clone())],
            &[("Outer.root", block), ("Outer.gone", block)],
            &[("Kind", "probe")]
        ),
        [
            "unclassified nested type Inner in Outer.inner",
            "listed hash field Outer.gone is gone"
        ]
    );
    assert_eq!(
        unclassified_value_fields(
            &[
                ("Outer", outer.clone()),
                ("Inner", inner.clone()),
                ("Kind", kind.clone())
            ],
            &[("Outer.root", block)],
            &[]
        ),
        [
            "unclassified hash field Inner.digest: Option<[u8; 32]>",
            "unclassified hash field Kind.Invalid: Hash",
            "unclassified nested type Other in Kind.Named"
        ]
    );
    assert!(
        unclassified_value_fields(
            &[("Outer", outer), ("Inner", inner), ("Kind", kind)],
            &[
                ("Outer.root", block),
                ("Inner.digest", HashUse::State("probe")),
                ("Kind.Invalid", block)
            ],
            &[("Other", "probe")]
        )
        .is_empty()
    );
    assert_eq!(declared_name("pub enum Kind {"), "Kind");
    assert!(is_hash_type("HashOf<X>") && is_hash_type("[u8; 32]") && !is_hash_type("[u8; 16]"));
    assert_eq!(
        named_types("Option<Vec<Inner>>"),
        ["Option", "Vec", "Inner"]
    );

    // Negative controls of the derivation check: the accessors are read from the source
    // with whitespace ignored, and an item ends at its own indentation.
    assert_eq!(
        world_accessors(
            "stx\n    .world\n    .assets\n    .get(x); block.world.roles.iter(); f(&block.world)"
        )
        .into_iter()
        .collect::<Vec<_>>(),
        ["assets", "roles"]
    );
    let body = item_body(
        "crates/iroha_core/src/validation_fee_rewards/head_tree.rs",
        "fn read_root(world: &impl WorldReadOnly) -> Result<Option<NodeRef>, ExecutionAttemptError<String>> {",
    );
    assert!(body.ends_with("\n}") && !body.contains("fn read_branch("));
    let mut sources = BTreeSet::new();
    canonical_sources(
        "world.parliament_timed_ovn_casting_candidates",
        &mut sources,
    );
    assert_eq!(
        sources.into_iter().collect::<Vec<_>>(),
        ["world.parliament_attempts"]
    );
}

/// The carrier walk (`specs/sumeragi.md` §16.8): every hash-bearing field of the listed
/// consensus-carried types and of their declared nested types is classified as a digest
/// of State content with its listed commitment, or as the content it commits, and every
/// nested type is walked or declared.
#[test]
fn native_result_carrier_walk_matches_every_fixed_header_byte_range() {
    use iroha_data_model::sumeragi_finality::{
        SccpFinalityHeaderV1,
        certified_result::{
            FLAG_ACTIVE, FLAG_ROTATION, SccpFinalityHeaderFieldsV1, X_LEN, X_MAGIC,
        },
    };
    let source = source(CERTIFIED_RESULT_MODEL);
    assert_eq!(
        source
            .matches("pub struct SccpFinalityHeaderV1([u8; X_LEN]);")
            .count(),
        1,
        "the reviewed wrapper must retain only its exact fixed byte array"
    );
    assert_eq!(core::mem::size_of::<SccpFinalityHeaderV1>(), 221);
    assert_eq!(X_LEN, 221);
    let fields = SccpFinalityHeaderFieldsV1 {
        network_id: [1; 32],
        height: 2,
        timestamp_ms: 3,
        flags: FLAG_ACTIVE | FLAG_ROTATION,
        message_count: 1,
        sccp_root: [4; 32],
        history_size: 1,
        history_root: [5; 32],
        generation: 1,
        committee_root: [6; 32],
        validity_ms: 7,
        next_committee_root: [8; 32],
    };
    let header = SccpFinalityHeaderV1::from_fields(&fields).unwrap();
    let bytes = header.as_bytes();
    assert_eq!(&bytes[..16], X_MAGIC);
    // Destructure without `..`: a new projected field requires an explicit byte-range review.
    let SccpFinalityHeaderFieldsV1 {
        network_id,
        height,
        timestamp_ms,
        flags,
        message_count,
        sccp_root,
        history_size,
        history_root,
        generation,
        committee_root,
        validity_ms,
        next_committee_root,
    } = header.fields();
    assert_eq!(&bytes[16..48], &network_id);
    assert_eq!(&bytes[48..56], &height.to_be_bytes());
    assert_eq!(&bytes[56..64], &timestamp_ms.to_be_bytes());
    assert_eq!(bytes[64], flags);
    assert_eq!(&bytes[65..69], &message_count.to_be_bytes());
    assert_eq!(&bytes[69..101], &sccp_root);
    assert_eq!(&bytes[101..109], &history_size.to_be_bytes());
    assert_eq!(&bytes[109..141], &history_root);
    assert_eq!(&bytes[141..149], &generation.to_be_bytes());
    assert_eq!(&bytes[149..181], &committee_root);
    assert_eq!(&bytes[181..189], &validity_ms.to_be_bytes());
    assert_eq!(&bytes[189..221], &next_committee_root);
    assert_eq!(header.fields(), fields);
    assert_eq!(SccpFinalityHeaderV1::parse(bytes).unwrap(), header);
    // Flip one actual byte in every field. Only the reserved flag mutation is structurally
    // invalid; the others must change exactly the corresponding decoded field. This guards
    // the real byte decoder, not merely the non-serialized Fields declaration.
    let expected = [
        "network_id",
        "height",
        "timestamp_ms",
        "flags",
        "message_count",
        "sccp_root",
        "history_size",
        "history_root",
        "generation",
        "committee_root",
        "validity_ms",
        "next_committee_root",
    ];
    let decoded_fields = declared_fields(&source, "pub struct SccpFinalityHeaderFieldsV1 {");
    assert_eq!(
        decoded_fields
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        expected
    );
    for (field, offset) in [47, 55, 63, 64, 68, 100, 108, 140, 148, 180, 188, 220]
        .into_iter()
        .enumerate()
    {
        let mut changed = *bytes;
        changed[offset] ^= 0x80;
        if field == 3 {
            assert!(SccpFinalityHeaderV1::parse(&changed).is_err());
            continue;
        }
        let actual = SccpFinalityHeaderV1::parse(&changed).unwrap().fields();
        let differences = [
            actual.network_id != fields.network_id,
            actual.height != fields.height,
            actual.timestamp_ms != fields.timestamp_ms,
            actual.flags != fields.flags,
            actual.message_count != fields.message_count,
            actual.sccp_root != fields.sccp_root,
            actual.history_size != fields.history_size,
            actual.history_root != fields.history_root,
            actual.generation != fields.generation,
            actual.committee_root != fields.committee_root,
            actual.validity_ms != fields.validity_ms,
            actual.next_committee_root != fields.next_committee_root,
        ];
        assert_eq!(
            differences,
            std::array::from_fn(|index| index == field),
            "{}",
            expected[field]
        );
    }
}

/// Exhaustively classify the original protocol carrier declarations and detect new fields.
#[test]
fn protocol_carriers_classify_every_hash_bearing_field() {
    check_carriers();
    let carrier = |id: &str| -> &'static Carrier {
        CARRIERS
            .iter()
            .find(|carrier| carrier.id == id)
            .unwrap_or_else(|| panic!("{id} is a listed carrier"))
    };
    let state_fields = |id: &str| -> Vec<(&'static str, &'static str)> {
        carrier(id)
            .hashes
            .iter()
            .filter_map(|(field, hash)| match hash {
                HashUse::State(root) => Some((*field, *root)),
                HashUse::Block(_) => None,
            })
            .collect()
    };
    // The digests of State content that each carrier holds.
    assert_eq!(
        state_fields("block_header"),
        [
            (
                "BlockHeader.da_proof_policies_hash",
                "da_proof_policy_bundle_hash"
            ),
            (
                "ConfidentialFeatureDigest.vk_set_hash",
                "confidential_feature_digest"
            ),
            (
                "ConfidentialFeatureDigest.zk_policy_hash",
                "confidential_feature_digest"
            ),
        ]
    );
    assert_eq!(
        state_fields("signed_genesis_consensus_parameters"),
        [
            (
                "SumeragiGenesisContextParameters.nexus_amx_context_hash",
                "nexus_amx_context_digest"
            ),
            (
                "SumeragiGenesisContextParameters.execution_policy_hash",
                "execution_policy_digest"
            ),
        ]
    );
    assert_eq!(
        state_fields("consensus_messages"),
        [("EpochId.context", "consensus_authority_binding")]
    );
    assert_eq!(
        state_fields("lane_result"),
        [("LaneResult.next_committee_digest", "lane_authority_binding")]
    );
    assert_eq!(
        state_fields("peer_handshake"),
        [
            (
                "ConsensusConfigCaps.execution_policy_hash",
                "execution_policy_digest"
            ),
            (
                "ConsensusConfigCaps.nexus_policy_digest",
                "execution_policy_digest"
            ),
            (
                "ConfidentialHandshakeCaps.features",
                "confidential_feature_digest"
            ),
            (
                "HandshakeConfidentialDigest.vk_set_hash",
                "confidential_feature_digest"
            ),
            (
                "HandshakeConfidentialDigest.zk_policy_hash",
                "confidential_feature_digest"
            ),
        ]
    );
    // The block payload and result: the DA proof-policy bundle, the beacon pulse and the
    // AXT policy snapshot are embedded records of listed commitments, and the snapshot's
    // 64-bit version is the one digest that only a review can list.
    let body = carrier("block_payload_and_result");
    assert_eq!(
        state_fields("block_payload_and_result"),
        [
            ("CanonicalParts.policy_hash", "da_proof_policy_bundle_hash"),
            ("AxtPolicyEntry.manifest_root", "axt_policy_snapshot"),
        ]
    );
    assert_eq!(
        body.embeds,
        [
            (
                "BlockPayload.da_proof_policies",
                "da_proof_policy_bundle_hash"
            ),
            (
                "BlockPayload.global_beacon_pulse",
                "consensus_authority_binding"
            ),
            ("BlockResult.axt_policy_snapshot", "axt_policy_snapshot"),
        ]
    );
    assert_eq!(
        body.reviewed,
        [(
            "AxtPolicySnapshot.version",
            HashUse::State("axt_policy_snapshot")
        )]
    );
    assert_eq!(
        body.exhaustive,
        ["SignedBlock", "BlockPayload", "BlockResult"]
    );
    // The three roots of a transfer SMT witness concern transcript-local balances.
    for field in ["root_before", "root_after", "siblings"] {
        let id = format!("TransferSmtWitness.{field}");
        assert!(
            body.hashes
                .iter()
                .any(|(listed, hash)| *listed == id
                    && *hash == HashUse::Block(TRANSCRIPT_LOCAL_TREE)),
            "{id}"
        );
    }
    assert!(TRANSCRIPT_LOCAL_TREE.contains("transcript-local balances"));
    // The identifiers that the header and the handshake carry for comparison beside the
    // two hashes of the confidential feature digest are listed by review as well.
    for id in ["block_header", "peer_handshake"] {
        assert_eq!(
            carrier(id)
                .reviewed
                .iter()
                .map(|(field, hash)| (field.rsplit('.').next(), *hash))
                .collect::<Vec<_>>(),
            [
                (
                    Some("poseidon_params_id"),
                    HashUse::State("confidential_feature_digest")
                ),
                (
                    Some("pedersen_params_id"),
                    HashUse::State("confidential_feature_digest")
                ),
            ],
            "{id}"
        );
    }
    // Every carrier classifies every field of the types that hold its State digests.
    for listed in CARRIERS {
        assert!(!listed.exhaustive.is_empty(), "{}", listed.id);
    }
    // The two enumerations of what travels between nodes are walked: a new consensus wire
    // message and a new kind of network message are each reported.
    let messages = carrier("consensus_messages");
    let mut wire = carrier_types(messages);
    let enumeration = wire
        .iter()
        .position(|(name, _)| *name == "WireMessage")
        .expect("the wire message enumeration is walked");
    assert_eq!(wire[enumeration].1.len(), 12);
    wire[enumeration]
        .1
        .push(("Shadow".to_owned(), "Box<ShadowMessage>".to_owned()));
    assert_eq!(
        unclassified_value_fields(&wire, messages.hashes, messages.opaque),
        ["unclassified nested type ShadowMessage in WireMessage.Shadow"]
    );
    let envelope = carrier("node_network_envelope");
    let mut network = carrier_types(envelope);
    assert_eq!(network[0].0, "NetworkMessage");
    assert_eq!(network[0].1.len(), 11);
    assert!(state_fields("node_network_envelope").is_empty());
    network[0]
        .1
        .push(("StateDigest".to_owned(), "[u8; 32]".to_owned()));
    assert_eq!(
        unlisted_carrier_fields(envelope, &network),
        ["unclassified field NetworkMessage.StateDigest: [u8; 32]"]
    );
    assert_eq!(
        unclassified_value_fields(&network, envelope.hashes, envelope.opaque),
        ["unclassified hash field NetworkMessage.StateDigest: [u8; 32]"]
    );
    assert_eq!(
        carrier("execution_result").embeds,
        [
            (
                "ExecutionResultCommitment.schedule",
                "consensus_authority_binding"
            ),
            (
                "ExecutionResultCommitment.beacon",
                "consensus_authority_binding"
            ),
            (
                "ExecutionResultCommitment.native_lanes",
                "native_lane_state_commitment"
            ),
        ]
    );
    // The current authority graph is walked from its actual wire fields. A new hash,
    // scalar or nested type in either original authorization or frozen preparation cannot
    // hide behind an opaque authority-generation record.
    let authority = carrier("execution_result");
    let mut authority_types = carrier_types(authority);
    for (name, field, kind) in [
        ("CertifiedResultV1", "shadow_header", "UnknownPolicy"),
        ("SccpFinalityHeaderFieldsV1", "shadow_root", "[u8; 32]"),
        ("SccpFinalityHeaderFieldsV1", "shadow_flag", "u8"),
        (
            "ValidatorEpochAuthorizationV1",
            "shadow_generation",
            "[u8; 32]",
        ),
        ("ValidatorCommitteePreparationV1", "shadow_selection", "u64"),
        (
            "ValidatorElectionPolicyV1",
            "shadow_policy",
            "UnknownPolicy",
        ),
    ] {
        let at = authority_types
            .iter()
            .position(|(known, _)| *known == name)
            .unwrap();
        authority_types[at]
            .1
            .push((field.to_owned(), kind.to_owned()));
        assert_eq!(
            unlisted_carrier_fields(authority, &authority_types),
            [format!("unclassified field {name}.{field}: {kind}")]
        );
        let unclassified =
            unclassified_value_fields(&authority_types, authority.hashes, authority.opaque);
        match kind {
            "[u8; 32]" => assert_eq!(
                unclassified,
                [format!("unclassified hash field {name}.{field}: {kind}")]
            ),
            "UnknownPolicy" => assert_eq!(
                unclassified,
                [format!("unclassified nested type {kind} in {name}.{field}")]
            ),
            _ => assert!(unclassified.is_empty()),
        }
        authority_types[at].1.pop();
    }
    // Sources outside the two scanned crates are read: the core messages and the
    // handshake capabilities.
    for (id, crate_path) in [
        ("consensus_messages", "crates/iroha_sumeragi/src/"),
        ("peer_handshake", "crates/iroha_p2p/src/"),
        ("node_network_envelope", "crates/iroha_core/src/"),
    ] {
        assert!(
            carrier(id)
                .types
                .iter()
                .all(|(path, _)| path.starts_with(crate_path)),
            "{id}"
        );
    }
    // The data-model header is declared inside a module and the core header has the same
    // name: both are read from their own declarations.
    let model_header = declared_fields(&source(HEADER_MODEL), "pub struct BlockHeader {");
    assert!(
        model_header
            .iter()
            .any(|(name, kind)| name == "confidential_features"
                && kind == "Option<ConfidentialFeatureDigest>")
    );
    assert!(
        model_header.iter().any(|(name, _)| name == "height")
            && !model_header.iter().any(|(name, _)| name == "signature"),
        "the header declaration ends at its own closing line, before the next type of the \
         module: {model_header:?}"
    );
    let core_header = declared_fields(&source(CORE_MESSAGES), "pub struct BlockHeader {");
    assert!(
        core_header
            .iter()
            .any(|(name, kind)| name == "epoch" && kind == "EpochId")
    );
    // The lines of the generated inventory: one per carrier.
    let lines = carrier_lines();
    assert_eq!(lines.len(), CARRIERS.len());
    assert!(lines[0].starts_with("{\"id\":\"block_header\",\"object\":\""));
    assert!(lines[0].contains(
        "{\"field\":\"ConfidentialFeatureDigest.vk_set_hash\",\"commits\":\"state\",\"root\":\"confidential_feature_digest\"}"
    ));
    assert!(lines[1].starts_with("{\"id\":\"block_payload_and_result\",\"object\":\""));
    assert!(lines[1].contains(
        "\"found_by_review\":[{\"field\":\"AxtPolicySnapshot.version\",\"commits\":\"state\",\"root\":\"axt_policy_snapshot\"}]"
    ));
    assert!(
        lines[1].contains(
            "\"every_field_classified\":[\"SignedBlock\",\"BlockPayload\",\"BlockResult\"]"
        )
    );
    assert!(
        lines[1].contains("{\"field\":\"BlockResult.axt_transitioned_dataspaces\",\"reason\":\"")
    );
    assert!(lines[3].contains(
        "\"embeds\":[{\"field\":\"ExecutionResultCommitment.schedule\",\"root\":\"consensus_authority_binding\"}"
    ));

    // Negative controls on the actual header declaration: a new hash field, a new field
    // of a hash-named wrapper type, a new nested record and a new typed hash are each
    // reported; a typed hash names no nested type.
    let header = carrier("block_header");
    let mut types = carrier_types(header);
    assert!(unclassified_value_fields(&types, header.hashes, header.opaque).is_empty());
    let report = |types: &[(&'static str, Vec<(String, String)>)]| {
        unclassified_value_fields(types, header.hashes, header.opaque)
    };
    types[0]
        .1
        .push(("shadow_root".to_owned(), "[u8; 32]".to_owned()));
    assert_eq!(
        report(&types),
        ["unclassified hash field BlockHeader.shadow_root: [u8; 32]"]
    );
    types[0].1.pop();
    types[0]
        .1
        .push(("shadow".to_owned(), "Option<ShadowDigestV2>".to_owned()));
    assert_eq!(
        report(&types),
        ["unclassified hash field BlockHeader.shadow: Option<ShadowDigestV2>"]
    );
    types[0].1.pop();
    types[0]
        .1
        .push(("shadow".to_owned(), "Vec<ShadowRecord>".to_owned()));
    assert_eq!(
        report(&types),
        ["unclassified nested type ShadowRecord in BlockHeader.shadow"]
    );
    types[0].1.pop();
    types[0].1.push((
        "shadow_hash".to_owned(),
        "Option<HashOf<ShadowBundle>>".to_owned(),
    ));
    assert_eq!(
        report(&types),
        ["unclassified hash field BlockHeader.shadow_hash: Option<HashOf<ShadowBundle>>"]
    );
    types[0].1.pop();
    // A field of the nested record is walked as well, and a removed listed field is
    // reported.
    types[1]
        .1
        .push(("shadow".to_owned(), "Option<[u8; 32]>".to_owned()));
    assert_eq!(
        report(&types),
        ["unclassified hash field ConfidentialFeatureDigest.shadow: Option<[u8; 32]>"]
    );
    types[1].1.pop();
    types[1].1.retain(|(name, _)| name != "vk_set_hash");
    assert_eq!(
        report(&types),
        ["listed hash field ConfidentialFeatureDigest.vk_set_hash is gone"]
    );
    // A nested record that is not walked hides nothing: the walk requires it to be walked
    // or declared with a reason.
    let result = carrier("execution_result");
    let unwalked: Vec<(&'static str, Vec<(String, String)>)> = carrier_types(result)
        .into_iter()
        .filter(|(name, _)| *name != "ScheduleOutcome")
        .collect();
    let missing = unclassified_value_fields(&unwalked, result.hashes, result.opaque);
    assert!(
        missing.contains(
            &"unclassified nested type ScheduleOutcome in ExecutionResultCommitment.schedule"
                .to_owned()
        ),
        "{missing:?}"
    );

    // Negative controls on the actual block result and payload. A field of the result
    // fails whatever its type: an integer, a copied table, a hash and a Merkle tree; so
    // does a hash field or an unclassified record in a payload bundle.
    let mut body_types = carrier_types(body);
    assert!(unclassified_value_fields(&body_types, body.hashes, body.opaque).is_empty());
    assert!(unlisted_carrier_fields(body, &body_types).is_empty());
    let position = |types: &[(&'static str, Vec<(String, String)>)], name: &str| {
        types
            .iter()
            .position(|(listed, _)| *listed == name)
            .unwrap_or_else(|| panic!("{name} is walked"))
    };
    let result_at = position(&body_types, "BlockResult");
    for (field, kind, by_hash_rule) in [
        ("shadow_version", "u64", None),
        (
            "shadow_table",
            "Vec<ShadowRow>",
            Some("unclassified nested type ShadowRow in BlockResult.shadow_table"),
        ),
        (
            "shadow_root",
            "Hash",
            Some("unclassified hash field BlockResult.shadow_root: Hash"),
        ),
        (
            "shadow_tree",
            "MerkleTree<ShadowRow>",
            Some("unclassified hash field BlockResult.shadow_tree: MerkleTree<ShadowRow>"),
        ),
        (
            "shadow_rows",
            "BTreeMap<AccountId, [u8; 32]>",
            Some("unclassified hash field BlockResult.shadow_rows: BTreeMap<AccountId, [u8; 32]>"),
        ),
    ] {
        body_types[result_at]
            .1
            .push((field.to_owned(), kind.to_owned()));
        assert_eq!(
            unlisted_carrier_fields(body, &body_types),
            [format!("unclassified field BlockResult.{field}: {kind}")],
            "{field}"
        );
        assert_eq!(
            unclassified_value_fields(&body_types, body.hashes, body.opaque),
            by_hash_rule
                .map(str::to_owned)
                .into_iter()
                .collect::<Vec<_>>(),
            "{field}"
        );
        body_types[result_at].1.pop();
    }
    let payload_at = position(&body_types, "BlockPayload");
    body_types[payload_at]
        .1
        .push(("shadow_epoch".to_owned(), "u64".to_owned()));
    assert_eq!(
        unlisted_carrier_fields(body, &body_types),
        ["unclassified field BlockPayload.shadow_epoch: u64"]
    );
    body_types[payload_at].1.pop();
    // The commitment bundle has its own carrier so its private Storage/CanonicalParts
    // declarations cannot alias the proof-policy wrapper's identically named types.
    let da = carrier("da_commitment_bundle");
    let mut da_types = carrier_types(da);
    let bundle = position(&da_types, "DaCommitmentBundle");
    da_types[bundle]
        .1
        .push(("shadow_root".to_owned(), "Option<Hash>".to_owned()));
    assert_eq!(
        unclassified_value_fields(&da_types, da.hashes, da.opaque),
        ["unclassified hash field DaCommitmentBundle.shadow_root: Option<Hash>"]
    );
    assert_eq!(
        unlisted_carrier_fields(da, &da_types),
        ["unclassified field DaCommitmentBundle.shadow_root: Option<Hash>"]
    );
    da_types[bundle].1.pop();
    let parts = position(&da_types, "CanonicalParts");
    da_types[parts]
        .1
        .push(("policy_hash".to_owned(), "Hash".to_owned()));
    assert_eq!(
        unclassified_value_fields(&da_types, da.hashes, da.opaque),
        ["unclassified hash field CanonicalParts.policy_hash: Hash"]
    );
    assert_eq!(
        unlisted_carrier_fields(da, &da_types),
        ["unclassified field CanonicalParts.policy_hash: Hash"]
    );
    da_types[parts].1.pop();
    da_types[parts]
        .1
        .push(("shadow_epoch".to_owned(), "u64".to_owned()));
    assert_eq!(
        unlisted_carrier_fields(da, &da_types),
        ["unclassified field CanonicalParts.shadow_epoch: u64"]
    );
    let effects = position(&body_types, "NposConsensusEffects");
    body_types[effects]
        .1
        .push(("shadow".to_owned(), "Vec<ShadowSummary>".to_owned()));
    assert_eq!(
        unclassified_value_fields(&body_types, body.hashes, body.opaque),
        ["unclassified nested type ShadowSummary in NposConsensusEffects.shadow"]
    );
    body_types[effects].1.pop();
    // A listed field that the types no longer have, a reviewed field whose type the hash
    // rules now match, an exhaustive type that is not walked and a not-walked type that
    // no field names are each reported.
    let snapshot = position(&body_types, "AxtPolicySnapshot");
    body_types[snapshot].1.retain(|(name, _)| name != "version");
    assert_eq!(
        unlisted_carrier_fields(body, &body_types),
        ["reviewed field AxtPolicySnapshot.version is gone"]
    );
    body_types[snapshot]
        .1
        .push(("version".to_owned(), "[u8; 32]".to_owned()));
    assert_eq!(
        unlisted_carrier_fields(body, &body_types),
        ["reviewed field AxtPolicySnapshot.version has a hash-bearing type: list it under hashes"]
    );
    let mut body_types = carrier_types(body);
    body_types[result_at]
        .1
        .retain(|(name, _)| name != "axt_policy_snapshot" && name != "outputs");
    assert_eq!(
        unlisted_carrier_fields(body, &body_types),
        [
            "embedded field BlockResult.axt_policy_snapshot is gone",
            "content field BlockResult.outputs is gone"
        ]
    );
    let without_result: Vec<(&'static str, Vec<(String, String)>)> = carrier_types(body)
        .into_iter()
        .filter(|(name, _)| *name != "BlockResult")
        .collect();
    assert!(
        unlisted_carrier_fields(body, &without_result)
            .contains(&"exhaustive type BlockResult is not walked".to_owned())
    );
    let mut body_types = carrier_types(body);
    let merge = position(&body_types, "SumeragiLaneMerge");
    body_types[merge].1.retain(|(name, _)| name != "lane");
    let context = position(&body_types, "ExternalExecutionContext");
    body_types[context].1.retain(|(name, _)| name != "lane_id");
    assert!(
        unlisted_carrier_fields(body, &body_types).is_empty(),
        "LaneId is still named by other fields"
    );
    for (_, fields) in &mut body_types {
        fields.retain(|(_, kind)| !kind.contains("LaneId"));
    }
    assert_eq!(
        unlisted_carrier_fields(body, &body_types),
        ["not-walked type LaneId is in no field"]
    );
    // Negative controls on the actual handshake and lane declarations. The hello record
    // that peers exchange, its four metadata records, the identity binding that the hello
    // signature covers, the three capability records and the lane batch are walked with
    // every field classified: a new field fails whatever its type, and a 32-byte or Hash
    // field is reported by the hash rule as well.
    let handshake = carrier("peer_handshake");
    let lane = carrier("lane_result");
    assert_eq!(
        handshake.exhaustive.len(),
        handshake.types.len(),
        "every walked type of the handshake classifies every field"
    );
    assert_eq!(lane.exhaustive, ["LaneBatch", "LaneResult"]);
    for (listed, walked) in [
        (
            handshake,
            &[
                "ConsensusHandshakeCaps",
                "ConsensusConfigCaps",
                "ConfidentialHandshakeCaps",
                "CryptoHandshakeCaps",
                "HandshakeHello",
                "HandshakeConsensusMeta",
                "HandshakeConfidentialMeta",
                "HandshakeCryptoMeta",
                "HandshakeTrustMeta",
                "HandshakeConfidentialDigest",
                "HandshakeIdentityBindingV1",
            ][..],
        ),
        (lane, &["LaneBatch", "LaneResult"][..]),
    ] {
        let mut types = carrier_types(listed);
        assert_eq!(
            types.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            walked,
            "{}",
            listed.id
        );
        assert!(unclassified_value_fields(&types, listed.hashes, listed.opaque).is_empty());
        assert!(unlisted_carrier_fields(listed, &types).is_empty());
        for name in walked {
            let at = position(&types, name);
            assert!(!types[at].1.is_empty(), "{name} declares fields");
            for (field, kind, by_hash_rule) in [
                ("shadow_root", "[u8; 32]", true),
                ("shadow_root", "Option<[u8; 32]>", true),
                ("shadow_hash", "Hash", true),
                ("shadow_hash", "HashOf<ShadowTable>", true),
                ("shadow_binding", "[u8; iroha_crypto::Hash::LENGTH]", true),
                ("shadow_digest", "Option<ShadowDigestV1>", true),
                ("shadow_version", "u64", false),
                ("shadow_flag", "Option<bool>", false),
            ] {
                types[at].1.push((field.to_owned(), kind.to_owned()));
                assert_eq!(
                    unlisted_carrier_fields(listed, &types),
                    [format!("unclassified field {name}.{field}: {kind}")],
                    "{name}.{field}"
                );
                assert_eq!(
                    unclassified_value_fields(&types, listed.hashes, listed.opaque),
                    if by_hash_rule {
                        vec![format!("unclassified hash field {name}.{field}: {kind}")]
                    } else {
                        Vec::new()
                    },
                    "{name}.{field}"
                );
                types[at].1.pop();
            }
            // A nested record that is neither walked nor declared is reported.
            types[at]
                .1
                .push(("shadow".to_owned(), "Vec<ShadowRecord>".to_owned()));
            assert_eq!(
                unclassified_value_fields(&types, listed.hashes, listed.opaque),
                [format!(
                    "unclassified nested type ShadowRecord in {name}.shadow"
                )],
                "{name}"
            );
            types[at].1.pop();
        }
    }
    // The hello record is read from its own declaration: nine fields, with the four
    // metadata records and the wire digest nested below it.
    let hello = declared_fields(
        &source(HANDSHAKE_WIRE),
        "pub(super) struct HandshakeHello {",
    );
    assert_eq!(
        hello
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        [
            "network_id",
            "public_key",
            "signature",
            "addr",
            "relay",
            "consensus",
            "confidential",
            "crypto",
            "trust"
        ]
    );
    assert!(
        hello
            .iter()
            .any(|(name, kind)| name == "confidential" && kind == "HandshakeConfidentialMeta")
    );
    assert_eq!(
        declared_fields(
            &source(HANDSHAKE_CAPS),
            "pub struct ConfidentialHandshakeCaps {"
        ),
        [
            ("enabled".to_owned(), "bool".to_owned()),
            ("assume_valid".to_owned(), "bool".to_owned()),
            ("verifier_backend".to_owned(), "String".to_owned()),
            (
                "features".to_owned(),
                "Option<ConfidentialFeatureDigest>".to_owned()
            ),
        ]
    );
    assert_eq!(
        declared_fields(&source(LANE_CORE), "pub struct LaneBatch {"),
        [
            ("anchor_height".to_owned(), "u64".to_owned()),
            (
                "anchor_hash".to_owned(),
                "HashOf<iroha_data_model::block::BlockHeader>".to_owned()
            ),
            (
                "transactions".to_owned(),
                "Vec<SignedTransaction>".to_owned()
            ),
        ]
    );
    // The digest that the confidential capabilities hold is found by its type name: with
    // the listing removed the field is reported, and the lane batch anchor likewise.
    let without = |listed: &'static Carrier, field: &str| -> Vec<String> {
        let hashes: Vec<(&str, HashUse)> = listed
            .hashes
            .iter()
            .copied()
            .filter(|(name, _)| *name != field)
            .collect();
        unclassified_value_fields(&carrier_types(listed), &hashes, listed.opaque)
    };
    assert_eq!(
        without(handshake, "ConfidentialHandshakeCaps.features"),
        [
            "unclassified hash field ConfidentialHandshakeCaps.features: Option<ConfidentialFeatureDigest>"
        ]
    );
    assert_eq!(
        without(handshake, "HandshakeConsensusMeta.consensus_fingerprint"),
        ["unclassified hash field HandshakeConsensusMeta.consensus_fingerprint: Option<[u8; 32]>"]
    );
    assert_eq!(
        without(lane, "LaneBatch.anchor_hash"),
        [
            "unclassified hash field LaneBatch.anchor_hash: HashOf<iroha_data_model::block::BlockHeader>"
        ]
    );
    // An array length is a constant, not a nested type.
    assert_eq!(
        named_types("Option<[u8; iroha_crypto::Hash::LENGTH]>"),
        ["Option", "Hash"]
    );
    assert_eq!(named_types("[u8; blake3::OUT_LEN]"), Vec::<&str>::new());
    for (name, constant) in [
        ("LENGTH", true),
        ("OUT_LEN", true),
        ("MAX_2", true),
        ("T", false),
        ("H256", false),
        ("Hash", false),
        ("HashOf", false),
    ] {
        assert_eq!(is_constant_name(name), constant, "{name}");
    }
    // The declarations with private storage: the DA proof-policy bundle is read through
    // its storage enumeration to its canonical parts.
    assert_eq!(
        declared_fields(&source(DA_POLICY_MODEL), "struct CanonicalParts {"),
        [
            ("version".to_owned(), "u16".to_owned()),
            ("policy_hash".to_owned(), "Hash".to_owned()),
            ("policies".to_owned(), "Vec<DaProofPolicy>".to_owned()),
        ]
    );
    assert_eq!(
        declared_fields(&source(DA_POLICY_MODEL), "enum Storage {"),
        [
            ("Untrusted".to_owned(), "CanonicalParts".to_owned()),
            (
                "Admitted".to_owned(),
                "ChargedShared<RetainedPayload<CanonicalParts>>".to_owned()
            ),
        ]
    );
    // The DA commitment bundle has the same private storage in its own source.
    // The block body delegates its complete walk to da_commitment_bundle; the
    // same-named proof-policy parts cannot mask a new hash in this distinct owner.
    assert_eq!(
        declared_fields(&source(DA_BUNDLE_MODEL), "pub struct DaCommitmentBundle {"),
        [("storage".to_owned(), "Storage".to_owned())]
    );
    assert_eq!(
        declared_fields(&source(DA_BUNDLE_MODEL), "enum Storage {"),
        declared_fields(&source(DA_POLICY_MODEL), "enum Storage {")
    );
    let commitment_parts = [
        ("version".to_owned(), "u16".to_owned()),
        (
            "commitments".to_owned(),
            "Vec<DaCommitmentRecord>".to_owned(),
        ),
    ];
    assert_eq!(
        declared_fields(&source(DA_BUNDLE_MODEL), "struct CanonicalParts {"),
        commitment_parts
    );
    let commitment = carrier("da_commitment_bundle");
    let mut commitment_types = carrier_types(commitment);
    let parts_at = commitment_types
        .iter()
        .position(|(name, fields)| *name == "CanonicalParts" && fields[..] == commitment_parts)
        .expect("the canonical parts of the commitment bundle are walked");
    commitment_types[parts_at]
        .1
        .push(("shadow_root".to_owned(), "Hash".to_owned()));
    assert_eq!(
        unclassified_value_fields(&commitment_types, commitment.hashes, commitment.opaque),
        ["unclassified hash field CanonicalParts.shadow_root: Hash"]
    );
    assert!(is_hash_type("MerkleTree<ExecutionOutputV1>") && !is_hash_type("Vec<u64>"));
    assert_eq!(
        named_types("BTreeMap<Hash, Vec<TransferTranscript>>"),
        ["BTreeMap", "Hash", "Vec", "TransferTranscript"]
    );
    assert_eq!(named_types("MerkleTree<ExecutionOutputV1>"), ["MerkleTree"]);

    // The declaration reader: a declaration inside a module, a variant with named fields,
    // and typed hashes.
    let nested = "mod model {\n    pub struct Inner {\n        pub a: Hash,\n    }\n    pub enum Slot {\n        Ready(Config),\n        Pending {\n            /// Identity.\n            id: [u8; 32],\n            params: Params,\n        },\n    }\n}\n";
    assert_eq!(
        declared_fields(nested, "pub struct Inner {"),
        [("a".to_owned(), "Hash".to_owned())]
    );
    assert_eq!(
        declared_fields(nested, "pub enum Slot {"),
        [
            ("Ready".to_owned(), "Config".to_owned()),
            ("Pending".to_owned(), String::new()),
            ("id".to_owned(), "[u8; 32]".to_owned()),
            ("params".to_owned(), "Params".to_owned()),
        ]
    );
    assert!(
        std::panic::catch_unwind(|| declared_fields(
            "pub struct A {\n}\npub struct A {\n}\n",
            "pub struct A {"
        ))
        .is_err(),
        "a declaration that occurs twice is ambiguous"
    );
    assert_eq!(
        named_types("Option<HashOf<MerkleTree<Entry>>>"),
        ["Option", "HashOf"]
    );
    assert_eq!(
        named_types("Option<MerkleTreeCommitment<EventBox>>"),
        ["Option", "MerkleTreeCommitment"]
    );
    assert_eq!(
        named_types("crate::types::ControlWitness"),
        ["ControlWitness"]
    );
    assert_eq!(named_types("[[Hash; 32]; 8]"), ["Hash"]);
}

/// The retired validator-set checkpoint layout is gone. It declared a parent and a post
/// State root beside a validator-set hash, was computed by nothing and carried by nothing,
/// and Torii's OpenAPI contract requires its schema to stay absent. No source of the two
/// scanned crates declares or names it, and the data model declares no other record with
/// that pair of State roots outside the listed execution result.
#[test]
fn retired_validator_set_checkpoint_layout_is_absent() {
    const RETIRED: &str = concat!("ValidatorSet", "Checkpoint");
    let mut pairs = Vec::new();
    for path in rust_sources(SCAN_SCOPE) {
        let text = source(&path);
        assert!(
            !text.contains(RETIRED),
            "{path} names the retired layout {RETIRED}: it was removed under the first-release \
             rule against retired layouts (specs/sumeragi.md section 16.8)"
        );
        if !is_test_source(&path)
            && path.starts_with("crates/iroha_data_model/src/")
            && path != RESULT_MODEL
            && text.contains("pub parent_state_root:")
            && text.contains("pub post_state_root:")
        {
            pairs.push(path);
        }
    }
    assert_eq!(
        pairs,
        Vec::<String>::new(),
        "a data-model record declares a parent and a post State root: list it as a commitment \
         or a carrier field"
    );
    let result = source(RESULT_MODEL);
    assert!(
        result.contains("pub parent_state_root:") && result.contains("pub post_state_root:"),
        "the execution result, which the execution_result carrier walks, declares both roots"
    );
    // The contract fixture that keeps the schema out of Torii's OpenAPI document.
    let contract = source("crates/iroha_torii/src/openapi/tests/openapi_contracts_v1.json");
    let (_, retired) = contract
        .split_once("\"ledger.state_finality.retired_schemas\"")
        .expect("the OpenAPI contract lists the retired finality schemas");
    let (retired, _) = retired.split_once(']').expect("the list ends");
    assert!(retired.contains(&format!("\"{RETIRED}\"")));
    // Its hash-version constant stays: lane committee records still name it.
    assert_eq!(
        source(BEACON_MODEL)
            .matches("pub const VALIDATOR_SET_HASH_VERSION_V1: u16 = 1;")
            .count(),
        1
    );
}

/// The fields of `ExecutionCommitment`, in declaration order, read from the data model.
fn execution_commitment_fields() -> Vec<String> {
    let text = source("crates/iroha_data_model/src/sumeragi_finality/commitment.rs");
    let (_, body) = text
        .split_once("pub struct ExecutionCommitment {")
        .expect("the data model declares ExecutionCommitment");
    let (body, _) = body.split_once("\n}").expect("the struct ends");
    body.lines()
        .filter_map(|line| line.trim().strip_prefix("pub "))
        .map(|line| {
            line.split_once(':')
                .expect("a typed public field")
                .0
                .to_owned()
        })
        .collect()
}

/// The field order of the layout block in `specs/sumeragi.md` §16.6.
fn specified_layout() -> Vec<String> {
    let spec = source(CONTRACT_PATH);
    let (_, section) = spec
        .split_once("\n### 16.6 Result layout and non-circular binding\n")
        .expect("the contract has section 16.6");
    let (_, block) = section
        .split_once("\nExecutionCommitment {\n")
        .expect("section 16.6 has the layout block");
    let (block, _) = block.split_once("\n}").expect("the layout block ends");
    block
        .lines()
        .map(|line| {
            line.trim()
                .split_once(',')
                .unwrap_or_else(|| panic!("a layout line without a field: {line}"))
                .0
                .to_owned()
        })
        .collect()
}

/// Contract §16.6: the keyed State roots replace the two World state roots in place and
/// every other field keeps its position.
///
/// TODO(G.3): when the replacement lands, the as-built names equal the specified ones
/// and this test compares the two lists directly.
#[test]
fn execution_commitment_layout_matches_the_specified_replacement() {
    let built = execution_commitment_fields();
    let parent = built
        .iter()
        .position(|field| field == "parent_world_state_root")
        .expect("the result binds the parent World state root");
    assert_eq!(
        built.get(parent + 1).map(String::as_str),
        Some("world_state_root")
    );
    let replaced: Vec<String> = built
        .iter()
        .map(|field| match field.as_str() {
            "parent_world_state_root" => "parent_keyed_state_root".to_owned(),
            "world_state_root" => "keyed_state_root".to_owned(),
            _ => field.clone(),
        })
        .collect();
    assert_eq!(specified_layout(), replaced);
    // The witnessed roots keep their names and positions.
    assert_eq!(
        built[..3],
        [
            "parent_state_root",
            "post_state_root",
            "ordinary_writes_root"
        ]
    );
}

/// Whether a source line starts a function item.
fn is_fn_signature(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("fn ")
        || line.starts_with("pub fn ")
        || (line.starts_with("pub(") && line.contains(") fn "))
}

/// Contract P1 as built: one production call advances the certified State commitment,
/// and the State publication owner makes it. Every other call is in a test source or in
/// a function compiled for tests and benches only.
#[test]
fn only_the_publication_owner_advances_the_certified_state_commitment() {
    const CALL: &str = ".advance_state_accumulator(";
    const OWNER: &str = "crates/iroha_core/src/state/publication.rs";
    let mut production = Vec::new();
    let mut fixtures = 0_usize;
    for path in rust_sources(&["crates/iroha_core/src"]) {
        if is_test_source(&path) {
            continue;
        }
        let text = source(&path);
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !line.contains(CALL) {
                continue;
            }
            let signature = lines[..index]
                .iter()
                .rposition(|line| is_fn_signature(line))
                .unwrap_or_else(|| panic!("{path}:{}: a call outside a function", index + 1));
            let fixture = lines[..signature]
                .iter()
                .rev()
                .map(|line| line.trim())
                .take_while(|line| line.starts_with("///") || line.starts_with("#["))
                .any(|line| {
                    line == "#[test]"
                        || line == "#[cfg(test)]"
                        || line.starts_with("#[cfg(any(test,")
                });
            if fixture {
                fixtures += 1;
            } else {
                production.push(path.clone());
            }
        }
    }
    assert_eq!(production, [OWNER]);
    assert!(
        fixtures > 0,
        "the fixture probe no longer sees the test-only caller"
    );
    assert!(is_fn_signature("    pub(in crate::state) fn advance("));
    assert!(is_fn_signature("fn f() {"));
    assert!(is_fn_signature(
        "    pub fn commit(self) -> Result<(), E> {"
    ));
    assert!(!is_fn_signature("    let fn_name = 1;"));
    assert!(!is_fn_signature("    // pub fn in a comment"));
}

/// The fourth inventory owner: `TransactionsStorage` is destructured without `..` beside
/// its declaration, and every physical field holds a declared membership identity or is
/// node-local with a reason.
#[test]
fn transactions_storage_fields_account_for_every_membership_identity() {
    let mut registry = Vec::new();
    flatten(STATE_FIELDS, &mut registry);
    let owner = registry
        .iter()
        .find(|field| field.id == "state.transactions")
        .expect("the registry declares the membership owner");
    let Role::Canonical(Canonical::Owner(children)) = owner.role else {
        panic!("state.transactions is a nested owner");
    };
    let declared: BTreeSet<&str> = children.iter().map(|field| field.id).collect();
    let mut held = BTreeSet::new();
    let mut names = Vec::new();
    for (name, role) in TRANSACTIONS_STORAGE_FIELDS {
        names.push(*name);
        match role {
            MembershipFieldRole::Canonical(ids) => {
                assert!(!ids.is_empty(), "{name}");
                held.extend(ids.iter().copied());
            }
            MembershipFieldRole::Local(reason) => assert!(!reason.is_empty(), "{name}"),
        }
    }
    assert_eq!(
        held, declared,
        "the physical fields hold exactly the declared membership identities"
    );
    // The classification lists the declared fields of the struct, in order.
    let text = source("crates/iroha_core/src/state/storage_transactions.rs");
    let (_, body) = text
        .split_once("pub struct TransactionsStorage {")
        .expect("the membership owner is declared");
    let (body, _) = body.split_once("\n}").expect("the struct ends");
    let fields: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .map(|line| {
            let (name, _) = line.split_once(": ").expect("a typed field");
            name.rsplit(' ').next().expect("a field name")
        })
        .collect();
    assert_eq!(fields, names);
    let rendered = physical_fields();
    assert!(rendered.starts_with(
        "[{\"name\":\"latest_block\",\"holds\":[\"state.transactions.frontier\",\"state.transactions.current\"]}"
    ));
    assert!(rendered.contains("{\"name\":\"write_lock\",\"local\":\""));
}

/// The contract text lives in `specs/sumeragi.md` §16: every publication and binding
/// rule is stated once, every pinned premise names one of them, and no standalone
/// contract document exists beside it.
#[test]
fn contract_section_states_every_publication_and_binding_rule_once() {
    let spec = source(CONTRACT_PATH);
    let (_, section) = spec
        .split_once("\n## 16. Keyed State commitment (application layer)\n")
        .expect("the contract is section 16 of the Sumeragi specification");
    let (section, _) = section
        .split_once("\n## Appendix E. As-built reconciliation\n")
        .expect("section 16 precedes Appendix E");
    assert!(
        section.contains("**Status: specified by ZK delivery plan task G.1, built by G.3;"),
        "the section states that it is not built"
    );
    for number in 1..=8 {
        assert_eq!(
            section.matches(&format!("\n### 16.{number} ")).count(),
            1,
            "section 16.{number}"
        );
    }
    let rules = [
        "P1", "P2", "P3", "P4", "P5", "P6", "N1", "N2", "N3", "N4", "N5",
    ];
    for rule in rules {
        assert_eq!(
            section.matches(&format!("\n- **{rule}.")).count(),
            1,
            "{rule}"
        );
    }
    for premise in PREMISES {
        assert!(
            premise.rule == "layout" || rules.contains(&premise.rule),
            "{}",
            premise.rule
        );
        assert!(!premise.evidence.is_empty(), "{}", premise.rule);
    }
    // P1 and section 16.8 carry the plan author's sentences on per-table roots, node-local
    // binding commitments, application accumulators and the drift test.
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let (_, p1) = section.split_once("\n- **P1.").expect("rule P1");
    let (p1, _) = p1.split_once("\n- **P2.").expect("rule P2 follows P1");
    let p1 = flat(p1);
    for sentence in [
        "independently authoritative per-table State roots are forbidden.",
        "Application accumulators may retain application-statement proofs under §16.8, but a \
         commitment that independently authenticates canonical State entries is a per-table \
         State root regardless of its carrier.",
        "Node-local binding commitments may remain only with an inventoried owner and reason; \
         they may authenticate local artifacts, including snapshot file bytes through chunk \
         proofs, but never authenticate State reads, determine transaction validity, or enter \
         protocol-authenticated roots or State witnesses.",
        "A protocol fingerprint may remain only as an inventoried comparison value that every \
         consuming validator recomputes from committed canonical entries at the specified \
         State cut, using only its inventoried block-header context and registered historical \
         inputs authenticated under §§16.1 and 16.7, or from canonical entries staged from the \
         signed genesis. It has no State-witness form and never substitutes for a keyed State \
         witness.",
        "A derived State field takes its authority only from its registered sources; a \
         protocol-carried copy may be installed only after equality with an independent \
         derivation from those sources at the specified State cut, and remains a comparison \
         value under the protocol-fingerprint rule.",
    ] {
        assert!(p1.contains(sentence), "P1 lacks: {sentence}");
    }
    let (_, cutover) = section
        .split_once("\n### 16.8 One root and cutover\n")
        .expect("section 16.8");
    let cutover = flat(cutover);
    for sentence in [
        "Every existing commitment over State content is enumerated under `roots` or, where the \
         application-accumulator exclusion applies, under `application_accumulator`.",
        ACCUMULATOR_RULE,
        "The drift test discovers hash-domain literals independently of ROOTS across both \
         crates and rejects every unclassified literal use, commitment-construction use and \
         hash-bearing execution-witness field; exemptions identify exact reviewed uses and \
         never match an open prefix.",
        "protocol fingerprints, flat digests or composite summaries of State content carried \
         for comparison in a header, the block result, signed genesis or peer handshake (made \
         a function of committed canonical entries or removed under their open defects; none \
         authenticates a State read)",
        "The block result also carries the AXT policy snapshot, tracked by G1-D11.",
        "the carrier walk reads the declarations of the block header, the block payload and \
         block result, the signed genesis consensus parameters, `R`, the lane batch and the \
         lane result with their nested records",
        "of the peer handshake (`crates/iroha_p2p`: the hello record that peers exchange with \
         its consensus, confidential, crypto and trust metadata and its wire digest, the \
         identity binding that the hello signature covers, and the consensus, confidential and \
         crypto capabilities that a node compares them with)",
        "In the types listed under `protocol_carriers[*].every_field_classified` every field \
         is classified, so a new field fails the check whatever its type. They are the block, \
         its payload and its result, the header with its confidential feature digest, the native \
         `CertifiedResultV1`, all twelve fixed X fields, the two body records of `R`, the walked \
         committee-member, authorization, beacon-binding and frozen-election-policy records, \
         the lane batch and the lane result, the genesis context parameters, the epoch identity, \
         every walked record of the peer handshake, the network envelope with its Sumeragi \
         frame, and the DA commitment bundle with its storage variants, canonical parts and \
         commitment records. In the other walked types a new field fails only when its type is hash-bearing \
         or names an unclassified nested type.",
        "It also matches a function that reads State and returns a walked record of the peer \
         handshake or of a lane block (`source_scan.carried_records`), whatever the name of \
         the record; it does not read the node binary, which fills the handshake capabilities.",
        "digests or embedded records that bind consensus authority, scheduling and finalized \
         beacon inputs in their specified roles under §§3, 4.1 and 10; they authenticate no \
         State read, and their canonical State source entries are also committed by the keyed \
         State root.",
        "Local bindings cover the tiered backend's separate key and value hashes, the \
         projection rowset hash and compressed archive/blob hash, and both private-settlement \
         evidence commitments: seven-table ledger evidence and replicated staged-lock \
         evidence. They authenticate only local artifacts or test observations, never State \
         reads or transaction validity.",
        "The drift test walks the listed consensus-carried types and their declared nested \
         types, rejecting unclassified hash-bearing fields or unclassified nested types. It \
         independently enumerates `iroha_core` functions and methods with a State/World \
         receiver or reader argument and a hash-bearing return value under documented type \
         rules, rejecting unclassified matches. Generated JSON pins each listed domain \
         literal's source paths and occurrence counts. These checks detect carrier, signature \
         and literal drift; they do not establish arbitrary State-dataflow completeness.",
    ] {
        assert!(cutover.contains(sentence), "section 16.8 lacks: {sentence}");
    }
    // The every-field sentence of section 16.8 is exact: the types it names are the types
    // listed under `every_field_classified`, carrier by carrier, and for the peer handshake
    // and the lane block they are every walked type.
    let exhaustive: Vec<(&str, &[&str])> = CARRIERS
        .iter()
        .map(|carrier| (carrier.id, carrier.exhaustive))
        .collect();
    assert_eq!(
        exhaustive,
        [
            (
                "block_header",
                &["BlockHeader", "ConfidentialFeatureDigest"][..]
            ),
            (
                "block_payload_and_result",
                &["SignedBlock", "BlockPayload", "BlockResult"][..]
            ),
            (
                "signed_genesis_consensus_parameters",
                &["SumeragiGenesisContextParameters"][..]
            ),
            (
                "execution_result",
                &[
                    "CertifiedResultV1",
                    "SccpFinalityHeaderFieldsV1",
                    "ExecutionResultCommitment",
                    "ExecutionCommitment",
                    "ValidatorCommitteeMemberV1",
                    "ValidatorEpochAuthorizationV1",
                    "BeaconEpochBindingV1",
                    "InstalledBeaconEpochBindingV1",
                    "ValidatorCommitteePreparationV1",
                    "ValidatorElectionPolicyV1",
                ][..]
            ),
            ("consensus_messages", &["EpochId"][..]),
            ("lane_result", &["LaneBatch", "LaneResult"][..]),
            (
                "peer_handshake",
                &[
                    "ConsensusHandshakeCaps",
                    "ConsensusConfigCaps",
                    "ConfidentialHandshakeCaps",
                    "CryptoHandshakeCaps",
                    "HandshakeHello",
                    "HandshakeConsensusMeta",
                    "HandshakeConfidentialMeta",
                    "HandshakeCryptoMeta",
                    "HandshakeTrustMeta",
                    "HandshakeConfidentialDigest",
                    "HandshakeIdentityBindingV1",
                ][..]
            ),
            (
                "node_network_envelope",
                &["NetworkMessage", "SumeragiFrame"][..]
            ),
            (
                "da_commitment_bundle",
                &[
                    "DaCommitmentBundle",
                    "Storage",
                    "CanonicalParts",
                    "DaCommitmentRecord"
                ][..]
            ),
        ]
    );
    for carrier in CARRIERS {
        if RECORD_RETURN_CARRIERS.contains(&carrier.id) {
            let walked: Vec<&str> = carrier
                .types
                .iter()
                .map(|(_, declaration)| declared_name(declaration))
                .collect();
            assert_eq!(carrier.exhaustive, walked, "{}", carrier.id);
        }
    }
    // Every record of the handshake in crates/iroha_p2p is walked: a struct of the two
    // sources whose name says that it is a handshake hello, metadata, digest, binding or
    // capability record.
    let handshake_types: BTreeSet<&str> = CARRIERS
        .iter()
        .filter(|carrier| carrier.id == "peer_handshake")
        .flat_map(|carrier| carrier.types.iter())
        .map(|(_, declaration)| declared_name(declaration))
        .collect();
    for path in [HANDSHAKE_CAPS, HANDSHAKE_WIRE] {
        let text = source(path);
        for line in text.lines() {
            let Some((_, rest)) = line.split_once("struct ") else {
                continue;
            };
            if line.trim_start().starts_with("//") {
                continue;
            }
            let name: String = rest
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect();
            if is_handshake_record_name(&name) {
                assert!(
                    handshake_types.contains(name.as_str()),
                    "{path} declares the handshake record {name}, which the peer_handshake \
                     carrier does not walk"
                );
            }
        }
    }
    // Section 16.8 names every protocol fingerprint and every open defect that tracks one,
    // and every class of the inventory.
    for name in [
        "execution-policy digest",
        "Nexus/AMX context hash",
        "DA proof-policy bundle hash",
        "confidential feature digest",
        "AXT policy snapshot",
        "G1-D3",
        "G1-D10",
        "G1-D11",
        "`EpochId.context`",
        "the pinned committee digest and parameters in every lane result",
    ] {
        assert!(cutover.contains(name), "section 16.8 lacks: {name}");
    }
    assert!(
        !cutover.contains("the protocol fingerprint of"),
        "section 16.8 names more than one protocol fingerprint"
    );
    for root in ROOTS {
        if root.class == RootClass::ProtocolFingerprint {
            let defect = root
                .defect
                .expect("a protocol fingerprint has an open defect");
            assert!(cutover.contains(defect), "section 16.8 lacks: {defect}");
        }
    }
    // P5 names the three distinct outcomes.
    let (_, p5) = section.split_once("\n- **P5.").expect("rule P5");
    let (p5, _) = p5.split_once("\n- **P6.").expect("rule P6 follows P5");
    for outcome in [
        "`ApplyDiverged`",
        "`NodeError::Replay`",
        "`PublicationRecoveryRequired`",
    ] {
        assert!(p5.contains(outcome), "{outcome}");
    }
    assert!(CONTRACT.starts_with(CONTRACT_PATH));
    assert!(repository().join(INTERFACE).is_file());
    assert!(
        !repository()
            .join("specs/state_keyed_commitment_contract.md")
            .exists(),
        "the contract is part of specs/sumeragi.md, not a standalone document"
    );
}

#[test]
fn inventory_text_helpers_escape_and_cite_exactly() {
    assert_eq!(string("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
    assert_eq!(list(["a", "b"]), "[\"a\",\"b\"]");
    assert_eq!(list(Vec::<&str>::new()), "[]");
    assert_eq!(pass_name("world.accounts"), Some("accounts"));
    assert_eq!(pass_name("triggers.data"), Some("triggers.data"));
    assert_eq!(pass_name("state.commit_topology"), None);
    assert_eq!(pass_name("runtime.lanes"), None);
    assert_eq!(shape_name(Some(TABLE)), "\"table\"");
    assert_eq!(shape_name(Some(CELL)), "\"cell\"");
    assert_eq!(shape_name(None), "null");
    let cited = evidence(
        "crates/iroha_core/src/state/world_state_accumulator.rs",
        "pub(crate) struct WorldStateAccumulator {",
    );
    assert!(cited.contains("\"occurrences\":1"), "{cited}");
    assert!(cited.starts_with(
        "{\"path\":\"crates/iroha_core/src/state/world_state_accumulator.rs\",\"line\":"
    ));
    assert!(
        std::panic::catch_unwind(|| evidence(
            "crates/iroha_core/src/state/world_state_accumulator.rs",
            "this marker is not in the source 5f0c",
        ))
        .is_err()
    );
    for defect in DEFECTS {
        assert_eq!(defect.assigned, "G.3", "{}", defect.id);
        assert!(!defect.evidence.is_empty(), "{}", defect.id);
        assert!(defect_fields(defect.id, &rows()).len() < rows().len());
    }
    assert_eq!(Commitment::Uncommitted.name(), "uncommitted");
    assert_eq!(RootClass::UncertifiedDraft.name(), "uncertified_draft");
    assert!(RootClass::CertifiedWitnessRoot.certified() && RootClass::CertifiedWitnessRoot.kept());
    assert!(!RootClass::CertifiedStateRoot.kept() && !RootClass::LocalBindingDigest.certified());
    assert_eq!(RootClass::ConsensusBinding.name(), "consensus_binding");
    assert!(RootClass::ConsensusBinding.certified() && RootClass::ConsensusBinding.kept());
    assert!(!RootClass::ProtocolFingerprint.kept() && !RootClass::ProtocolFingerprint.certified());
    assert_eq!(
        owner_json(UseOwner::Roots(&["a", "b"])),
        "\"roots\":[\"a\",\"b\"]"
    );
    assert_eq!(
        owner_json(UseOwner::Accumulator("x")),
        "\"application_accumulator\":\"x\""
    );
    assert_eq!(
        owner_json(UseOwner::Other(Use::Seed, "why")),
        "\"use\":\"seed\",\"reason\":\"why\""
    );
    assert_eq!(
        defect_fields("G1-D10", &rows()),
        [
            "world.verifying_keys",
            "world.poseidon_params",
            "world.pedersen_params",
            "world.sccp_light_client_profiles"
        ]
    );
    assert_eq!(DEFECTS.last().map(|defect| defect.id), Some("G1-D11"));
    assert_eq!(
        without_line_numbers("{\"line\":38185,\"occurrences\":1},{\"line\":7}"),
        "{\"line\":0,\"occurrences\":1},{\"line\":0}"
    );
    assert_eq!(without_line_numbers("no evidence"), "no evidence");
    let mut text = String::new();
    put(&mut text, "[");
    put_lines(&mut text, "  ", &["1".to_owned(), "2".to_owned()]);
    put(&mut text, "]");
    assert_eq!(text, "[\n  1,\n  2\n]\n");
}
