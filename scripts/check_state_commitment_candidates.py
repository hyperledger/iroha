#!/usr/bin/env python3
"""Check, or rebuild, the tracked comparison of the State commitment candidates.

``specs/state_commitment_candidates.json`` is the output of ZK delivery plan
task G.2: the native and in-circuit measurements of the development-only
prototypes in ``crates/fastpq_prover/src/state_commitment_prototypes``. Task
G.3 selects a construction from it; this file selects nothing.

Without arguments the script checks the tracked file against the tree:

* its structure, and that no construction is recorded as selected;
* every number lies under an explicit ``class`` (measured, accounting model,
  projection, ...) and every measured table names its units;
* the benchmark identity is complete: hardware, observed host, profile,
  configuration, source commit and, per run, the executable digest, the
  manifest digest, the load and the verdict;
* the prototype sources are the ones that were measured: the run
  configuration carries a digest of every prototype, adapter and measurement
  source, and the tree must still have that digest;
* the descriptive sections are this script's own tables, and those tables
  agree with the sources: construction identities and types, the set of
  engines, hash-profile identities and constants, known-answer tests, the
  conformance test table with its engine and profile types, the relation
  geometry, the gadget geometry, the storage-model constants and the as-built
  gadget constants are all read from the Rust sources;
* a measurement test that was run more than once is pooled row by row, its
  further runs are listed with how far their medians moved, and every row
  names the runs it pools;
* every derived figure is consistent with the figures it is derived from:
  relation width and constraints from the register count, the equality of
  in-circuit and native hash counts, the storage model from its constants,
  projection statuses from the recorded values, repetition statistics;
* the measured schema is the schema the tracked State inventory declares:
  every record names the tables, cells and descriptor digest its process
  read, and every native row counted the entries the workload builds over
  that schema;
* every committed-proof field is null with its reason.

``--reproduce`` additionally rebuilds the comparison from the raw records it
cites and requires the tracked file to be exactly that. The raw records are
untracked, so this check runs only where the run directories are present; it
is how an edited measured number is found.

``--refresh RUN_DIR...`` rebuilds the file from harness run directories
(``scripts/zk_resource_harness.py run``; untracked under ``dist/``). The raw
records stay untracked; the tracked file cites each run by directory name and
manifest digest. ``--source-digest`` prints the digest of the prototype
sources, to be put into the ``--config`` of the harness runs.

Inventory consistency only. Nothing here qualifies a construction, a hash or
a proof system, and no measurement affects validity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
SUMMARY = Path("specs/state_commitment_candidates.json")
SCHEMA = "iroha.state_commitment_candidates.v2"
PROTOTYPES = Path("crates/fastpq_prover/src/state_commitment_prototypes")
PROTOTYPE_ROOT = Path("crates/fastpq_prover/src/state_commitment_prototypes.rs")
ADAPTERS = Path(
    "crates/iroha_core/src/state/authority_registry/keyed_commitment/candidates_tests.rs"
)
INTERFACE = Path("crates/iroha_core/src/state/authority_registry/keyed_commitment.rs")
MEASUREMENT = Path(
    "crates/iroha_core_privacy/tests/state_commitment_candidates_measurement.rs"
)
INVENTORY = Path("specs/state_table_inventory.json")
BLAKE2B_GADGET = Path("crates/fastpq_prover/src/gadgets/compact_blake2b_air.rs")
SMT_GADGET = Path("crates/fastpq_prover/src/gadgets/compact_smt_air.rs")
RAW_ROOT = "dist/zk-resource-harness"
WORKLOAD_PREFIX = "state_candidates."
CONFIG_PREFIX = "state-candidates/inventory-schema/seed-0x473220261005/src-"
# Repetitions of a timed native phase below which a timing is not replicated.
MIN_REPETITIONS = 5
# Repetitions of a reference build and check below which it is not replicated.
MIN_REFERENCE_REPETITIONS = 3
# The recorder's limit: root time outside every phase, in parts per million.
UNATTRIBUTED_LIMIT_PPM = 10_000
# Largest trace order the uncommitted reference supports.
REFERENCE_ROWS = 65_536

CLASSES = (
    "measured",
    "measured_deterministic_count",
    "derived_from_measured",
    "accounting_model",
    "projection",
    "declared_assumption",
    "as_built_source_constant",
    "published_parameter",
    "identity",
)

# Sources that may name the prototype module. Anything else is a leak of
# development-only code into another owner.
PROTOTYPE_REFERENCES = {
    "crates/fastpq_prover/src/lib.rs",
    str(ADAPTERS),
    str(INTERFACE),
    str(MEASUREMENT),
}

B2_REASON = (
    "No committed proof of this relation exists: the committed q77 engine accepts "
    "only its sealed relations until task B.2 generalizes it. Trace-cell scaling "
    "from the sealed proof is not an estimate of these fields."
)

CONSTRUCTIONS = [
    {
        "id": "radix",
        "identity": "sparse-radix-critbit-merkle/key-order/v0",
        "source": str(PROTOTYPES / "radix.rs"),
        "type": "RadixTree",
        "summary": (
            "Path-compressed binary radix (crit-bit) Merkle tree over an "
            "order-preserving, prefix-free bit encoding of the composite key. "
            "Leaves are in canonical key order; the shape depends on the key set alone."
        ),
        "inclusion": "Branching bit index and sibling digest per branch on the leaf's path; sides are key bits.",
        "absence": "The path the absent key's bits select and the disclosed leaf it ends at. One path.",
        "complete_range": "Postfix witness of the covering subtrees: hidden subtrees need a disclosed leaf on their side, none is hidden between revealed leaves.",
        "update": "One compression per distinct branch on the touched paths (dirty marking, one rehash pass).",
        "depth": "About log2(n) for scattered keys plus about log2 of the table count, because the table position heads the composite key; at most 9*len+1 for adversarial keys of len bytes.",
        "in_circuit": "measured",
    },
    {
        "id": "btree",
        "identity": "sorted-merkle-btree/content-defined-pages-16/v0",
        "source": str(PROTOTYPES / "btree.rs"),
        "type": "MerkleBTree",
        "summary": (
            "Canonical sorted Merkle B-tree whose page boundaries are chosen by the key "
            "digests (a key ends a page of level l when its digest has l+1 leading zero "
            "nibbles; sixteen items per page on average). Pages are Merkle-hashed as "
            "binary subtrees, so the structure is one binary tree over the sorted leaves."
        ),
        "inclusion": "Side and sibling digest per binary node on the leaf's path.",
        "absence": "The empty complete range [key, key || 0x00): the two adjacent leaves, disclosed.",
        "complete_range": "The same postfix witness as the radix tree, without branching indices.",
        "update": "Every page on the path of a touched key is rehashed (about fifteen compressions per level); a key that newly ends a page also rehashes the following page. The prototype recomputes page-internal nodes; as_built_alternatives projects the cost with those nodes kept.",
        "depth": "About log2(n) plus the imbalance of geometric page sizes. Page sizes are unbounded: chosen keys can grind long pages.",
        "in_circuit": "measured",
    },
    {
        "id": "linked",
        "identity": "indexed-linked-leaf-merkle-map/hashed-address-critbit/v0",
        "source": str(PROTOTYPES / "linked.rs"),
        "type": "LinkedLeafMap",
        "summary": (
            "Indexed linked-leaf Merkle map: every leaf binds its key digest, its value "
            "digest and the key digest of the next key in canonical order, between a "
            "lower and an upper sentinel. Leaves live in a compressed sparse Merkle tree "
            "addressed by key digest, so positions depend on keys alone."
        ),
        "inclusion": "The successor's key digest and the leaf's address path.",
        "absence": "The leaf whose key and successor bracket the absent key, both disclosed. One path, no key-bit selection.",
        "complete_range": "The bracketing leaf below the interval, one address path per claimed entry and the disclosed successor of the last; each successor digest is the next claimed key. The prototype witness carries every path whole; as_built_alternatives counts what paths that share their common nodes would carry.",
        "update": "An insertion or removal rewrites two leaves, a value update one; the sorted neighbour index is not authenticated.",
        "depth": "About log2(n) expected; at most 256.",
        "in_circuit": "measured",
    },
    {
        "id": "chain",
        "identity": "sorted-hash-chain/baseline/v0",
        "source": str(PROTOTYPES / "chain.rs"),
        "type": "SortedHashChain",
        "summary": (
            "Baseline: the entries in canonical order folded into one running digest. "
            "No tree. It shows what the tree candidates buy; it is not a proposal."
        ),
        "inclusion": "The accumulator before the entry and the leaf digest of every later entry.",
        "absence": "The empty complete range [key, key || 0x00).",
        "complete_range": "The accumulator before the disclosed predecessor, the predecessor and successor leaves and every later leaf digest.",
        "update": "Linear: every accumulator after the first changed position.",
        "depth": "n.",
        "in_circuit": "not_shortlisted: every statement is linear in the population",
    },
]

HASH_PROFILES = [
    {
        "id": "blake2b",
        "identity": "blake2b-256-raw",
        "kind": "native_fast",
        "source": str(PROTOTYPES / "hash.rs"),
        "rust_type": "Blake2bProfile",
        "parameters": "BLAKE2b with 256-bit output through iroha_crypto::blake2; all 256 bits kept, no iroha_crypto::Hash marker bit.",
        "framing": "hash_bytes = B(0x00 || le64(domain) || le64(len) || bytes); compress = B(0x01 || le64(domain) || le64(aux) || left || right).",
        "known_answer_test": None,
        "known_answer_test_reason": "The primitive is the repository's existing BLAKE2b owner; the prototype adds framing only.",
        "in_circuit": "as_built_comparator",
    },
    {
        "id": "blake3",
        "identity": "blake3-256-raw",
        "kind": "native_fast",
        "source": str(ADAPTERS),
        "rust_type": "Blake3Profile",
        "parameters": "BLAKE3 with 256-bit output. Supplied by the two consumer crates that own a blake3 dependency (the proof crate has none): the conformance adapters and the measurement target each define it, and each checks it against blake3::hash. The framing is the same ByteProfile.",
        "framing": "As blake2b.",
        "known_answer_test": "candidates_are_four_distinct_constructions_over_named_profiles",
        "second_definition": str(MEASUREMENT),
        "second_definition_test": "smoke_every_candidate_yields_valid_native_and_circuit_records",
        "in_circuit": "not_measured",
    },
    {
        "id": "poseidon2",
        "identity": "poseidon2-goldilocks-t12-rf8-rp22-x7/sponge-r8-c4",
        "kind": "arithmetization_friendly",
        "source": str(PROTOTYPES / "poseidon2.rs"),
        "rust_type": "Poseidon2Profile",
        "constants": {"class": "published_parameter", "width": 12, "full_rounds": 8, "partial_rounds": 22, "rounds": 30},
        "parameters": "Poseidon2 over Goldilocks, width 12, x^7, 8 full and 22 partial rounds, external matrix circ(2*M4, M4, M4), internal matrix J + diag(d) with the published diagonal. Sponge: capacity 4, rate 8, 4-element digest.",
        "published_source": "Grassi, Khovratovich, Schofnegger, 'Poseidon2: A Faster Version of the Poseidon Hash Function' (2023); Goldilocks width-12 instance of the reference implementation. Round constants are regenerated with the published Grain LFSR procedure and pinned by digest.",
        "known_answer_test": "permutation_reproduces_the_published_known_answer_vector",
        "security_note": "Published round counts; no security claim is made or checked here (task H.1).",
        "in_circuit": "measured",
    },
    {
        "id": "rescue-prime",
        "identity": "rescue-prime-rp64-256-goldilocks-t12-n7-x7/sponge-r8-c4",
        "kind": "arithmetization_friendly",
        "source": str(PROTOTYPES / "rescue.rs"),
        "rust_type": "RescuePrimeProfile",
        "constants": {"class": "published_parameter", "width": 12, "rounds": 7},
        "parameters": "Rescue-Prime Rp64_256 over Goldilocks, width 12, x^7 and its inverse, seven rounds, circulant MDS with first row 7,23,8,26,13,10,9,7,6,22,21,8. Sponge: capacity 4, rate 8, 4-element digest.",
        "published_source": "Szepieniec, Ashur, Dhooghe, 'Rescue-Prime: a Standard Specification (SoK)' (2020), as instantiated by winter-crypto 0.13.1 (Rp64_256), whose permutation known-answer vector is pinned.",
        "known_answer_test": "permutation_reproduces_the_published_known_answer_vector",
        "security_note": "Published round count; no security claim is made or checked here (task H.1). This is Rescue-Prime, not Rescue-Prime Optimized.",
        "in_circuit": "measured",
    },
    {
        "id": "digest384",
        "identity": "in-repo-poseidon-x7-w3-digest384-first-four-lanes",
        "kind": "in_repo_comparator",
        "source": str(PROTOTYPES / "hash.rs"),
        "rust_type": "Digest384Comparator",
        "parameters": "The repository's six-lane width-3 Poseidon digest (fastpq_isi::poseidon_digest384), reused unchanged and truncated to four lanes so a node keeps 32 bytes. A measurement device, not a proposed construction.",
        "known_answer_test": None,
        "known_answer_test_reason": "The digest is owned and pinned by fastpq_isi; the prototype calls its public entry point.",
        "security_note": "Each lane is a capacity-one sponge; the security of the lane composition and of any truncation is task H.1's subject.",
        "in_circuit": "projection",
    },
]

CONFORMANCE_PROFILES = {
    "blake2b": "blake2b",
    "blake3": "blake3",
    "poseidon2": "poseidon2",
    "rescue-prime": "rescue_prime",
    "digest384": "the_in_repo_digest",
}
CONFORMANCE_NAMES = {
    "radix": "radix_tree",
    "btree": "merkle_btree",
    "linked": "linked_leaf_map",
    "chain": "sorted_hash_chain",
}

UNITS = {
    "wall_ns": "nanoseconds of wall time of the phase, as recorded by iroha_measurement",
    "timing": "an object {min, median, max, repetitions}: the stated quantity in each repetition of the phase on identical inputs, in nanoseconds per the stated unit of work. The repetitions of one run ran one after another in one process; a row of a test that was run more than once counts the repetitions of every run (record.replicates, timing_comparability.run_to_run). Their spread is the timing's uncertainty under the recorded load. Thread and process CPU time moved with wall time on this host and are not recorded as a load-independent figure.",
    "bytes": "bytes of the canonical prototype witness encoding, or of the named structure",
    "heap_bytes": "bytes this executable's counting allocator saw allocated and not yet freed: requested layout sizes, without the allocator's own bookkeeping. A map's heap is counted on the building thread alone; the peak of a reference build or check is counted over every thread of the process",
    "compressions": "calls of the two-to-one compression of the hash profile",
    "byte_hashes": "calls of the byte-string hash of the hash profile",
    "permutations": "width-12 sponge permutations (width-3 lane permutations for digest384)",
    "rows": "trace rows after padding to a power of two",
    "width": "trace columns, verifier-known columns included",
    "registers": "digests the relation's register file holds: the number the statement's evaluation schedule uses, fixed for the trace",
    "peak_rss_bytes": "process high-water resident set size when the record's session ended; it never falls within a process, so it does not compare candidates measured one after another",
    "load_milli": "one-minute system load average times 1000",
    "unattributed_ppm": "root wall time outside every phase, in parts per million of the root; the recorder's limit is 10,000",
}

RELATION_SCOPE = {
    "relation": "One hash-chain relation per sponge permutation, written against fastpq_prover::air::SemanticAir (crates/fastpq_prover/src/state_commitment_prototypes/circuit.rs): one row per permutation round, a register file of R digests, 18 + 4R numerators of degree at most 8, 13 + 4R private and 20 + 2R verifier-known columns besides the permutation's periodic ones.",
    "registers": "R is the number of registers the statement's evaluation schedule uses (Program::registers), at least one. It is fixed for one trace and is part of the relation's identity, width and statement bytes. A deployed relation would fix one R; the figure recorded per statement is what that statement needs.",
    "constrained_in_relation": [
        "every permutation round of every hash the native verifier computes, each exactly once: the sponge over the key and value bytes of the statement, the leaf compression, every branch of an opened range tree and the root normalisation",
        "the chaining of each digest into the next permutation, with the side of the previous digest, and the digest a register holds from the block that saved it to the compression that reads it",
        "the statement (key and value blocks), the schema digest and the root, as verifier-known columns and constants",
        "every side that the statement fixes: the bits of the absent key at the disclosed branching indices, every side of an opened range tree (adjacency of the revealed leaves is read from them) and the leaf and link compressions",
        "the successor of every linked leaf of an absence or range statement, as the digest of the disclosed or claimed successor key hashed in the same trace",
    ],
    "hash_count": "For every statement of the native sample the program's permutation count equals the native verifier's, plus one root normalisation for each anchored chain after the first. Only the linked-leaf range has more than one: it anchors the chain of every leaf where its native verifier compares structure roots and normalises once.",
    "outside_the_relation": [
        "Structural checks without a hash (key order against a disclosed neighbour, the shape rules of a range witness) run on verifier-known values when the program is derived, and the skeleton they read (disclosed keys, branching bit indices, statement-fixed sides) is public.",
        "A relation that hides the key, as a State read inside a private execution proof needs, must make the key words private and constrain them. The two gadgets that takes (in_circuit.gadgets) are built and checked as relations of their own; they are not composed into the hash-chain trace. Binding the gadget's limbs to the sponge's message words, hiding the branching indices behind private selectors and constraining the range shape rules remain open for the selected construction (G.3, B.2).",
    ],
    "proof_system": "Uncommitted algebraic reference of task B.1 (air::build_reference / check_reference): the complete trace in the clear, no commitment, masking, FRI or transcript. Its time and memory are not committed-proof figures.",
    "forgery_tests": "crates/fastpq_prover/src/state_commitment_prototypes/circuit_tests.rs. Inclusion: forged siblings, roots and statements are rejected (radix). Absence and complete range, for each of radix, B-tree and linked-leaf under both permutations, through absence_program and range_program: a radix prover following another leaf's path for a committed key, a B-tree absence and a radix or B-tree range that hide a committed entry on the wrong side of its neighbour, a linked leaf whose successor is not the next claimed key; each is rejected by the relation and accepted only without the binding it violates. Each of the eight constraint groups is shown load-bearing by a forged trace that only the relation without that group accepts. The native completeness rules of the range witness have their own crafted-witness tests in fringe.rs.",
}

GADGET_SCOPE = {
    "relations": "crates/fastpq_prover/src/state_commitment_prototypes/key_gadgets.rs: KeyOrderAir (byte-string order, one byte per row, 32 private and 10 verifier-known columns, 47 numerators of degree at most 4) and KeyBitAir (stated bits of the order-preserving key encoding, 11 private and 26 verifier-known columns, 25 numerators of degree at most 3). Both tie the scanned bytes to the byte length and seven-byte limbs the sponge absorbs.",
    "status": "Built and checked standalone with the uncommitted reference, with a forged trace per constraint group. Not composed into the hash-chain trace: the limbs and the length are verifier-known columns here and would be the sponge's private message words in a composed trace.",
    "instances": "Declared per construction and statement kind (WitnessPrograms::ABSENCE_GADGETS, RANGE_GADGETS; recorded with every in-circuit row). Inclusion needs none. Radix absence: two bit scans (the absent key at the branching indices and at one index where the disclosed leaf differs; the disclosed leaf at that index). B-tree and linked-leaf absence: two comparisons (predecessor below the key, successor above it). Every complete range: two comparisons (predecessor below the lower bound, upper bound not above the successor).",
    "combined_cost": "Each in-circuit row carries the sum of its hash-chain trace cells and the trace cells of its gadget instances as a projection. It is a sum of separately measured relations, not the cell count of a composed trace, whose width and degree are open.",
}

STORAGE_MODEL = {
    "class": "accounting_model",
    "note": "Engine::storage(): what a persisted node store would keep per node, with node counts read from the structure the prototype holds and bytes per node declared as constants in each construction's source (MODEL_*_BYTES). A model, not a measurement: nothing is persisted, and the B-tree's figure follows from the modelling choice not to keep page-internal nodes. The heap the prototype's containers really hold is in native.rows[].memory.",
    "constants": {
        "radix": {"leaf_bytes": 64, "branch_bytes": 44},
        "btree": {"entry_bytes": 65, "upper_item_bytes": 41},
        "linked": {"leaf_bytes": 96, "branch_bytes": 44, "index_entry_bytes": 8},
        "chain": {"entry_bytes": 96, "root_bytes": 32},
    },
    "formulas": {
        "radix": "entries * leaf_bytes + (entries - 1) * branch_bytes",
        "btree": "entries * entry_bytes + upper_items * upper_item_bytes, upper_items = structure_digests - 2 * entries",
        "linked": "(entries + 1) * leaf_bytes + entries * branch_bytes; auxiliary: entries * index_entry_bytes",
        "chain": "entries * entry_bytes + root_bytes",
    },
}

MEMORY_NOTE = (
    "heap_live_bytes is what the building thread held more after the cold build than before it: the measuring "
    "executable's allocator counts, for this figure, the allocations and frees of that thread alone while the build "
    "runs, so no other thread's allocation is in it. It is the heap of the prototype's own containers (std BTreeMap "
    "nodes, the node arena with its spare capacity, the key bytes the prototype keeps, twice for the radix tree), "
    "requested layout sizes without the allocator's bookkeeping, and the same in every build of the same State. The "
    "figure is the value a strict majority of the cold builds read, in every run that measured the row; heap_readings "
    "says how many builds read it and the lowest and highest reading, so a reading that differed would show there. "
    "It measures the prototype's in-memory data structures, not a persisted node store. heap_peak_build_bytes is the "
    "most the building thread held more during the build, taken the same way. record.peak_rss_bytes is a process "
    "high-water mark and compares nothing."
)

DECISION_CRITERIA = {
    "status": "proposed for G.3; not frozen and not applied here",
    "selection_recorded_here": False,
    "admissible_measures": [
        "Deterministic counts separate candidates: compressions, byte hashes, permutations, witness bytes, rows, registers, gadget instances. They are identical in every repetition and on every machine.",
        "A timing separates two candidates only where timing_comparability lists the pair as separated for that measure: the intervals of their repetitions do not overlap. A pair listed as overlapping differs by less than the observed spread and is not distinguished by time. timing_comparability.run_to_run states how far the medians of a test moved between two runs; a separation taken from one run alone is weaker than one whose intervals span two.",
        "A timing with replicated: false separates nothing: a cold build run fewer than five times, and every reference build or check of a trace above 4,096 rows.",
        "The storage model is an accounting model and the heap figure is of the prototype's containers; neither is a persisted size. Peak RSS compares nothing.",
        "In-circuit rows compare candidates by their permutation counts, which equal the native verifier's, and by the declared gadget instances. The sum with gadget trace cells is a projection of an uncomposed relation.",
    ],
    "screening": [
        "K1..K12 conformance of the construction under the profile (met by every candidate listed; see conformance).",
        "A written collision and preimage argument for the hash profile at the root's 256 bits, with the cross-witness consistency of sumeragi.md section 16.4 for any construction built from more than one authenticated component (task H.1 for the hash, G.3 for the construction).",
        "Bit-identical roots, witnesses and verdicts across platforms: cross-platform vectors do not exist yet.",
        "Bounded verification: witness bytes and claimed entries bound the work. The B-tree's page sizes and the radix tree's adversarial depth must be capped or charged before either is admissible.",
    ],
    "criteria": [
        {
            "id": "native_update",
            "question": "What does one block's change set cost the publication owner?",
            "measures": ["native.rows[].updates[].compressions_per_change", "native.rows[].cold_build compressions", "native.rows[].updates[].wall_ns_per_change where timing_comparability separates", "as_built_alternatives.btree_cached_page_nodes"],
            "proposed_weight": 0.2,
        },
        {
            "id": "storage",
            "question": "How large is the authenticated structure beside the State, and how large is retained history per block (changed nodes)?",
            "measures": ["native.rows[].storage_model (accounting model)", "native.rows[].memory.heap_live_bytes (prototype containers)", "native.rows[].updates[].compressions_per_change"],
            "proposed_weight": 0.1,
        },
        {
            "id": "carried_witness",
            "question": "How many bytes does a transaction carry per statement kind, and what does a validator spend to verify them?",
            "measures": ["native.rows[].witness.*.bytes_mean", "native.rows[].witness.*.verify_compressions_per_statement", "native.rows[].witness.range[]", "as_built_alternatives.linked_range_shared_paths"],
            "proposed_weight": 0.25,
        },
        {
            "id": "in_circuit",
            "question": "How many permutations, registers and trace cells does each statement kind need, and what do the gadgets of a private key add?",
            "measures": ["in_circuit.rows[].statements", "in_circuit.rows[].geometry", "in_circuit.rows[].gadget_instances", "in_circuit.gadgets", "in_circuit.relation_scope.outside_the_relation"],
            "proposed_weight": 0.3,
        },
        {
            "id": "robustness",
            "question": "How do adversarial keys change depth, page size and update cost; how much logic must be exactly canonical?",
            "measures": ["native.rows[] with key_shape shared-prefix-32 and long-128", "native.rows[].storage_model.max_depth", "constructions[].depth"],
            "proposed_weight": 0.15,
        },
    ],
    "sensitivity": "G.3 publishes the outcome under each criterion alone and under the proposed weights before it freezes a choice; a candidate that wins only under one weighting is reported as such.",
    "hybrid_note": "A native value hash under an algebraic tree is admissible only if a proof that asserts value bytes also proves the native value hash; an unconstrained digest is not the value.",
}

LIMITS = [
    "The populations are declared experimental assumptions. Neither the State inventory nor this task establishes a production bound; 2^20 entries in one table is the maximum measured population, not a supported maximum.",
    "Times were taken on a shared development host under the recorded load, one measurement run at a time, each timed phase repeated on identical inputs. The deterministic counts do not depend on load; wall times do, and their repetition spread is recorded with them. Only the tests listed in timing_comparability.run_to_run were run twice; every other timing comes from one process.",
    "The algebraic profiles run on the proof crate's reference field arithmetic (128-bit reduction, no vector code). Their native latencies are those of this prototype, not of an optimized implementation.",
    "Witness encodings are prototype encodings (32-bit counts, 32-byte digests). G.3 freezes the wire encoding; byte counts here compare constructions, they are not wire sizes.",
    "No committed proof of the witness relation exists (task B.2). Reference build and check times are for an uncommitted, non-hiding artifact.",
    "The witness relation reads a verifier-known skeleton. The key gadgets of a private key are built and measured on their own and are not composed into the trace; no figure here is the cost of a complete private-key witness relation.",
    "x86-64, device and accelerator measurements were not made. Historical-version storage, pruning, crash recovery and publication are G.3 and G.4 subjects and are not measured.",
    "Rescue-Prime Optimized, Monolith, Tip5 and Anemoi are not implemented; their entries are projections.",
]

WORKLOAD_NOTES = {
    "populated_table": "world.accounts",
    "representative_population_log2": 16,
    "maximum_note": "Maximum measured population, not a maximum supported State workload. The inventory states no population.",
    "background": "Every cell holds its one entry and every other keyed table four entries, so the commitment spans the whole schema.",
    "key_shapes": {
        "scattered-32": "32 scattered bytes",
        "shared-prefix-32": "24 fixed bytes and an 8-byte counter",
        "long-128": "96 fixed bytes and 32 scattered bytes",
    },
    "change_sets": "1, 100 and 10,000 changes over several tables: of every ten, seven rewrite an entry of the populated table, one inserts there, one removes there and one rewrites an entry of another table or a cell. A size above half the population is not run. Each repetition replays the same sets on a clone of the same built State.",
    "ranges": "Complete ranges of 0, 1, 16 and 1,024 claimed entries with a committed key on each side; in-circuit also 64.",
    "seed": "0x473220261005; every workload is a pure function of its parameters (workload.rs)",
    "not_run": [
        "chain under poseidon2 at 2^20 and under rescue-prime above 2^10: linear in the population under a sponge profile",
        "digest384 beyond radix at 2^16 and all four constructions at 2^10, with fewer statements and no 10,000-change set: one hash costs several thousand BLAKE2b compressions",
        "more than one cold build under rescue-prime at 2^20 and under digest384 at 2^16: one build takes minutes; those builds are marked replicated: false",
        "2^24 entries in one table",
    ],
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prototype_sources(repository: Path) -> list[Path]:
    """Every source the measured executable's candidate code comes from."""
    paths = sorted((repository / PROTOTYPES).glob("*.rs"))
    paths += [repository / PROTOTYPE_ROOT, repository / ADAPTERS, repository / MEASUREMENT]
    return [path for path in paths if path.is_file()]


def source_digest(repository: Path) -> dict[str, Any]:
    """One digest over the path and content digest of every prototype source."""
    hasher = hashlib.sha256()
    paths = prototype_sources(repository)
    for path in paths:
        relative = path.relative_to(repository).as_posix()
        hasher.update(f"{relative}\0{sha256_file(path)}\n".encode())
    return {"class": "identity", "sha256": hasher.hexdigest(), "files": len(paths)}


def expected_config(repository: Path) -> str:
    """The harness configuration that binds a run to the prototype sources."""
    return CONFIG_PREFIX + source_digest(repository)["sha256"][:16]


REPEATED = re.compile(r"^r(\d+)\.(.+)$")


class Record:
    """One measurement record with lookups by phase label.

    A timed phase that is repeated on identical inputs is recorded once per
    repetition under ``r<k>.<phase>``; ``<phase>`` is its base label.

    A workload measured by more than one run of the same executable is read as
    one record: `pool` adds the record of a further run, whose repetitions
    then count with this record's. Everything that is not a time must be the
    same in every run, and `pool` refuses a record where it is not.
    """

    def __init__(self, document: dict[str, Any], run: str, path: str) -> None:
        self.document = document
        self.run = run
        self.path = path
        self.replicates: list[Record] = []
        self.workload: str = document["identity"]["workload"]
        self.nodes: list[dict[str, Any]] = document["phase_tree"]["nodes"]
        self.work: dict[tuple[int, str], dict[str, Any]] = {
            (entry["phase"], entry["label"]): entry
            for entry in document["work_counters"]["entries"]
        }
        self.bytes: dict[tuple[int, str], dict[str, Any]] = {
            (entry["phase"], entry["label"]): entry
            for entry in document["byte_counters"]["entries"]
        }
        self.index: dict[str, int] = {}
        self.repeats: dict[str, list[tuple[int, int]]] = {}
        self.bases: list[str] = []
        for index, node in enumerate(self.nodes):
            label = node["label"]
            self.index.setdefault(label, index)
            match = REPEATED.match(label)
            base = match.group(2) if match else label
            if base not in self.bases:
                self.bases.append(base)
            if match:
                self.repeats.setdefault(base, []).append((int(match.group(1)), index))
        for entries in self.repeats.values():
            entries.sort()

    def pooled(self) -> list[Record]:
        """This record and the records of the further runs pooled into it."""
        return [self, *self.replicates]

    def fixed_counters(self) -> dict[tuple[str, str, str], tuple[int, ...]]:
        """Every counter of a phase that is not a repetition: label, kind, name."""
        found = {}
        for kind, table, keys in (
            ("work", self.work, ("count", "total_units", "min_units", "max_units")),
            ("bytes", self.bytes, ("count", "total_bytes", "min_bytes", "max_bytes")),
        ):
            for (index, name), entry in table.items():
                label = self.nodes[index]["label"]
                if not REPEATED.match(label):
                    found[(label, kind, name)] = tuple(entry[key] for key in keys)
        return found

    def pool(self, other: Record) -> None:
        """Count the repetitions of another run's record of this workload with this one's.

        The phases and every counter outside the repetitions must agree: they
        are deterministic functions of the workload.
        """
        if other.workload != self.workload:
            raise ValueError(f"{self.workload}: cannot pool the record of `{other.workload}`")
        if [node["label"] for node in other.nodes] != [node["label"] for node in self.nodes]:
            raise ValueError(f"{self.workload}: runs {self.run} and {other.run} recorded different phases")
        if other.fixed_counters() != self.fixed_counters():
            raise ValueError(
                f"{self.workload}: a deterministic counter differs between runs {self.run} and {other.run}"
            )
        self.replicates.append(other)

    def phase(self, label: str) -> int | None:
        return self.index.get(label)

    def wall(self, label: str) -> int | None:
        index = self.phase(label)
        return None if index is None else self.nodes[index]["wall_inclusive_ns"]

    def counter(self, label: str, counter: str) -> dict[str, Any] | None:
        index = self.phase(label)
        return None if index is None else self.work.get((index, counter))

    def units(self, label: str, counter: str) -> int | None:
        entry = self.counter(label, counter)
        return None if entry is None else entry["total_units"]

    def size(self, label: str, counter: str) -> dict[str, Any] | None:
        index = self.phase(label)
        return None if index is None else self.bytes.get((index, counter))

    def labels(self) -> list[str]:
        """Base labels in first-appearance order."""
        return list(self.bases)

    def repetitions(self, base: str) -> list[str]:
        """Labels of this run's repetitions of a phase."""
        return [self.nodes[index]["label"] for _, index in self.repeats.get(base, [])]

    def run_walls(self, base: str) -> list[int]:
        """Wall time of this run's repetitions of a phase."""
        return [self.nodes[index]["wall_inclusive_ns"] for _, index in self.repeats.get(base, [])]

    def walls(self, base: str) -> list[int]:
        """Wall time of every repetition of a phase, in every pooled run."""
        return [wall for record in self.pooled() for wall in record.run_walls(base)]

    def process_cpus(self, base: str) -> list[int]:
        return [
            record.nodes[index]["process_cpu_window_inclusive_ns"]
            for record in self.pooled()
            for _, index in record.repeats.get(base, [])
        ]

    def repetition_units(self, base: str, counter: str) -> list[int]:
        """A counter of every repetition of a phase that reports it, in every pooled run."""
        values = [
            record.units(label, counter) for record in self.pooled() for label in record.repetitions(base)
        ]
        return [value for value in values if value is not None]

    def same_units(self, base: str, counter: str) -> int | None:
        """A counter that every repetition of every pooled run must report with the same value."""
        values = {
            record.units(label, counter) for record in self.pooled() for label in record.repetitions(base)
        }
        if not values:
            return None
        if len(values) != 1:
            raise ValueError(
                f"{self.workload}: `{counter}` of `{base}` differs between repetitions: {sorted(map(str, values))}"
            )
        return values.pop()

    def majority_units(self, base: str, counter: str) -> dict[str, int] | None:
        """The value most repetitions of a phase report for a counter, with how many did.

        For a reading that is deterministic but taken from a process-wide
        counter: a repetition that another thread's allocation fell into reads
        higher. The value is the one a strict majority of the repetitions of
        every pooled run read; without such a majority the reading is refused.
        """
        values = self.repetition_units(base, counter)
        if not values:
            return None
        value = max(set(values), key=values.count)
        agreeing = values.count(value)
        if 2 * agreeing <= len(values):
            raise ValueError(
                f"{self.workload}: `{counter}` of `{base}` has no value that most repetitions agree on: {sorted(set(values))}"
            )
        return {"value": value, "agreeing": agreeing, "repetitions": len(values), "min": min(values), "max": max(values)}

    def same_size(self, base: str, counter: str) -> dict[str, Any] | None:
        """A byte counter that every repetition of every pooled run must report identically."""
        keys = ("count", "total_bytes", "min_bytes", "max_bytes")
        seen = []
        for record in self.pooled():
            for label in record.repetitions(base):
                entry = record.size(label, counter)
                seen.append(None if entry is None else tuple(entry[key] for key in keys))
        if not seen or seen[0] is None:
            return None
        if len(set(seen)) != 1:
            raise ValueError(f"{self.workload}: `{counter}` of `{base}` differs between repetitions")
        return dict(zip(keys, seen[0]))

    def run_facts(self) -> dict[str, Any]:
        """What one run observed around this record's flow."""
        process = self.document["process"]
        root = self.nodes[0]
        return {
            "run": self.run,
            "flow_wall_ns": root["wall_inclusive_ns"],
            "unattributed_ppm": round(root["wall_exclusive_ns"] * 1_000_000 / max(root["wall_inclusive_ns"], 1)),
            "peak_rss_bytes": process["peak_rss_bytes"],
            "peak_rss_bytes_at_begin": process["peak_rss_bytes_at_begin"],
            "load_milli_begin": process["load_milli_begin"],
            "load_milli_finish": process["load_milli_finish"],
        }

    def provenance(self) -> dict[str, Any]:
        """The first run's observations, and those of every further run pooled into the row."""
        facts = self.run_facts()
        return {
            "class": "measured",
            "run": facts.pop("run"),
            "workload": self.workload,
            **facts,
            "replicates": [record.run_facts() for record in self.replicates],
        }

    def median_ratios(self) -> dict[str, list[float]]:
        """Per further run: for every timed phase, that run's median wall time over the first run's."""
        ratios: dict[str, list[float]] = {}
        for record in self.replicates:
            for base in self.repeats:
                first, other = self.run_walls(base), record.run_walls(base)
                if first and other and statistics.median(first) > 0:
                    ratios.setdefault(record.run, []).append(statistics.median(other) / statistics.median(first))
        return ratios


def ratio(numerator: int | None, denominator: int | None, digits: int = 1) -> float | None:
    if numerator is None or not denominator:
        return None
    return round(numerator / denominator, digits)


def timing(walls: list[int], count: int | None, digits: int = 1) -> dict[str, Any] | None:
    """Minimum, median and maximum over the repetitions, per unit of work."""
    if not walls or not count:
        return None
    per = sorted(wall / count for wall in walls)
    return {
        "min": round(per[0], digits),
        "median": round(statistics.median(per), digits),
        "max": round(per[-1], digits),
        "repetitions": len(per),
    }


def hash_work(record: Record, base: str) -> dict[str, Any]:
    return {
        "compressions": record.same_units(base, "hash.compressions"),
        "byte_hashes": record.same_units(base, "hash.byte_hashes"),
        "hashed_bytes": record.same_units(base, "hash.hashed_bytes"),
        "permutations": record.same_units(base, "hash.permutations"),
    }


def witness_kind(record: Record, name: str) -> dict[str, Any] | None:
    prove, verify = f"prove_{name}", f"verify_{name}"
    statements = record.same_units(verify, "statements")
    size = record.same_size(prove, "witness")
    if not statements or size is None:
        return None
    work = hash_work(record, verify)
    return {
        "statements": statements,
        "bytes_mean": ratio(size["total_bytes"], size["count"]),
        "bytes_min": size["min_bytes"],
        "bytes_max": size["max_bytes"],
        "prove_ns_per_statement": timing(record.walls(prove), statements),
        "verify_ns_per_statement": timing(record.walls(verify), statements),
        "verify_compressions_per_statement": ratio(work["compressions"], statements),
        "verify_byte_hashes_per_statement": ratio(work["byte_hashes"], statements),
        "verify_permutations_per_statement": ratio(work["permutations"], statements),
    }


def workload_tags(workload: str) -> dict[str, Any]:
    parts = workload[len(WORKLOAD_PREFIX) :].split(".")
    flow, construction, profile, population, key_shape, value = parts
    return {
        "flow": flow,
        "construction": construction,
        "profile": profile,
        "population_log2": int(population[1:]),
        "key_shape": key_shape,
        "value_bytes": int(value[1:]),
    }


def native_row(record: Record) -> dict[str, Any]:
    tags = workload_tags(record.workload)
    entries = record.same_units("cold_build", "entries")
    builds = record.walls("cold_build")
    updates = []
    ranges = []
    for label in record.labels():
        if label.startswith("update_set_"):
            sets = record.same_units(label, "change_sets")
            changes = record.same_units(label, "changes")
            work = hash_work(record, label)
            updates.append(
                {
                    "changes_per_set": int(label.rsplit("_", 1)[1]),
                    "change_sets": sets,
                    "wall_ns_per_change": timing(record.walls(label), changes),
                    "compressions_per_change": ratio(work["compressions"], changes, 2),
                    "byte_hashes_per_change": ratio(work["byte_hashes"], changes, 2),
                    "permutations_per_change": ratio(work["permutations"], changes, 2),
                }
            )
        elif label.startswith("verify_range_"):
            claimed = int(label.rsplit("_", 1)[1])
            kind = witness_kind(record, f"range_{claimed}")
            if kind is not None:
                ranges.append({"claimed_entries": claimed, **kind})
    structure = record.units("storage", "structure_bytes")
    live = record.majority_units("cold_build", "heap.live_bytes")
    peak = record.majority_units("cold_build", "heap.peak_bytes")
    return {
        "construction": tags["construction"],
        "profile": tags["profile"],
        "population_log2": tags["population_log2"],
        "key_shape": tags["key_shape"],
        "value_bytes": tags["value_bytes"],
        "entries_total": entries,
        "cold_build": {
            "ns_per_entry": timing(builds, entries),
            "replicated": len(builds) >= MIN_REPETITIONS,
            **hash_work(record, "cold_build"),
        },
        "updates": updates,
        "storage_model": {
            "class": "accounting_model",
            "entries": record.units("storage", "entries"),
            "structure_bytes": structure,
            "structure_bytes_per_entry": ratio(structure, record.units("storage", "entries"), 2),
            "structure_digests": record.units("storage", "structure_digests"),
            "auxiliary_bytes": record.units("storage", "auxiliary_bytes"),
            "max_depth": record.units("storage", "max_depth"),
        },
        "memory": {
            "heap_live_bytes": None if live is None else live["value"],
            "heap_live_bytes_per_entry": None if live is None else ratio(live["value"], entries),
            "heap_peak_build_bytes": None if peak is None else peak["value"],
            "heap_readings": (
                None
                if live is None
                else {
                    "repetitions": live["repetitions"],
                    "agreeing": live["agreeing"],
                    "live_min": live["min"],
                    "live_max": live["max"],
                }
            ),
        },
        "witness": {
            "inclusion": witness_kind(record, "inclusion"),
            "absence": witness_kind(record, "absence"),
            "cell_inclusion": witness_kind(record, "cell_inclusion"),
            "range": ranges,
        },
        "record": record.provenance(),
    }


COMMITTED_PROOF = {
    "prove_time_ns": None,
    "verify_time_ns": None,
    "proof_bytes": None,
    "prover_memory_bytes": None,
    "null_reason": "task B.2: see in_circuit.committed_proof_null_reason",
}


def spread(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    """Count, total, minimum, mean and maximum of a counter reported per statement."""
    if entry is None or not entry["count"]:
        return None
    return {
        "count": entry["count"],
        "total": entry["total_units"],
        "min": entry["min_units"],
        "mean": round(entry["total_units"] / entry["count"], 1),
        "max": entry["max_units"],
    }


def circuit_rows(record: Record) -> list[dict[str, Any]]:
    tags = workload_tags(record.workload)
    rows = []
    for label in record.labels():
        if not label.endswith(".geometry"):
            continue
        kind = label[: -len(".geometry")]
        sample = f"{kind}.statements"
        exceeds = bool(record.units(label, "exceeds_reference_rows"))
        witness = record.size(sample, "native_witness")
        statements = None
        if record.phase(sample) is not None:
            registers = record.counter(sample, "registers")
            trace_rows = record.counter(sample, "rows")
            statements = {
                "permutations": spread(record.counter(sample, "permutations")),
                "native_verifier_permutations": spread(record.counter(sample, "native_permutations")),
                "anchors": spread(record.counter(sample, "anchors")),
                "private_siblings": spread(record.counter(sample, "private_siblings")),
                "registers_min": None if registers is None else registers["min_units"],
                "registers_max": None if registers is None else registers["max_units"],
                "rows_min": None if trace_rows is None else trace_rows["min_units"],
                "rows_max": None if trace_rows is None else trace_rows["max_units"],
                "native_witness_bytes_mean": None if witness is None else ratio(witness["total_bytes"], witness["count"]),
                "native_witness_bytes_max": None if witness is None else witness["max_bytes"],
            }
        geometry = {
            "permutations": record.units(label, "permutations"),
            "registers": record.units(label, "registers"),
            "rows_per_permutation": record.units(label, "rows_per_permutation"),
            "rows": record.units(label, "rows"),
            "width": record.units(label, "width"),
            "constraints": record.units(label, "constraints"),
            "private_siblings": record.units(label, "private_siblings"),
            "numerator_degree_bound": record.units(label, "numerator_degree_bound"),
            "trace_cells": record.units(label, "trace_cells"),
            "interpolation_rows": record.units(label, "interpolation_rows"),
        }
        reference = None
        if not exceeds:
            build, check = f"{kind}.reference_build", f"{kind}.reference_check"
            artifact = record.same_size(build, "uncommitted_reference_artifact")
            repetitions = len(record.walls(build))
            heap = record.repetition_units(build, "heap.peak_bytes")
            check_heap = record.repetition_units(check, "heap.peak_bytes")
            reference = {
                "label": "uncommitted reference of task B.1; not a committed proof",
                "replicated": repetitions >= MIN_REFERENCE_REPETITIONS,
                "witness_columns_wall_ns": timing(record.walls(f"{kind}.witness_columns"), 1, 0),
                "build_wall_ns": timing(record.walls(build), 1, 0),
                "build_process_cpu_ns_median": round(statistics.median(record.process_cpus(build))),
                "check_wall_ns": timing(record.walls(check), 1, 0),
                "check_process_cpu_ns_median": round(statistics.median(record.process_cpus(check))),
                "build_peak_heap_bytes": max(heap, default=None),
                "check_peak_heap_bytes": max(check_heap, default=None),
                "declared_payload_bytes": record.units(label, "reference_declared_payload_bytes"),
                "declared_work_units": record.units(label, "reference_declared_work_units"),
                "uncommitted_artifact_bytes": None if artifact is None else artifact["max_bytes"],
            }
        rows.append(
            {
                "construction": tags["construction"],
                "profile": tags["profile"],
                "population_log2": tags["population_log2"],
                "key_shape": tags["key_shape"],
                "value_bytes": tags["value_bytes"],
                "statement": kind,
                "statements": statements,
                "gadget_instances": {
                    "class": "as_built_source_constant",
                    "bit_scans": record.units(sample, "gadget_bit_scans"),
                    "comparisons": record.units(sample, "gadget_comparisons"),
                },
                "geometry": geometry,
                "exceeds_reference_limit": exceeds,
                "reference": reference,
                "reference_null_reason": (
                    "The trace needs more rows than the reference's supported order (65,536); the shape is recorded and not built."
                    if exceeds
                    else None
                ),
                "committed_proof": dict(COMMITTED_PROOF),
                "record": record.provenance(),
            }
        )
    forged = record.units("forged_traces_rejected", "forged_traces_rejected")
    for row in rows:
        row["record"]["forged_traces_rejected"] = forged
    return rows


GADGET_KINDS = {"order": "KeyOrderAir", "bits": "KeyBitAir"}


def gadget_rows(record: Record) -> list[dict[str, Any]]:
    rows = []
    for label in record.labels():
        if not label.endswith(".geometry"):
            continue
        kind = label[: -len(".geometry")]
        gadget, key = kind.split("_k")
        rows.append(
            {
                "gadget": gadget,
                "relation": GADGET_KINDS[gadget],
                "key_bytes": int(key),
                "rows": record.units(label, "rows"),
                "width": record.units(label, "width"),
                "private_columns": record.units(label, "private_columns"),
                "constraints": record.units(label, "constraints"),
                "numerator_degree_bound": record.units(label, "numerator_degree_bound"),
                "trace_cells": record.units(label, "trace_cells"),
                "reference": {
                    "label": "uncommitted reference of task B.1; not a committed proof",
                    "witness_columns_wall_ns": timing(record.walls(f"{kind}.witness_columns"), 1, 0),
                    "build_wall_ns": timing(record.walls(f"{kind}.reference_build"), 1, 0),
                    "check_wall_ns": timing(record.walls(f"{kind}.reference_check"), 1, 0),
                },
            }
        )
    return rows


def latency_rows(record: Record) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = []
    for base in record.labels():
        calls = record.same_units(base, "calls")
        if calls is None:
            continue
        profile, operation = base.rsplit(".", 1)
        rows.append(
            {
                "profile": profile,
                "operation": operation,
                "calls": calls,
                "ns_per_call": timing(record.walls(base), calls),
            }
        )
    gadget = {
        "class": "as_built_source_constant",
        "source": f"{BLAKE2B_GADGET} (ROW_COUNT, COLUMN_COUNT), {SMT_GADGET} (PHYSICAL_HASH_ROWS)",
        "rows": record.units("as_built_blake2b_gadget", "rows"),
        "columns": record.units("as_built_blake2b_gadget", "columns"),
        "physical_rows_per_hash_slot": record.units(
            "as_built_blake2b_gadget", "physical_rows_per_hash_slot"
        ),
        "note": "Geometry of one BLAKE2b compression in the sealed q77 relation; the comparator for a byte-hash tree in-circuit. Read from the source constants; not measured by this task.",
    }
    return rows, gadget


def shared_path_rows(record: Record) -> list[dict[str, Any]]:
    """What linked-leaf range witnesses would carry with shared address paths.

    The counts are phases of the linked-leaf map's native record; a record
    without them yields no row.
    """
    tags = workload_tags(record.workload)
    rows = []
    for label in record.labels():
        if not label.startswith("shared_paths_range_"):
            continue
        leaves = record.counter(label, "leaves")
        steps = record.counter(label, "carried_steps")
        branches = record.counter(label, "distinct_branches")
        siblings = record.counter(label, "carried_siblings")
        witness = record.size(label, "witness")
        if not leaves or not leaves["count"] or witness is None:
            continue
        count = leaves["count"]
        means = {
            name: round(entry["total_units"] / count, 1)
            for name, entry in (("leaves", leaves), ("steps", steps), ("branches", branches), ("siblings", siblings))
        }
        bytes_mean = witness["total_bytes"] / count
        # A carried step is a 4-byte index and a 32-byte sibling. The shared
        # form carries each sibling outside the union once and, per branch of
        # the union, its index and one token byte.
        shared_bytes = bytes_mean - 36 * means["steps"] + 32 * means["siblings"] + 5 * means["branches"]
        rows.append(
            {
                "profile": tags["profile"],
                "population_log2": tags["population_log2"],
                "key_shape": tags["key_shape"],
                "value_bytes": tags["value_bytes"],
                "claimed_entries": int(label.rsplit("_", 1)[1]),
                "statements": count,
                "leaves_mean": means["leaves"],
                "prototype_path_steps_mean": means["steps"],
                "prototype_witness_bytes_mean": round(bytes_mean, 1),
                "shared_branches_mean": means["branches"],
                "shared_carried_siblings_mean": means["siblings"],
                "shared_witness_bytes_mean": round(shared_bytes, 1),
            }
        )
    return rows


def load_run(run_dir: Path) -> dict[str, Any]:
    report = json.loads((run_dir / "report.json").read_text())
    manifest_path = run_dir / "manifest.json"
    records = []
    for entry in report["records"]:
        path = entry["json"]["path"]
        document = json.loads((run_dir / path).read_text())
        if not document["identity"]["workload"].startswith(WORKLOAD_PREFIX):
            continue
        records.append(Record(document, run_dir.name, path))
    arguments = report["command"].get("arguments") or []
    test = next(
        (arguments[index + 1] for index, word in enumerate(arguments) if word == "--exact"),
        None,
    )
    loads = [
        record.document["process"][key]
        for record in records
        for key in ("load_milli_begin", "load_milli_finish")
    ]
    return {
        "report": report,
        "records": records,
        "summary": {
            "class": "identity",
            "run": run_dir.name,
            "raw_records": f"{RAW_ROOT}/{run_dir.name}/child/",
            "test": test,
            "verdict": report["verdict"],
            "reasons": report["reasons"],
            "manifest_sha256": sha256_file(manifest_path),
            "executable_sha256": report["command"]["executable_sha256"],
            "source_commit": report["context"]["source_commit"],
            "source_dirty": report["context"]["source_dirty"],
            "source_dirty_digest": report["context"]["source_dirty_digest"],
            "config": report["context"].get("config"),
            "records": len(records),
            "process_wall_ns": report["process"]["wall_ns"],
            "process_cpu_user_ns": report["process"]["cpu_user_ns"],
            "process_peak_rss_bytes": report["process"]["peak_rss_bytes"],
            "load_milli_min": min(loads) if loads else None,
            "load_milli_max": max(loads) if loads else None,
            "unattributed_ppm_max": max(
                (record.provenance()["unattributed_ppm"] for record in records), default=None
            ),
            "workers": sorted({record.document["scheduling"]["workers"] for record in records}),
            "thermal_states": sorted(
                {
                    record.document["process"][key]
                    for record in records
                    for key in ("thermal_begin", "thermal_finish")
                }
            ),
        },
    }


SCHEMA_COUNTERS = ("tables", "cells", "descriptor_bytes", "descriptor_sha256_prefix")


def recorded_schema(records: list[Record]) -> dict[str, Any] | None:
    """The schema identity every record of every run names, or None without records.

    Each flow records the keyed tables, the cells, the descriptor length and
    the first eight bytes of the descriptor's SHA-256 of the schema its
    process read. Runs that read different schemas are not one comparison.
    """
    seen = {}
    for first in records:
        for record in first.pooled():
            identity = tuple(record.units("schema", f"schema.{name}") for name in SCHEMA_COUNTERS)
            if None in identity:
                raise ValueError(f"{record.workload}: run {record.run} does not name the schema it read")
            seen.setdefault(identity, record.run)
    if not seen:
        return None
    if len(seen) != 1:
        raise ValueError(f"the runs read different schemas: {sorted(seen.values())}")
    tables, cells, length, prefix = next(iter(seen))
    return {
        "class": "measured_deterministic_count",
        "tables": tables,
        "cells": cells,
        "descriptor_bytes": length,
        "descriptor_sha256_prefix": f"{prefix:016x}",
    }


def pool_records(runs: list[dict[str, Any]]) -> list[Record]:
    """One record per workload, in first-appearance order.

    The record of a workload that a later run measured again is pooled into
    the first one. A run records a workload once.
    """
    pooled: dict[str, Record] = {}
    for run in runs:
        seen = set()
        for record in run["records"]:
            if record.workload in seen:
                raise ValueError(f"{record.workload}: recorded twice by run {record.run}")
            seen.add(record.workload)
            first = pooled.get(record.workload)
            if first is None:
                pooled[record.workload] = record
            else:
                first.pool(record)
    return list(pooled.values())


def run_to_run(runs: list[dict[str, Any]], records: list[Record]) -> list[dict[str, Any]]:
    """How far the median of every timed phase moved between two runs of one test."""
    tests = {run["summary"]["run"]: run["summary"]["test"] for run in runs}
    ratios: dict[tuple[str, str], list[float]] = {}
    workloads: dict[tuple[str, str], int] = {}
    for record in records:
        for further, values in record.median_ratios().items():
            pair = (record.run, further)
            ratios.setdefault(pair, []).extend(values)
            workloads[pair] = workloads.get(pair, 0) + 1
    out = []
    for (first, further), values in ratios.items():
        values.sort()
        out.append(
            {
                "class": "derived_from_measured",
                "test": tests.get(first),
                "first_run": first,
                "further_run": further,
                "workloads": workloads[(first, further)],
                "timed_phases": len(values),
                "median_wall_ratio": {
                    "min": round(values[0], 3),
                    "median": round(statistics.median(values), 3),
                    "max": round(values[-1], 3),
                },
                "phases_within_ten_percent": sum(1 for value in values if 0.9 <= value <= 1.1),
            }
        )
    return out


def inventory_schema(repository: Path) -> dict[str, Any]:
    """Counts and descriptor digest of the schema the inventory declares."""
    inventory = json.loads((repository / INVENTORY).read_text())
    rows = []
    for field in inventory["fields"]:
        if field["role"] != "canonical":
            continue
        key = field["key"] if field["shape"] == "table" else ""
        rows.append((field["id"], key, field["value"]))
    rows.sort(key=lambda row: row[0].encode())
    descriptor = bytearray(b"iroha:state-keyed-commitment:schema:v1\0")
    descriptor += len(rows).to_bytes(4, "little")
    for identity, key, value in rows:
        descriptor.append(1 if key == "" else 0)
        for text in (identity, key, value):
            encoded = text.encode()
            descriptor += len(encoded).to_bytes(4, "little") + encoded
    return {
        "class": "identity",
        "source": str(INVENTORY),
        "tables": sum(1 for _, key, _ in rows if key != ""),
        "cells": sum(1 for _, key, _ in rows if key == ""),
        "descriptor_bytes": len(descriptor),
        "descriptor_sha256": hashlib.sha256(bytes(descriptor)).hexdigest(),
        "checked_against_registry_by": "measured_schema_is_the_registry_schema_of_the_actual_state",
    }


def find_native(native: list[dict[str, Any]], **tags: Any) -> dict[str, Any] | None:
    for row in native:
        if all(row.get(key) == value for key, value in tags.items()):
            return row
    return None


def find_latency(latency: list[dict[str, Any]], profile: str, operation: str) -> float | None:
    for row in latency:
        if row["profile"] == profile and row["operation"] == operation:
            return row["ns_per_call"]["median"]
    return None


CONSTRUCTION_ORDER = [entry["id"] for entry in CONSTRUCTIONS]


def comparability(native: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Which pairs of constructions a timing separates in each measured group.

    Two constructions are separated for a measure when the intervals of their
    repetitions do not overlap, and overlapping otherwise. A timing that was
    not replicated separates nothing.
    """

    def measures(row: dict[str, Any]) -> dict[str, dict[str, Any] | None]:
        build = row["cold_build"]
        found: dict[str, dict[str, Any] | None] = {
            "cold_build.ns_per_entry": build["ns_per_entry"] if build["replicated"] else None
        }
        for update in row["updates"]:
            found[f"updates[{update['changes_per_set']}].wall_ns_per_change"] = update["wall_ns_per_change"]
        for kind in ("inclusion", "absence"):
            if row["witness"][kind]:
                found[f"witness.{kind}.verify_ns_per_statement"] = row["witness"][kind]["verify_ns_per_statement"]
        for entry in row["witness"]["range"]:
            found[f"witness.range[{entry['claimed_entries']}].verify_ns_per_statement"] = entry["verify_ns_per_statement"]
        return found

    groups: dict[tuple[Any, ...], dict[str, dict[str, dict[str, Any] | None]]] = {}
    for row in native:
        key = (row["profile"], row["population_log2"], row["key_shape"], row["value_bytes"])
        groups.setdefault(key, {})[row["construction"]] = measures(row)
    out = []
    for (profile, population, key_shape, value_bytes), by_construction in groups.items():
        names = [name for name in CONSTRUCTION_ORDER if name in by_construction]
        labels: list[str] = []
        for name in names:
            for label in by_construction[name]:
                if label not in labels:
                    labels.append(label)
        for label in labels:
            timed = {name: by_construction[name].get(label) for name in names if label in by_construction[name]}
            separated, overlapping = [], []
            usable = [name for name in timed if timed[name] is not None]
            for position, left in enumerate(usable):
                for right in usable[position + 1 :]:
                    a, b = timed[left], timed[right]
                    if a["max"] < b["min"]:
                        separated.append(f"{left}<{right}")
                    elif b["max"] < a["min"]:
                        separated.append(f"{right}<{left}")
                    else:
                        overlapping.append(f"{left}~{right}")
            out.append(
                {
                    "profile": profile,
                    "population_log2": population,
                    "key_shape": key_shape,
                    "value_bytes": value_bytes,
                    "measure": label,
                    "separated": separated,
                    "overlapping": overlapping,
                    "not_replicated": [name for name in timed if timed[name] is None],
                }
            )
    return out


COMPARABILITY_RULE = (
    "For each measured group and timing, two constructions are separated (a<b: a is faster) when the [min, max] "
    "intervals of their repetitions do not overlap, and overlapping (a~b) otherwise. A timing that was not replicated "
    "separates nothing. Where a test was run more than once (run_to_run), a row pools the repetitions of every run, so "
    "its interval spans the runs and their different load. Where a test was run once, its repetitions ran back to back "
    "inside one process; a difference that is separated there can still be within what another run would show."
)
RUN_TO_RUN_NOTE = (
    "A measurement test that was run more than once, by the same executable at another time: for every timed phase "
    "of every workload, the further run's median wall time over the first run's. Every count that is not a time was "
    "required to be identical in both runs before the rows were written. The rows of such a test pool the repetitions "
    "of both runs (record.replicates names the further run and its load)."
)

MEMO = "Plan-author design memo for G.2 (2026-10-04), Part A; every figure in it was a projection to be replaced by measurement."

PROJECTION_STATUSES = ("confirmed", "contradicted", "not_comparable", "unmeasured", "revised_by_model")

# Projections whose status is not a comparison of two recorded numbers.
FIXED_STATUS = {
    "native-rpo-permutation": "not_comparable",
    "air-rpo-permutation": "not_comparable",
    "storage-tree-hashes-per-row": "revised_by_model",
    "air-blake2b-as-built": "unmeasured",
    "air-in-repo-digest384": "unmeasured",
    "monolith-64": "unmeasured",
    "tip5": "unmeasured",
    "anemoi": "unmeasured",
    "x86-64-latencies": "unmeasured",
    "population-2-24": "unmeasured",
}


def projection_status(entry: dict[str, Any]) -> str:
    """The status a projection has, from its own recorded values alone."""
    identifier = entry["id"]
    if identifier in FIXED_STATUS:
        return FIXED_STATUS[identifier]
    measured = (entry.get("measured") or {}).get("value")
    if measured is None:
        return "unmeasured"
    projected = entry["projection"]["value"]
    comparison = entry["projection"].get("comparison")
    if comparison == "interval":
        return "confirmed" if projected[0] <= measured <= projected[1] else "contradicted"
    if comparison == "at_most":
        return "confirmed" if measured <= projected else "contradicted"
    if comparison == "within_half":
        return "confirmed" if 0.5 * projected <= measured <= 1.5 * projected else "contradicted"
    if comparison == "geometry":
        low, high = projected["columns"]
        same = measured["rows"] == projected["rows"] and low <= measured["columns_total"] <= high
        return "confirmed" if same else "contradicted"
    raise ValueError(f"projection `{identifier}` has no comparison rule")


def projection(
    identifier: str,
    quantity: str,
    projected: Any,
    unit: str | None,
    comparison: str | None,
    measured_value: Any = None,
    revision: str | None = None,
    measured_note: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    entry = {
        "id": identifier,
        "quantity": quantity,
        "projection": {
            "class": "projection",
            "value": projected,
            "unit": unit,
            "comparison": comparison,
            "source": MEMO,
        },
        "measured": (
            None
            if measured_value is None
            else {"class": "derived_from_measured", "value": measured_value, "unit": unit, "note": measured_note}
        ),
        **extra,
    }
    entry["status"] = projection_status(entry)
    entry["revision"] = revision if entry["status"] in ("contradicted", "not_comparable", "revised_by_model") else None
    return entry


def build_projections(
    native: list[dict[str, Any]],
    circuit: list[dict[str, Any]],
    latency: list[dict[str, Any]],
    gadget: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    out = []
    base = {"population_log2": 20, "key_shape": "scattered-32", "value_bytes": 32}

    blake3 = find_latency(latency, "blake3", "hash_bytes_36")
    out.append(
        projection(
            "native-blake3-short-message",
            "BLAKE3-256 of a short message, Apple M-series, one warm core",
            [40, 150],
            "ns",
            "interval",
            blake3,
            f"Measured median {blake3} ns for a 36-byte key under the prototype framing (17 bytes of mode, domain and length) on the loaded host.",
            "hash_bytes of 36 bytes: 53 bytes hashed; median of the repetitions",
        )
    )
    blake2b = find_latency(latency, "blake2b", "hash_bytes_36")
    out.append(
        projection(
            "native-blake2b-short-message",
            "BLAKE2b-256 of a short message, Apple M-series, one warm core",
            [70, 250],
            "ns",
            "interval",
            blake2b,
            f"Measured median {blake2b} ns on the loaded host.",
            "hash_bytes of 36 bytes: 53 bytes hashed; median of the repetitions",
        )
    )
    poseidon2 = find_latency(latency, "poseidon2", "permutation")
    out.append(
        projection(
            "native-poseidon2-permutation",
            "Poseidon2 width-12 permutation, Apple M-series, optimized code",
            [200, 1000],
            "ns",
            "interval",
            poseidon2,
            (
                f"The prototype permutation takes a median of {poseidon2} ns on the proof crate's reference field arithmetic "
                "(128-bit reduction, no vector code) under the recorded load. The projection assumed optimized code; "
                "for G.3 the measured prototype figure replaces it, and an optimized implementation stays a projection "
                "until one exists in the tree."
            ),
            "median of the repetitions",
        )
    )
    rescue = find_latency(latency, "rescue-prime", "permutation")
    out.append(
        projection(
            "native-rpo-permutation",
            "Rescue-Prime Optimized width-12 permutation, Apple M-series, optimized code",
            [1000, 5000],
            "ns",
            None,
            None,
            (
                "RPO itself is not implemented, so the projection stands unmeasured and nothing is compared with it. "
                f"For reference only: the Rescue-Prime Rp64_256 prototype, which has the same S-boxes, width and round "
                f"count, takes a median of {rescue} ns on the reference field arithmetic under the recorded load. Nothing about "
                "RPO's native performance is inferred from it."
            ),
        )
    )

    def geometry(profile: str) -> dict[str, Any] | None:
        for row in circuit:
            if row["profile"] == profile and row["statement"] == "inclusion":
                return row["geometry"]
        return None

    poseidon2_geometry = geometry("poseidon2")
    out.append(
        projection(
            "air-poseidon2-permutation",
            "Poseidon2 permutation in the AIR: rows and columns",
            {"rows": 30, "columns": [24, 60], "degree": "7, or quadratic with auxiliary columns"},
            "rows, columns",
            "geometry",
            None
            if poseidon2_geometry is None
            else {
                "rows": poseidon2_geometry["rows_per_permutation"],
                "columns_total": poseidon2_geometry["width"],
                "private_columns": 13 + 4 * poseidon2_geometry["registers"],
                "registers": poseidon2_geometry["registers"],
                "degree_bound_factor": 8,
            },
            (
                "The relation uses 32 rows per permutation, not 30: one row for the initial linear layer and one link row "
                "that ties the output to the next permutation. It needs no auxiliary S-box columns: with one register, 12 "
                "state columns, one side bit and four register columns are private (17), the other columns are verifier-known "
                "selectors, round constants and statement words; each further register adds four private and two "
                "verifier-known columns. Numerators have degree at most 8 (a selector times x^7)."
            ),
            "one round per row; width counts verifier-known columns; an inclusion statement, which needs one register",
        )
    )
    rescue_geometry = geometry("rescue-prime")
    out.append(
        projection(
            "air-rpo-permutation",
            "RPO permutation in the AIR: rows and columns",
            {"rows": 14, "columns": [24, 60], "degree": "7 with inverse-check equations"},
            "rows, columns",
            None,
            None,
            (
                "RPO was not implemented or measured, so this stays an unmeasured geometry projection. A replacement "
                "projection follows from the measured Rescue-Prime Rp64_256 relation, whose trace geometry RPO shares "
                "(same width, S-boxes and round count): a whole round fits one row, because the inverse S-box of the second "
                "half is checked forwards as (MDS^-1(next - ARK2))^7 = MDS(current^7) + ARK1, with 12 state columns and no "
                "auxiliary columns."
            ),
            replacement_projection=(
                None
                if rescue_geometry is None
                else {
                    "class": "projection",
                    "rows": rescue_geometry["rows_per_permutation"],
                    "columns_total": rescue_geometry["width"],
                    "private_columns": 13 + 4 * rescue_geometry["registers"],
                    "source": "geometry of the measured Rescue-Prime Rp64_256 relation; not a measurement of RPO",
                }
            ),
        )
    )

    radix = find_native(native, construction="radix", profile="blake2b", **base)
    radix_bytes = None if radix is None else radix["witness"]["inclusion"]["bytes_mean"]
    out.append(
        projection(
            "witness-binary-path-20-siblings",
            "Authentication data of a binary path at 2^20 entries (20 siblings of 32 bytes)",
            640,
            "bytes",
            "at_most",
            radix_bytes,
            (
                f"The radix inclusion witness is {radix_bytes} bytes on average at 2^20 populated entries: each branch carries a "
                "4-byte branching index beside its 32-byte sibling, the count takes 4 bytes, and the tree spans every table "
                "of the schema, so paths are slightly longer than log2 of one table."
            ),
            "radix tree over BLAKE2b, mean of the measured inclusion witnesses",
        )
    )
    btree = find_native(native, construction="btree", profile="blake2b", **base)
    btree_bytes = None if btree is None else btree["witness"]["inclusion"]["bytes_mean"]
    out.append(
        projection(
            "witness-btree-16-way",
            "A 16-way B-tree proof: 15 sibling digests on each of five levels",
            2400,
            "bytes",
            "within_half",
            btree_bytes,
            (
                f"The prototype B-tree hashes each page as a binary Merkle subtree, so a path carries about four siblings per "
                f"level instead of fifteen: {btree_bytes} bytes on average at 2^20 populated entries. The 2,400-byte figure "
                "describes a page hashed flat, which the prototype does not use."
            ),
            "B-tree over BLAKE2b, mean of the measured inclusion witnesses",
        )
    )
    linked = find_native(native, construction="linked", profile="blake2b", **base)
    linked_depth = None
    if linked is not None:
        # nkd (32) + count (4) + 36 bytes per branch.
        linked_depth = round((linked["witness"]["inclusion"]["bytes_mean"] - 36) / 36, 1)
    out.append(
        projection(
            "linked-leaf-expected-depth",
            "Hashed-address sparse tree: expected path length about log2(n) at 2^20 entries",
            [18, 24],
            "branches",
            "interval",
            linked_depth,
            f"Measured mean path length {linked_depth} branches.",
            "mean branches on a linked-leaf inclusion path, from the witness size",
        )
    )
    model = None if radix is None else radix["storage_model"]["structure_bytes"]
    heap = None if radix is None else radix["memory"]["heap_live_bytes"]
    out.append(
        projection(
            "storage-tree-hashes-per-row",
            "Two 32-byte tree hashes per row at 2^20 rows",
            64 * 1024 * 1024,
            "bytes",
            None,
            None,
            (
                "No persisted size was measured, so the projection is not confirmed or contradicted by a measurement. It is "
                f"revised by the accounting model: the radix tree's model keeps {model} bytes for the measured State, a leaf "
                "digest and a value digest per entry (64 bytes) and, per branch, a digest, a branching index and two child "
                "references (44 bytes), about 108 bytes per entry, where the projection counted two digests per row and no "
                f"node metadata. For reference, the prototype's in-memory containers held {heap} heap bytes for that State, "
                "key copies included."
            ),
            model=(
                None
                if model is None
                else {"class": "accounting_model", "value": model, "unit": "bytes", "note": "radix tree, storage_model.structure_bytes"}
            ),
        )
    )
    out.append(
        projection(
            "air-blake2b-as-built",
            "As-built BLAKE2b gadget of the sealed relation: 408 rows, 310 columns, 512 physical rows per hash slot",
            {"rows": 408, "columns": 310, "physical_rows_per_hash_slot": 512},
            "rows, columns",
            None,
            None,
            None,
            source_constant=(
                None
                if gadget is None
                else {
                    "class": "as_built_source_constant",
                    "rows": gadget["rows"],
                    "columns": gadget["columns"],
                    "physical_rows_per_hash_slot": gadget["physical_rows_per_hash_slot"],
                    "note": "The memo quoted these constants; the checker reads them from the gadget's source. Nothing was measured.",
                }
            ),
        )
    )
    digest = find_native(native, construction="radix", profile="digest384", population_log2=10)
    comparator = None
    if digest is not None and digest["cold_build"]["compressions"]:
        build = digest["cold_build"]
        hashes = build["compressions"] + build["byte_hashes"]
        comparator = round(build["permutations"] / hashes, 1)
    entry = projection(
        "air-in-repo-digest384",
        "In-repo six-lane width-3 Poseidon digest as a tree hash in-circuit",
        None
        if comparator is None
        else {
            "width3_permutations_per_hash": comparator,
            "rounds_per_permutation": 65,
            "rows_per_hash_at_one_round_per_row": round(comparator * 65),
        },
        "permutations, rows",
        None,
    )
    entry["projection"]["source"] = (
        "Derived here from the measured number of width-3 permutations per prototype hash and the digest's 65 rounds; "
        "no relation for it was written. A projection."
    )
    out.append(entry)
    for name, note in (
        ("monolith-64", "Monolith-64 (Grassi et al., 2023): not prototyped."),
        ("tip5", "Tip5 (Szepieniec et al., 2023): not prototyped; its 40-byte digest needs a root mapping."),
        ("anemoi", "Anemoi (Bouvier et al., 2023): not prototyped; no certified Goldilocks instantiation."),
        ("x86-64-latencies", "Every x86-64 latency of the memo: no x86-64 host was measured."),
        ("population-2-24", "2^24 entries in one table: not run. From the measured 2^16 to 2^20 scaling a tree path grows by about one branch per doubling; the chain grows linearly."),
    ):
        out.append(projection(name, note, None, None, None))
    return out


def cached_page_rows(native: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The B-tree's single-change cost and model size if page nodes were kept."""
    rows = []
    for row in native:
        inclusion = row["witness"]["inclusion"]
        single = next((entry for entry in row["updates"] if entry["changes_per_set"] == 1), None)
        if row["construction"] != "btree" or inclusion is None or single is None:
            continue
        model = row["storage_model"]
        entries = model["entries"]
        upper = model["structure_digests"] - 2 * entries
        internal = entries - 1 - upper
        rows.append(
            {
                "profile": row["profile"],
                "population_log2": row["population_log2"],
                "key_shape": row["key_shape"],
                "value_bytes": row["value_bytes"],
                "prototype_compressions_per_single_change": single["compressions_per_change"],
                # The leaf and one node per level of its path: the inclusion
                # verifier's compressions without the root normalisation.
                "cached_compressions_per_value_rewrite": round(inclusion["verify_compressions_per_statement"] - 1, 1),
                "page_internal_nodes": internal,
                "prototype_model_bytes_per_entry": model["structure_bytes_per_entry"],
                "cached_model_bytes_per_entry": round((model["structure_bytes"] + 32 * internal) / entries, 2),
            }
        )
    return rows


def conformance_tests() -> list[dict[str, Any]]:
    types = {entry["id"]: entry["type"] for entry in CONSTRUCTIONS}
    profiles = {entry["id"]: entry["rust_type"] for entry in HASH_PROFILES}
    tests = []
    for construction, stem in CONFORMANCE_NAMES.items():
        for profile, word in CONFORMANCE_PROFILES.items():
            tests.append(
                {
                    "construction": construction,
                    "profile": profile,
                    "engine_type": types[construction],
                    "profile_type": profiles[profile],
                    "test": f"{stem}_over_{word}_satisfies_the_keyed_state_contract",
                }
            )
    return tests


def gadget_cells(gadgets: list[dict[str, Any]], gadget: str, key_bytes: int) -> int | None:
    for row in gadgets:
        if row["gadget"] == gadget and row["key_bytes"] == key_bytes:
            return row["trace_cells"]
    return None


def composite_key_bytes(key_shape: str) -> int:
    """Four bytes of table position and the key bytes of the shape."""
    return 4 + (128 if key_shape == "long-128" else 32)


def private_key_projection(row: dict[str, Any], gadgets: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Hash-chain cells plus the cells of the row's gadget instances; a projection."""
    key_bytes = composite_key_bytes(row["key_shape"])
    bits, order = gadget_cells(gadgets, "bits", key_bytes), gadget_cells(gadgets, "order", key_bytes)
    geometry, instances = row["geometry"], row["gadget_instances"]
    if bits is None or order is None or instances["bit_scans"] is None:
        return None
    chain = geometry["rows"] * geometry["width"]
    gadget = instances["bit_scans"] * bits + instances["comparisons"] * order
    return {
        "class": "projection",
        "key_bytes": key_bytes,
        "hash_chain_trace_cells": chain,
        "gadget_trace_cells": gadget,
        "sum_trace_cells": chain + gadget,
    }


STATIC_SECTIONS = {
    "schema": SCHEMA,
    "plan": {
        "document": "specs/zk_delivery_plan.md",
        "task": "G.2",
        "consumed_by": ["G.3"],
        "requires": ["G.1", "B.1", "E.1"],
    },
    "purpose": (
        "Native measurements of four authenticated-map constructions under five hash profiles and in-circuit "
        "measurements of the three tree candidates under two sponge profiles, against the keyed State contract of "
        "specs/sumeragi.md section 16. Input of the G.3 selection."
    ),
    "selection": None,
    "selection_note": "No construction or hash is selected here. G.3 selects, freezes the semantic profile and repeats the final measurements on it.",
    "checked_by": "scripts/check_state_commitment_candidates.py",
    "regenerate": "python3 scripts/check_state_commitment_candidates.py --refresh dist/zk-resource-harness/<run>...",
    "contract": {
        "specification": "specs/sumeragi.md section 16 (rules K1..K12)",
        "interface": str(INTERFACE),
        "conformance_suite": "crates/iroha_core/src/state/authority_registry/keyed_commitment/conformance.rs",
    },
    "source": {
        "development_only": True,
        "prototypes": str(PROTOTYPE_ROOT),
        "prototype_gate": '#[cfg(any(test, feature = "dev-tools"))] in crates/fastpq_prover/src/lib.rs',
        "adapters": str(ADAPTERS),
        "adapter_gate": '#[cfg(all(test, feature = "state-commitment-prototypes"))] in ' + str(INTERFACE),
        "measurement": str(MEASUREMENT),
        "measurement_gate": 'integration test target, required-features = ["fastpq-replay-measurement"]',
        "replacement": "TODO(G.3): the prototypes, their adapters and this measurement target are deleted when the selected construction is implemented by its State owner; none survives as a second implementation.",
    },
    "constructions": CONSTRUCTIONS,
    "hash_profiles": HASH_PROFILES,
    "conformance": {
        "command": "cargo test -p iroha_core --lib --features state-commitment-prototypes keyed_commitment::candidates_tests",
        "tests": conformance_tests(),
        "schema_binding_test": "measured_schema_is_the_registry_schema_of_the_actual_state",
    },
    "units": UNITS,
    "storage_model": STORAGE_MODEL,
    "decision_criteria": DECISION_CRITERIA,
    "limits": LIMITS,
}


def build_summary(run_dirs: Iterable[Path], repository: Path) -> dict[str, Any]:
    runs = [load_run(run_dir) for run_dir in run_dirs]
    native: list[dict[str, Any]] = []
    circuit: list[dict[str, Any]] = []
    latency: list[dict[str, Any]] = []
    gadgets: list[dict[str, Any]] = []
    shared: list[dict[str, Any]] = []
    latency_record = None
    gadget_record = None
    gadget = None
    false_statements = None
    records = pool_records(runs)
    for record in records:
        flow = record.workload[len(WORKLOAD_PREFIX) :].split(".", 1)[0]
        if flow == "native":
            native.append(native_row(record))
            shared.extend(shared_path_rows(record))
        elif flow == "circuit":
            circuit.extend(circuit_rows(record))
        elif flow == "latency":
            latency, gadget = latency_rows(record)
            latency_record = record.provenance()
        elif flow == "gadget":
            gadgets = gadget_rows(record)
            gadget_record = record.provenance()
            false_statements = record.units("false_statements_rejected", "false_statements_rejected")
    order = {entry["id"]: index for index, entry in enumerate(CONSTRUCTIONS)}
    profiles = {entry["id"]: index for index, entry in enumerate(HASH_PROFILES)}
    native.sort(
        key=lambda row: (
            profiles[row["profile"]],
            row["population_log2"],
            row["key_shape"],
            row["value_bytes"],
            order[row["construction"]],
        )
    )
    circuit.sort(
        key=lambda row: (
            profiles[row["profile"]],
            row["population_log2"],
            row["key_shape"],
            row["value_bytes"],
            order[row["construction"]],
            row["geometry"]["permutations"] or 0,
        )
    )
    shared.sort(
        key=lambda row: (
            profiles[row["profile"]],
            row["population_log2"],
            row["key_shape"],
            row["value_bytes"],
            row["claimed_entries"],
        )
    )
    for row in circuit:
        row["private_key_projection"] = private_key_projection(row, gadgets)
    # The dirty digest of a shared checkout changes between runs; the identity
    # that must agree is the asserted context and the measured executable.
    contexts = {
        json.dumps(
            {
                key: run["report"]["context"].get(key)
                for key in ("artifact", "cache_policy", "config", "hardware", "profile", "source_commit")
            },
            sort_keys=True,
        )
        for run in runs
    }
    first = runs[0]["report"] if runs else {"context": {}, "host": {}}
    combinations = sorted(
        {
            (row["profile"], row["construction"], row["population_log2"], row["key_shape"], row["value_bytes"])
            for row in native
        }
    )
    summary = dict(STATIC_SECTIONS)
    summary.update(
        {
            "benchmark_identity": {
                "class": "identity",
                "contexts_agree": len(contexts) <= 1,
                "hardware": first["context"].get("hardware"),
                "hardware_note": "Asserted by the operator of the harness; the observed host facts are recorded beside it.",
                "host": first.get("host"),
                "profile": first["context"].get("profile"),
                "config": first["context"].get("config"),
                "config_note": "The last component is the first sixteen digits of prototype_sources.sha256: the runs were made from exactly the prototype, adapter and measurement sources of that digest, and the checker fails when the tree's differ.",
                "prototype_sources": source_digest(repository),
                "cache_policy": first["context"].get("cache_policy"),
                "source_commit": first["context"].get("source_commit"),
                "source_dirty": first["context"].get("source_dirty"),
                "source_dirty_note": "The checkout held the uncommitted work of this and other tasks; each run records its own dirty digest. The measured executable is identified by its SHA-256.",
                "harness": "scripts/zk_resource_harness.py run (task E.1); records written by crates/iroha_measurement",
                "load_note": "The measurement runs executed one at a time, none beside another, on a shared development host that other work was also using; the one-minute load average at the start and end of every record is in its row. Every timed phase was repeated on identical inputs inside its run. A test listed more than once in runs was measured again by the same executable; its rows pool both runs.",
                "allocator_note": "The measuring executable counts heap bytes in its global allocator (two relaxed atomic updates and one thread-local read per allocation, the same for every candidate).",
                "raw_records_tracked": False,
                "runs": [run["summary"] for run in runs],
            },
            "workloads": {
                "class": "declared_assumption",
                "schema": inventory_schema(repository),
                "schema_recorded_by_the_runs": recorded_schema(records),
                "populations_log2": sorted({row["population_log2"] for row in native}),
                "maximum_measured_population_log2": max(
                    (row["population_log2"] for row in native), default=None
                ),
                "value_bytes": sorted({row["value_bytes"] for row in native}),
                **WORKLOAD_NOTES,
                "combinations_run": [
                    {
                        "profile": profile,
                        "construction": construction,
                        "population_log2": population,
                        "key_shape": key_shape,
                        "value_bytes": value_bytes,
                    }
                    for profile, construction, population, key_shape, value_bytes in combinations
                ],
            },
            "latency": {
                "class": "measured",
                "unit": "ns_per_call: timing",
                "record": latency_record,
                "note": "Prototype implementations: the algebraic profiles use the proof crate's reference field arithmetic. hash_bytes_N hashes N bytes under the profile's framing. Each operation was timed five times.",
                "rows": latency,
            },
            "as_built_blake2b_gadget": gadget,
            "native": {
                "class": "measured",
                "note": "Compression, byte-hash and permutation counts are deterministic functions of the workload and identical in every repetition (class measured_deterministic_count). Timings are {min, median, max, repetitions} over repetitions on identical inputs. storage_model is an accounting model (see storage_model); memory is the heap of the prototype's containers.",
                "memory_note": MEMORY_NOTE,
                "rows": native,
            },
            "timing_comparability": {
                "class": "derived_from_measured",
                "rule": COMPARABILITY_RULE,
                "run_to_run_note": RUN_TO_RUN_NOTE,
                "run_to_run": run_to_run(runs, records),
                "groups": comparability(native),
            },
            "in_circuit": {
                "class": "measured",
                "note": "Geometry and permutation counts are deterministic. statements summarises the program of every statement of the native sample beside the permutations of its native verification; geometry and reference describe the first of them. Times are of the uncommitted reference. Every committed-proof field is null with its reason.",
                "memory_note": "reference.build_peak_heap_bytes and check_peak_heap_bytes are the most heap the process held during the reference build or check above what it held before, from the counting allocator: the memory of the uncommitted reference for that trace, not prover memory of a committed proof. declared_payload_bytes is the reference's own declared simultaneous payload.",
                "committed_proof_null_reason": B2_REASON,
                "relation_scope": RELATION_SCOPE,
                "gadget_scope": GADGET_SCOPE,
                "gadgets": {
                    "record": gadget_record,
                    "false_statements_rejected": false_statements,
                    "rows": gadgets,
                },
                "rows": circuit,
            },
            "as_built_alternatives": {
                "class": "projection",
                "note": "Two prototype shortcuts shape the comparison as much as the constructions do. These rows project each construction without its shortcut, from counts the measurement took; neither alternative is implemented.",
                "linked_range_shared_paths": {
                    "note": "The prototype's linked-leaf range witness carries one whole address path per leaf. If the paths shared their common nodes (a multiproof), a verifier would hash each branch of their union once and the witness would carry only the siblings outside it. Counted from the prototype's own witnesses; shared_witness_bytes_mean charges 32 bytes per carried sibling and 5 per branch.",
                    "rows": shared,
                },
                "btree_cached_page_nodes": {
                    "note": "The prototype B-tree recomputes page-internal nodes on every update and keeps none. If every node of the binary tree were kept, a value rewrite would recompute the leaf and one node per level of its path, and the storage model would grow by one 32-byte digest per page-internal node.",
                    "rows": cached_page_rows(native),
                },
            },
            "projections": build_projections(native, circuit, latency, gadget),
        }
    )
    ordered = [
        "schema", "plan", "purpose", "selection", "selection_note", "checked_by", "regenerate", "contract", "source",
        "constructions", "hash_profiles", "conformance", "benchmark_identity", "workloads", "units", "latency",
        "as_built_blake2b_gadget", "storage_model", "native", "timing_comparability", "in_circuit",
        "as_built_alternatives", "projections", "decision_criteria", "limits",
    ]
    return {key: summary[key] for key in ordered}


def walk_numbers(node: Any, path: str, classified: bool, errors: list[str]) -> None:
    if isinstance(node, dict):
        declared = node.get("class")
        if declared is not None and declared not in CLASSES:
            errors.append(f"{path}: unknown class `{declared}`")
        inside = classified or declared in CLASSES
        for key, value in node.items():
            walk_numbers(value, f"{path}.{key}", inside, errors)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            walk_numbers(value, f"{path}[{index}]", classified, errors)
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        if not classified:
            errors.append(f"{path}: number {node!r} has no class")


SELECTION_WORDS = ("winner", "selected", "chosen", "recommended_construction", "ranking")


def walk_keys(node: Any, path: str, errors: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if any(word in key.lower() for word in SELECTION_WORDS):
                errors.append(f"{path}.{key}: the comparison must not record a selection")
            walk_keys(value, f"{path}.{key}", errors)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            walk_keys(value, f"{path}[{index}]", errors)


def rust_sources(repository: Path) -> Iterable[Path]:
    for root in ("crates", "integration_tests", "xtask", "tools"):
        base = repository / root
        if base.is_dir():
            for path in base.rglob("*.rs"):
                if "target" not in path.parts:
                    yield path


class SourceError(Exception):
    """A source no longer has the shape the checker reads a fact from."""


def read_integer(text: str, pattern: str, what: str) -> int:
    match = re.search(pattern, text)
    if match is None:
        raise SourceError(f"cannot read {what} from the source")
    return int(match.group(1).replace("_", ""))


def function_body(text: str, name: str) -> str | None:
    """The attributes and body of the function `name`, or None when it is absent."""
    match = re.search(rf"((?:[ \t]*#\[[^\n]*\]\n)*)[ \t]*(?:pub(?:\([a-z:]+\))? )?fn {re.escape(name)}\b[^{{]*\{{", text)
    if match is None:
        return None
    depth, position = 1, match.end()
    while depth and position < len(text):
        depth += {"{": 1, "}": -1}.get(text[position], 0)
        position += 1
    return match.group(1) + text[match.end() : position]


def engines_in_source(repository: Path) -> set[tuple[str, str, str]]:
    """Every engine of the prototype module: its source, type and identity."""
    found = set()
    for path in sorted((repository / PROTOTYPES).glob("*.rs")):
        text = path.read_text()
        for match in re.finditer(r"impl<H: HashProfile> Engine for (\w+)<H> \{", text):
            identity = re.search(r'const CONSTRUCTION: &\'static str\s*=\s*"([^"]+)";', text[match.end() :])
            if identity is None:
                raise SourceError(f"{path.name}: engine `{match.group(1)}` states no construction identity")
            found.add((str(path.relative_to(repository)), match.group(1), identity.group(1)))
    return found


def conformance_table(adapters: str) -> list[tuple[str, str, str]]:
    """The rows of the adapters' `conformance_tests!` table: test, engine, profile."""
    block = re.search(r"\nconformance_tests! \{\n(.*?)\n\}\n", adapters, re.DOTALL)
    if block is None:
        raise SourceError(f"{ADAPTERS}: the conformance test table is missing")
    rows = []
    for line in block.group(1).splitlines():
        row = re.fullmatch(r"\s*(\w+): (\w+)<(\w+)>;", line)
        if row is None:
            raise SourceError(f"{ADAPTERS}: unreadable conformance table row `{line.strip()}`")
        rows.append(row.groups())
    return rows


def gadget_use_in_source(circuit: str) -> dict[str, dict[str, tuple[int, int]]]:
    """Declared gadget instances per engine type: absence and range."""
    found: dict[str, dict[str, tuple[int, int]]] = {}
    blocks = re.split(r"\nimpl<P: AirPermutation> WitnessPrograms for (\w+)<AlgebraicSponge<P>> \{", circuit)
    for name, body in zip(blocks[1::2], blocks[2::2]):
        uses = {}
        for kind in ("ABSENCE", "RANGE"):
            match = re.search(
                rf"const {kind}_GADGETS: GadgetUse = GadgetUse \{{\s*bit_scans: (\d+),\s*comparisons: (\d+),\s*\}};",
                body,
            )
            if match is None:
                raise SourceError(f"circuit.rs: `{name}` declares no {kind.lower()} gadget instances")
            uses[kind.lower()] = (int(match.group(1)), int(match.group(2)))
        found[name] = uses
    return found


def relation_constants(repository: Path) -> dict[str, Any]:
    """Geometry of the hash-chain relation, read from its source."""
    circuit = (repository / PROTOTYPES / "circuit.rs").read_text()
    poseidon2 = (repository / PROTOTYPES / "poseidon2.rs").read_text()
    rescue = (repository / PROTOTYPES / "rescue.rs").read_text()
    const = r"const {}: usize = (\d[\d_]*);"
    p2_rounds = read_integer(poseidon2, const.format("FULL_ROUNDS"), "Poseidon2 full rounds") + read_integer(
        poseidon2, const.format("PARTIAL_ROUNDS"), "Poseidon2 partial rounds"
    )
    if not re.search(r"pub const ROUNDS: usize = FULL_ROUNDS \+ PARTIAL_ROUNDS;", poseidon2):
        raise SourceError("cannot read the Poseidon2 round count from the source")
    p2_width = read_integer(poseidon2, const.format("WIDTH"), "Poseidon2 width")
    rp_rounds = read_integer(rescue, const.format("ROUNDS"), "Rescue-Prime rounds")
    rp_width = read_integer(rescue, const.format("WIDTH"), "Rescue-Prime width")
    constraints = re.search(r"(\d+) \+ (\d+) \* self\.registers \+ (\d+) \+ (\d+) \+ (\d+)\n", circuit)
    if constraints is None:
        raise SourceError("cannot read the relation's numerator count from the source")
    parts = [int(word) for word in constraints.groups()]
    return {
        "poseidon2": {
            "rows": p2_rounds + read_integer(circuit, r"const ROWS: usize = poseidon2::ROUNDS \+ (\d+);", "Poseidon2 block rows"),
            "periodic": read_integer(circuit, r"const PERIODIC: usize = (\d+) \+ poseidon2::WIDTH;", "Poseidon2 periodic columns") + p2_width,
        },
        "rescue-prime": {
            "rows": rp_rounds + read_integer(circuit, r"const ROWS: usize = rescue::ROUNDS \+ (\d+);", "Rescue-Prime block rows"),
            "periodic": read_integer(circuit, r"const PERIODIC: usize = (\d+) \+ \d+ \* rescue::WIDTH;", "Rescue-Prime periodic columns")
            + read_integer(circuit, r"const PERIODIC: usize = \d+ \+ (\d+) \* rescue::WIDTH;", "Rescue-Prime periodic columns") * rp_width,
        },
        "private_base": read_integer(circuit, const.format("SAVED"), "the first register column"),
        "private_per_register": read_integer(circuit, r"SAVED \+ (\d+) \* self\.registers\n", "register words"),
        "public_base": read_integer(circuit, const.format("FIXED_PUBLIC"), "the fixed verifier-known columns"),
        "public_per_register": read_integer(
            circuit, r"self\.private\(\) \+ FIXED_PUBLIC \+ (\d+) \* self\.registers\n", "register selectors"
        ),
        "constraints_base": parts[0] + parts[2] + parts[3] + parts[4],
        "constraints_per_register": parts[1],
        "degree": read_integer(circuit, const.format("DEGREE"), "the relation's degree"),
        "hash_constants": {
            "poseidon2": {"width": p2_width, "full_rounds": read_integer(poseidon2, const.format("FULL_ROUNDS"), "rounds"), "partial_rounds": read_integer(poseidon2, const.format("PARTIAL_ROUNDS"), "rounds"), "rounds": p2_rounds},
            "rescue-prime": {"width": rp_width, "rounds": rp_rounds},
        },
    }


def gadget_constants(repository: Path) -> dict[str, dict[str, int]]:
    """Geometry of the two key gadgets, read from their source."""
    text = (repository / PROTOTYPES / "key_gadgets.rs").read_text()
    const = r"const {}: usize = (\d[\d_]*);"
    lane = read_integer(text, const.format("LANE_WIDTH"), "the scan's private columns")
    lane_constraints = read_integer(text, const.format("LANE_CONSTRAINTS"), "the scan's numerators")
    shared = read_integer(text, const.format("SHARED_WIDTH"), "the scan's shared columns")
    encoded = read_integer(text, const.format("ENCODED_BITS_PER_BYTE"), "encoded bits per byte")
    flags = read_integer(text, r"const ORDER_GAP: usize = ORDER_PREFIX \+ (\d+);", "the order flags")
    gap = read_integer(text, r"const ORDER_PRIVATE: usize = ORDER_GAP \+ (\d+);", "the order gap bits")
    order_rules = re.search(r"pub const CONSTRAINTS: usize = (\d+) \* LANE_CONSTRAINTS \+ (\d+) \+ (\d+);", text)
    degrees = re.findall(r"pub const DEGREE: usize = (\d+);", text)
    if order_rules is None or len(degrees) != 2:
        raise SourceError("cannot read the key gadgets' numerators and degrees from the source")
    if not re.search(r"pub const CONSTRAINTS: usize = LANE_CONSTRAINTS \+ ENCODED_BITS_PER_BYTE;", text):
        raise SourceError("cannot read the bit gadget's numerators from the source")
    order_private = 2 * lane + flags + gap
    return {
        "order": {
            "private_columns": order_private,
            "width": order_private + shared + 4,
            "constraints": int(order_rules.group(1)) * lane_constraints + int(order_rules.group(2)) + int(order_rules.group(3)),
            "degree": int(degrees[0]),
        },
        "bits": {
            "private_columns": lane,
            "width": lane + shared + 2 + 2 * encoded,
            "constraints": lane_constraints + encoded,
            "degree": int(degrees[1]),
        },
    }


def gadget_rows_for(longest: int) -> int:
    """`key_gadgets::rows_for`."""
    rows = max(1 << (longest).bit_length(), 8)
    while 7 * (rows // 7) < longest:
        rows *= 2
    return rows


def storage_constants(repository: Path) -> dict[str, dict[str, int]]:
    found = {}
    for construction in CONSTRUCTIONS:
        text = (repository / construction["source"]).read_text()
        found[construction["id"]] = {
            name.lower() + "_bytes": int(value)
            for name, value in re.findall(r"pub const MODEL_(\w+)_BYTES: u64 = (\d+);", text)
        }
    return found


def background_entries(repository: Path) -> int:
    """Entries the workload puts into every keyed table beside the populated one."""
    workload = (repository / PROTOTYPES / "workload.rs").read_text()
    return read_integer(workload, r"pub const BACKGROUND_ENTRIES: u64 = (\d[\d_]*);", "the background entries of a table")


def populated_entries(schema: dict[str, Any], population_log2: int, background: int) -> int:
    """Entries of the State the workload builds over a schema: the populated
    table, one entry per cell and the background entries of every other table."""
    return (1 << population_log2) + schema["cells"] + background * (schema["tables"] - 1)


def as_built_constants(repository: Path) -> dict[str, int]:
    blake2b = (repository / BLAKE2B_GADGET).read_text()
    smt = (repository / SMT_GADGET).read_text()
    const = r"pub const {}: usize = (\d[\d_]*);"
    return {
        "rows": read_integer(blake2b, const.format("ROW_COUNT"), "the BLAKE2b gadget rows"),
        "columns": read_integer(blake2b, const.format("COLUMN_COUNT"), "the BLAKE2b gadget columns"),
        "physical_rows_per_hash_slot": read_integer(smt, const.format("PHYSICAL_HASH_ROWS"), "the hash slot rows"),
    }


def storage_model_bytes(construction: str, model: dict[str, Any], constants: dict[str, dict[str, int]]) -> tuple[int, int]:
    """Structure and auxiliary bytes the declared model gives for a row's node counts."""
    sizes, entries = constants[construction], model["entries"]
    if construction == "radix":
        return entries * sizes["leaf_bytes"] + max(entries - 1, 0) * sizes["branch_bytes"], 0
    if construction == "btree":
        upper = model["structure_digests"] - 2 * entries
        return entries * sizes["entry_bytes"] + upper * sizes["upper_item_bytes"], 0
    if construction == "linked":
        return (entries + 1) * sizes["leaf_bytes"] + entries * sizes["branch_bytes"], entries * sizes["index_entry_bytes"]
    return entries * sizes["entry_bytes"] + sizes["root_bytes"], 0


def check_sources(summary: dict[str, Any], repository: Path, errors: list[str]) -> None:
    def read(relative: str) -> str | None:
        path = repository / relative
        if not path.is_file():
            errors.append(f"{relative}: named by the comparison, missing from the tree")
            return None
        return path.read_text()

    for construction in summary.get("constructions", []):
        text = read(construction["source"])
        if text is None:
            continue
        if f'"{construction["identity"]}"' not in text:
            errors.append(
                f"{construction['source']}: construction identity `{construction['identity']}` not found"
            )
        if f"pub struct {construction['type']}<" not in text:
            errors.append(f"{construction['source']}: type `{construction['type']}` not found")
        if "TODO(G.3)" not in text:
            errors.append(f"{construction['source']}: prototype lacks its TODO(G.3) replacement marker")
    stated = {(entry["source"], entry["type"], entry["identity"]) for entry in summary.get("constructions", [])}
    engines = engines_in_source(repository)
    for source, name, identity in sorted(engines - stated):
        errors.append(f"{source}: engine `{name}` (`{identity}`) is not a construction of the comparison")
    for source, name, identity in sorted(stated - engines):
        errors.append(f"{source}: construction `{name}` (`{identity}`) is not an engine of the prototype module")

    for profile in summary.get("hash_profiles", []):
        text = read(profile["source"])
        if text is not None and f'"{profile["identity"]}"' not in text:
            errors.append(f"{profile['source']}: hash profile identity `{profile['identity']}` not found")
        tests = [(profile["source"], profile.get("known_answer_test"))]
        if profile.get("second_definition"):
            tests.append((profile["second_definition"], profile.get("second_definition_test")))
        for source, test in tests:
            if test is None:
                if not profile.get("known_answer_test_reason"):
                    errors.append(f"hash profile `{profile['id']}`: no known-answer test and no reason")
                continue
            body = function_body(read(source) or "", test)
            if body is None:
                errors.append(f"{source}: known-answer test `{test}` not found")
            elif "#[test]" not in body or "#[ignore" in body or "assert_eq!(" not in body:
                errors.append(f"{source}: known-answer test `{test}` is not a running test with an equality assertion")
            elif profile["id"] == "blake3" and "blake3::hash(" not in body:
                errors.append(f"{source}: `{test}` no longer compares the profile with blake3::hash")

    adapters = read(str(ADAPTERS))
    if adapters is not None:
        table = set(conformance_table(adapters))
        stated_tests = {
            (entry["test"], entry.get("engine_type"), entry.get("profile_type"))
            for entry in summary.get("conformance", {}).get("tests", [])
        }
        for test, engine, profile in sorted(stated_tests - table, key=str):
            errors.append(f"{ADAPTERS}: conformance test `{test}` for {engine}<{profile}> not found")
        for test, engine, profile in sorted(table - stated_tests, key=str):
            errors.append(f"{ADAPTERS}: conformance test `{test}` for {engine}<{profile}> is not in the comparison")
        binding = summary.get("conformance", {}).get("schema_binding_test")
        if binding and f"fn {binding}(" not in adapters:
            errors.append(f"{ADAPTERS}: schema binding test `{binding}` not found")
        if "check_contract::<Candidate<E>>()" not in adapters or not re.search(
            r"assert_eq!\(conforms::<\$engine<\$profile>>\(\), Ok\(\(\)\)\);", adapters
        ):
            errors.append(f"{ADAPTERS}: the adapters no longer run the conformance suite")
        if "#[ignore" in adapters:
            errors.append(f"{ADAPTERS}: an adapter test is ignored")
    library = read("crates/fastpq_prover/src/lib.rs")
    if library is not None and not re.search(
        r'#\[cfg\(any\(test, feature = "dev-tools"\)\)\]\s*pub mod state_commitment_prototypes;',
        library,
    ):
        errors.append("crates/fastpq_prover/src/lib.rs: the prototype module is not development-only")
    interface = read(str(INTERFACE))
    if interface is not None and not re.search(
        r'#\[cfg\(all\(test, feature = "state-commitment-prototypes"\)\)\]\s*mod candidates_tests;',
        interface,
    ):
        errors.append(f"{INTERFACE}: the candidate adapters are not test-only behind their feature")
    for path in sorted((repository / PROTOTYPES).glob("*.rs")) + [repository / PROTOTYPE_ROOT]:
        if path.is_file() and "TODO(G.3)" not in path.read_text() and path.name not in (
            "codec.rs",
            "critbit.rs",
            "fringe.rs",
            "keyed.rs",
            "tests.rs",
            "circuit_tests.rs",
            "key_gadgets_tests.rs",
        ):
            errors.append(f"{path.relative_to(repository)}: prototype lacks its TODO(G.3) marker")
    references = set()
    for path in rust_sources(repository):
        relative = str(path.relative_to(repository))
        if relative.startswith(str(PROTOTYPES)) or relative == str(PROTOTYPE_ROOT):
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        if "state_commitment_prototypes" in text:
            references.add(relative)
    for extra in sorted(references - PROTOTYPE_REFERENCES):
        errors.append(
            f"{extra}: names the development-only prototypes; only their gate, their adapters and their measurement target may"
        )


def check_timing(value: Any, where: str, least: int, errors: list[str]) -> None:
    """A repetition statistic: ordered, and with enough repetitions."""
    if not isinstance(value, dict) or set(value) != {"min", "median", "max", "repetitions"}:
        errors.append(f"{where}: not a timing of the form min, median, max, repetitions")
        return
    if not value["min"] <= value["median"] <= value["max"]:
        errors.append(f"{where}: minimum, median and maximum are not ordered")
    if value["repetitions"] < least:
        errors.append(f"{where}: {value['repetitions']} repetitions, fewer than {least}")


def further_runs(summary: dict[str, Any], run_names: set[str], errors: list[str]) -> dict[str, set[str]]:
    """Check timing_comparability.run_to_run and return, per first run, the further runs of its test."""
    section = summary.get("timing_comparability", {})
    if section.get("rule") != COMPARABILITY_RULE or section.get("run_to_run_note") != RUN_TO_RUN_NOTE:
        errors.append("timing_comparability: the rule or the run-to-run note differs from the checker's table")
    runs = summary.get("benchmark_identity", {}).get("runs") or []
    tests = {run.get("run"): run.get("test") for run in runs}
    # A test's first run is its primary; every later run of it is a further run.
    first_of: dict[Any, Any] = {}
    expected: dict[str, set[str]] = {}
    for run in runs:
        primary = first_of.setdefault(run.get("test"), run.get("run"))
        if primary != run.get("run"):
            expected.setdefault(primary, set()).add(run.get("run"))
    listed: dict[str, set[str]] = {}
    for index, entry in enumerate(section.get("run_to_run", [])):
        where = f"timing_comparability.run_to_run[{index}]"
        first, further = entry.get("first_run"), entry.get("further_run")
        if first not in run_names or further not in run_names or first == further:
            errors.append(f"{where}: its runs are not two runs of the benchmark identity")
            continue
        if tests.get(first) != tests.get(further) or entry.get("test") != tests.get(first):
            errors.append(f"{where}: its runs are not two runs of the test it names")
        ratio = entry.get("median_wall_ratio") or {}
        if set(ratio) != {"min", "median", "max"} or not ratio["min"] <= ratio["median"] <= ratio["max"]:
            errors.append(f"{where}.median_wall_ratio is not an ordered minimum, median and maximum")
        phases = entry.get("timed_phases") or 0
        if phases < 1 or not 0 <= (entry.get("phases_within_ten_percent") or 0) <= phases:
            errors.append(f"{where}: the counted phases are inconsistent")
        listed.setdefault(first, set()).add(further)
    if listed != expected:
        errors.append(
            "timing_comparability.run_to_run does not list exactly the runs that measured a test again: "
            f"the benchmark identity gives {sorted((key, sorted(value)) for key, value in expected.items())}"
        )
    if not expected:
        errors.append(
            "timing_comparability.run_to_run is empty: no measurement test was run a second time, so nothing "
            "shows how far the timings move between runs"
        )
    return expected


def check_record(
    record: dict[str, Any], where: str, run_names: set[str], pooled: dict[str, set[str]], errors: list[str]
) -> None:
    """A row's provenance: its run and every further run pooled into it."""
    if record.get("run") not in run_names:
        errors.append(f"{where}: its record is from a run the benchmark identity does not list")
    replicates = record.get("replicates")
    if not isinstance(replicates, list):
        errors.append(f"{where}.record.replicates is missing")
        replicates = []
    for facts in [record, *replicates]:
        for key in ("peak_rss_bytes", "load_milli_begin", "load_milli_finish", "unattributed_ppm"):
            if facts.get(key) is None:
                errors.append(f"{where}.record.{key} is missing")
        if (facts.get("unattributed_ppm") or 0) > UNATTRIBUTED_LIMIT_PPM:
            errors.append(f"{where}: more than one percent of the flow is in no phase")
    if {facts.get("run") for facts in replicates} != pooled.get(record.get("run"), set()) or len(
        {facts.get("run") for facts in replicates}
    ) != len(replicates):
        errors.append(f"{where}.record.replicates are not the further runs of its test")


def check_native(
    summary: dict[str, Any], repository: Path, run_names: set[str], pooled: dict[str, set[str]], errors: list[str]
) -> None:
    constructions = {entry["id"] for entry in summary.get("constructions", [])}
    profiles = {entry["id"]: entry for entry in summary.get("hash_profiles", [])}
    conformance = {(entry["construction"], entry["profile"]) for entry in summary.get("conformance", {}).get("tests", [])}
    constants = storage_constants(repository)
    if summary.get("storage_model", {}).get("constants") != constants:
        errors.append("storage_model.constants differ from the MODEL_*_BYTES constants of the construction sources")
    native_rows = summary.get("native", {}).get("rows", [])
    if not native_rows:
        errors.append("native.rows is empty")
    declared_schema = summary.get("workloads", {}).get("schema") or {}
    background = background_entries(repository)
    measured_constructions = set()
    for index, row in enumerate(native_rows):
        where = f"native.rows[{index}]"
        if row["construction"] not in constructions or row["profile"] not in profiles:
            errors.append(f"{where}: unknown construction or profile")
            continue
        measured_constructions.add(row["construction"])
        # The entries a run counted after its cold build are those of the
        # schema it read: a run over another table or cell count shows here.
        if declared_schema.get("tables") and declared_schema.get("cells") is not None:
            populated = populated_entries(declared_schema, row["population_log2"], background)
            if row.get("entries_total") != populated:
                errors.append(
                    f"{where}.entries_total is {row.get('entries_total')}; the declared schema and population give "
                    f"{populated}: the run populated another schema"
                )
        if (row["construction"], row["profile"]) not in conformance:
            errors.append(f"{where}: {row['construction']} over {row['profile']} was measured without a conformance test")
        check_record(row.get("record", {}), where, run_names, pooled, errors)
        build = row.get("cold_build", {})
        repetitions = (build.get("ns_per_entry") or {}).get("repetitions", 0)
        check_timing(build.get("ns_per_entry"), f"{where}.cold_build.ns_per_entry", 1, errors)
        if build.get("replicated") is not (repetitions >= MIN_REPETITIONS):
            errors.append(f"{where}.cold_build.replicated does not follow from its {repetitions} repetitions")
        if not row.get("updates"):
            errors.append(f"{where}: no update measurement")
        for update in row.get("updates", []):
            check_timing(
                update.get("wall_ns_per_change"),
                f"{where}.updates[{update.get('changes_per_set')}].wall_ns_per_change",
                MIN_REPETITIONS,
                errors,
            )
        witness = row.get("witness", {})
        kinds = [(kind, witness.get(kind)) for kind in ("inclusion", "absence")]
        kinds += [(f"range[{entry.get('claimed_entries')}]", entry) for entry in witness.get("range", [])]
        for kind, entry in kinds:
            if not entry:
                errors.append(f"{where}: no {kind} witness measurement")
                continue
            for key in ("prove_ns_per_statement", "verify_ns_per_statement"):
                check_timing(entry.get(key), f"{where}.witness.{kind}.{key}", MIN_REPETITIONS, errors)
            if not entry["bytes_min"] <= entry["bytes_mean"] <= entry["bytes_max"]:
                errors.append(f"{where}.witness.{kind}: the mean witness size is outside its smallest and largest")
        if not witness.get("range"):
            errors.append(f"{where}: no complete-range witness measurement")
        model = row.get("storage_model", {})
        if model.get("class") != "accounting_model":
            errors.append(f"{where}.storage_model is not classified as an accounting model")
        elif model.get("entries") is not None and constants.get(row["construction"]):
            try:
                expected = storage_model_bytes(row["construction"], model, constants)
            except KeyError:
                expected = None
            if expected != (model.get("structure_bytes"), model.get("auxiliary_bytes")):
                errors.append(f"{where}.storage_model does not follow from its node counts and the declared constants")
            if model.get("structure_bytes_per_entry") != ratio(model.get("structure_bytes"), model["entries"], 2):
                errors.append(f"{where}.storage_model.structure_bytes_per_entry is not its bytes over its entries")
        memory = row.get("memory", {})
        readings = memory.get("heap_readings") or {}
        if not memory.get("heap_live_bytes") or not memory.get("heap_peak_build_bytes"):
            errors.append(f"{where}.memory: the heap of the built map is not recorded")
        elif memory["heap_peak_build_bytes"] < memory["heap_live_bytes"]:
            errors.append(f"{where}.memory: the peak during the build is below what the map holds")
        elif (
            set(readings) != {"repetitions", "agreeing", "live_min", "live_max"}
            or not readings["live_min"] <= memory["heap_live_bytes"] <= readings["live_max"]
            or not readings["repetitions"] >= readings["agreeing"] > readings["repetitions"] / 2
            or readings["repetitions"] != repetitions
            or (readings["agreeing"] == readings["repetitions"]) != (readings["live_min"] == readings["live_max"])
        ):
            errors.append(
                f"{where}.memory.heap_readings: the heap figure is not the reading of a strict majority of its cold builds"
            )
        if memory.get("heap_live_bytes") and memory.get("heap_live_bytes_per_entry") != ratio(
            memory["heap_live_bytes"], row.get("entries_total")
        ):
            errors.append(f"{where}.memory.heap_live_bytes_per_entry is not its bytes over the entries of the State")
    if measured_constructions != constructions:
        errors.append("native.rows does not cover every construction")
    for profile in sorted(set(profiles) - {row["profile"] for row in native_rows}):
        errors.append(f"native.rows: hash profile `{profile}` has no native measurement")
    populations = {row["population_log2"] for row in native_rows}
    workloads = summary.get("workloads", {})
    if workloads.get("maximum_measured_population_log2") != (max(populations) if populations else None):
        errors.append("workloads.maximum_measured_population_log2 is not the largest measured population")
    if workloads.get("representative_population_log2") not in populations:
        errors.append("workloads: the representative population was not measured")
    listed = {
        (entry["profile"], entry["construction"], entry["population_log2"], entry["key_shape"], entry["value_bytes"])
        for entry in workloads.get("combinations_run", [])
    }
    actual = {
        (row["profile"], row["construction"], row["population_log2"], row["key_shape"], row["value_bytes"])
        for row in native_rows
    }
    if listed != actual:
        errors.append("workloads.combinations_run differs from the measured rows")
    declared = inventory_schema(repository)
    if workloads.get("schema") != declared:
        errors.append(
            f"workloads.schema is not the schema {INVENTORY} declares: the measurement no longer covers the inventory"
        )
    # What every record named when it ran, against the inventory now.
    named = {
        "class": "measured_deterministic_count",
        "tables": declared["tables"],
        "cells": declared["cells"],
        "descriptor_bytes": declared["descriptor_bytes"],
        "descriptor_sha256_prefix": declared["descriptor_sha256"][:16],
    }
    if workloads.get("schema_recorded_by_the_runs") != named:
        errors.append(
            f"workloads.schema_recorded_by_the_runs is not the schema {INVENTORY} declares: the runs read another schema"
        )
    comparability_ = summary.get("timing_comparability", {})
    try:
        expected_groups = comparability(native_rows)
    except (KeyError, TypeError):
        expected_groups = None
    if comparability_.get("groups") != expected_groups:
        errors.append("timing_comparability.groups do not follow from the repetition intervals of the native rows")
    cached = summary.get("as_built_alternatives", {}).get("btree_cached_page_nodes", {}).get("rows")
    try:
        expected_cached = cached_page_rows(native_rows)
    except (KeyError, TypeError):
        expected_cached = None
    if cached != expected_cached:
        errors.append("as_built_alternatives.btree_cached_page_nodes.rows do not follow from the native rows")


def check_circuit(
    summary: dict[str, Any], repository: Path, run_names: set[str], pooled: dict[str, set[str]], errors: list[str]
) -> None:
    section = summary.get("in_circuit", {})
    relation = relation_constants(repository)
    gadget_geometry = gadget_constants(repository)
    circuit_source = (repository / PROTOTYPES / "circuit.rs").read_text()
    declared_use = gadget_use_in_source(circuit_source)
    types = {entry["id"]: entry["type"] for entry in summary.get("constructions", [])}
    for profile in summary.get("hash_profiles", []):
        constants = dict(profile.get("constants") or {})
        constants.pop("class", None)
        if constants and constants != relation["hash_constants"].get(profile["id"]):
            errors.append(f"hash profile `{profile['id']}`: its constants differ from the source's")

    gadgets = section.get("gadgets", {})
    gadget_rows_ = gadgets.get("rows", [])
    if {(row.get("gadget"), row.get("key_bytes")) for row in gadget_rows_} != {
        (gadget, key) for gadget in ("order", "bits") for key in (36, 132)
    }:
        errors.append("in_circuit.gadgets: both gadgets must be measured for 36-byte and 132-byte keys")
    if not gadgets.get("false_statements_rejected"):
        errors.append("in_circuit.gadgets: no false statement was shown rejected")
    check_record(gadgets.get("record") or {}, "in_circuit.gadgets", run_names, pooled, errors)
    for index, row in enumerate(gadget_rows_):
        where = f"in_circuit.gadgets.rows[{index}]"
        expected = gadget_geometry.get(row.get("gadget"), {})
        rows = row.get("rows") or 0
        facts = {
            "rows": gadget_rows_for(row.get("key_bytes") or 0),
            "width": expected.get("width"),
            "private_columns": expected.get("private_columns"),
            "constraints": expected.get("constraints"),
            "numerator_degree_bound": (expected.get("degree") or 0) * (rows - 1) + 1,
            "trace_cells": rows * (expected.get("width") or 0),
        }
        for key, value in facts.items():
            if row.get(key) != value:
                errors.append(f"{where}.{key} is {row.get(key)}, the gadget's source gives {value}")
        reference = row.get("reference") or {}
        if "uncommitted" not in str(reference.get("label")):
            errors.append(f"{where}.reference is not labelled as the uncommitted reference")
        for key in ("build_wall_ns", "check_wall_ns"):
            check_timing(reference.get(key), f"{where}.reference.{key}", MIN_REFERENCE_REPETITIONS, errors)

    circuit_rows_ = section.get("rows", [])
    shortlisted = {entry["id"] for entry in summary.get("constructions", []) if entry.get("in_circuit") == "measured"}
    covered: dict[tuple[str, str], set[str]] = {}
    for index, row in enumerate(circuit_rows_):
        where = f"in_circuit.rows[{index}]"
        proof = row.get("committed_proof", {})
        for key in ("prove_time_ns", "verify_time_ns", "proof_bytes", "prover_memory_bytes"):
            if key not in proof or proof[key] is not None:
                errors.append(f"{where}.committed_proof.{key} must be null until task B.2")
        if "B.2" not in str(proof.get("null_reason")):
            errors.append(f"{where}.committed_proof: the null fields have no reason naming task B.2")
        geometry = row.get("geometry", {})
        for key in ("rows", "width", "permutations", "rows_per_permutation", "registers", "constraints"):
            if not geometry.get(key):
                errors.append(f"{where}.geometry.{key} is missing")
        block = relation.get(row.get("profile"))
        registers, rows = geometry.get("registers") or 0, geometry.get("rows") or 0
        if block is not None and geometry.get("permutations"):
            blocks = 1 << (geometry["permutations"] - 1).bit_length()
            facts = {
                "rows_per_permutation": block["rows"],
                "rows": blocks * block["rows"],
                "width": relation["private_base"]
                + relation["private_per_register"] * registers
                + relation["public_base"]
                + relation["public_per_register"] * registers
                + block["periodic"],
                "constraints": relation["constraints_base"] + relation["constraints_per_register"] * registers,
            }
            if not row.get("exceeds_reference_limit"):
                facts["numerator_degree_bound"] = relation["degree"] * (rows - 1) + 1
                facts["trace_cells"] = rows * facts["width"]
            for key, value in facts.items():
                if geometry.get(key) != value:
                    errors.append(f"{where}.geometry.{key} is {geometry.get(key)}, the relation's source gives {value}")
        if bool(row.get("exceeds_reference_limit")) != (rows > REFERENCE_ROWS):
            errors.append(f"{where}.exceeds_reference_limit does not follow from its {rows} rows")
        if row.get("exceeds_reference_limit"):
            if row.get("reference") is not None or not row.get("reference_null_reason"):
                errors.append(f"{where}: a shape beyond the reference limit must have no reference figures and a reason")
        else:
            reference = row.get("reference") or {}
            for key in ("declared_payload_bytes", "build_peak_heap_bytes", "check_peak_heap_bytes"):
                if not reference.get(key):
                    errors.append(f"{where}.reference.{key} is missing")
            for key in ("build_wall_ns", "check_wall_ns"):
                check_timing(reference.get(key), f"{where}.reference.{key}", 1, errors)
            repetitions = (reference.get("build_wall_ns") or {}).get("repetitions", 0)
            if reference.get("replicated") is not (repetitions >= MIN_REFERENCE_REPETITIONS):
                errors.append(f"{where}.reference.replicated does not follow from its {repetitions} repetitions")
            for key in ("numerator_degree_bound", "trace_cells"):
                if not geometry.get(key):
                    errors.append(f"{where}.geometry.{key} is missing")
            if "uncommitted" not in str(reference.get("label")):
                errors.append(f"{where}.reference is not labelled as the uncommitted reference")
        record = row.get("record", {})
        check_record(record, where, run_names, pooled, errors)
        if not record.get("forged_traces_rejected"):
            errors.append(f"{where}: its record shows no forged trace rejected")
        statement = row["statement"]
        kind = "range" if statement.startswith("range_") else statement
        covered.setdefault((row["construction"], row["profile"]), set()).add(kind)

        # Every statement of the sample: as many permutations as the native
        # verifier computes, plus one root normalisation per further anchor.
        statements = row.get("statements") or {}
        circuit, native, anchors = (
            statements.get("permutations"),
            statements.get("native_verifier_permutations"),
            statements.get("anchors"),
        )
        if not circuit or not native or not anchors:
            errors.append(f"{where}.statements: the native verifier's permutations are not recorded beside the program's")
        elif circuit["total"] != native["total"] + anchors["total"] - anchors["count"] or circuit["count"] != native["count"]:
            errors.append(f"{where}.statements: the program does not hash what the native verifier hashes")
        elif row["construction"] != "linked" and anchors["total"] != anchors["count"]:
            errors.append(f"{where}.statements: more than one anchored chain per statement")
        use = declared_use.get(types.get(row["construction"], ""), {})
        expected_use = (0, 0) if kind == "inclusion" else use.get(kind)
        instances = row.get("gadget_instances", {})
        if (instances.get("bit_scans"), instances.get("comparisons")) != expected_use:
            errors.append(f"{where}.gadget_instances differ from the instances circuit.rs declares")
        try:
            expected_projection = private_key_projection(row, gadget_rows_)
        except (KeyError, TypeError):
            expected_projection = None
        if row.get("private_key_projection") != expected_projection:
            errors.append(f"{where}.private_key_projection is not the sum of its hash-chain and gadget trace cells")
    # Every shortlisted construction under every profile declared as measured
    # in-circuit, with all three statement kinds, and nothing else.
    measured_profiles = {
        entry["id"] for entry in summary.get("hash_profiles", []) if entry.get("in_circuit") == "measured"
    }
    for construction in sorted(shortlisted):
        for profile in sorted(measured_profiles):
            kinds = covered.get((construction, profile))
            if kinds is None:
                errors.append(f"in_circuit: shortlisted construction `{construction}` has no measurement over `{profile}`")
                continue
            missing = {"inclusion", "absence", "range"} - kinds
            if missing:
                errors.append(f"in_circuit: {construction} over {profile} lacks {sorted(missing)}")
    for construction, profile in sorted(covered):
        if construction not in shortlisted or profile not in measured_profiles:
            errors.append(
                f"in_circuit: rows of {construction} over {profile}, which the comparison does not declare as measured in-circuit"
            )
    if "B.2" not in str(section.get("committed_proof_null_reason")):
        errors.append("in_circuit.committed_proof_null_reason must name task B.2")
    for key, expected in (("relation_scope", RELATION_SCOPE), ("gadget_scope", GADGET_SCOPE)):
        scope = section.get(key, {})
        for part in expected:
            if not scope.get(part):
                errors.append(f"in_circuit.{key}.{part} is missing")
        if scope != expected:
            errors.append(f"in_circuit.{key} differs from the checker's table")


def check_summary(summary: Any, repository: Path) -> list[str]:
    """Every inconsistency of a comparison with the tree; it never raises.

    A file of another layout is refused at its schema name and not read
    further. A file of this layout whose sections are not the shapes this
    script writes is reported with what was found up to that point.
    """
    if not isinstance(summary, dict) or summary.get("schema") != SCHEMA:
        refusal = (
            f"schema must be `{SCHEMA}`: a comparison of another layout is not read further; "
            "rebuild it from harness runs with --refresh"
        )
        return [refusal]
    errors: list[str] = []
    try:
        check_sections(summary, repository, errors)
    except (AttributeError, IndexError, KeyError, TypeError) as error:
        errors.append(
            f"malformed comparison: a section is not the shape this script writes ({type(error).__name__}: {error})"
        )
    return errors


def check_static_text(expected: dict[str, Any], actual: Any, where: str, errors: list[str]) -> None:
    """Every class, unit, rule and note of a section is the text this script writes.

    `expected` is the comparison this script builds from no run at all: what
    is text there is no measurement. Lists are rows and are not compared here.
    """
    for key, value in expected.items():
        found = actual.get(key) if isinstance(actual, dict) else None
        if isinstance(value, str):
            if found != value:
                errors.append(f"{where}.{key} differs from the checker's text")
        elif isinstance(value, dict):
            check_static_text(value, found, f"{where}.{key}", errors)


def check_sections(summary: dict[str, Any], repository: Path, errors: list[str]) -> None:
    """The checks of `check_summary` on a comparison of this layout."""
    if "selection" not in summary or summary["selection"] is not None:
        errors.append("selection must be present and null: G.3 selects")
    walk_keys({key: value for key, value in summary.items() if key not in ("selection", "selection_note")}, "$", errors)
    criteria = summary.get("decision_criteria", {})
    if criteria.get("selection_recorded_here") is not False or "proposed" not in str(criteria.get("status")):
        errors.append("decision_criteria must be proposed and must not record a selection")
    weights = [entry.get("proposed_weight") for entry in criteria.get("criteria", [])]
    if not weights or abs(sum(weights) - 1.0) > 1e-9:
        errors.append("decision_criteria.criteria: proposed weights must be present and sum to 1")
    walk_numbers(
        {key: value for key, value in summary.items() if key != "decision_criteria"},
        "$",
        False,
        errors,
    )
    # The descriptive sections are this script's tables, word for word.
    for key, expected in STATIC_SECTIONS.items():
        if key not in ("schema", "selection") and summary.get(key) != expected:
            errors.append(f"{key} differs from the checker's table")
    workloads = summary.get("workloads", {})
    for key, expected in WORKLOAD_NOTES.items():
        if workloads.get(key) != expected:
            errors.append(f"workloads.{key} differs from the checker's table")
    # The measured sections carry this script's classes, units, rules and notes.
    template = build_summary([], repository)
    for key, expected in template.items():
        if key not in STATIC_SECTIONS and key != "projections" and isinstance(expected, dict):
            check_static_text(expected, summary.get(key), key, errors)

    identity = summary.get("benchmark_identity", {})
    for key in ("hardware", "host", "profile", "config", "cache_policy", "source_commit"):
        if not identity.get(key):
            errors.append(f"benchmark_identity.{key} is missing")
    if identity.get("contexts_agree") is not True:
        errors.append("benchmark_identity: the runs do not share one identity context")
    if identity.get("raw_records_tracked") is not False:
        errors.append("benchmark_identity.raw_records_tracked must be false")
    sources = source_digest(repository)
    if identity.get("prototype_sources") != sources or identity.get("config") != expected_config(repository):
        errors.append(
            "benchmark_identity: the prototype, adapter or measurement sources are not the ones that were measured "
            f"(the tree's digest is {sources['sha256'][:16]}, the runs' configuration is `{identity.get('config')}`); "
            "measure again and refresh"
        )
    host = identity.get("host") or {}
    for key in ("model", "cpu", "logical_cpus", "physical_memory_bytes", "system"):
        if not host.get(key):
            errors.append(f"benchmark_identity.host.{key} is missing")
    # The asserted hardware record names the machine the harness observed.
    record = re.fullmatch(r"([^/]+)/[^/]+/(\d+)c/(\d+)GiB", str(identity.get("hardware")))
    if record is None:
        errors.append("benchmark_identity.hardware is not a record of the form model/chip/<cores>c/<memory>GiB")
    elif (record.group(1), int(record.group(2)), int(record.group(3)) << 30) != (
        host.get("model"),
        host.get("logical_cpus"),
        host.get("physical_memory_bytes"),
    ):
        errors.append("benchmark_identity.hardware does not name the host the harness observed")
    commit = str(identity.get("source_commit"))
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        errors.append("benchmark_identity.source_commit is not a full commit name")
    runs = identity.get("runs") or []
    if not runs:
        errors.append("benchmark_identity.runs is empty")
    run_names = set()
    for index, run in enumerate(runs):
        where = f"benchmark_identity.runs[{index}]"
        run_names.add(run.get("run"))
        if run.get("verdict") != "accepted" or run.get("reasons"):
            errors.append(f"{where}: the harness did not accept the run")
        for key in ("manifest_sha256", "executable_sha256", "source_dirty_digest"):
            if not re.fullmatch(r"[0-9a-f]{64}", str(run.get(key))):
                errors.append(f"{where}.{key} is not a SHA-256 digest")
        if not str(run.get("raw_records", "")).startswith(f"{RAW_ROOT}/"):
            errors.append(f"{where}.raw_records must be under the untracked {RAW_ROOT}/")
        if run.get("load_milli_min") is None or run.get("load_milli_max") is None:
            errors.append(f"{where}: the load of the run is not recorded")
        if not run.get("thermal_states"):
            errors.append(f"{where}: the thermal state of the run is not recorded")
        if run.get("source_commit") != identity.get("source_commit"):
            errors.append(f"{where}: source commit differs from the benchmark identity")
        if run.get("config") != identity.get("config"):
            errors.append(f"{where}: configuration differs from the benchmark identity")
        if (run.get("unattributed_ppm_max") or 0) > UNATTRIBUTED_LIMIT_PPM:
            errors.append(f"{where}: a record has more than one percent of its flow in no phase")
    executables = {run.get("executable_sha256") for run in runs}
    if len(executables) > 1:
        errors.append("benchmark_identity.runs: the runs measured different executables")
    ignore = repository / ".gitignore"
    if ignore.is_file() and "dist/*" not in ignore.read_text().splitlines():
        errors.append(".gitignore no longer ignores dist/*: raw records would be tracked")

    constructions = {entry["id"] for entry in summary.get("constructions", [])}
    profiles = {entry["id"]: entry for entry in summary.get("hash_profiles", [])}
    if len(constructions) < 4:
        errors.append("fewer than four constructions")
    if not any(entry["kind"] == "native_fast" for entry in profiles.values()):
        errors.append("no native-fast hash profile")
    algebraic = [entry for entry in profiles.values() if entry["kind"] == "arithmetization_friendly"]
    if len(algebraic) < 2:
        errors.append("fewer than two arithmetization-friendly hash profiles")
    for entry in algebraic:
        if not entry.get("published_source") or not entry.get("known_answer_test"):
            errors.append(f"hash profile `{entry['id']}`: published parameters and a known-answer test are required")

    latency = summary.get("latency", {})
    for index, row in enumerate(latency.get("rows", [])):
        check_timing(row.get("ns_per_call"), f"latency.rows[{index}].ns_per_call", MIN_REPETITIONS, errors)
    if not latency.get("rows"):
        errors.append("latency.rows is empty")

    try:
        pooled = further_runs(summary, run_names, errors)
        check_record(latency.get("record") or {}, "latency", run_names, pooled, errors)
        check_native(summary, repository, run_names, pooled, errors)
        check_circuit(summary, repository, run_names, pooled, errors)
        built = as_built_constants(repository)
        gadget = summary.get("as_built_blake2b_gadget") or {}
        if {key: gadget.get(key) for key in built} != built:
            errors.append(f"as_built_blake2b_gadget differs from the constants of {BLAKE2B_GADGET} and {SMT_GADGET}")
        for entry in summary.get("projections", []):
            constant = entry.get("source_constant")
            if constant is not None and {key: constant.get(key) for key in built} != built:
                errors.append(f"projections ({entry.get('id')}): its source constant differs from the gadget's source")
        check_sources(summary, repository, errors)
    except SourceError as error:
        errors.append(str(error))
    except FileNotFoundError as error:
        errors.append(f"{error.filename}: a source the comparison is checked against is missing")

    seen = set()
    for index, entry in enumerate(summary.get("projections", [])):
        where = f"projections[{index}] ({entry.get('id')})"
        seen.add(entry.get("id"))
        status = entry.get("status")
        if status not in PROJECTION_STATUSES:
            errors.append(f"{where}: unknown status `{status}`")
            continue
        if entry.get("projection", {}).get("class") != "projection":
            errors.append(f"{where}: the projected value is not classified as a projection")
        try:
            expected = projection_status(entry)
        except (KeyError, TypeError, ValueError):
            expected = None
        if status != expected:
            errors.append(f"{where}: status `{status}` does not follow from its recorded values (`{expected}`)")
        if status in ("contradicted", "not_comparable", "revised_by_model") and not entry.get("revision"):
            errors.append(f"{where}: a projection that is {status.replace('_', ' ')} needs its revision")
        if status in ("confirmed", "contradicted") and entry.get("measured") is None:
            errors.append(f"{where}: status `{status}` without a measured value")
        if status in ("not_comparable", "unmeasured", "revised_by_model") and entry.get("measured") is not None:
            errors.append(f"{where}: status `{status}` with a measured value")
    for identifier in FIXED_STATUS:
        if identifier not in seen:
            errors.append(f"projections: `{identifier}` is missing")
    if not summary.get("limits"):
        errors.append("limits is empty")


RENDER_WIDTH = 420


def _render(value: Any, depth: int) -> str:
    """JSON with scalar-only objects and arrays kept on one line when they fit."""
    pad = " " * depth
    if isinstance(value, (dict, list)):
        children = value.values() if isinstance(value, dict) else value
        if not value:
            return "{}" if isinstance(value, dict) else "[]"
        if all(not isinstance(child, (dict, list)) for child in children):
            inline = json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
            if depth + len(inline) <= RENDER_WIDTH:
                return inline
        inner = " " * (depth + 1)
        if isinstance(value, dict):
            parts = [
                f"{inner}{json.dumps(key, ensure_ascii=False)}: {_render(child, depth + 1)}"
                for key, child in value.items()
            ]
            return "{\n" + ",\n".join(parts) + "\n" + pad + "}"
        parts = [f"{inner}{_render(child, depth + 1)}" for child in value]
        return "[\n" + ",\n".join(parts) + "\n" + pad + "]"
    return json.dumps(value, ensure_ascii=False)


def render(summary: dict[str, Any]) -> str:
    return _render(summary, 0) + "\n"


def reproduction_errors(summary: dict[str, Any], tracked: str, repository: Path) -> list[str]:
    """Whether the tracked text is what the raw records of its cited runs give.

    The raw records are untracked, so this is a local check: it needs every
    cited run directory. The runs are read in the order the file lists them,
    which is the order they were given to `--refresh`.
    """
    names = [run.get("run") for run in summary["benchmark_identity"]["runs"]]
    directories = [repository / RAW_ROOT / str(name) for name in names]
    missing = [str(name) for name, directory in zip(names, directories) if not (directory / "report.json").is_file()]
    if missing:
        return [f"--reproduce: the raw records of {', '.join(missing)} are not under {RAW_ROOT}/"]
    try:
        rebuilt = build_summary(directories, repository)
    except (ValueError, KeyError, OSError) as error:
        return [f"--reproduce: the cited runs do not build a comparison ({error})"]
    if render(rebuilt) == tracked:
        return []
    differing = [key for key in rebuilt if summary.get(key) != rebuilt[key]] or ["its rendering"]
    return [f"--reproduce: the tracked comparison is not what its cited runs give; first difference in `{differing[0]}`"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument(
        "--refresh",
        nargs="+",
        type=Path,
        metavar="RUN_DIR",
        help="rebuild the tracked comparison from these harness run directories",
    )
    parser.add_argument(
        "--source-digest",
        action="store_true",
        help="print the --config value that binds a harness run to the prototype sources",
    )
    parser.add_argument(
        "--reproduce",
        action="store_true",
        help="also rebuild the comparison from the raw records it cites (untracked, under "
        f"{RAW_ROOT}/) and require the tracked file to be exactly that",
    )
    arguments = parser.parse_args(argv)
    repository = arguments.repository.resolve()
    path = repository / SUMMARY
    if arguments.source_digest:
        print(expected_config(repository))
        return 0
    if arguments.refresh:
        try:
            summary = build_summary([run.resolve() for run in arguments.refresh], repository)
        except (ValueError, KeyError, OSError) as error:
            # Records that disagree, a directory that is not a harness run, or
            # a report of another shape: say so and write nothing.
            print(f"{type(error).__name__}: {error}", file=sys.stderr)
            print(f"{SUMMARY}: not written", file=sys.stderr)
            return 1
        errors = check_summary(summary, repository)
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            print(f"{SUMMARY}: not written, {len(errors)} inconsistencies", file=sys.stderr)
            return 1
        path.write_text(render(summary))
        print(f"{SUMMARY}: written from {len(arguments.refresh)} runs")
        return 0
    if not path.is_file():
        print(f"{SUMMARY}: missing", file=sys.stderr)
        return 1
    try:
        summary = json.loads(path.read_text())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        print(f"{SUMMARY}: not a JSON document ({error})", file=sys.stderr)
        return 1
    errors = check_summary(summary, repository)
    if arguments.reproduce and not errors:
        errors = reproduction_errors(summary, path.read_text(), repository)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print(f"{SUMMARY}: {len(errors)} inconsistencies", file=sys.stderr)
        return 1
    native = len(summary["native"]["rows"])
    circuit = len(summary["in_circuit"]["rows"])
    reproduced = " It is exactly what its cited raw records give." if arguments.reproduce else ""
    print(
        f"{SUMMARY}: {native} native rows and {circuit} in-circuit rows are classified and match the tree."
        f"{reproduced} Inventory consistency only; no construction is selected or qualified."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
