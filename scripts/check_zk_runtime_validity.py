#!/usr/bin/env python3
"""Check the runtime-validity census against the source tree.

The census (specs/zk_runtime_validity_census.json, task F.4 of
specs/zk_delivery_plan.md) lists every place where the validity or
availability of a ZK, privacy, FHE or proof operation depends on something
other than committed State and the transaction bytes: an environment variable,
node-local configuration, a Cargo feature, a binary/source/catalog digest, a
chain-identity condition, a readiness or qualification record, an activation
or lifecycle switch, a global all-protocol manifest, or a wall clock.

Requires Python 3.9+ and its standard library; reads no environment variable
and needs no installed package. In a Git checkout the file list comes from
`git ls-files -co --exclude-standard`; elsewhere the tree is walked. The check
is read-only. It establishes that the census matches the tree. It does not
establish that a gate is removed, that an operation is secure or that anything
is deployed.

The check fails when
* a detector finds a site (file, detector, token, occurrence count) the census
  does not attribute to exactly one entry or one `not_gates` group, or a listed
  site is gone or occurs a different number of times;
* an entry names a path, symbol, anchor or test that does not exist, or a
  `removed` symbol that is back;
* a field of one of the node-configuration policy catalogs recorded by
  specs/zk_resource_contract.json is not assigned to exactly one entry;
* a Cargo feature of a scanned crate is not classified, or a classified one
  is gone;
* an entry has an unknown kind, status or owner task, an open entry has no
  reason, or a `done` entry names no test and no removal;
* the detector table in the census differs from the one compiled into this
  script (a detector cannot be narrowed by editing only the census).

Besides gate names the scan detects: every installation of a complete ZK or
pipeline settings value into a State, every write to a `zk` or `pipeline`
settings field (plain and compound assignment), every mutable borrow or
`clone_from` of one, and every production use of a protocol-default gas
schedule or settings value (`DEFAULT_ZK_GAS`, `Zk::default()`,
`ConfidentialGas::default()`, `Pipeline::default()`); every
read of a field of the node-configuration policy catalogs that is not committed
yet (named by the catalog field it reaches, from the resource contract); the
confidential switches of the P2P handshake; clock readings and reviewer or
approval names in Core's admission, execution, validation and publication
files outside the proof path; and comparisons with a literal network name in
the crates that decide or verify.

Two classes of an identifier hit are derived from the source, not from the
name: an identifier that is the name of a lifecycle enum whose variants only
say whether a committed record is still in force (`Active`/`Revoked`, with or
without `Superseded`) is class `revocation_state`, and an identifier that is a
`const NAME: bool = true` is class `constant_true`. A new variant or a
constant set to `false` moves the hits to another class, which the census
does not list, so the check fails until the entry is read again. A `bool`
constant on the proof path that is `false` and named as an availability or
completion flag is a row of its own (detector `unfinished_constant`).

Limits of the check:
* Rust is read as text with comments and literal contents masked and inline
  test items blanked, not with a compiler. A gate written with none of the
  detected names, or built by a macro, is invisible to it.
* A node-policy field read through a local variable instead of a field path,
  and a result selected under a Cargo feature the census does not classify as
  a gate, are not seen.
* Test-only files are recognized by name and by `#[cfg(test)] mod name;`
  declarations, including one renamed with `#[path = "file.rs"]`. A production
  file with a test-like name is not scanned.
* Counts are occurrences of a detector token in a file. Moving a gate inside a
  file without changing its tokens is not seen.

Maintainer modes (the default run changes nothing):
* `--print-scan` prints the fresh scan as JSON (path, detector, token, count).
* `--propose` prints, for every unattributed site, the row to add.
* `--refresh` rewrites only occurrence counts of rows that still exist and
  prints each change; it never adds, removes or reclassifies a row.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CENSUS = "specs/zk_runtime_validity_census.json"
RESOURCE_CONTRACT = "specs/zk_resource_contract.json"
DELIVERY_GRAPH = "specs/zk_delivery_graph.json"
SCHEMA = "iroha.zk_runtime_validity_census.v1"

KINDS = (
    "environment",
    "node_local_config",
    "cargo_feature",
    "digest",
    "chain_identity",
    "readiness_qualification",
    "activation_lifecycle",
    "global_manifest",
    "wall_clock",
)
STATUSES = ("open", "done", "unsupported", "local_resource")

# Production Rust sources scanned for gates: the crates on the proof,
# privacy, FHE and execution path, the node with its configuration, P2P
# handshake and Torii, the genesis and deployment tools, the test network, the
# command line, the Rust SDK and the native bridges the other SDKs call.
RUST_CRATES = (
    "connect_norito_bridge",
    "fastpq_isi",
    "fastpq_prover",
    "iroha",
    "iroha_cli",
    "iroha_config",
    "iroha_core",
    "iroha_core_privacy",
    "iroha_core_timed_ovn",
    "iroha_core_zk",
    "iroha_crypto",
    "iroha_data_model",
    "iroha_deploy",
    "iroha_fhe",
    "iroha_genesis",
    "iroha_js_host",
    "iroha_kagami",
    "iroha_p2p",
    "iroha_plonk",
    "iroha_plonk_gadgets",
    "iroha_plonk_oracle",
    "iroha_test_network",
    "iroha_torii",
    "iroha_torii_shared",
    "iroha_zkp_halo2",
    "irohad",
    "ivm",
    "kaigi_zk",
    "zk_ace_prover",
)
# SDK sources scanned for availability checks (file-level rows).
SDK_ROOTS = (
    "IrohaSwift/Sources",
    "csharp/src",
    "javascript/iroha_js/src",
    "kotlin/client-android/src/main",
    "kotlin/core-jvm/src/main",
    "kotlin/kagemusha-wallet-android/src/main",
    "python/iroha_python",
    "python/iroha_torii_client",
)
SDK_SUFFIXES = (".swift", ".kt", ".java", ".js", ".ts", ".mjs", ".py", ".cs")

# A file is on the ZK, privacy, FHE or proof path when its repository path
# matches this expression; an identifier is on it when its text does. A
# detector marked `family` counts every hit in such a file and, elsewhere,
# only identifiers that are themselves on the path (text detectors marked
# `family` scan only such files).
FAMILY_PATH = re.compile(
    r"(privacy|zk|confidential|ram_?lfe|fhe|bfv|bgv|mkhe|soracloud|kaigi|proof|"
    r"verifying_?key|x509|masp|orchard|fcmp|vega|jindo|pgc|verange|lantern|bootle|"
    r"ballot|timed_?ovn|axt|fastpq|kagemusha|stark|halo2|plonk|sccp|preverify|exact_?12)",
    re.IGNORECASE,
)

TEST_PATH = re.compile(
    r"(^|/)(tests?|benches|examples|fixtures|bin)(/|$)"
    r"|(^|/)tests?\.rs$"
    r"|_tests?(_[0-9a-z]+)?\.rs$"
    r"|(^|/)test_[^/]*\.rs$"
    r"|test_(support|helpers|utils|fixtures|chain|samples)"
    r"|_fixtures?(_v[0-9]+)?\.rs$"
    r"|(^|/)[^/]*_bench[^/]*\.rs$"
)


# Crates whose code decides or verifies; clock detectors scan only these.
VERIFICATION_CRATES = (
    r"^crates/(?:fastpq_isi|iroha_core|iroha_core_privacy|iroha_core_timed_ovn|iroha_core_zk|"
    r"iroha_crypto|iroha_data_model|iroha_fhe|iroha_zkp_halo2|ivm|kaigi_zk|zk_ace_prover)/"
)


# Core files that admit, execute, validate and publish every transaction and
# block, whatever their path says: the clock and review detectors scan them
# even where they are not on the proof path.
CORE_VALIDATION_FILES = (
    r"^crates/iroha_core/src/(?:queue|tx|block|executor|gas|state)\.rs$|"
    r"^crates/iroha_core/src/(?:smartcontracts|pipeline|block|state)/"
)


class Detector:
    """One detection pattern: its kind, where it applies and how a hit is named.

    A `text` detector counts every match in the masked source. An `identifier`
    detector counts each identifier that contains a match once, named by the
    leftmost match inside it. `needles` are plain substrings one of which a file
    must contain before a `text` pattern is run on it; they only save time.
    """

    def __init__(self, ident: str, kind: str, pattern: str, *, what: str,
                 mode: str = "text", strings: bool = False, family: bool = False,
                 paths: Optional[str] = None, token: str = "match",
                 needles: tuple[str, ...] = (), outside_family: bool = False) -> None:
        self.ident = ident
        self.kind = kind
        self.pattern = pattern
        self.regex = re.compile(pattern)
        self.what = what
        self.mode = mode
        # Scan the text with string literals kept (True) or blanked (False).
        self.strings = strings
        # Scan only files on the ZK, privacy, FHE or proof path.
        self.family = family
        # Scan only files whose path matches this expression.
        self.paths = re.compile(paths) if paths else None
        self.paths_source = paths
        # How a hit is named: `match` (the matched text), `group` (the first
        # non-empty group) or `class` (the name of the first non-empty named group).
        self.token = token
        self.needles = needles
        # Scan only files that are not on the ZK, privacy, FHE or proof path
        # (the family detectors already cover those).
        self.outside_family = outside_family

    def applies(self, path: str) -> bool:
        if self.paths is not None and not self.paths.search(path):
            return False
        if self.outside_family and FAMILY_PATH.search(path):
            return False
        if self.family and self.mode == "text" and not FAMILY_PATH.search(path):
            return False
        return True

    def describe(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "kind": self.kind, "what": self.what, "mode": self.mode, "pattern": self.pattern,
        }
        if self.family:
            record["family_files_only"] = True
        if self.outside_family:
            record["outside_family_files_only"] = True
        if self.paths_source:
            record["paths"] = self.paths_source
        return record

    def _name(self, match: "re.Match[str]") -> str:
        if self.token == "catalog_field":
            return catalog_field_token(match.group(1), match.group(2))
        if self.token == "group":
            return next((group for group in match.groups() if group), "") or "<expression>"
        if self.token == "class":
            return next((key for key, value in match.groupdict().items() if value), "") or "<unnamed>"
        return re.sub(r"\s+", "", match.group(0))

    def identifier_token(self, identifier: str) -> Optional[str]:
        """The token of an identifier this detector matches, or None."""
        match = self.regex.search(identifier)
        return self._name(match) if match else None

    def hits(self, text: str) -> Counter:
        """Token -> occurrence count of a `text` detector in one file."""
        found: Counter = Counter()
        if self.needles and not any(needle in text for needle in self.needles):
            return found
        for match in self.regex.finditer(text):
            name = self._name(match)
            if name:
                found[name] += 1
        return found


# Field paths of the node-configuration policy catalogs, filled from the
# resource contract before a scan: dotted read path -> catalog field name.
CATALOG_FIELD_PATHS: dict[str, str] = {}
# Section names as State and services spell them -> the catalog's spelling.
_SECTION_ALIASES = {"gov": "governance"}


def set_catalog_field_paths(contract: Any) -> None:
    """Record the catalog fields a `node_policy_read` hit is named by."""
    CATALOG_FIELD_PATHS.clear()
    for catalog in contract.get("catalogs", []) if isinstance(contract, dict) else []:
        if catalog.get("id") not in ("execution_policy_digest_v1", "nexus_consensus_policy_v1"):
            continue
        prefix = "nexus." if catalog["id"] == "nexus_consensus_policy_v1" else ""
        names = list(catalog.get("fields", {}))
        for group in catalog.get("excluded", []):
            names.extend(group.get("fields", []))
        for name in names:
            CATALOG_FIELD_PATHS[prefix + name] = name


def catalog_field_token(section: str, tail: str) -> str:
    """The catalog field a read of `.section.a.b.c` reaches, or '' when none.

    The longest prefix of the path that is a catalog field names the hit. A
    read that stops at a group of fields is named `<group>.*`.
    """
    segments = [_SECTION_ALIASES.get(section, section)]
    segments += [part for part in re.split(r"[\s.()]+", tail) if part]
    for length in range(len(segments), 0, -1):
        path = ".".join(segments[:length])
        if path in CATALOG_FIELD_PATHS:
            return CATALOG_FIELD_PATHS[path]
    for length in range(len(segments), 1, -1):
        path = ".".join(segments[:length]) + "."
        for known, name in CATALOG_FIELD_PATHS.items():
            if known.startswith(path):
                group = name[: len(name) - (len(known) - len(path))]
                return group + "*"
    return ""


RUST_DETECTORS = (
    Detector(
        "env_read", "environment",
        r"\b(?:env::var_os|env::var|env::vars|option_env!)\s*\(\s*(?:\"([^\"]*)\"|([A-Za-z_][A-Za-z0-9_:]*))?",
        what="A process environment variable or a build-time environment value is read.",
        strings=True, token="group", needles=("env::var", "option_env!"),
    ),
    Detector(
        "config_env_alias", "environment",
        r"\benv\s*=\s*\"([A-Z0-9_]+)\"",
        what="A node-configuration field can be set from a process environment variable.",
        strings=True, token="group", paths=r"^crates/iroha_config/src/", needles=("env",),
    ),
    Detector(
        "dev_env_flag", "environment",
        r"\bdev_env_flag\b",
        what="A developer environment flag is consulted.",
        token="match", needles=("dev_env_flag",),
    ),
    Detector(
        "config_switch", "node_local_config",
        r"\b(?:halo2|stark|confidential|zk|zk_cfg|zk_config)\w*(?:\(\))?\s*\.\s*(?:(?:halo2|stark)\s*\.\s*)?"
        r"(enabled|assume_valid)\b",
        what="An enable or assume-valid switch of the [zk] or [confidential] node configuration is read.",
        token="group", needles=("enabled", "assume_valid"),
    ),
    Detector(
        "node_config_read", "node_local_config",
        r"\b(?:config|cfg|configuration)\s*\.\s*(zk|confidential)\b",
        what="A service reads the [zk] or [confidential] section of the node configuration directly.",
        token="group", needles=("zk", "confidential"),
    ),
    Detector(
        "handshake_switch", "node_local_config",
        r"\b(assume_valid|verifier_backend)\b",
        what="The confidential capability a node advertises in the P2P handshake from its own "
             "configuration (`confidential.enabled`, `assume_valid`, `verifier_backend`) is read, "
             "carried or compared.",
        token="group", paths=r"^crates/(?:iroha_p2p|irohad|iroha_config|iroha_test_network|iroha_deploy)/",
        needles=("assume_valid", "verifier_backend"),
    ),
    Detector(
        "zk_settings_install", "node_local_config",
        r"\.\s*(set_zk|install_zk_for_isolated_prevalidation)\s*\(",
        what="A complete ZK settings value, validity values included, is installed into a State. "
             "Production code installs local resources only (State::install_node_zk); the complete "
             "installer exists in test builds, so every production call site is a defect.",
        token="group", needles=("set_zk", "install_zk_for_isolated_prevalidation"),
    ),
    Detector(
        "zk_settings_write", "node_local_config",
        r"\.\s*zk\s*(?:\.\s*([a-z_][a-z0-9_]*))?(?:\s*\.\s*[a-z_][a-z0-9_]*)*\s*"
        r"(?:[-+*/%|&^]|<<|>>)?=(?!=)",
        what="A field named `zk` (the ZK settings of a State or of a configuration value) is "
             "assigned, with `=` or a compound operator, named by the first field written below "
             "it. Production code may write local resource settings only; every other write is a "
             "defect.",
        token="group", needles=("zk",),
    ),
    Detector(
        "pipeline_settings_install", "node_local_config",
        r"\.\s*(set_pipeline)\s*\(",
        what="A complete pipeline settings value, execution limits included, is installed into a "
             "State. Production code installs local resources only (State::install_node_pipeline); "
             "the complete installer exists in test builds, so every production call site is a defect.",
        token="group", needles=("set_pipeline",),
    ),
    Detector(
        "pipeline_settings_write", "node_local_config",
        r"\.\s*pipeline\s*(?:\.\s*([a-z_][a-z0-9_]*))?(?:\s*\.\s*[a-z_][a-z0-9_]*)*\s*"
        r"(?:[-+*/%|&^]|<<|>>)?=(?!=)",
        what="A field named `pipeline` (the pipeline settings of a State or of a configuration "
             "value) is assigned, with `=` or a compound operator, named by the first field "
             "written below it. Production code may write local resource settings only; every "
             "other write is a defect.",
        token="group", needles=("pipeline",),
    ),
    Detector(
        "settings_mut_borrow", "node_local_config",
        r"&\s*mut\s+[A-Za-z_][A-Za-z0-9_.()]*\.\s*(zk|pipeline)\b(?!\s*\()|"
        r"\.\s*(zk|pipeline)\s*(?:\.\s*[a-z_][a-z0-9_]*)*\s*\.\s*clone_from\s*\(",
        what="A field named `zk` or `pipeline` is borrowed mutably (`&mut x.zk`, which is also how "
             "`mem::replace`, `mem::swap` and `mem::take` reach it) or overwritten with "
             "`clone_from`, named by the field. The settings fields of `State` are private, so "
             "outside the State modules such a line does not compile; inside them every site is "
             "listed.",
        token="group", needles=("zk", "pipeline"),
    ),
    Detector(
        "default_validity_settings", "node_local_config",
        r"\b(DEFAULT_ZK_GAS)\b|\b((?:Zk|ConfidentialGas|Pipeline)::default)\s*\(",
        what="Production code names the protocol-default verification gas schedule "
             "(`DEFAULT_ZK_GAS`) or builds a default ZK, gas or pipeline settings value "
             "(`Zk::default()`, `ConfidentialGas::default()`, `Pipeline::default()`). Metering, "
             "admission and fee bounds must take the schedule and limits frozen in the block or "
             "view they execute in; a default value passed to a meter, a host or a quote instead "
             "is a defect, so every site is listed.",
        token="group", needles=("DEFAULT_ZK_GAS", "::default"),
    ),
    Detector(
        "node_policy_read", "node_local_config",
        r"\.\s*(pipeline|nexus|gov|crypto|oracle|fraud_monitoring|content|settlement)"
        r"((?:\s*(?:\(\))?\s*\.\s*[a-z_][a-z0-9_]*){1,3})",
        what="State, a block, a view or a service reads a field of the node-configuration policy "
             "sections whose validity values are not committed yet ([pipeline], [nexus], [gov], "
             "[crypto], [oracle], [fraud_monitoring], [content], [settlement]). A row is recorded "
             "when the path read is a field of one of the catalogs the resource contract records, "
             "named by the catalog field it reaches.",
        token="catalog_field", paths=r"^crates/(?:iroha_core|iroha_core_privacy|iroha_core_zk|"
        r"iroha_core_timed_ovn|iroha_torii|irohad)/",
        needles=("pipeline", "nexus", "gov", "crypto", "oracle", "fraud_monitoring", "content",
                 "settlement"),
    ),
    Detector(
        "feature_cfg", "cargo_feature",
        r"\bfeature\s*=\s*\"([A-Za-z0-9_-]+)\"",
        what="Code is compiled or selected under a Cargo feature. Rows are required only for "
             "features the census classifies as validity or availability gates.",
        strings=True, token="group", needles=("feature",),
    ),
    Detector(
        "digest_identity", "digest",
        r"(?<![a-z])(?:(?P<source>[Ss]ource|SOURCE)|(?P<binary>[Bb]inary|BINARY|[Ee]xecutable|EXECUTABLE)|"
        r"(?P<build>(?!build_sha[0-9]*_[a-z])(?:[Bb]uild|BUILD)|[Gg]it|GIT|"
        r"(?:rustc|RUSTC)_(?:commit|COMMIT))|"
        r"(?P<catalog>[Cc]atalog|CATALOG)|(?P<release>[Rr]elease|RELEASE))_?"
        r"(?:[Dd]igest|DIGEST|[Hh]ash|HASH|[Ss]ha|SHA|[Ff]ingerprint|FINGERPRINT)(?![a-z])",
        what="An identifier on the ZK, privacy, FHE or proof path names a source, binary, build, "
             "catalog or release digest. The class word starts a word of the identifier and the "
             "digest word ends one, so `resource_shape` and `ReleaseShare` do not match; a plain "
             "`commit_hash` or `commit_digest` is a commitment value and is not matched, and a "
             "builder function named `build_sha<bits>_<what>` (the verb `build` followed by a hash "
             "function and the thing built, such as `build_sha256_word_circuit_v1`) is not a build "
             "digest and is not matched.",
        mode="identifier", token="class", family=True,
    ),
    Detector(
        "chain_condition", "chain_identity",
        r"(?P<production>is_production|production_chain|production_network|IsProduction)|"
        r"(?P<integration>is_integration|integration_chain|integration_root|IntegrationRoot)|"
        r"(?P<testnet>is_testnet|testnet_only|allow_testnet|AllowTestnet|experimental_release)|"
        r"(?P<mainnet>is_mainnet|mainnet_only)|"
        r"(?P<pinned_chain>pinned_chain|PinnedChain|pinned_network|PinnedNetwork)",
        what="An identifier names a production, integration, testnet, mainnet or pinned-chain condition.",
        mode="identifier", token="class",
    ),
    Detector(
        "chain_literal", "chain_identity",
        r"(?:==|!=)\s*\"([^\"\n]*(?:[Mm]inamoto|[Tt]aira|[Mm]ainnet|[Tt]estnet|[Dd]evnet)[^\"\n]*)\"|"
        r"\"([^\"\n]*(?:[Mm]inamoto|[Tt]aira|[Mm]ainnet|[Tt]estnet|[Dd]evnet)[^\"\n]*)\"\s*(?:==|!=|=>)",
        what="A value is compared with, or matched against, a string literal that names a network "
             "(minamoto, taira, mainnet, testnet, devnet) in a crate that decides or verifies.",
        strings=True, token="group", paths=VERIFICATION_CRATES,
        needles=("inamoto", "aira", "ainnet", "estnet", "evnet"),
    ),
    Detector(
        "qualification", "readiness_qualification",
        r"(?P<qualification>(?<![Ff]ully_)(?<![Ff]ully)(?<!FULLY_)(?:[Qq]ualif|QUALIF))|"
        r"(?P<readiness>[Rr]eadiness|READINESS)|"
        r"(?P<reviewer>[Rr]eviewer|REVIEWER|[Ss]ignoff|SIGNOFF|[Ss]ign_off|SIGN_OFF|"
        r"[Aa]udit_?[Cc]ertificate|AUDIT_CERTIFICATE)",
        what="An identifier on the ZK, privacy, FHE or proof path names a qualification, a readiness "
             "record, a reviewer or an audit signoff. `fully_qualified` (a complete `name@domain` "
             "identifier, as in `parse_fully_qualified`) is a parsing term and is not matched.",
        mode="identifier", token="class", family=True,
    ),
    Detector(
        "activation", "activation_lifecycle",
        r"(?P<activation>[Aa]ctivat|ACTIVAT)|(?P<lifecycle>[Ll]ifecycle|LIFECYCLE)",
        what="An identifier on the ZK, privacy, FHE or proof path names an activation or a lifecycle. "
             "Class `revocation_state` is derived from the source: the identifier is the name of a "
             "lifecycle enum whose variants are exactly `Active` and `Revoked`, or `Active`, "
             "`Superseded` and `Revoked`, the in-force state of a committed record. Class "
             "`constant_true` (any identifier detector) is a `const NAME: bool = true`.",
        mode="identifier", token="class", family=True,
    ),
    Detector(
        "unavailable", "activation_lifecycle",
        r"(?P<local_resource>(?:[Rr]andom(?:ness)?|RANDOM(?:NESS)?|[Ee]ntropy|ENTROPY|[Rr]ng|RNG|"
        r"[Aa]llocation|ALLOCATION|[Ss]torage|STORAGE|[Dd]evice|DEVICE|[Gg]pu|GPU|[Cc]uda|CUDA|"
        r"[Hh]ost|HOST|[Cc]apacity|CAPACITY)[A-Za-z0-9]*_?(?:[Uu]navailable|UNAVAILABLE)|"
        r"(?:[Uu]navailable|UNAVAILABLE)_?[A-Za-z0-9_]*(?:Rng|RNG|rng|[Ee]ntropy|ENTROPY)|"
        r"(?:[Uu]nsupported|UNSUPPORTED)_?(?:[Pp]latform|PLATFORM))|"
        r"(?P<version_check>(?:[Uu]nsupported|UNSUPPORTED)_?[A-Za-z0-9]*_?(?:[Vv]ersion|VERSION))|"
        r"(?P<unavailable>[Uu]navailable|UNAVAILABLE)|(?P<suspended>[Ss]uspend|SUSPEND)|"
        r"(?P<unsupported>[Uu]nsupported|UNSUPPORTED|[Nn]ot_?[Ii]mplemented|NOT_IMPLEMENTED)",
        what="An identifier on the ZK, privacy, FHE or proof path names an unavailable, suspended or "
             "unsupported outcome. Class `local_resource` is a failure of this node's entropy, "
             "allocator, storage, accelerator, host or platform; class `version_check` is the "
             "rejection of an encoding version this release does not define; the other classes are "
             "either a gate or the accurate error of an unfinished operation.",
        mode="identifier", token="class", family=True,
    ),
    Detector(
        "unfinished_constant", "activation_lifecycle",
        r"\bconst\s+[A-Z][A-Z0-9_]*(?:AVAILABLE|IMPLEMENTED|QUALIFIED|READY|SUPPORTED|WIRED|COMPLETE|"
        r"VERIFIED|INTEGRATED)[A-Z0-9_]*\s*:\s*bool\s*=\s*(false)\s*;",
        what="A file on the ZK, privacy, FHE or proof path defines a `bool` constant set to `false` "
             "whose name says that something is available, implemented, qualified, ready, supported, "
             "wired, complete, verified or integrated: the compile-time record of an unfinished "
             "step, which the code that reads it turns into a refusal or a not-ready status.",
        token="group", family=True, needles=("bool",),
    ),
    Detector(
        "global_manifest", "global_manifest",
        r"(?P<exact12>[Ee]xact_?12|EXACT_?12)|(?P<capability_manifest>[Cc]apability_?[Mm]anifest|"
        r"CAPABILITY_MANIFEST|[Cc]apability_?[Aa]rchive|CAPABILITY_ARCHIVE)|"
        r"(?P<release_manifest>[Rr]elease_?[Mm]anifest|RELEASE_MANIFEST)|"
        r"(?P<availability_pin>[Aa]vailability_?[Pp]in|AVAILABILITY_PIN|[Zz]ero_?[Pp]in|ZERO_PIN)",
        what="An identifier names the Exact12 catalog, a capability or release manifest, or an availability pin.",
        mode="identifier", token="class",
    ),
    Detector(
        "wall_clock", "wall_clock",
        r"(?P<instant>\bInstant::now\b)|(?P<system_time>\bSystemTime::now\b|\bUNIX_EPOCH\b)|"
        r"(?P<elapsed>\.\s*elapsed\s*\()",
        what="A wall clock or an elapsed-time reading on the ZK, privacy, FHE or proof path.",
        token="class", family=True, paths=VERIFICATION_CRATES,
        needles=("Instant::now", "SystemTime::now", "UNIX_EPOCH", "elapsed"),
    ),
    Detector(
        "core_wall_clock", "wall_clock",
        r"(?P<instant>\bInstant::now\b)|(?P<system_time>\bSystemTime::now\b|\bUNIX_EPOCH\b)|"
        r"(?P<elapsed>\.\s*elapsed\s*\()",
        what="A wall clock or an elapsed-time reading in Core's admission, execution, validation "
             "and publication files that are not on the proof path (the `wall_clock` detector covers "
             "those that are).",
        token="class", paths=CORE_VALIDATION_FILES, outside_family=True,
        needles=("Instant::now", "SystemTime::now", "UNIX_EPOCH", "elapsed"),
    ),
    Detector(
        "core_review_gate", "readiness_qualification",
        r"(?P<reviewer>[Rr]eviewer|REVIEWER|[Ss]ignoff|SIGNOFF|[Ss]ign_off|SIGN_OFF|"
        r"[Aa]udit_?[Cc]ertificate|AUDIT_CERTIFICATE|[Aa]pproved_?[Bb]y|APPROVED_BY)",
        what="An identifier in Core's admission, execution, validation and publication files that "
             "are not on the proof path names a reviewer, a signoff, an audit certificate or an "
             "approval.",
        mode="identifier", token="class", paths=CORE_VALIDATION_FILES, outside_family=True,
    ),
    Detector(
        "time_budget", "wall_clock",
        r"(?P<height_deadline>(?:[Dd]eadline|DEADLINE)_?(?:[Hh]eight|HEIGHT|[Bb]lock|BLOCK|[Ee]poch|EPOCH)|"
        r"(?:[Hh]eight|HEIGHT|[Bb]lock|BLOCK|[Ee]poch|EPOCH)_?(?:[Dd]eadline|DEADLINE))|"
        r"(?P<deadline_outcome>(?:[Dd]eadline|DEADLINE)_?(?:[Ee]xpired|EXPIRED))|"
        r"(?P<timeout>[Tt]imeout|TIMEOUT)|(?P<deadline>[Dd]eadline|DEADLINE)|"
        r"(?P<budget_ms>budget_ms|BUDGET_MS)",
        what="An identifier on the ZK, privacy, FHE or proof path names a timeout, a deadline or a "
             "millisecond budget. Class `height_deadline` is a deadline expressed as a block height "
             "or epoch, which is committed State and not a clock. Class `deadline_outcome` names the "
             "outcome of a deadline that has passed (`...DeadlineExpired`), a failure kind recorded "
             "from committed State.",
        mode="identifier", token="class", family=True, paths=VERIFICATION_CRATES,
    ),
)

SDK_DETECTORS = (
    Detector(
        "sdk_availability", "readiness_qualification",
        r"(?P<qualification>[Qq]ualif|QUALIF)|(?P<readiness>[Rr]eadiness|READINESS)|"
        r"(?P<capability_manifest>[Cc]apability_?[Mm]anifest|CAPABILITY_MANIFEST)|"
        r"(?P<release_manifest>[Rr]elease_?[Mm]anifest|RELEASE_MANIFEST)|"
        r"(?P<exact12>[Ee]xact_?12|EXACT_?12)",
        what="An SDK source names a qualification, a readiness record, a capability or release "
             "manifest or the Exact12 catalog (one row per file and class).",
        strings=True, token="class",
    ),
)

# Variant sets of a lifecycle enum that only records whether a committed record
# is still in force. Nothing is activated: the record is usable from its
# registration and can be revoked, or superseded by a newer version.
REVOCATION_VARIANT_SETS = (
    frozenset({"Active", "Revoked"}),
    frozenset({"Active", "Superseded", "Revoked"}),
)
_LIFECYCLE_ENUM = re.compile(r"\benum\s+([A-Za-z0-9_]*Lifecycle[A-Za-z0-9_]*)\s*\{")
_BOOL_CONSTANT = re.compile(r"\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*bool\s*=\s*(true|false)\s*;")
_ATTRIBUTE = re.compile(r"#\s*\[[^\]]*\]")


def enum_variants(code: str, open_at: int) -> frozenset:
    """Variant names of the enum whose body opens at `open_at` in masked code."""
    body = code[open_at + 1:_matching_brace(code, open_at)]
    depth = 0
    flat: list[str] = []
    for char in body:
        if char in "{(":
            depth += 1
        elif char in "})":
            depth -= 1
        elif depth == 0:
            flat.append(char)
    text = _ATTRIBUTE.sub("", "".join(flat))
    names = (item.split("=")[0].strip() for item in text.split(","))
    return frozenset(name for name in names if name)


DETECTORS = {detector.ident: detector for detector in RUST_DETECTORS + SDK_DETECTORS}
IDENTIFIER_DETECTORS = tuple(detector for detector in RUST_DETECTORS if detector.mode == "identifier")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# ---------------------------------------------------------------------------
# Source reading
# ---------------------------------------------------------------------------

def list_repository_files(root: Path) -> list[str]:
    """Tracked and unignored files, or every file when `root` is not a Git checkout."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard"],
            check=True, capture_output=True, text=True,
        )
        files = [line for line in result.stdout.splitlines() if line]
        if files:
            return sorted(set(files))
    except (OSError, subprocess.CalledProcessError):
        pass
    return sorted(
        str(path.relative_to(root)).replace("\\", "/")
        for path in root.rglob("*") if path.is_file()
    )


_RUST_TOKEN = re.compile(
    r"//[^\n]*"
    r"|/\*"
    r"|(?<![A-Za-z0-9_])(?:br|rb|r)(#*)\""
    r"|b?\"(?:[^\"\\]|\\.)*\""
    r"|b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,8}\}|.)|[^'\\\n])'",
    re.DOTALL,
)
_BLOCK_COMMENT_EDGE = re.compile(r"/\*|\*/")
_NOT_NEWLINE = re.compile(r"[^\n]")


def _spaces(text: str) -> str:
    return _NOT_NEWLINE.sub(" ", text)


def mask_rust(source: str) -> tuple[str, str]:
    """Return (code, code_with_strings): comments blanked in both, literal
    contents blanked in the first. Offsets and newlines are preserved."""
    code: list[str] = []
    with_strings: list[str] = []
    position = 0
    length = len(source)
    while position < length:
        match = _RUST_TOKEN.search(source, position)
        if match is None:
            break
        start = match.start()
        plain = source[position:start]
        code.append(plain)
        with_strings.append(plain)
        token = match.group(0)
        if token.startswith("//"):
            end = match.end()
            blank = _spaces(source[start:end])
            code.append(blank)
            with_strings.append(blank)
        elif token == "/*":
            depth = 1
            end = match.end()
            while depth:
                edge = _BLOCK_COMMENT_EDGE.search(source, end)
                if edge is None:
                    end = length
                    break
                depth += 1 if edge.group(0) == "/*" else -1
                end = edge.end()
            blank = _spaces(source[start:end])
            code.append(blank)
            with_strings.append(blank)
        elif match.group(1) is not None:
            terminator = '"' + match.group(1)
            close = source.find(terminator, match.end())
            close = length if close < 0 else close
            end = min(length, close + len(terminator))
            code.append(token + _spaces(source[match.end():close]) + source[close:end])
            with_strings.append(source[start:end])
        else:
            end = match.end()
            quote = token.index('"') if '"' in token[:2] else token.index("'")
            code.append(token[:quote + 1] + _spaces(token[quote + 1:-1]) + token[-1])
            with_strings.append(token)
        position = end
    tail = source[position:]
    code.append(tail)
    with_strings.append(tail)
    return "".join(code), "".join(with_strings)


TEST_ATTRIBUTE = re.compile(r"#\s*\[\s*(?:cfg\s*\(([^\]]*)\)|(?:[a-z_]+::)*test\b[^\]]*)\s*\]")
_FOLLOWING_ATTRIBUTES = re.compile(r"(?:\s*#\s*\[[^\]]*\])*\s*")
_ITEM_START = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:unsafe\s+)?(?:async\s+)?(?:const\s+)?(?:extern\s*(?:\"[^\"]*\"\s*)?)?"
    r"(fn|mod|impl|struct|enum|union|trait|const|static|type|use|macro_rules)\b"
)
_MODULE_DECLARATION = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
_PATH_ATTRIBUTE = re.compile(r"#\s*\[\s*path\s*=\s*\"([^\"\n]+)\"\s*\]")
_BRACKET = re.compile(r"[()\[\]{};,]")
_BRACE = re.compile(r"[{}]")


def is_test_cfg(expression: Optional[str]) -> bool:
    """Whether a cfg expression selects test builds (and is not `not(test)`)."""
    if expression is None:
        return True  # a `#[test]`-like attribute
    return re.search(r"\btest\b", re.sub(r"not\s*\(\s*test\s*\)", "", expression)) is not None


def _matching_brace(code: str, open_at: int) -> int:
    """Offset just after the brace that closes the one at `open_at`."""
    depth = 0
    for edge in _BRACE.finditer(code, open_at):
        depth += 1 if edge.group(0) == "{" else -1
        if depth == 0:
            return edge.end()
    return len(code)


def _attributed_end(code: str, start: int) -> int:
    """Offset just after the item, field, arm or statement that starts at `start`."""
    if code.startswith("{", start):
        return _matching_brace(code, start)
    is_item = _ITEM_START.match(code, start) is not None
    depth = 0
    for edge in _BRACKET.finditer(code, start):
        char = edge.group(0)
        if char in "([":
            depth += 1
        elif char in ")]":
            if depth == 0:
                return edge.start()
            depth -= 1
        elif char == "{":
            if depth == 0 and is_item:
                return _matching_brace(code, edge.start())
            if depth == 0:
                # A block inside a field initializer, arm or statement: skip it.
                closed = _matching_brace(code, edge.start())
                return _attributed_end_after_block(code, closed)
            depth += 1
        elif char == "}":
            if depth == 0:
                return edge.start()
            depth -= 1
        elif char == ";" and depth == 0:
            return edge.end()
        elif char == "," and depth == 0 and not is_item:
            return edge.end()
    return len(code)


def _attributed_end_after_block(code: str, closed: int) -> int:
    """A non-item construct continues after a block only up to its `,` or `;`."""
    tail = re.match(r"\s*[,;]", code[closed:closed + 64])
    return closed + tail.end() if tail else closed


def blank_test_items(code: str, with_strings: str) -> tuple[str, str, list[str]]:
    """Blank inline constructs compiled only for tests; return the names of
    out-of-line modules declared only for tests. A declaration that carries
    `#[path = "file.rs"]` is also returned as `path:file.rs`."""
    modules: list[str] = []
    ranges: list[tuple[int, int]] = []
    covered = 0
    for match in TEST_ATTRIBUTE.finditer(code):
        if match.start() < covered or not is_test_cfg(match.group(1)):
            continue
        start = _FOLLOWING_ATTRIBUTES.match(code, match.end()).end()
        declaration = _MODULE_DECLARATION.match(code, start)
        if declaration:
            # `#[path = "file.rs"]` names the file instead of the module name.
            renamed = _PATH_ATTRIBUTE.search(with_strings, match.start(), start)
            if renamed:
                modules.append(f"path:{renamed.group(1)}")
            modules.append(declaration.group(1))
            end = declaration.end()
        else:
            end = _attributed_end(code, start)
        ranges.append((match.start(), end))
        covered = end
    if not ranges:
        return code, with_strings, modules
    code_parts: list[str] = []
    string_parts: list[str] = []
    position = 0
    for start, end in ranges:
        code_parts.append(code[position:start])
        string_parts.append(with_strings[position:start])
        blank = _spaces(code[start:end])
        code_parts.append(blank)
        string_parts.append(blank)
        position = end
    code_parts.append(code[position:])
    string_parts.append(with_strings[position:])
    return "".join(code_parts), "".join(string_parts), modules


class Scan:
    """The fresh scan of a tree: (path, detector, token) -> occurrence count."""

    def __init__(self, root: Path, files: Optional[Iterable[str]] = None) -> None:
        self.root = root
        self.files = sorted(files) if files is not None else list_repository_files(root)
        self.file_set = set(self.files)
        self._text: dict[str, Optional[str]] = {}
        self.rows: Counter = Counter()
        self.test_only: set[str] = set()
        self.feature_rows: Counter = Counter()
        # Source-derived identifier classes (see `token_of`).
        self.revocation_enums: set[str] = set()
        self.true_constants: set[str] = set()
        contract_text = self.text(RESOURCE_CONTRACT) if RESOURCE_CONTRACT in self.file_set else None
        try:
            set_catalog_field_paths(json.loads(contract_text) if contract_text else {})
        except json.JSONDecodeError:
            set_catalog_field_paths({})
        self._scan()

    def text(self, path: str) -> Optional[str]:
        if path not in self._text:
            try:
                self._text[path] = (self.root / path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                self._text[path] = None
        return self._text[path]

    def token_of(self, detector: Detector, identifier: str) -> Optional[str]:
        """The token `detector` gives `identifier`, with the source-derived classes."""
        token = detector.identifier_token(identifier)
        if token is None:
            return None
        if identifier in self.true_constants:
            return "constant_true"
        if detector.ident == "activation" and identifier in self.revocation_enums:
            return "revocation_state"
        return token

    def _derive_source_classes(self, masked: dict[str, tuple[str, str]]) -> None:
        """Find revocation lifecycle enums and `bool` constants that are `true`.

        A name defined more than once belongs to a class only when every
        definition does.
        """
        enums: dict[str, set[frozenset]] = defaultdict(set)
        constants: dict[str, set[str]] = defaultdict(set)
        for path, (code, _) in masked.items():
            if path in self.test_only:
                continue
            if "Lifecycle" in code:
                for match in _LIFECYCLE_ENUM.finditer(code):
                    enums[match.group(1)].add(enum_variants(code, match.end() - 1))
            if "bool" in code:
                for match in _BOOL_CONSTANT.finditer(code):
                    constants[match.group(1)].add(match.group(2))
        self.revocation_enums = {
            name for name, variants in enums.items()
            if all(variant in REVOCATION_VARIANT_SETS for variant in variants)
        }
        self.true_constants = {name for name, values in constants.items() if values == {"true"}}

    def rust_sources(self) -> list[str]:
        prefixes = tuple(f"crates/{crate}/src/" for crate in RUST_CRATES)
        return [path for path in self.files if path.endswith(".rs") and path.startswith(prefixes)]

    def sdk_sources(self) -> list[str]:
        prefixes = tuple(root + "/" for root in SDK_ROOTS)
        return [
            path for path in self.files
            if path.startswith(prefixes) and path.endswith(SDK_SUFFIXES)
            and not re.search(r"(^|/)(tests?|Tests|__tests__|generated|build|node_modules)(/|$)", path)
        ]

    def _scan(self) -> None:
        masked: dict[str, tuple[str, str]] = {}
        declared_test: set[str] = set()
        renamed_tests: list[tuple[str, str, str]] = []
        for path in self.rust_sources():
            if TEST_PATH.search(path.split("/src/", 1)[1]):
                self.test_only.add(path)
                continue
            source = self.text(path)
            if source is None:
                continue
            code, with_strings = mask_rust(source)
            code, with_strings, modules = blank_test_items(code, with_strings)
            masked[path] = (code, with_strings)
            directory, name = path.rsplit("/", 1)
            base = directory if name in ("mod.rs", "lib.rs", "main.rs") else f"{directory}/{name[:-3]}"
            for module in modules:
                if module.startswith("path:"):
                    renamed_tests.append((directory, base, module[len("path:"):]))
                    continue
                declared_test.add(f"{base}/{module}.rs")
                declared_test.add(f"{base}/{module}/")
        # A `#[path]` is relative to the declaring file, or to the directory of
        # the inline module that holds the declaration, which lies below `base`.
        # The renamed file and the directory of its own submodules are test-only.
        for directory, base, relative in renamed_tests:
            if not relative.endswith(".rs"):
                continue
            suffix = "/" + relative
            files = {f"{directory}/{relative}"}
            files.update(
                path for path in masked if path.startswith(f"{base}/") and path.endswith(suffix)
            )
            for file in files:
                declared_test.add(file)
                stem = file[:-len("/mod.rs")] if file.endswith("/mod.rs") else file[:-len(".rs")]
                declared_test.add(f"{stem}/")
        test_directories = tuple(prefix for prefix in declared_test if prefix.endswith("/"))
        for path in masked:
            if path in declared_test or path.startswith(test_directories):
                self.test_only.add(path)
        self._derive_source_classes(masked)
        # Identifiers repeat across files: each distinct one is matched once.
        identifier_hits: dict[str, tuple[tuple[str, str, bool], ...]] = {}
        for path, (code, with_strings) in masked.items():
            if path in self.test_only:
                continue
            applicable = [detector for detector in RUST_DETECTORS if detector.applies(path)]
            for detector in applicable:
                if detector.mode != "text":
                    continue
                text = with_strings if detector.strings else code
                for token, count in detector.hits(text).items():
                    if detector.ident == "feature_cfg":
                        self.feature_rows[(path, token)] += count
                    else:
                        self.rows[(path, detector.ident, token)] += count
            wanted = {detector.ident for detector in applicable if detector.mode == "identifier"}
            if not wanted:
                continue
            family_file = FAMILY_PATH.search(path) is not None
            for identifier, count in Counter(_IDENTIFIER.findall(code)).items():
                matched = identifier_hits.get(identifier)
                if matched is None:
                    family_identifier = FAMILY_PATH.search(identifier) is not None
                    matched = tuple(
                        (detector.ident, token, detector.family and not family_identifier)
                        for detector in IDENTIFIER_DETECTORS
                        for token in (self.token_of(detector, identifier),) if token is not None
                    )
                    identifier_hits[identifier] = matched
                for ident, token, needs_family_file in matched:
                    if ident in wanted and (family_file or not needs_family_file):
                        self.rows[(path, ident, token)] += count
        for path in self.sdk_sources():
            source = self.text(path)
            if source is None:
                continue
            for detector in SDK_DETECTORS:
                for token, count in detector.hits(source).items():
                    self.rows[(path, detector.ident, token)] += count

    def crate_features(self) -> dict[str, list[str]]:
        """Features each scanned crate declares in its manifest."""
        result: dict[str, list[str]] = {}
        for crate in RUST_CRATES:
            manifest = self.text(f"crates/{crate}/Cargo.toml")
            if manifest is None:
                continue
            features: list[str] = []
            section = False
            for line in manifest.splitlines():
                stripped = line.strip()
                if stripped.startswith("["):
                    section = stripped == "[features]"
                    continue
                match = re.match(r"([A-Za-z0-9_-]+)\s*=", stripped)
                if section and match:
                    features.append(match.group(1))
            result[crate] = sorted(set(features))
        return result


# ---------------------------------------------------------------------------
# Census check
# ---------------------------------------------------------------------------

ENTRY_KEYS = {
    "id", "kind", "status", "owner", "path", "symbol", "gates", "decided_by", "attribution",
    "note", "open_reason", "anchors", "removed", "tests", "sites",
}
ATTRIBUTIONS = ("read", "path_rule")
FEATURE_CLASSES = (
    "validity_gate", "availability_gate", "acceleration", "observability", "service_surface",
    "development_or_test", "packaging",
)
GATE_FEATURE_CLASSES = ("validity_gate", "availability_gate")
# The node-configuration policy catalogs of the resource contract: every field
# of each is node-local configuration that decides validity or effects.
CONFIG_CATALOGS = ("execution_policy_digest_v1", "zk_consensus_policy_hash", "nexus_consensus_policy_v1")
_TEST_FUNCTION = r"#\s*\[\s*(?:[a-z_]+::)*test\b[^\]]*\]\s*(?:#\s*\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{name}\b"


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def contract_catalog_fields(contract: Any) -> dict[str, list[str]]:
    """Field names of each node-configuration catalog of the resource contract."""
    result: dict[str, list[str]] = {}
    for catalog in contract.get("catalogs", []) if isinstance(contract, dict) else []:
        if catalog.get("id") not in CONFIG_CATALOGS:
            continue
        fields = list(catalog.get("fields", {}))
        for group in catalog.get("excluded", []):
            fields.extend(group.get("fields", []))
        fields.extend(catalog.get("digests", {}) or {})
        result[catalog["id"]] = fields
    return result


def test_exists(text: Optional[str], name: str) -> bool:
    """Whether `text` defines an active Rust `#[test]` function or a Python test `name`."""
    if text is None:
        return False
    match = re.search(_TEST_FUNCTION.format(name=re.escape(name)), text)
    if match:
        return re.search(r"#\s*\[\s*ignore\b", match.group(0)) is None
    return re.search(rf"^\s*def\s+{re.escape(name)}\s*\(", text, re.MULTILINE) is not None


class CensusChecker:
    """Compare a census document with a scan and with the files it names."""

    def __init__(self, scan: Scan, census: Any, contract: Any, graph: Any) -> None:
        self.scan = scan
        self.census = census if isinstance(census, dict) else {}
        self.contract = contract
        self.graph = graph
        self.errors: list[str] = []
        if not isinstance(census, dict):
            self.errors.append("census: the document is not a JSON object")

    def error(self, message: str) -> None:
        self.errors.append(message)

    # -- small helpers -----------------------------------------------------

    def _occurrences(self, path: str, needle: str) -> Optional[int]:
        text = self.scan.text(path) if path in self.scan.file_set else None
        return None if text is None else text.count(needle)

    def _task_ids(self) -> set[str]:
        tasks = self.graph.get("tasks", []) if isinstance(self.graph, dict) else []
        return {task.get("id") for task in tasks if isinstance(task, dict)}

    # -- sections ----------------------------------------------------------

    def check_header(self) -> None:
        census = self.census
        if census.get("schema") != SCHEMA:
            self.error(f"census: schema must be {SCHEMA!r}")
        if census.get("task") != "F.4":
            self.error("census: task must be 'F.4'")
        if set(census.get("kinds", {})) != set(KINDS):
            self.error(f"census: kinds must be exactly {sorted(KINDS)}")
        scan = census.get("scan", {})
        if scan.get("rust_crates") != list(RUST_CRATES):
            self.error("census: scan.rust_crates differs from the crates this script scans")
        if scan.get("sdk_roots") != list(SDK_ROOTS):
            self.error("census: scan.sdk_roots differs from the SDK roots this script scans")
        if scan.get("family") != FAMILY_PATH.pattern:
            self.error("census: scan.family differs from the path expression this script uses")
        compiled = {ident: detector.describe() for ident, detector in DETECTORS.items()}
        if scan.get("detectors") != compiled:
            changed = sorted(
                ident for ident in set(compiled) | set(scan.get("detectors", {}))
                if compiled.get(ident) != scan.get("detectors", {}).get(ident)
            )
            self.error(f"census: scan.detectors differs from this script's detectors: {changed}")
        derived = {
            "revocation_enums": sorted(self.scan.revocation_enums),
            "true_constants": sorted(
                name for name in self.scan.true_constants
                if any(detector.identifier_token(name) for detector in IDENTIFIER_DETECTORS)
            ),
        }
        for key, found in derived.items():
            if scan.get(key) != found:
                self.error(
                    f"census: scan.{key} must be {found}: the source-derived class changed, read "
                    "the entries that list its sites again"
                )

    def check_entries(self) -> dict[tuple[str, str, str], str]:
        """Validate entries; return the site -> entry attribution."""
        attributed: dict[tuple[str, str, str], str] = {}
        tasks = self._task_ids()
        seen: set[str] = set()
        entries = self.census.get("entries", [])
        if not isinstance(entries, list):
            self.error("census: entries must be a list")
            return attributed
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                self.error("census: an entry is not an object with an id")
                continue
            ident = entry["id"]
            where = f"entry {ident}"
            if ident in seen:
                self.error(f"{where}: listed twice")
            seen.add(ident)
            unknown = set(entry) - ENTRY_KEYS
            if unknown:
                self.error(f"{where}: unknown keys {sorted(unknown)}")
            if entry.get("kind") not in KINDS:
                self.error(f"{where}: unknown kind {entry.get('kind')!r}")
            status = entry.get("status")
            if status not in self.census.get("statuses", {}):
                self.error(f"{where}: unknown status {status!r}")
            if entry.get("attribution") not in ATTRIBUTIONS:
                self.error(f"{where}: attribution must be one of {ATTRIBUTIONS}")
            for key in ("gates", "decided_by"):
                if not isinstance(entry.get(key), str) or not entry[key].strip():
                    self.error(f"{where}: `{key}` must say what is gated and what decides instead")
            owner = entry.get("owner")
            if status in ("not_a_gate", "out_of_plan"):
                if owner is not None:
                    self.error(f"{where}: a {status} entry names no owner task")
                if not entry.get("note"):
                    self.error(f"{where}: a {status} entry states its reason in `note`")
            elif owner not in tasks:
                self.error(f"{where}: owner {owner!r} is not a task of {DELIVERY_GRAPH}")
            if status == "open" and owner == "F.4" and not entry.get("open_reason"):
                self.error(f"{where}: an open F.4 entry states why it is not changed now")
            if status == "done" and not (entry.get("tests") or entry.get("removed")):
                self.error(f"{where}: a done entry names a test or a removed construct")
            # The anchor: path and symbol exist.
            path = entry.get("path")
            symbol = entry.get("symbol")
            if not isinstance(path, str) or path not in self.scan.file_set:
                self.error(f"{where}: path {path!r} does not exist")
            elif not isinstance(symbol, str) or not symbol:
                self.error(f"{where}: no symbol")
            elif not self._occurrences(path, symbol):
                self.error(f"{where}: symbol {symbol!r} does not occur in {path}")
            for anchor in entry.get("anchors", []):
                found = self._occurrences(anchor.get("path", ""), anchor.get("contains", "\0"))
                wanted = anchor.get("count", 1)
                if found is None:
                    self.error(f"{where}: anchor path {anchor.get('path')!r} does not exist")
                elif found != wanted:
                    self.error(
                        f"{where}: anchor {anchor.get('contains')!r} occurs {found} time(s) in "
                        f"{anchor.get('path')}, the census records {wanted}"
                    )
            for removed in entry.get("removed", []):
                found = self._occurrences(removed.get("path", ""), removed.get("contains", "\0"))
                if found is None:
                    self.error(f"{where}: removed-construct path {removed.get('path')!r} does not exist")
                elif found:
                    self.error(
                        f"{where}: removed construct {removed.get('contains')!r} is back in "
                        f"{removed.get('path')}"
                    )
            for test in entry.get("tests", []):
                path = test.get("path", "")
                text = self.scan.text(path) if path in self.scan.file_set else None
                if not test_exists(text, test.get("name", "\0")):
                    self.error(f"{where}: test {test.get('name')!r} is not an active test in {path}")
            for site in entry.get("sites", []):
                if not (isinstance(site, list) and len(site) == 4):
                    self.error(f"{where}: a site is not [path, detector, token, count]")
                    continue
                key = (site[0], site[1], site[2])
                if site[1] not in DETECTORS or site[1] == "feature_cfg":
                    self.error(f"{where}: site {key} names no row-producing detector")
                if DETECTORS.get(site[1]) is not None and DETECTORS[site[1]].kind != entry.get("kind") \
                        and status not in ("not_a_gate", "out_of_plan"):
                    self.error(
                        f"{where}: site {key} is of kind {DETECTORS[site[1]].kind}, the entry of "
                        f"kind {entry.get('kind')}"
                    )
                if key in attributed:
                    self.error(f"site {key}: attributed to both {attributed[key]} and {ident}")
                attributed[key] = ident
                found = self.scan.rows.get(key, 0)
                if found == 0:
                    self.error(
                        f"{where}: listed site {key} is gone; remove the row and reconcile the entry"
                    )
                elif found != site[3]:
                    self.error(
                        f"{where}: site {key} occurs {found} time(s), the census records {site[3]}"
                    )
        return attributed

    def check_coverage(self, attributed: dict[tuple[str, str, str], str]) -> None:
        for key, count in sorted(self.scan.rows.items()):
            if key not in attributed:
                self.error(
                    f"unlisted site: {key[0]} detector {key[1]} token {key[2]!r} x{count} "
                    f"({DETECTORS[key[1]].kind}); attribute it to an entry of the census"
                )

    def check_catalogs(self) -> None:
        recorded = contract_catalog_fields(self.contract)
        entries = {entry.get("id") for entry in self.census.get("entries", []) if isinstance(entry, dict)}
        listed = {catalog.get("catalog"): catalog for catalog in self.census.get("config_catalogs", [])}
        for ident in CONFIG_CATALOGS:
            if ident not in recorded:
                self.error(f"catalog {ident}: missing from {RESOURCE_CONTRACT}")
                continue
            catalog = listed.get(ident)
            if catalog is None:
                self.error(f"catalog {ident}: not in the census")
                continue
            assigned: Counter = Counter()
            for group in catalog.get("groups", []):
                if group.get("entry") not in entries:
                    self.error(f"catalog {ident}: group names unknown entry {group.get('entry')!r}")
                assigned.update(group.get("fields", []))
            wanted = Counter(recorded[ident])
            for field in sorted(set(wanted) - set(assigned)):
                self.error(f"catalog {ident}: field {field!r} is not assigned to an entry")
            for field in sorted(set(assigned) - set(wanted)):
                self.error(f"catalog {ident}: field {field!r} is not a field of the catalog")
            for field, count in sorted(assigned.items()):
                if count > 1:
                    self.error(f"catalog {ident}: field {field!r} is assigned {count} times")
        for ident in set(listed) - set(CONFIG_CATALOGS):
            self.error(f"catalog {ident!r}: not a node-configuration catalog of the contract")

    def check_features(self) -> None:
        entries = {entry.get("id") for entry in self.census.get("entries", []) if isinstance(entry, dict)}
        declared = self.scan.crate_features()
        used: dict[str, Counter] = defaultdict(Counter)
        for (path, feature), count in self.scan.feature_rows.items():
            used[path.split("/")[1]][feature] += count
        listed = self.census.get("features", {})
        for crate in sorted(set(declared) | set(used) | set(listed)):
            wanted = set(declared.get(crate, [])) | set(used.get(crate, {}))
            recorded = listed.get(crate, {})
            for feature in sorted(wanted - set(recorded)):
                self.error(f"feature {crate}/{feature}: not classified in the census")
            for feature in sorted(set(recorded) - wanted):
                self.error(f"feature {crate}/{feature}: classified but neither declared nor used")
            for feature, record in sorted(recorded.items()):
                where = f"feature {crate}/{feature}"
                if record.get("class") not in FEATURE_CLASSES:
                    self.error(f"{where}: unknown class {record.get('class')!r}")
                    continue
                gate = record["class"] in GATE_FEATURE_CLASSES
                if gate and record.get("entry") not in entries:
                    self.error(f"{where}: a gate feature names the census entry that owns it")
                if not gate and not record.get("reason"):
                    self.error(f"{where}: a non-gate feature states why in `reason`")
                if gate:
                    found = used.get(crate, {}).get(feature, 0)
                    if record.get("cfg_sites", 0) != found:
                        self.error(
                            f"{where}: {found} conditional-compilation site(s) in production "
                            f"source, the census records {record.get('cfg_sites', 0)}"
                        )

    def check_summary(self) -> None:
        entries = [entry for entry in self.census.get("entries", []) if isinstance(entry, dict)]
        by_status = Counter(entry.get("status") for entry in entries)
        by_owner = Counter(entry.get("owner") or "-" for entry in entries)
        summary = {
            "entries": len(entries),
            "sites": sum(len(entry.get("sites", [])) for entry in entries),
            "by_status": dict(sorted(by_status.items())),
            "by_owner": dict(sorted(by_owner.items())),
        }
        if self.census.get("summary") != summary:
            self.error(f"census: summary must be {json.dumps(summary, sort_keys=True)}")

    def run(self) -> list[str]:
        if not self.errors:
            self.check_header()
            attributed = self.check_entries()
            self.check_coverage(attributed)
            self.check_catalogs()
            self.check_features()
            self.check_summary()
        return self.errors


def check(root: Path, census: Any, files: Optional[Iterable[str]] = None,
          contract: Any = None, graph: Any = None) -> list[str]:
    """Return the list of differences between the census and the tree at `root`."""
    scan = Scan(root, files)
    if contract is None:
        contract = load_json(root / RESOURCE_CONTRACT)
    if graph is None:
        graph = load_json(root / DELIVERY_GRAPH)
    return CensusChecker(scan, census, contract, graph).run()


def render(census: Any) -> str:
    """The canonical text of a census: one site per line, stable key order."""
    def compact(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))

    def emit(value: Any, indent: int, key: Optional[str] = None) -> str:
        pad = " " * indent
        if key in ("sites", "fields", "rust_crates", "sdk_roots") and isinstance(value, list):
            if not value:
                return "[]"
            rows = ",\n".join(f"{pad} {compact(item)}" for item in value)
            return f"[\n{rows}\n{pad}]"
        if isinstance(value, dict):
            if not value:
                return "{}"
            if all(not isinstance(item, (dict, list)) for item in value.values()) and key not in (None, "kinds", "statuses"):
                return compact(value)
            rows = ",\n".join(
                f"{pad} {json.dumps(name)}: {emit(item, indent + 1, name)}" for name, item in value.items()
            )
            return f"{{\n{rows}\n{pad}}}"
        if isinstance(value, list):
            if not value:
                return "[]"
            rows = ",\n".join(f"{pad} {emit(item, indent + 1)}" for item in value)
            return f"[\n{rows}\n{pad}]"
        return json.dumps(value, ensure_ascii=False)

    return emit(census, 0) + "\n"


def refresh_counts(scan: Scan, census: dict[str, Any]) -> list[str]:
    """Rewrite the occurrence counts of rows that still exist; report each change."""
    changes: list[str] = []
    for entry in census.get("entries", []):
        for site in entry.get("sites", []):
            found = scan.rows.get((site[0], site[1], site[2]), 0)
            if found and found != site[3]:
                changes.append(f"{entry['id']}: {site[0]} {site[1]} {site[2]} {site[3]} -> {found}")
                site[3] = found
    used: dict[str, Counter] = defaultdict(Counter)
    for (path, feature), count in scan.feature_rows.items():
        used[path.split("/")[1]][feature] += count
    for crate, features in census.get("features", {}).items():
        for feature, record in features.items():
            if record.get("class") in GATE_FEATURE_CLASSES:
                found = used.get(crate, {}).get(feature, 0)
                if record.get("cfg_sites", 0) != found:
                    changes.append(f"feature {crate}/{feature}: cfg_sites {record.get('cfg_sites', 0)} -> {found}")
                    record["cfg_sites"] = found
    return changes


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--census", default=DEFAULT_CENSUS, help="census path relative to the root")
    parser.add_argument("--print-scan", action="store_true", help="print the fresh scan as JSON")
    parser.add_argument("--propose", action="store_true", help="print the rows of unattributed sites")
    parser.add_argument("--refresh", action="store_true",
                        help="rewrite occurrence counts of existing rows and print each change")
    arguments = parser.parse_args(argv)
    root = arguments.root.resolve()
    scan = Scan(root)
    if arguments.print_scan:
        rows = [
            {"path": path, "detector": detector, "token": token, "count": count}
            for (path, detector, token), count in sorted(scan.rows.items())
        ]
        features = [
            {"path": path, "feature": feature, "count": count}
            for (path, feature), count in sorted(scan.feature_rows.items())
        ]
        json.dump({"rows": rows, "feature_rows": features, "features": scan.crate_features()},
                  sys.stdout, indent=1)
        sys.stdout.write("\n")
        return 0
    census_path = root / arguments.census
    try:
        census = load_json(census_path)
        contract = load_json(root / RESOURCE_CONTRACT)
        graph = load_json(root / DELIVERY_GRAPH)
    except (OSError, ValueError) as error:
        print(f"check_zk_runtime_validity: cannot read an input: {error}", file=sys.stderr)
        return 2
    if arguments.propose:
        attributed = {
            (site[0], site[1], site[2])
            for entry in census.get("entries", []) for site in entry.get("sites", [])
        }
        for key, count in sorted(scan.rows.items()):
            if key not in attributed:
                print(json.dumps([key[0], key[1], key[2], count]))
        return 0
    if arguments.refresh:
        changes = refresh_counts(scan, census)
        for change in changes:
            print(change)
        if changes:
            census_path.write_text(render(census), encoding="utf-8")
        return 0
    errors = CensusChecker(scan, census, contract, graph).run()
    if errors:
        for error in errors:
            print(f"check_zk_runtime_validity: {error}", file=sys.stderr)
        print(f"check_zk_runtime_validity: {len(errors)} difference(s) between "
              f"{arguments.census} and the tree", file=sys.stderr)
        return 1
    entries = census.get("entries", [])
    print(
        f"check_zk_runtime_validity: OK ({len(entries)} entries, "
        f"{sum(len(entry.get('sites', [])) for entry in entries)} sites, "
        f"{len(scan.rows)} scanned rows)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
