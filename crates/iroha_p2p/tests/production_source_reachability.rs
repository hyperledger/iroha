//! Guards the production P2P source graph against orphaned shipping modules.

use std::{collections::BTreeSet, fs, path::Path};

const PRODUCTION_SOURCES: &[&str] = &[
    "src/dial_policy.rs",
    "src/lib.rs",
    "src/network.rs",
    "src/network/admission.rs",
    "src/network/connection_arbitration.rs",
    "src/network/best_effort_admission.rs",
    "src/network/reliable_actor.rs",
    "src/peer.rs",
    "src/peer/post_admission.rs",
    "src/peer/quic_datagram.rs",
    "src/peer/receive_credit.rs",
    "src/peer/receive_credit/negotiation.rs",
    "src/peer/receive_credit/record.rs",
    "src/peer/receive_credit/stream.rs",
    "src/peer/run/granted.rs",
    "src/peer/tenure.rs",
    "src/preauth.rs",
    "src/puzzle_work_admission.rs",
    "src/soranet_handshake_runtime.rs",
    "src/streaming/mod.rs",
    "src/streaming/quic.rs",
    "src/transport.rs",
];

const TEST_ONLY_SOURCES: &[&str] = &[
    "src/frame_identity_tests.rs",
    "src/network/actor_admission_fixture.rs",
    "src/network/admission_class_tests.rs",
    "src/network/connection_arbitration/tests.rs",
    "src/network/connection_lifecycle_tests.rs",
    "src/network/data_frame_wire_len_tests.rs",
    "src/network/frame_identity_tests.rs",
    "src/network/handle_update_tests.rs",
    "src/network/queue_depth_tests.rs",
    "src/network/runtime_tests.rs",
    "src/network/tcp_listener_bind_tests.rs",
    "src/network/tests.rs",
    "src/payload_codec_tests.rs",
    "src/peer/receive_credit/tests.rs",
    "src/peer/receive_credit/arbitration_tests.rs",
    "src/peer/receive_credit/stream/health_tests.rs",
    "src/peer/run/admission_class_tests.rs",
    "src/peer/run/payload_codec_tests.rs",
    "src/peer_consensus_mode_test.rs",
    "src/peer_handshake_config_tests.rs",
    "src/peer_state_tests.rs",
    "src/peer_tests.rs",
    "src/puzzle_work_admission/tests.rs",
];

#[derive(Clone, Copy)]
enum ProductionGate<'a> {
    Unconditional,
    Feature(&'a str),
}

struct ProductionEdge<'a> {
    parent: &'a str,
    declaration: &'a str,
    child: &'a str,
    gate: ProductionGate<'a>,
}

const PRODUCTION_EDGES: &[ProductionEdge<'_>] = &[
    ProductionEdge {
        parent: "src/network.rs",
        declaration: "mod connection_arbitration;",
        child: "src/network/connection_arbitration.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/peer.rs",
        declaration: "pub(crate) mod tenure;",
        child: "src/peer/tenure.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/lib.rs",
        declaration: "mod dial_policy;",
        child: "src/dial_policy.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/lib.rs",
        declaration: "pub mod network;",
        child: "src/network.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/lib.rs",
        declaration: "pub mod peer;",
        child: "src/peer.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/lib.rs",
        declaration: "mod preauth;",
        child: "src/preauth.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/lib.rs",
        declaration: "mod puzzle_work_admission;",
        child: "src/puzzle_work_admission.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/lib.rs",
        declaration: "mod soranet_handshake_runtime;",
        child: "src/soranet_handshake_runtime.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/lib.rs",
        declaration: "pub mod streaming;",
        child: "src/streaming/mod.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/lib.rs",
        declaration: "pub mod transport;",
        child: "src/transport.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/network.rs",
        declaration: "mod admission;",
        child: "src/network/admission.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/network.rs",
        declaration: "mod best_effort_admission;",
        child: "src/network/best_effort_admission.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/network.rs",
        declaration: "mod reliable_actor;",
        child: "src/network/reliable_actor.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/peer.rs",
        declaration: "mod quic_datagram;",
        child: "src/peer/quic_datagram.rs",
        gate: ProductionGate::Feature("quic"),
    },
    ProductionEdge {
        parent: "src/streaming/mod.rs",
        declaration: "pub mod quic;",
        child: "src/streaming/quic.rs",
        gate: ProductionGate::Feature("quic"),
    },
    ProductionEdge {
        parent: "src/peer.rs",
        declaration: "pub(crate) mod post_admission;",
        child: "src/peer/post_admission.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/peer.rs",
        declaration: "pub(crate) mod receive_credit;",
        child: "src/peer/receive_credit.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/peer.rs",
        declaration: "mod granted;",
        child: "src/peer/run/granted.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/peer/receive_credit.rs",
        declaration: "pub(super) mod negotiation;",
        child: "src/peer/receive_credit/negotiation.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/peer/receive_credit.rs",
        declaration: "pub(super) mod record;",
        child: "src/peer/receive_credit/record.rs",
        gate: ProductionGate::Unconditional,
    },
    ProductionEdge {
        parent: "src/peer/receive_credit.rs",
        declaration: "pub(super) mod stream;",
        child: "src/peer/receive_credit/stream.rs",
        gate: ProductionGate::Unconditional,
    },
];

fn collect_rust_sources(root: &Path, directory: &Path, output: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).expect("read P2P source directory") {
        let entry = entry.expect("read P2P source entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(root, &path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(root)
                .expect("P2P source stays below its crate root")
                .to_string_lossy()
                .replace('\\', "/");
            assert!(output.insert(relative), "duplicate P2P source path");
        }
    }
}

fn locked_package_versions<'a>(lockfile: &'a str, package: &str) -> Vec<&'a str> {
    lockfile
        .split("[[package]]")
        .filter_map(|entry| {
            let mut name = None;
            let mut version = None;
            for line in entry.lines().map(str::trim) {
                if let Some(value) = line
                    .strip_prefix("name = \"")
                    .and_then(|value| value.strip_suffix('"'))
                {
                    name = Some(value);
                } else if let Some(value) = line
                    .strip_prefix("version = \"")
                    .and_then(|value| value.strip_suffix('"'))
                {
                    version = Some(value);
                }
            }
            (name == Some(package)).then_some(version).flatten()
        })
        .collect()
}

fn stable_semver_triplet(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((major, minor, patch))
}

fn declaration_attributes<'a>(source: &'a str, declaration: &str) -> Vec<&'a str> {
    let lines: Vec<_> = source.lines().map(str::trim).collect();
    let matches: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (*line == declaration).then_some(index))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "production module declaration `{declaration}` must occur exactly once"
    );
    let mut attributes = Vec::new();
    let mut cursor = matches[0];
    while cursor > 0 {
        let previous = lines[cursor - 1];
        if previous.starts_with("#[") {
            attributes.push(previous);
        } else if !(previous.is_empty()
            || previous.starts_with("///")
            || previous.starts_with("//!"))
        {
            break;
        }
        cursor -= 1;
    }
    attributes.reverse();
    attributes
}

#[test]
fn shipping_source_inventory_and_module_graph_are_closed() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut actual = BTreeSet::new();
    collect_rust_sources(crate_root, &crate_root.join("src"), &mut actual);

    let expected: BTreeSet<_> = PRODUCTION_SOURCES
        .iter()
        .chain(TEST_ONLY_SOURCES)
        .map(|path| (*path).to_owned())
        .collect();
    assert_eq!(
        actual, expected,
        "classify every P2P Rust source explicitly as production-reachable or test-only"
    );

    let mut reached = BTreeSet::from(["src/lib.rs"]);
    for edge in PRODUCTION_EDGES {
        assert!(
            PRODUCTION_SOURCES.contains(&edge.parent),
            "production edge parent is not shipping: {}",
            edge.parent
        );
        assert!(
            PRODUCTION_SOURCES.contains(&edge.child),
            "production edge child is not shipping: {}",
            edge.child
        );
        let source = fs::read_to_string(crate_root.join(edge.parent))
            .unwrap_or_else(|error| panic!("read {}: {error}", edge.parent));
        let attributes = declaration_attributes(&source, edge.declaration);
        assert!(
            attributes
                .iter()
                .all(|attribute| !attribute.contains("test")),
            "shipping edge {} -> {} is test-gated: {attributes:?}",
            edge.parent,
            edge.child
        );
        match edge.gate {
            ProductionGate::Unconditional => assert!(
                attributes
                    .iter()
                    .all(|attribute| !attribute.starts_with("#[cfg")),
                "unconditional shipping edge {} -> {} gained a cfg gate: {attributes:?}",
                edge.parent,
                edge.child
            ),
            ProductionGate::Feature(feature) => {
                let expected = format!("#[cfg(feature = \"{feature}\")]");
                assert_eq!(
                    attributes,
                    [expected.as_str()],
                    "feature-gated shipping edge {} -> {} must use only its declared production feature",
                    edge.parent,
                    edge.child
                );
            }
        }
        reached.insert(edge.child);
    }

    let production: BTreeSet<_> = PRODUCTION_SOURCES.iter().copied().collect();
    assert_eq!(
        reached, production,
        "every shipping P2P source must have an explicit production module edge"
    );
}

#[test]
fn shipping_quinn_resolution_keeps_unqualified_releases_fail_closed() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_root
        .parent()
        .and_then(Path::parent)
        .expect("P2P crate lives below the workspace root");
    let lockfile =
        fs::read_to_string(workspace_root.join("Cargo.lock")).expect("read the workspace lockfile");

    let quinn = locked_package_versions(&lockfile, "quinn");
    assert_eq!(
        quinn.len(),
        1,
        "the workspace must resolve one Quinn release"
    );
    let quinn = stable_semver_triplet(quinn[0]).expect("Quinn uses stable semver");
    assert!(((0, 11, 12)..(0, 12, 0)).contains(&quinn));

    let proto = locked_package_versions(&lockfile, "quinn-proto");
    assert_eq!(
        proto.len(),
        1,
        "the workspace must resolve exactly one Quinn protocol release"
    );
    let proto = stable_semver_triplet(proto[0]).expect("quinn-proto uses stable semver");
    assert!(((0, 11, 18)..(0, 12, 0)).contains(&proto));

    // Dependency patches alone never authorize shipping endpoint admission.
    {
        for relative in [
            "src/network.rs",
            "src/transport.rs",
            "src/streaming/quic.rs",
        ] {
            let source = fs::read_to_string(crate_root.join(relative))
                .unwrap_or_else(|error| panic!("read {relative}: {error}"));
            assert!(
                source.contains("QUIC_DEPENDENCY_BLOCK_REASON"),
                "{relative} must fail closed while quinn-proto {proto:?} is locked"
            );
        }
    }
}
