//! Definition parsing tests: committed definitions, fixtures, and one negative
//! case per validation rule.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::account::{AccountId, address::ChainDiscriminantGuard};
use iroha_deploy::definition::{
    Become, CommitteeSource, DataspaceDefinition, DefinitionError, FailureDomain, HostIdentity,
    NetworkDefinition, NetworkRef, NodePorts, ProfileId, ReleaseSource, Role, Upstream, Visibility,
};

const HOME: &str = "/home/op";
const NETWORK_FILE: &str = "/defs/networks/test.toml";
const DATASPACE_FILE: &str = "/defs/dataspaces/test.toml";

const KEY_A: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJx61jSMsPGwubMm7CiE1KkCd7Awvkl/Cgr7EvdSzhH9";
const KEY_B: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJVyAKJzTpzSN4LdGL1E0Id05Hlk1bO6i4pflYC0csl5";
const KEY_C: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEoQXPl4+7bLqedCuGjcOtPBl7EOfF4S3ayBg+gw4O+x";
const KEY_D: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIGFS0A0UonCmwO/c2Il8nuW0Glh8aPdagsGzVght7JR";
const KEY_EDGE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII/Qy9iUV0qtyLY+1eFlrL4Of4FHwMdxxqCRC51i2K6L";

const LOCAL: &str = r#"
[network]
name = "test"
profile = "iroha-dev-v1"
[[node]]
name = "n0"
[[node]]
name = "n1"
[[node]]
name = "n2"
[[node]]
name = "n3"
"#;

const ED25519_KEY: &str = "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0";

/// Add `line` to the `[network]` table of `text`.
fn network_line(text: &str, line: &str) -> String {
    text.replacen("[network]\n", &format!("[network]\n{line}\n"), 1)
}

/// Add `line` to the `index`th `[[node]]` of `text`.
fn node_line(text: &str, index: usize, line: &str) -> String {
    let mut offset = 0;
    for _ in 0..=index {
        offset += text[offset..].find("[[node]]\n").unwrap() + "[[node]]\n".len();
    }
    format!("{}{line}\n{}", &text[..offset], &text[offset..])
}

/// A local definition with `validators` validators.
fn local_with(validators: usize) -> String {
    let mut text = String::from("[network]\nname = \"test\"\nprofile = \"iroha-dev-v1\"\n");
    for index in 0..validators {
        write!(text, "[[node]]\nname = \"n{index}\"\n").unwrap();
    }
    text
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Four remote validators on distinct pinned hosts, with `[ssh]`.
fn remote(extra: &str) -> String {
    let mut text = String::from(
        "[network]\nname = \"test\"\nprofile = \"sora-nexus-v1\"\n\n[ssh]\nidentity = \"~/.ssh/deploy.pub\"\n",
    );
    text.push_str(extra);
    for (index, key) in [KEY_A, KEY_B, KEY_C, KEY_D].iter().enumerate() {
        write!(
            text,
            "\n[[node]]\nname = \"v{index}\"\nhost = \"v{index}.example\"\nhost_key = \"{key}\"\n"
        )
        .unwrap();
    }
    text
}

/// A remote definition with an `[edge]`, a public root and per-node domains.
fn with_edge(edge_extra: &str) -> String {
    let mut text = remote(&format!(
        "\n[edge]\nhost = \"edge.example\"\nhost_key = \"{KEY_EDGE}\"\ndomain = \"test.example\"\ntls_certificate = \"/etc/tls/cert.pem\"\ntls_private_key = \"/etc/tls/key.pem\"\n{edge_extra}\n"
    ));
    text = text.replacen(
        "profile = \"sora-nexus-v1\"\n",
        "profile = \"sora-nexus-v1\"\npublic_root = \"https://test.example\"\n",
        1,
    );
    text
}

fn network(text: &str) -> Result<NetworkDefinition, DefinitionError> {
    NetworkDefinition::parse(text, NETWORK_FILE, Some(Path::new(HOME)))
}

fn dataspace(text: &str) -> Result<DataspaceDefinition, DefinitionError> {
    DataspaceDefinition::parse(text, DATASPACE_FILE, Some(Path::new(HOME)))
}

fn issue_keys(error: &DefinitionError) -> Vec<String> {
    assert!(
        matches!(error, DefinitionError::Invalid { .. }),
        "expected validation issues, got: {error}"
    );
    error
        .issues()
        .iter()
        .map(|issue| issue.key.clone())
        .collect()
}

#[track_caller]
fn assert_network_issue(text: &str, key: &str) {
    let error = network(text).expect_err("definition must be rejected");
    let keys = issue_keys(&error);
    assert!(
        keys.iter().any(|found| found == key),
        "no `{key}` in {keys:?}\n{error}"
    );
}

#[track_caller]
fn assert_dataspace_issue(text: &str, key: &str) {
    let error = dataspace(text).expect_err("definition must be rejected");
    let keys = issue_keys(&error);
    assert!(
        keys.iter().any(|found| found == key),
        "no `{key}` in {keys:?}\n{error}"
    );
}

/// A read error must name the file and every needle (keys, messages).
#[track_caller]
fn assert_read_error(
    result: Result<impl std::fmt::Debug, DefinitionError>,
    file: &str,
    needles: &[&str],
) {
    let error = result.expect_err("definition must be rejected");
    assert!(matches!(error, DefinitionError::Read { .. }), "{error}");
    let rendered = error.to_string();
    assert!(rendered.contains(file), "file missing from:\n{rendered}");
    for needle in needles {
        assert!(
            rendered.contains(needle),
            "`{needle}` missing from:\n{rendered}"
        );
    }
}

// ---- committed definitions and fixtures ----

#[test]
fn committed_network_definitions_parse() {
    let dev = NetworkDefinition::load(repo_root().join("networks/dev.toml")).unwrap();
    assert_eq!(dev.network.name.as_str(), "dev");
    assert_eq!(dev.network.profile, ProfileId::SoraNexusV1Qual);
    assert_eq!(dev.network.chain_id, None);
    assert!(dev.is_local());
    assert_eq!(dev.f(), 1);
    assert_eq!(
        dev.node_ports(0),
        Some(NodePorts {
            p2p: 29337,
            torii: 29080
        })
    );
    let ci = NetworkDefinition::load(repo_root().join("networks/ci.toml")).unwrap();
    assert_eq!(ci.network.name.as_str(), "ci");
    assert_eq!(ci.nodes, dev.nodes);
    let perf = NetworkDefinition::load(repo_root().join("networks/perf-10k.toml")).unwrap();
    assert_eq!(perf.network.profile, ProfileId::SoraNexusV1Qual);
    let scaling = perf.scaling.unwrap();
    assert_eq!((scaling.lanes, scaling.accounts), (8, 10_000));
    let names: Vec<_> = std::fs::read_dir(repo_root().join("networks"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    for path in names {
        NetworkDefinition::load(&path).unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn committed_dataspace_examples_parse() {
    for entry in std::fs::read_dir(repo_root().join("dataspaces")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            DataspaceDefinition::load(&path).unwrap_or_else(|error| panic!("{error}"));
        }
    }
}

#[test]
fn committed_dpn_definition_contains_only_dataspace_decisions() {
    let file = repo_root().join("dataspaces/dpn.toml");
    let text = std::fs::read_to_string(&file).unwrap();
    let table: toml::Table = toml::from_str(&text).unwrap();
    assert_eq!(
        table.len(),
        1,
        "DPN must not contain node or network settings"
    );
    let section = table["dataspace"].as_table().unwrap();
    let mut keys: Vec<_> = section.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["account_alias", "max_fee", "name", "network", "owner_key"]
    );

    let definition = DataspaceDefinition::load(&file).unwrap();
    assert_eq!(definition.dataspace.name.as_str(), "dpn");
    assert_eq!(definition.dataspace.visibility, Visibility::Restricted);
    assert_eq!(definition.committee.source, CommitteeSource::Network);
    assert!(definition.committee.nodes.is_empty());
    assert!(definition.ssh.is_none());
    assert!(definition.edge.is_none());
}

#[test]
fn taira_fixture_parses() {
    let taira =
        NetworkDefinition::load_with_home(fixture("taira.toml"), Some(Path::new(HOME))).unwrap();
    assert!(!taira.is_local());
    assert_eq!(taira.f(), 1);
    assert_eq!(taira.chain_discriminant(), 369);
    assert_eq!(
        taira.network.admin_key.as_deref(),
        Some(Path::new("/home/op/.iroha/keys/taira-admin.key"))
    );
    let ssh = taira.ssh.as_ref().unwrap();
    assert_eq!(
        ssh.identity,
        PathBuf::from("/home/op/.ssh/taira_deploy_ed25519.pub")
    );
    assert!(ssh.agent);
    assert_eq!(
        (ssh.user.as_str(), ssh.port, ssh.escalation()),
        ("root", 22, Become::None)
    );
    assert!(taira.inrou.enabled);
    assert_eq!(taira.faucet.enabled, Some(true));
    assert_eq!(taira.onboarding_credentials.len(), 1);
    let edge = taira.edge.as_ref().unwrap();
    assert_eq!(edge.upstream, Upstream::Mtls);
    assert!(edge.per_node_domains);
    assert_eq!(edge.cors_origins.len(), 2);
    assert_eq!(
        taira.monitor.webhook_file.as_deref(),
        Some(Path::new("/home/op/.iroha/secrets/taira-webhook.url"))
    );
    assert!(taira.grants.is_empty());
    assert_eq!(taira.nodes.len(), 4);
    assert!(taira.nodes.iter().all(|node| node.role == Role::Validator));
    assert_eq!(
        taira.node_ports(3),
        Some(NodePorts {
            p2p: 1337,
            torii: 8080
        })
    );
    assert_eq!(
        taira.advertised_address(0).as_deref(),
        Some("taira-v1.sora.org")
    );
    let identity = taira.host_identity(0).unwrap();
    assert!(matches!(identity, HostIdentity::Key(_)));
    assert_eq!(taira.failure_domain(0), Some(FailureDomain::Host(identity)));
}

#[test]
fn dataspace_fixtures_parse() {
    let home = Some(Path::new(HOME));
    let on_taira =
        DataspaceDefinition::load_with_home(fixture("acme-on-taira.toml"), home).unwrap();
    assert_eq!(on_taira.dataspace.name.as_str(), "acme");
    assert_eq!(on_taira.committee.source, CommitteeSource::Network);
    assert!(matches!(on_taira.dataspace.network, NetworkRef::Url(_)));
    assert_eq!(
        on_taira.dataspace.owner_key,
        PathBuf::from("/home/op/.iroha/keys/acme-owner.key")
    );
    assert_eq!(on_taira.dataspace.max_fee.to_string(), "20");

    let acme = DataspaceDefinition::load_with_home(fixture("acme.toml"), home).unwrap();
    assert_eq!(acme.committee.source, CommitteeSource::Owner);
    assert_eq!(acme.f(), Some(1));
    assert!(!acme.is_local());
    assert!(acme.dataspace.network_id.is_some());
    assert_eq!(acme.dataspace.visibility, Visibility::Restricted);
    assert_eq!(acme.ssh.as_ref().unwrap().escalation(), Become::Sudo);
    assert!(acme.edge.is_some());
    // The edge shares a host, and its pinned key, with acme-1.
    let edge_key = acme.edge.as_ref().unwrap().host_key;
    assert_eq!(acme.host_identity(0), Some(HostIdentity::Key(edge_key)));
    assert_eq!(
        acme.node_ports(0),
        Some(NodePorts {
            p2p: 1337,
            torii: 8080
        })
    );

    let local = DataspaceDefinition::load_with_home(fixture("acme-local.toml"), home).unwrap();
    assert!(local.is_local());
    let NetworkRef::Definition(parent) = &local.dataspace.network else {
        panic!("expected a network definition path");
    };
    let parent = NetworkDefinition::load(parent).unwrap();
    assert_eq!(parent.network.name.as_str(), "dev");
}

// ---- reader errors: unknown keys, types and origins ----

#[test]
fn unknown_keys_are_rejected_with_origin() {
    let text = format!("{LOCAL}\n[network.extra]\nx = 1\n[inrou]\nenabld = true\n");
    assert_read_error(
        network(&text.replace(
            "profile = \"iroha-dev-v1\"",
            "profile = \"iroha-dev-v1\"\nnmae = \"x\"",
        )),
        NETWORK_FILE,
        &["network.nmae", "network.extra", "inrou.enabld"],
    );
    assert_read_error(
        network(&LOCAL.replacen("name = \"n1\"", "name = \"n1\"\nhots = \"x\"", 1)),
        NETWORK_FILE,
        &["node", "[1]", "unknown field `hots`"],
    );
    assert_read_error(
        network(&format!("{LOCAL}\n[nework]\n")),
        NETWORK_FILE,
        &["nework"],
    );
}

#[test]
fn unknown_keys_in_a_file_name_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("typo.toml");
    std::fs::write(&path, format!("{LOCAL}\nstray = 1\n")).unwrap();
    let file = path.to_str().unwrap().to_owned();
    assert_read_error(NetworkDefinition::load(&path), &file, &["stray"]);
}

#[test]
fn mistyped_and_missing_values_are_read_errors() {
    assert_read_error(
        network(&LOCAL.replace("\"iroha-dev-v1\"", "\"sora-nexus-v2\"")),
        NETWORK_FILE,
        &["network.profile", "sora-nexus-v2"],
    );
    assert_read_error(
        network(&LOCAL.replace("name = \"test\"", "name = \"Test\"")),
        NETWORK_FILE,
        &["network.name"],
    );
    assert_read_error(
        network(&LOCAL.replace("name = \"test\"\n", "")),
        NETWORK_FILE,
        &["network.name"],
    );
    assert_read_error(
        network(&LOCAL.replacen("name = \"n0\"", "name = \"n0\"\nrole = \"leader\"", 1)),
        NETWORK_FILE,
        &["node", "leader"],
    );
    assert_read_error(
        network(&remote("").replacen(KEY_A, "ssh-ed25519 AAAA...v1", 1)),
        NETWORK_FILE,
        &["node", "host key"],
    );
    assert_read_error(
        network(&with_edge("").replace(&format!("host_key = \"{KEY_EDGE}\"\n"), "")),
        NETWORK_FILE,
        &["edge.host_key"],
    );
}

#[test]
fn grant_permission_is_restricted() {
    let text = format!("{LOCAL}\n[[grant]]\naccount = \"x\"\npermission = \"CanManagePeers\"\n");
    assert_read_error(
        network(&text),
        NETWORK_FILE,
        &["grant", "CanRegisterDataspace"],
    );
    let text =
        format!("{LOCAL}\n[[grant]]\naccount = \"x\"\npermission = \"CanRegisterDataspace\"\n");
    assert_network_issue(&text, "grant[0].account");
}

// ---- network validation rules ----

#[test]
fn chain_discriminant_defaults_from_profile() {
    assert_eq!(network(LOCAL).unwrap().chain_discriminant(), 753);
    let qual = LOCAL.replace("iroha-dev-v1", "sora-nexus-v1-qual");
    assert_eq!(network(&qual).unwrap().chain_discriminant(), 369);
    let explicit = LOCAL.replace(
        "profile = \"iroha-dev-v1\"",
        "profile = \"iroha-dev-v1\"\nchain_discriminant = 7",
    );
    assert_eq!(network(&explicit).unwrap().chain_discriminant(), 7);
}

#[test]
fn node_names_are_unique() {
    assert_network_issue(&LOCAL.replace("\"n1\"", "\"n0\""), "node");
}

#[test]
fn validators_are_exactly_3f_plus_1_and_at_least_4() {
    let five = format!("{LOCAL}[[node]]\nname = \"n4\"\n");
    assert_network_issue(&five, "node");
    let one = "[network]\nname = \"t\"\nprofile = \"iroha-dev-v1\"\n[[node]]\nname = \"n0\"\n";
    assert_network_issue(one, "node");
    // The protocol caps a global roster at 31 validators.
    assert_eq!(network(&local_with(31)).unwrap().f(), 10);
    assert_network_issue(&local_with(34), "node");
    let observer = format!("{LOCAL}[[node]]\nname = \"o0\"\nrole = \"observer\"\n");
    let definition = network(&observer).unwrap();
    assert_eq!(
        (
            definition.validators().count(),
            definition.observers().count()
        ),
        (4, 1)
    );
    assert_eq!(definition.f(), 1);
}

#[test]
fn local_and_remote_nodes_do_not_mix() {
    let mixed = LOCAL.replacen("name = \"n0\"", "name = \"n0\"\nhost = \"h.example\"", 1);
    assert_network_issue(&mixed, "node");
}

#[test]
fn at_most_f_validators_per_host_identity() {
    // Two aliases pinned to one key are one host.
    let aliased = remote("").replacen(KEY_B, KEY_A, 1);
    assert_network_issue(&aliased, "node");
    let same_name = remote("")
        .replace("v1.example", "v0.example")
        .replacen(KEY_B, KEY_A, 1);
    assert_network_issue(&same_name, "node");
}

#[test]
fn at_most_f_validators_per_failure_domain() {
    let text = remote("")
        .replacen(
            "host = \"v0.example\"",
            "host = \"v0.example\"\nfailure_domain = \"rack-1\"",
            1,
        )
        .replacen(
            "host = \"v1.example\"",
            "host = \"v1.example\"\nfailure_domain = \"rack-1\"",
            1,
        );
    assert_network_issue(&text, "node");
}

#[test]
fn one_host_name_has_one_key() {
    let text = remote("").replace("v1.example", "v0.example");
    assert_network_issue(&text, "node[1].host_key");
}

#[test]
fn cohosted_nodes_need_distinct_ports() {
    let text = remote("")
        .replace("host = \"v1.example\"", "host = \"v0.example\"")
        .replacen(KEY_B, KEY_A, 1);
    assert_network_issue(&text, "node[1].p2p_port");
}

#[test]
fn ssh_is_required_iff_remote() {
    assert_network_issue(
        &remote("").replace("[ssh]\nidentity = \"~/.ssh/deploy.pub\"\n", ""),
        "ssh",
    );
    assert_network_issue(&format!("{LOCAL}\n[ssh]\nidentity = \"k\"\n"), "ssh");
}

#[test]
fn ssh_become_is_required_for_non_root_users() {
    assert_network_issue(&remote("user = \"deploy\"\n"), "ssh.become");
    assert_network_issue(
        &remote("user = \"deploy\"\nbecome = \"none\"\n"),
        "ssh.become",
    );
    let definition = network(&remote("user = \"deploy\"\nbecome = \"sudo\"\n")).unwrap();
    assert_eq!(definition.ssh.unwrap().escalation(), Become::Sudo);
    let root = network(&remote("become = \"none\"\n")).unwrap();
    assert_eq!(root.ssh.unwrap().escalation(), Become::None);
}

#[test]
fn ssh_user_and_jump_targets_are_checked() {
    assert_network_issue(&remote("user = \"Deploy\"\n"), "ssh.user");
    for bad in ["ops@[bastion]", "ops@[::1]2222", "ops@bastion.example:0"] {
        assert_read_error(
            network(&remote(&format!(
                "jump = \"{bad}\"\njump_host_key = \"{KEY_EDGE}\"\n"
            ))),
            NETWORK_FILE,
            &["ssh.jump"],
        );
    }
}

#[test]
fn jump_host_key_is_required_iff_jump() {
    assert_network_issue(
        &remote("jump = \"ops@bastion.example\"\n"),
        "ssh.jump_host_key",
    );
    assert_network_issue(
        &remote(&format!("jump_host_key = \"{KEY_EDGE}\"\n")),
        "ssh.jump_host_key",
    );
    let ok = remote(&format!(
        "jump = \"ops@bastion.example:2222\"\njump_host_key = \"{KEY_EDGE}\"\n"
    ));
    assert_eq!(network(&ok).unwrap().ssh.unwrap().jump.unwrap().port, 2222);
}

#[test]
fn ssh_agent_false_is_refused_with_edge() {
    let text = with_edge("").replacen(
        "identity = \"~/.ssh/deploy.pub\"\n",
        "identity = \"~/.ssh/deploy\"\nagent = false\n",
        1,
    );
    assert_network_issue(&text, "ssh.agent");
    assert!(network(&remote("agent = false\n")).is_ok());
}

#[test]
fn edge_and_public_root_go_together() {
    assert!(network(&with_edge("")).is_ok());
    let without_root = with_edge("").replace("public_root = \"https://test.example\"\n", "");
    assert_network_issue(&without_root, "network.public_root");
    let without_edge = LOCAL.replace(
        "profile = \"iroha-dev-v1\"",
        "profile = \"iroha-dev-v1\"\npublic_root = \"https://x.example\"",
    );
    assert_network_issue(&without_edge, "network.public_root");
}

#[test]
fn edge_requires_every_node_host_key() {
    let text = with_edge("").replacen(&format!("host_key = \"{KEY_C}\"\n"), "", 1);
    assert_network_issue(&text, "node[2].host_key");
}

#[test]
fn edge_needs_remote_nodes() {
    // One issue, not advice to pin hosts that local nodes cannot have.
    let text = network_line(
        &format!(
            "{LOCAL}\n[edge]\nhost = \"edge.example\"\nhost_key = \"{KEY_EDGE}\"\ndomain = \"test.example\"\ntls_certificate = \"/c.pem\"\ntls_private_key = \"/k.pem\"\n"
        ),
        "public_root = \"https://test.example\"",
    );
    let keys = issue_keys(&network(&text).unwrap_err());
    assert_eq!(keys, ["edge"]);
}

#[test]
fn edge_explorer_domain_is_a_host_name() {
    assert_network_issue(
        &with_edge("explorer_domain = \"bad domain\"\nexplorer_root = \"/srv/explorer\"\n"),
        "edge.explorer_domain",
    );
}

#[test]
fn edge_remote_paths_must_be_absolute() {
    let text = with_edge("").replace("/etc/tls/key.pem", "tls/key.pem");
    assert_network_issue(&text, "edge.tls_private_key");
    assert_network_issue(
        &with_edge("explorer_domain = \"explorer.example\"\n"),
        "edge.explorer_root",
    );
    assert_network_issue(
        &with_edge("cors_origins = [\"https://a.example/\"]\n"),
        "edge.cors_origins[0]",
    );
}

#[test]
fn private_upstream_requires_every_node_private_address() {
    assert_network_issue(
        &with_edge("upstream = \"private\"\n"),
        "node[0].private_address",
    );
    let stray = remote("").replacen(
        "host = \"v0.example\"",
        "host = \"v0.example\"\nprivate_address = \"10.0.0.1\"",
        1,
    );
    assert_network_issue(&stray, "node[0].private_address");
    let mut text = with_edge("upstream = \"private\"\n");
    for index in 0..4 {
        text = text.replacen(
            &format!("host = \"v{index}.example\""),
            &format!("host = \"v{index}.example\"\nprivate_address = \"10.0.0.{index}\""),
            1,
        );
    }
    assert_eq!(
        network(&text).unwrap().edge.unwrap().upstream,
        Upstream::Private
    );
    // Observers run Torii too, so they need an address to bind it to.
    let observer = format!(
        "{text}\n[[node]]\nname = \"o0\"\nrole = \"observer\"\nhost = \"edge.example\"\nhost_key = \"{KEY_EDGE}\"\n"
    );
    assert_network_issue(&observer, "node[4].private_address");
    let bad = text.replacen("10.0.0.0", "internal.example", 1);
    assert_network_issue(&bad, "node[0].private_address");
}

#[test]
fn per_node_domains_require_node_domains() {
    assert_network_issue(&with_edge("per_node_domains = true\n"), "node[0].domain");
    let stray = remote("").replacen(
        "host = \"v0.example\"",
        "host = \"v0.example\"\ndomain = \"v0.public.example\"",
        1,
    );
    assert_network_issue(&stray, "node[0].domain");
}

#[test]
fn local_and_scaling_are_local_only() {
    assert_network_issue(&remote("\n[local]\nbind_host = \"127.0.0.1\"\n"), "local");
    assert_network_issue(
        &remote("\n[scaling]\nlanes = 2\naccounts = 10\n"),
        "scaling",
    );
    let bind_all = format!("{LOCAL}\n[local]\nbind_host = \"0.0.0.0\"\n");
    assert_network_issue(&bind_all, "local.public_host");
    let custom = format!(
        "{LOCAL}\n[local]\nbind_host = \"0.0.0.0\"\npublic_host = \"devbox\"\nbase_torii_port = 1000\n"
    );
    let definition = network(&custom).unwrap();
    assert_eq!(definition.advertised_address(1).as_deref(), Some("devbox"));
    assert_eq!(definition.node_ports(1).unwrap().torii, 1001);
    assert_network_issue(
        &format!("{LOCAL}\n[local]\nbind_host = \"localhost\"\n"),
        "local.bind_host",
    );
    assert_network_issue(
        &format!("{LOCAL}\n[local]\npublic_host = \"dev box\"\n"),
        "local.public_host",
    );
    assert_network_issue(
        &format!("{LOCAL}\n[scaling]\nlanes = 0\naccounts = 10\n"),
        "scaling.lanes",
    );
}

#[test]
fn inrou_is_a_host_precondition_not_a_definition_rule() {
    // `up` refuses it on hosts without Linux, KVM and root (G0, P5).
    for text in [LOCAL.to_owned(), remote("")] {
        let text = format!("{text}\n[inrou]\nenabled = true\n");
        assert!(network(&text).unwrap().inrou.enabled);
    }
}

#[test]
fn onboarding_credential_ids_are_unique() {
    let credential = "\n[[onboarding.credential]]\nid = \"app\"\nscope = \"universal\"\n";
    assert_network_issue(
        &format!("{LOCAL}{credential}{credential}"),
        "onboarding.credential",
    );
    let bad_scope =
        format!("{LOCAL}\n[[onboarding.credential]]\nid = \"app\"\nscope = \"domain:x\"\n");
    assert_read_error(
        network(&bad_scope),
        NETWORK_FILE,
        &["onboarding.credential"],
    );
}

#[test]
fn release_signers_must_be_ed25519_and_nonempty() {
    assert_network_issue(
        &format!("{LOCAL}\n[release]\nsigners = []\n"),
        "release.signers",
    );
    let bls = KeyPair::from_seed(vec![7; 32], Algorithm::BlsNormal)
        .public_key()
        .to_string();
    assert_network_issue(
        &format!("{LOCAL}\n[release]\nsigners = [\"{ED25519_KEY}\", \"{bls}\"]\n"),
        "release.signers[1]",
    );
    assert_network_issue(
        &format!("{LOCAL}\n[release]\nsigners = [\"{ED25519_KEY}\", \"{ED25519_KEY}\"]\n"),
        "release.signers",
    );
    let text = format!(
        "{LOCAL}\n[release]\nsource = \"../dist\"\nsigners = [\"ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0\"]\n"
    );
    let definition = network(&text).unwrap();
    assert_eq!(
        definition.release.source,
        Some(ReleaseSource::Directory(PathBuf::from(
            "/defs/networks/../dist"
        )))
    );
}

#[test]
fn paths_resolve_against_the_file_and_home() {
    let text = LOCAL.replace(
        "profile = \"iroha-dev-v1\"",
        "profile = \"iroha-dev-v1\"\nadmin_key = \"keys/admin.key\"",
    ) + "\n[monitor]\nwebhook_file = \"~/secrets/hook.url\"\ninterval = \"90s\"\n";
    let definition = network(&text).unwrap();
    assert_eq!(
        definition.network.admin_key,
        Some(PathBuf::from("/defs/networks/keys/admin.key"))
    );
    assert_eq!(
        definition.monitor.webhook_file,
        Some(PathBuf::from("/home/op/secrets/hook.url"))
    );
    assert_eq!(definition.monitor.interval.get().as_secs(), 90);
    let no_home = NetworkDefinition::parse(&text, NETWORK_FILE, None).unwrap_err();
    assert_eq!(issue_keys(&no_home), ["monitor.webhook_file"]);
    let absolute = LOCAL.replace(
        "profile = \"iroha-dev-v1\"",
        "profile = \"iroha-dev-v1\"\nadmin_key = \"/etc/iroha/admin.key\"",
    );
    assert_eq!(
        network(&absolute).unwrap().network.admin_key,
        Some(PathBuf::from("/etc/iroha/admin.key"))
    );
}

#[test]
fn network_section_values_are_checked() {
    for chain_id in ["", " taira "] {
        assert_network_issue(
            &network_line(LOCAL, &format!("chain_id = \"{chain_id}\"")),
            "network.chain_id",
        );
    }
    assert_network_issue(
        &network_line(
            LOCAL,
            &format!("operators = [\"{ED25519_KEY}\", \"{ED25519_KEY}\"]"),
        ),
        "network.operators",
    );
    assert_network_issue(
        &format!("{LOCAL}\n[retention]\nreleases = 0\n"),
        "retention.releases",
    );
}

#[test]
fn duplicate_grants_are_reported_at_their_index() {
    let key: iroha_crypto::PublicKey = ED25519_KEY.parse().unwrap();
    // `sora-nexus-v1-qual` accounts use chain discriminant 369, not the
    // process default, and the issue quotes the literal as written.
    let account = {
        let _scope = ChainDiscriminantGuard::enter(369);
        AccountId::new(key).to_string()
    };
    let qual = LOCAL.replace("iroha-dev-v1", "sora-nexus-v1-qual");
    let grant =
        format!("\n[[grant]]\naccount = \"{account}\"\npermission = \"CanRegisterDataspace\"\n");
    let error = network(&format!("{qual}{grant}{grant}")).unwrap_err();
    assert_eq!(issue_keys(&error), ["grant[1]"]);
    assert!(error.to_string().contains(&account), "{error}");
    assert_eq!(network(&format!("{qual}{grant}")).unwrap().grants.len(), 1);
}

#[test]
fn node_hosts_failure_domains_and_ports_are_checked() {
    assert_network_issue(
        &remote("").replacen("v0.example", "bad_host.example", 1),
        "node[0].host",
    );
    assert_network_issue(
        &node_line(&remote(""), 0, "failure_domain = \" \""),
        "node[0].failure_domain",
    );
    assert_network_issue(
        &node_line(&remote(""), 0, "p2p_port = 0"),
        "node[0].p2p_port",
    );
    assert_network_issue(&node_line(LOCAL, 1, "torii_port = 0"), "node[1].torii_port");
}

#[test]
fn all_issues_are_reported_together() {
    let text = format!(
        "{LOCAL}[[node]]\nname = \"n0\"\n\n[ssh]\nidentity = \"k\"\n\n[retention]\nreleases = 0\n"
    );
    let keys = issue_keys(&network(&text).unwrap_err());
    for key in ["node", "ssh", "retention.releases"] {
        assert!(
            keys.iter().any(|found| found == key),
            "{key} missing from {keys:?}"
        );
    }
    assert!(keys.len() >= 4, "{keys:?}");
}

// ---- dataspace validation rules ----

const DS_NETWORK: &str = r#"
[dataspace]
name = "acme"
network = "https://taira.sora.org"
owner_key = "~/.iroha/keys/acme-owner.key"
max_fee = "20"

[committee]
source = "network"
"#;

fn owner(extra: &str) -> String {
    let mut text = DS_NETWORK.replace("source = \"network\"", "source = \"owner\"");
    text.push_str("\n[ssh]\nidentity = \"~/.ssh/acme.pub\"\n");
    text.push_str(extra);
    for (index, key) in [KEY_A, KEY_B, KEY_C, KEY_D].iter().enumerate() {
        write!(
            text,
            "\n[[committee.node]]\nname = \"acme-{index}\"\nhost = \"dsv{index}.example\"\nhost_key = \"{key}\"\n"
        )
        .unwrap();
    }
    text
}

#[test]
fn dataspace_defaults() {
    let definition = dataspace(DS_NETWORK).unwrap();
    assert_eq!(definition.dataspace.visibility, Visibility::Restricted);
    assert_eq!(definition.dataspace.lease_years, 1);
    assert!(definition.dataspace.operators.is_empty());
    assert!(dataspace(&owner("")).is_ok());
}

#[test]
fn omitted_committee_matches_explicit_parent_network_committee() {
    let explicit = dataspace(DS_NETWORK).unwrap();
    let absent = DS_NETWORK.replace("[committee]\nsource = \"network\"\n", "");
    for text in [absent, DS_NETWORK.replace("source = \"network\"\n", "")] {
        let implicit = dataspace(&text).unwrap();
        assert_eq!(implicit.dataspace, explicit.dataspace);
        assert_eq!(implicit.committee, explicit.committee);
        assert_eq!(implicit.ssh, explicit.ssh);
        assert_eq!(implicit.edge, explicit.edge);
        assert!(!implicit.is_local());
        assert_eq!(implicit.f(), None);
    }
}

#[test]
fn owner_nodes_require_explicit_owner_committee_source() {
    let text = owner("").replace("source = \"owner\"\n", "");
    assert_dataspace_issue(&text, "committee.node");
    assert_dataspace_issue(&text, "ssh");
    assert!(
        dataspace(&text)
            .unwrap_err()
            .to_string()
            .contains("committee.source = \"owner\"")
    );
}

#[test]
fn dataspace_rejects_global_node_and_network_configuration() {
    for (section, setting) in [
        ("network", "profile = \"sora-nexus-v1\""),
        ("sumeragi", "role = \"validator\""),
        ("nexus", "lane_count = 7"),
        ("gov", "enabled = true"),
        ("sorafs.storage", "enabled = true"),
        ("soracloud_runtime", "production_mode = true"),
        ("streaming", "enabled = true"),
        ("taikai", "enabled = true"),
        ("oracle", "enabled = true"),
        ("zk.pipa_r", "enabled = true"),
        ("confidential", "enabled = true"),
        ("torii", "address = \"127.0.0.1:8080\""),
        ("pipeline", "signature_batch_max_bls = 4"),
        ("crypto", "allowed_signing = [\"ed25519\"]"),
        ("genesis", "file = \"genesis.signed.nrt\""),
    ] {
        assert_read_error(
            dataspace(&format!("{DS_NETWORK}\n[{section}]\n{setting}\n")),
            DATASPACE_FILE,
            &[section.split('.').next().unwrap()],
        );
    }
    for (key, value) in [
        ("profile", "\"sora-nexus-v1\""),
        ("role", "\"validator\""),
        ("validators", "4"),
        ("data_dir", "\"/var/lib/iroha\""),
    ] {
        assert_read_error(
            dataspace(&format!("{key} = {value}\n{DS_NETWORK}")),
            DATASPACE_FILE,
            &[key],
        );
    }
}

#[test]
fn committee_source_is_network_or_owner() {
    for value in ["\"validators\"", "\"\"", "true", "4", "[]", "{}"] {
        assert_read_error(
            dataspace(&DS_NETWORK.replace("\"network\"\n", &format!("{value}\n"))),
            DATASPACE_FILE,
            &["committee.source"],
        );
    }
    assert_read_error(
        dataspace(&DS_NETWORK.replace("source =", "sorce =")),
        DATASPACE_FILE,
        &["committee.sorce"],
    );
    let no_committee = DS_NETWORK.replace("[committee]\nsource = \"network\"\n", "");
    assert_read_error(
        dataspace(&format!("committee = \"network\"\n{no_committee}")),
        DATASPACE_FILE,
        &["committee"],
    );
}

#[test]
fn owner_committee_is_exactly_3f_plus_1() {
    let text = owner("");
    let three = &text[..text.rfind("[[committee.node]]").unwrap()];
    assert_dataspace_issue(three, "committee.node");
    // Owner committees are capped at 128 members.
    let rehearsal = |members: usize| {
        let mut text = DS_NETWORK
            .replace("source = \"network\"", "source = \"owner\"")
            .replace("https://taira.sora.org", "../networks/dev.toml");
        for index in 0..members {
            write!(text, "\n[[committee.node]]\nname = \"m{index}\"\n").unwrap();
        }
        text
    };
    assert_eq!(dataspace(&rehearsal(127)).unwrap().f(), Some(42));
    assert_dataspace_issue(&rehearsal(130), "committee.node");
}

#[test]
fn local_rehearsals_run_under_a_network_definition() {
    let local = std::fs::read_to_string(fixture("acme-local.toml")).unwrap();
    assert!(local.contains("network = \"../../../../networks/dev.toml\""));
    for parent in ["https://taira.sora.org", "../networks/taira.card.toml"] {
        let text = local.replace("../../../../networks/dev.toml", parent);
        assert_dataspace_issue(&text, "dataspace.network");
    }
}

#[test]
fn dataspace_operators_require_owner_committee() {
    let with_operator = |text: &str| {
        text.replace(
            "max_fee",
            &format!("operators = [\"{ED25519_KEY}\"]\nmax_fee"),
        )
    };
    assert_dataspace_issue(&with_operator(DS_NETWORK), "dataspace.operators");
    let implicit_network = DS_NETWORK.replace("[committee]\nsource = \"network\"\n", "");
    assert_dataspace_issue(&with_operator(&implicit_network), "dataspace.operators");
    let owner_definition = dataspace(&with_operator(&owner(""))).unwrap();
    assert_eq!(owner_definition.dataspace.operators.len(), 1);
}

#[test]
fn dataspace_operators_are_unique() {
    let text = owner("").replace(
        "max_fee",
        &format!("operators = [\"{ED25519_KEY}\", \"{ED25519_KEY}\"]\nmax_fee"),
    );
    assert_dataspace_issue(&text, "dataspace.operators");
}

#[test]
fn owner_committee_limits_shared_hosts() {
    assert_dataspace_issue(&owner("").replacen(KEY_B, KEY_A, 1), "committee.node");
}

#[test]
fn owner_committee_limits_shared_failure_domains() {
    let text = owner("")
        .replacen(
            "host = \"dsv0.example\"",
            "host = \"dsv0.example\"\nfailure_domain = \"dc\"",
            1,
        )
        .replacen(
            "host = \"dsv1.example\"",
            "host = \"dsv1.example\"\nfailure_domain = \"dc\"",
            1,
        );
    assert_dataspace_issue(&text, "committee.node");
}

#[test]
fn dataspace_ssh_only_for_remote_owner_nodes() {
    assert_dataspace_issue(&format!("{DS_NETWORK}\n[ssh]\nidentity = \"k\"\n"), "ssh");
    assert_dataspace_issue(
        &owner("").replace("[ssh]\nidentity = \"~/.ssh/acme.pub\"\n", ""),
        "ssh",
    );
    let local = fixture("acme-local.toml");
    let text = std::fs::read_to_string(local).unwrap() + "\n[ssh]\nidentity = \"k\"\n";
    assert_dataspace_issue(&text, "ssh");
    assert_dataspace_issue(&owner("user = \"deploy\"\n"), "ssh.become");
}

#[test]
fn dataspace_edge_only_for_owner_committees() {
    let edge = format!(
        "\n[edge]\nhost = \"dsv0.example\"\nhost_key = \"{KEY_A}\"\ndomain = \"ds.example\"\ntls_certificate = \"/c.pem\"\ntls_private_key = \"/k.pem\"\n"
    );
    assert_dataspace_issue(&format!("{DS_NETWORK}{edge}"), "edge");
    assert!(dataspace(&owner(&edge)).is_ok());
    let unpinned = owner(&edge).replacen(&format!("host_key = \"{KEY_D}\"\n"), "", 1);
    assert_dataspace_issue(&unpinned, "committee.node[3].host_key");
    let agentless = owner(&format!("agent = false\n{edge}"));
    assert_dataspace_issue(&agentless, "ssh.agent");

    // Members become DNS labels under the edge domain.
    let trailing = owner(&edge).replacen("name = \"acme-1\"", "name = \"acme-\"", 1);
    assert_dataspace_issue(&trailing, "committee.node[1].name");
    assert!(dataspace(&owner("").replacen("name = \"acme-1\"", "name = \"acme-\"", 1)).is_ok());

    // The private upstream is unsettled for owner committees (P6).
    let private = owner(&format!("{edge}upstream = \"private\"\n"));
    assert_dataspace_issue(&private, "edge.upstream");

    // A local owner committee cannot have an edge; that is the only issue.
    let local = std::fs::read_to_string(fixture("acme-local.toml")).unwrap();
    let local_edge = format!(
        "{local}\n[edge]\nhost = \"edge.example\"\nhost_key = \"{KEY_EDGE}\"\ndomain = \"ds.example\"\ntls_certificate = \"/c.pem\"\ntls_private_key = \"/k.pem\"\n"
    );
    let keys = issue_keys(&dataspace(&local_edge).unwrap_err());
    assert_eq!(keys, ["edge"]);
}

#[test]
fn committee_nodes_require_owner_source() {
    let text = format!("{DS_NETWORK}\n[[committee.node]]\nname = \"acme-1\"\n");
    assert_dataspace_issue(&text, "committee.node");
}

#[test]
fn dataspace_network_is_https_or_a_path() {
    assert_read_error(
        dataspace(&DS_NETWORK.replace("https://taira.sora.org", "http://taira.sora.org")),
        DATASPACE_FILE,
        &["dataspace.network"],
    );
    let anchor =
        dataspace(&DS_NETWORK.replace("https://taira.sora.org", "../networks/taira.card.toml"))
            .unwrap();
    assert_eq!(
        anchor.dataspace.network,
        NetworkRef::CardAnchor(PathBuf::from(
            "/defs/dataspaces/../networks/taira.card.toml"
        ))
    );
}

#[test]
fn dataspace_lease_years_are_1_to_10() {
    let with =
        |years: u8| DS_NETWORK.replace("max_fee", &format!("lease_years = {years}\nmax_fee"));
    assert_dataspace_issue(&with(0), "dataspace.lease_years");
    assert_dataspace_issue(&with(11), "dataspace.lease_years");
    assert_eq!(dataspace(&with(10)).unwrap().dataspace.lease_years, 10);
}

#[test]
fn dataspace_visibility_is_restricted_or_public() {
    let public = DS_NETWORK.replace("max_fee", "visibility = \"public\"\nmax_fee");
    assert_eq!(
        dataspace(&public).unwrap().dataspace.visibility,
        Visibility::Public
    );
    assert_read_error(
        dataspace(&DS_NETWORK.replace("max_fee", "visibility = \"private\"\nmax_fee")),
        DATASPACE_FILE,
        &["dataspace.visibility"],
    );
}

#[test]
fn dataspace_rejects_inrou_and_noncanonical_names() {
    assert_read_error(
        dataspace(&format!("{DS_NETWORK}\n[inrou]\nenabled = true\n")),
        DATASPACE_FILE,
        &["inrou"],
    );
    assert_read_error(
        dataspace(&DS_NETWORK.replace("name = \"acme\"", "name = \"Acme\"")),
        DATASPACE_FILE,
        &["dataspace.name"],
    );
    assert_read_error(
        dataspace(&DS_NETWORK.replace("max_fee = \"20\"", "max_fee = \"-1\"")),
        DATASPACE_FILE,
        &["dataspace.max_fee"],
    );
}
