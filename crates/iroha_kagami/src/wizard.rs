//! Interactive onboarding wizard for staging a Sora Nexus observer configuration.
use crate::genesis::PUBLIC_NEXUS_CHAIN_ID;
use crate::{Outcome, RunArgs, tui};
use clap::{Args as ClapArgs, ValueEnum};
use color_eyre::eyre::{Context as _, Result, ensure, eyre};
use inquire::{Select, Text};
use iroha_config::parameters::{actual, defaults};
use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair, PublicKey, bls_normal_pop_verify};
use iroha_data_model::peer::Peer;
use iroha_genesis::validate_genesis_manifest_json;
use iroha_model_base::peer::PeerId;
use iroha_primitives::addr::SocketAddr;
use norito::json::{self, Value as JsonValue};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{BufWriter, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    str::FromStr,
};
use toml::{Value as TomlValue, value::Table as TomlTable};
use zeroize::Zeroizing;

const WIZARD_PROFILE_LABEL: &str = "Sora Nexus observer";
const NEXUS_CHAIN_DISCRIMINANT: i64 = 753;
const NEXUS_CONFIG_TEMPLATE: &str = include_str!("../../../configs/soranexus/nexus/config.toml");
const NEXUS_GENESIS_TEMPLATE: &[u8] =
    include_bytes!("../../../configs/soranexus/nexus/genesis.template.json");
/// CLI entrypoint for the setup wizard.
#[derive(Debug, ClapArgs, Clone)]
pub struct Args {
    /// Directory where generated config/genesis files will be written.
    #[arg(long, value_name = "PATH", default_value = "wizard-output")]
    pub output_dir: PathBuf,
    /// Run non-interactively, accepting defaults for prompts that are not supplied via flags.
    #[arg(long)]
    pub non_interactive: bool,
    /// Override the public P2P host/IP advertised for this generated observer.
    #[arg(long, value_name = "HOST")]
    pub p2p_host: Option<String>,
    /// Override the public P2P port for this peer.
    #[arg(long, value_name = "PORT")]
    pub p2p_port: Option<u16>,
    /// Override the local Torii listener port for this peer.
    #[arg(long, value_name = "PORT")]
    pub torii_port: Option<u16>,
    /// Override the relay mode instead of prompting interactively.
    #[arg(long, value_enum)]
    pub relay_mode: Option<RelayMode>,
    /// Relay hub addresses (`host:port`), repeat once per hub when relay mode uses them.
    #[arg(long = "relay-hub-address", value_name = "HOST:PORT")]
    pub relay_hub_addresses: Vec<String>,
    /// Trusted roster (`pubkey` or `pubkey@host:port`); include a reachable address without a relay.
    #[arg(long, value_name = "PEERS")]
    pub trusted_peers: Option<String>,
    /// Comma-separated PoP entries for trusted peers (`pubkey=pop_hex`).
    #[arg(long, value_name = "POPS")]
    pub trusted_peers_pop: Option<String>,
}
#[derive(Clone, Debug)]
struct Answers {
    p2p_host: String,
    p2p_port: u16,
    torii_port: u16,
    trusted_peers: Vec<String>,
    relay_mode: RelayMode,
    relay_hub_addresses: Vec<String>,
    output_dir: PathBuf,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum RelayMode {
    Disabled,
    Hub,
    Spoke,
    Assist,
}
impl fmt::Display for RelayMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayMode::Disabled => write!(f, "disabled (full mesh)"),
            RelayMode::Hub => write!(f, "hub (static IP)"),
            RelayMode::Spoke => write!(f, "spoke (dial hub only)"),
            RelayMode::Assist => write!(f, "assist (direct + hub fallback)"),
        }
    }
}
#[derive(Clone, Copy, Debug)]
struct ProfileDefaults {
    chain: &'static str,
    p2p_port: u16,
    torii_port: u16,
    observer_public_host: &'static str,
    relay_hub_host: &'static str,
    trusted_peers: &'static [&'static str],
}
impl ProfileDefaults {
    const fn nexus() -> Self {
        Self {
            chain: PUBLIC_NEXUS_CHAIN_ID,
            p2p_port: 1337,
            torii_port: 8080,
            observer_public_host: "127.0.0.1",
            relay_hub_host: "nexus.mof2.sora.org",
            trusted_peers: &[concat!(
                "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2@",
                "nexus.mof2.sora.org:1337"
            )],
        }
    }
}
impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        print_banner();
        let answers = gather_answers(&self)?;
        crate::shell::quote_path(&answers.output_dir)
            .wrap_err("validate requested wizard output path for shell handoff command")?;
        let keypair = KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
            .wrap_err("failed to generate wizard BLS key pair")?;
        let soranet_transport_keypair = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .wrap_err("failed to generate wizard SoraNet transport key pair")?;
        let streaming_identity_keypair = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .wrap_err("failed to generate wizard streaming identity key pair")?;
        if streaming_identity_keypair.public_key() == soranet_transport_keypair.public_key() {
            return Err(eyre!(
                "wizard streaming and SoraNet transport identities must be distinct"
            ));
        }
        let trusted_pops = resolve_trusted_peers_pop(&self, &answers, &keypair)?;
        tui::status("Generating config and genesis files");
        let mut config = load_config_template(&answers, &keypair, &trusted_pops)?;
        apply_overrides(
            &mut config,
            &answers,
            &keypair,
            &soranet_transport_keypair,
            &streaming_identity_keypair,
            &trusted_pops,
        )?;
        let genesis = load_genesis_template()?;
        let mut config_payload = Zeroizing::new(
            toml::to_string_pretty(&*config)
                .wrap_err("failed to serialise config after wizard updates")?,
        );
        // Surface optional networking knobs in the generated config without changing defaults.
        config_payload.push_str(
            r#"

# ---
# P2P advanced options (optional)
#
# [network]
# # Outbound proxy (HTTP CONNECT / SOCKS5):
# p2p_proxy = "http://proxy.example.com:8080" # or socks5://...
# p2p_proxy_required = false
# p2p_no_proxy = ["localhost", ".example.com"]
# # Deny rules take precedence; empty allow lists are unrestricted:
# outbound_dial_allow_cidrs = ["192.0.2.0/24", "2001:db8::/32"]
# outbound_dial_deny_cidrs = ["127.0.0.0/8", "::1/128"]
# outbound_dial_allow_dns_suffixes = [".example.com"]
# outbound_dial_deny_dns_suffixes = [".blocked.example.com"]
#
# # If p2p_proxy starts with https://, the proxy hop uses pinned TLS:
# p2p_proxy_tls_verify = true
# p2p_proxy_tls_pinned_cert_der_base64 = "BASE64_DER"
#
# Notes:
# - When p2p_proxy_required=true, p2p_no_proxy must be empty.
# - HTTPS proxy credentials are allowed only with verification and an exact pinned cert.
# - Dial policy checks hostnames and every resolved address for direct and proxied dials.
# - P2P always serves TLS 1.3 on network.address; there is no plaintext listener or fallback.
"#,
        );
        let genesis_payload = json::to_string_pretty(&genesis)
            .wrap_err("failed to serialise genesis after wizard updates")?;
        validate_genesis_manifest_json(genesis_payload.as_bytes())
            .wrap_err("generated wizard genesis exceeds fixed resource bounds")?;
        let output_dir = crate::secure_fs::prepare_empty_private_directory(&answers.output_dir)
            .wrap_err("prepare fresh wizard private output directory")?;
        let shell_output_dir = crate::shell::absolute_quote_path(&output_dir)
            .wrap_err("validate wizard output path for shell handoff command")?;
        let config_path = output_dir.join("config.toml");
        let genesis_path = output_dir.join("genesis.template.json");
        crate::secure_fs::write_private_file_atomic(&config_path, config_payload.as_bytes())
            .wrap_err_with(|| format!("failed to write config to {}", config_path.display()))?;
        crate::secure_fs::write_private_file_atomic(&genesis_path, genesis_payload.as_bytes())
            .wrap_err_with(|| format!("failed to write genesis to {}", genesis_path.display()))?;
        let guide_path = output_dir.join("README.md");
        let start_command = format!(
            "cd {} && iroha3d --sora --config config.toml",
            shell_output_dir
        );
        write_wizard_readme(
            &guide_path,
            ProfileDefaults::nexus().chain,
            keypair.public_key(),
            &config_path,
            &genesis_path,
            &start_command,
        )?;
        crate::secure_fs::harden_private_tree_with_owner_executables(&output_dir, &[])
            .wrap_err("harden wizard private artifact tree")?;
        tui::success(format!(
            "Config and reference genesis manifest staged under {}",
            output_dir.display()
        ));
        writeln!(writer, "profile: {WIZARD_PROFILE_LABEL}")?;
        writeln!(writer, "chain_id: {}", ProfileDefaults::nexus().chain)?;
        writeln!(writer, "generated_public_key: {}", keypair.public_key())?;
        writeln!(writer, "config: {}", config_path.display())?;
        writeln!(writer, "genesis_manifest: {}", genesis_path.display())?;
        writeln!(writer, "guide: {}", guide_path.display())?;
        writeln!(writer, "sora profile: pass --sora when starting iroha3d")?;
        writeln!(
            writer,
            "next: obtain the authoritative genesis.signed.nrt and expected hash; see {}",
            guide_path.display()
        )?;
        Ok(())
    }
}
fn gather_answers(args: &Args) -> Result<Answers> {
    let defaults = ProfileDefaults::nexus();
    let p2p_host = resolve_text(
        "Observer public P2P host",
        args.p2p_host.clone(),
        defaults.observer_public_host.to_string(),
        args.non_interactive,
    )?;
    let p2p_host = iroha_deploy::localnet::canonical_host(&p2p_host, "p2p host")?;
    let p2p_port = resolve_number(
        "P2P port",
        args.p2p_port,
        defaults.p2p_port,
        args.non_interactive,
    )?;
    if p2p_port == 0 {
        return Err(eyre!("P2P port must be greater than zero"));
    }
    let torii_port = resolve_number(
        "Local Torii listener port",
        args.torii_port,
        defaults.torii_port,
        args.non_interactive,
    )?;
    if torii_port == 0 {
        return Err(eyre!("Torii port must be greater than zero"));
    }
    if p2p_port == torii_port {
        return Err(eyre!("P2P and Torii listener ports must be distinct"));
    }
    let relay_mode = resolve_relay_mode(args.relay_mode, args.non_interactive)?;
    let relay_hub_addresses = if matches!(relay_mode, RelayMode::Spoke | RelayMode::Assist) {
        if args.relay_hub_addresses.is_empty() {
            let raw = resolve_text(
                "Relay hub addresses (comma separated host:port)",
                None,
                format!("{}:{}", defaults.relay_hub_host, defaults.p2p_port),
                args.non_interactive,
            )?;
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        } else {
            args.relay_hub_addresses.clone()
        }
    } else {
        Vec::new()
    }
    .into_iter()
    .map(|address| canonical_addr_literal(&address))
    .collect::<Result<Vec<_>>>()?;
    let default_trusted = defaults.trusted_peers.join(", ");
    let trusted_default = args
        .trusted_peers
        .as_deref()
        .unwrap_or(default_trusted.as_str());
    let trusted_prompt = resolve_text(
        "Trusted peers (comma separated pubkey or pubkey@host:port; PoPs mark validators)",
        args.trusted_peers.clone(),
        trusted_default.to_string(),
        args.non_interactive,
    )?;
    let trusted_peers = trusted_prompt
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let trusted_peers = sanitize_trusted_peers(&trusted_peers)?;
    ensure!(
        matches!(relay_mode, RelayMode::Spoke | RelayMode::Assist)
            || trusted_peers.iter().any(|peer| peer.contains('@')),
        "trusted peer roster must include at least one reachable pubkey@host:port entry unless spoke/assist relay hubs provide the bootstrap route"
    );
    Ok(Answers {
        p2p_host,
        p2p_port,
        torii_port,
        trusted_peers,
        relay_mode,
        relay_hub_addresses,
        output_dir: args.output_dir.clone(),
    })
}
fn resolve_trusted_peers_pop(
    args: &Args,
    answers: &Answers,
    keypair: &KeyPair,
) -> Result<BTreeMap<PublicKey, Vec<u8>>> {
    if args.non_interactive && args.trusted_peers.is_none() {
        return Err(eyre!(
            "non-interactive Sora wizard onboarding requires --trusted-peers with the authoritative full validator roster"
        ));
    }
    if args.non_interactive && args.trusted_peers_pop.is_none() {
        return Err(eyre!(
            "non-interactive Sora wizard onboarding requires --trusted-peers-pop matching the authoritative signed genesis roster"
        ));
    }
    let mut peers = answers.trusted_peers.clone();
    let self_peer = format!(
        "{}@{}",
        keypair.public_key(),
        addr_literal(&answers.p2p_host, answers.p2p_port)?
    );
    if !trusted_peers_contain_key(&peers, keypair.public_key())? {
        peers.push(self_peer);
    }
    let peer_ids = parse_trusted_peer_ids(&peers)?;
    let roster_keys: BTreeSet<PublicKey> = peer_ids
        .iter()
        .map(|peer| peer.public_key().clone())
        .collect();
    for pk in &roster_keys {
        if pk.algorithm() != Algorithm::BlsNormal {
            return Err(eyre!("trusted peer {pk} must use a BLS-Normal key"));
        }
    }
    let mut pops = parse_trusted_peers_pop_arg(args.trusted_peers_pop.as_deref())?;
    if pops.contains_key(keypair.public_key()) {
        return Err(eyre!(
            "the newly generated Sora peer must start as an observer; its local key must not appear in --trusted-peers-pop"
        ));
    }
    let extras: Vec<_> = pops
        .keys()
        .filter(|pk| !roster_keys.contains(*pk))
        .cloned()
        .collect();
    if !extras.is_empty() {
        return Err(eyre!(
            "trusted_peers_pop contains keys not in trusted_peers: {extras:?}"
        ));
    }
    let missing: Vec<PublicKey> = roster_keys
        .iter()
        .filter(|pk| !pops.contains_key(*pk))
        .cloned()
        .collect();
    if !missing.is_empty() && !args.non_interactive {
        for pk in missing {
            if pk == *keypair.public_key() {
                continue;
            }
            let pop = prompt_pop_for_peer(&pk)?;
            pops.insert(pk, pop);
        }
    }
    let missing = roster_keys
        .iter()
        .filter(|public_key| *public_key != keypair.public_key() && !pops.contains_key(*public_key))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(eyre!(
            "Sora wizard validator roster is missing authoritative PoPs for: {missing:?}"
        ));
    }
    if !iroha_data_model::block::consensus::is_valid_committee_size(pops.len()) {
        return Err(eyre!(
            "Sora wizard authoritative validator roster must contain an exact 3f + 1 committee of 4, 7, ... 31 PoPs; got {}",
            pops.len()
        ));
    }
    Ok(pops)
}
fn parse_trusted_peer_ids(peers: &[String]) -> Result<Vec<PeerId>> {
    peers
        .iter()
        .map(|entry| {
            let public_key = entry.split_once('@').map_or(entry.as_str(), |(pk, _)| pk);
            PeerId::from_str(public_key)
                .wrap_err_with(|| format!("invalid trusted peer entry: {entry}"))
        })
        .collect()
}
fn parse_trusted_peers_pop_arg(raw: Option<&str>) -> Result<BTreeMap<PublicKey, Vec<u8>>> {
    let mut pops = BTreeMap::new();
    let Some(raw) = raw else {
        return Ok(pops);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(pops);
    }
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (pk_raw, pop_raw) = entry
            .split_once('=')
            .ok_or_else(|| eyre!("trusted_peers_pop entry must be pubkey=pop_hex: {entry}"))?;
        let pk = PublicKey::from_str(pk_raw.trim()).wrap_err_with(|| {
            format!("trusted_peers_pop entry has invalid public key: {pk_raw}")
        })?;
        if pk.algorithm() != Algorithm::BlsNormal {
            return Err(eyre!("trusted_peers_pop entry uses non-BLS key: {pk}"));
        }
        let pop = decode_pop_hex(pop_raw.trim())
            .wrap_err_with(|| format!("trusted_peers_pop entry has invalid hex for {pk}"))?;
        if let Err(err) = bls_normal_pop_verify(&pk, &pop) {
            return Err(eyre!(
                "trusted_peers_pop entry has invalid PoP for {pk}: {err}"
            ));
        }
        if pops.insert(pk, pop).is_some() {
            return Err(eyre!("trusted_peers_pop entry duplicated for {entry}"));
        }
    }
    Ok(pops)
}
fn decode_pop_hex(raw: &str) -> Result<Vec<u8>> {
    let trimmed = raw.trim_start_matches("0x");
    hex::decode(trimmed).wrap_err("invalid PoP hex")
}
fn prompt_pop_for_peer(public_key: &PublicKey) -> Result<Vec<u8>> {
    loop {
        let prompt = format!("PoP for {public_key} (hex)");
        let input = Text::new(&prompt)
            .prompt()
            .wrap_err_with(|| format!("PoP prompt failed for {public_key}"))?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            tui::warn("PoP cannot be empty");
            continue;
        }
        let pop = match decode_pop_hex(trimmed) {
            Ok(pop) => pop,
            Err(err) => {
                tui::warn(format!("invalid PoP hex: {err}"));
                continue;
            }
        };
        if let Err(err) = bls_normal_pop_verify(public_key, &pop) {
            tui::warn(format!("invalid PoP for {public_key}: {err}"));
            continue;
        }
        return Ok(pop);
    }
}
#[allow(clippy::needless_raw_string_hashes)]
fn print_banner() {
    // Retro ASCII splash for a late-80s terminal vibe.
    let banner = r#"
  ________________________________________________________________
 /================================================================\
||  イ ロ ハ     ネ ッ ト ワ ー ク     IROHA NETWORK SETUP        ||
||                                                                ||
||      ⛩  I R O H A   S E T U P   T E R M I N A L  ⛩             ||
||                                                                ||
||  flow: keys → config → genesis → done                          ||
 ||  controls: ENTER to accept, ESC/CTRL+C to abort                ||
 ||                                                                ||
  \================================================================/
  ````````````````````````````````````````````````````````````````
"#;
    eprintln!("{banner}");
}
fn resolve_relay_mode(cli_value: Option<RelayMode>, non_interactive: bool) -> Result<RelayMode> {
    if let Some(mode) = cli_value {
        return Ok(mode);
    }
    if non_interactive {
        return Ok(RelayMode::Disabled);
    }
    Select::new(
        "Relay mode (hub/spoke for constrained topologies; assist adds hub fallback without forcing all peers)",
        vec![
            RelayMode::Disabled,
            RelayMode::Hub,
            RelayMode::Spoke,
            RelayMode::Assist,
        ],
    )
    .prompt()
    .wrap_err("failed to read relay mode selection")
}
fn resolve_text(
    prompt: &str,
    cli_value: Option<String>,
    default: String,
    non_interactive: bool,
) -> Result<String> {
    if let Some(value) = cli_value {
        return Ok(value);
    }
    if non_interactive {
        return Ok(default);
    }
    Text::new(prompt)
        .with_initial_value(&default)
        .prompt()
        .wrap_err_with(|| format!("{prompt} prompt failed"))
}
fn resolve_number(
    prompt: &str,
    cli_value: Option<u16>,
    default: u16,
    non_interactive: bool,
) -> Result<u16> {
    if let Some(value) = cli_value {
        return Ok(value);
    }
    if non_interactive {
        return Ok(default);
    }
    let text = Text::new(prompt)
        .with_initial_value(&default.to_string())
        .prompt()
        .wrap_err_with(|| format!("{prompt} prompt failed"))?;
    text.parse::<u16>()
        .wrap_err_with(|| format!("{prompt} must be a u16 port"))
}
fn write_wizard_readme(
    path: &Path,
    chain_id: &str,
    public_key: &PublicKey,
    config_path: &Path,
    genesis_path: &Path,
    start_command: &str,
) -> Result<()> {
    let rendered = format!(
        concat!(
            "# Kagami Wizard Output\n\n",
            "- Profile: `{profile}`\n",
            "- Chain ID: `{chain_id}`\n",
            "- Generated public key: `{public_key}`\n",
            "- Config: `{config}`\n",
            "- Reference genesis manifest: `{genesis}`\n\n",
            "This output is staged, not a locally signed replacement for the selected network's genesis.\n\n",
            "## Prerequisites\n\n",
            "1. Obtain the network-authoritative `genesis.signed.nrt` from the operator.\n",
            "2. Obtain its canonical checked NetworkId, derived from the exact signed genesis hash, as `genesis.expected_hash`.\n",
            "3. Verify both artifacts through the network's authenticated distribution channel.\n\n",
            "4. Confirm `trusted_peers` and `trusted_peers_pop` are the full operator-authenticated validator roster encoded by the signed genesis; the generated local peer starts as an observer.\n\n",
            "`genesis.template.json` is an incomplete source reference and must never be used as `genesis.file` or `genesis.manifest_json`.\n\n",
            "## Start after provisioning\n\n",
            "```bash\n",
            "{start_command}\n",
            "```\n",
        ),
        profile = WIZARD_PROFILE_LABEL,
        chain_id = chain_id,
        public_key = public_key,
        config = config_path.display(),
        genesis = genesis_path.display(),
        start_command = start_command,
    );
    crate::secure_fs::write_private_file_atomic(path, rendered.as_bytes())
        .wrap_err_with(|| format!("failed to write wizard guide to {}", path.display()))
}
fn load_config_template(
    answers: &Answers,
    keypair: &KeyPair,
    trusted_pops: &BTreeMap<PublicKey, Vec<u8>>,
) -> Result<crate::secret_toml::Value> {
    let mut config = crate::secret_toml::Value::new(
        toml::from_str(NEXUS_CONFIG_TEMPLATE)
            .wrap_err("failed to parse embedded Nexus config template")?,
    );
    ensure_nexus_config_identity(&config)?;
    ensure_trusted_peer_list(
        &mut config,
        keypair,
        &answers.trusted_peers,
        &answers.p2p_host,
        answers.p2p_port,
        trusted_pops,
    )?;
    Ok(config)
}
fn ensure_nexus_config_identity(config: &TomlValue) -> Result<()> {
    let defaults = ProfileDefaults::nexus();
    let root = config
        .as_table()
        .ok_or_else(|| eyre!("Nexus config template root must be a TOML table"))?;
    ensure!(
        root.get("chain").and_then(TomlValue::as_str) == Some(defaults.chain),
        "Nexus config template chain must remain pinned to {}",
        defaults.chain
    );
    ensure!(
        root.get("chain_discriminant")
            .and_then(TomlValue::as_integer)
            == Some(NEXUS_CHAIN_DISCRIMINANT),
        "Nexus config template chain discriminant must remain pinned to {NEXUS_CHAIN_DISCRIMINANT}"
    );
    Ok(())
}
#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn apply_overrides(
    config: &mut TomlValue,
    answers: &Answers,
    keypair: &KeyPair,
    soranet_transport_keypair: &KeyPair,
    streaming_identity_keypair: &KeyPair,
    trusted_pops: &BTreeMap<PublicKey, Vec<u8>>,
) -> Result<()> {
    set_string(config, "public_key", keypair.public_key().to_string());
    set_string(
        config,
        "private_key",
        ExposedPrivateKey(keypair.private_key().clone()).to_string(),
    );
    set_string(
        config,
        "soranet_transport_public_key",
        soranet_transport_keypair.public_key().to_string(),
    );
    set_string(
        config,
        "soranet_transport_private_key",
        ExposedPrivateKey(soranet_transport_keypair.private_key().clone()).to_string(),
    );
    if let TomlValue::Table(root) = config {
        crate::secret_toml::remove(root, "private_key_file");
        crate::secret_toml::remove(root, "soranet_transport_private_key_file");
    }
    let mut streaming = table(config, "streaming");
    crate::secret_toml::insert(
        &mut streaming,
        "identity_public_key".into(),
        TomlValue::String(streaming_identity_keypair.public_key().to_string()),
    );
    crate::secret_toml::insert(
        &mut streaming,
        "identity_private_key".into(),
        TomlValue::String(
            ExposedPrivateKey(streaming_identity_keypair.private_key().clone()).to_string(),
        ),
    );
    crate::secret_toml::remove(&mut streaming, "identity_private_key_file");
    set_table(config, "streaming", streaming);
    // Observer onboarding does not provision the governed gateway-compliance controller or
    // runtime providers required for an embedded storage-provider role, so record that posture
    // explicitly in the generated operator configuration.
    let mut storage = table(config, "sorafs.storage");
    crate::secret_toml::insert(&mut storage, "enabled".into(), TomlValue::Boolean(false));
    set_table(config, "sorafs.storage", storage);
    // trusted peers + ensure self is present
    let mut peers = answers.trusted_peers.clone();
    let self_peer = format!(
        "{}@{}",
        keypair.public_key(),
        addr_literal(&answers.p2p_host, answers.p2p_port)?
    );
    if !trusted_peers_contain_key(&peers, keypair.public_key())? {
        peers.push(self_peer);
    }
    set_array(config, "trusted_peers", peers);
    set_trusted_peers_pop(config, trusted_pops);
    let mut sumeragi = table(config, "sumeragi");
    crate::secret_toml::insert(
        &mut sumeragi,
        "role".into(),
        TomlValue::String("observer".into()),
    );
    set_table(config, "sumeragi", sumeragi);
    let remote_trusted_peer_count = wizard_remote_trusted_peer_count(config)?;
    let reply_source_capacity = wizard_reply_source_capacity(config)?;
    if remote_trusted_peer_count > reply_source_capacity {
        return Err(eyre!(
            "wizard trusted-peer full fanout requires {remote_trusted_peer_count} remote connections, above the effective network connection capacity {reply_source_capacity}"
        ));
    }
    let mut network = table(config, "network");
    let network_template = network
        .get("address")
        .and_then(TomlValue::as_str)
        .unwrap_or("");
    let network_address = rewrite_address_port(network_template, answers.p2p_port)?;
    crate::secret_toml::insert(
        &mut network,
        "address".into(),
        TomlValue::String(network_address),
    );
    let public_network_template = network
        .get("public_address")
        .and_then(TomlValue::as_str)
        .unwrap_or("");
    let _ = parse_addr(public_network_template)
        .wrap_err("Nexus config template has an invalid public P2P address")?;
    let public_network_address = addr_literal(&answers.p2p_host, answers.p2p_port)?;
    crate::secret_toml::insert(
        &mut network,
        "public_address".into(),
        TomlValue::String(public_network_address),
    );
    let relay_hub_addresses = &answers.relay_hub_addresses;
    match answers.relay_mode {
        RelayMode::Disabled => {
            crate::secret_toml::remove(&mut network, "relay_mode");
            crate::secret_toml::remove(&mut network, "relay_hub_address");
            crate::secret_toml::remove(&mut network, "relay_hub_addresses");
        }
        RelayMode::Hub => {
            crate::secret_toml::insert(
                &mut network,
                "relay_mode".into(),
                TomlValue::String("hub".to_owned()),
            );
            crate::secret_toml::remove(&mut network, "relay_hub_address");
            crate::secret_toml::remove(&mut network, "relay_hub_addresses");
        }
        RelayMode::Spoke => {
            crate::secret_toml::insert(
                &mut network,
                "relay_mode".into(),
                TomlValue::String("spoke".to_owned()),
            );
            crate::secret_toml::remove(&mut network, "relay_hub_address");
            crate::secret_toml::insert(
                &mut network,
                "relay_hub_addresses".into(),
                TomlValue::Array(
                    relay_hub_addresses
                        .iter()
                        .cloned()
                        .map(TomlValue::String)
                        .collect(),
                ),
            );
        }
        RelayMode::Assist => {
            crate::secret_toml::insert(
                &mut network,
                "relay_mode".into(),
                TomlValue::String("assist".to_owned()),
            );
            crate::secret_toml::remove(&mut network, "relay_hub_address");
            crate::secret_toml::insert(
                &mut network,
                "relay_hub_addresses".into(),
                TomlValue::Array(
                    relay_hub_addresses
                        .iter()
                        .cloned()
                        .map(TomlValue::String)
                        .collect(),
                ),
            );
        }
    }
    set_table(config, "network", network);
    let mut torii = table(config, "torii");
    let torii_template = torii
        .get("address")
        .and_then(TomlValue::as_str)
        .unwrap_or("");
    let torii_address = rewrite_address_port(torii_template, answers.torii_port)?;
    crate::secret_toml::insert(
        &mut torii,
        "address".into(),
        TomlValue::String(torii_address),
    );
    set_table(config, "torii", torii);
    let mut genesis = table(config, "genesis");
    crate::secret_toml::insert(
        &mut genesis,
        "file".into(),
        TomlValue::String("genesis.signed.nrt".to_owned()),
    );
    crate::secret_toml::remove(&mut genesis, "expected_hash");
    crate::secret_toml::insert(
        &mut genesis,
        "expected_hash_file".into(),
        TomlValue::String("genesis.expected_hash".to_owned()),
    );
    set_table(config, "genesis", genesis);
    Ok(())
}
fn load_genesis_template() -> Result<JsonValue> {
    validate_genesis_manifest_json(NEXUS_GENESIS_TEMPLATE)
        .wrap_err("embedded Nexus genesis template exceeds fixed resource bounds")?;
    parse_nexus_genesis_template(NEXUS_GENESIS_TEMPLATE)
}
fn parse_nexus_genesis_template(raw: &[u8]) -> Result<JsonValue> {
    let genesis: JsonValue =
        json::from_slice(raw).wrap_err("failed to parse embedded Nexus genesis template")?;
    let defaults = ProfileDefaults::nexus();
    ensure!(
        genesis.get("chain").and_then(JsonValue::as_str) == Some(defaults.chain),
        "Nexus genesis template chain must remain pinned to {}",
        defaults.chain
    );
    ensure!(
        genesis
            .get("chain_discriminant")
            .and_then(JsonValue::as_i64)
            == Some(NEXUS_CHAIN_DISCRIMINANT),
        "Nexus genesis template chain discriminant must remain pinned to {NEXUS_CHAIN_DISCRIMINANT}"
    );
    Ok(genesis)
}
fn set_string(config: &mut TomlValue, key: &str, value: String) {
    if let TomlValue::Table(root) = config {
        crate::secret_toml::insert(root, key.to_owned(), TomlValue::String(value));
    }
}
fn set_array(config: &mut TomlValue, key: &str, values: Vec<String>) {
    if let TomlValue::Table(root) = config {
        crate::secret_toml::insert(
            root,
            key.to_owned(),
            TomlValue::Array(values.into_iter().map(TomlValue::String).collect()),
        );
    }
}
fn set_trusted_peers_pop(config: &mut TomlValue, pops: &BTreeMap<PublicKey, Vec<u8>>) {
    if let TomlValue::Table(root) = config {
        crate::secret_toml::insert(
            root,
            "trusted_peers_pop".into(),
            trusted_peers_pop_value(pops),
        );
    }
}
fn trusted_peers_pop_value(pops: &BTreeMap<PublicKey, Vec<u8>>) -> TomlValue {
    let entries = pops
        .iter()
        .map(|(pk, pop)| {
            let mut entry = TomlTable::new();
            entry.insert("public_key".into(), TomlValue::String(pk.to_string()));
            entry.insert("pop_hex".into(), TomlValue::String(hex::encode(pop)));
            TomlValue::Table(entry)
        })
        .collect();
    TomlValue::Array(entries)
}
fn wizard_reply_source_capacity(config: &TomlValue) -> Result<usize> {
    let network = table(config, "network");
    if let Some(value) = network.get("max_total_connections") {
        let value = value.as_integer().ok_or_else(|| {
            eyre!("wizard template network.max_total_connections must be an integer")
        })?;
        return usize::try_from(value)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                eyre!("wizard template network.max_total_connections must be greater than zero")
            });
    }
    let lane_profile = network
        .get("lane_profile")
        .and_then(TomlValue::as_str)
        .unwrap_or(defaults::network::lane_profile::DEFAULT);
    let lane_profile = actual::LaneProfile::parse_label(lane_profile).ok_or_else(|| {
        eyre!("wizard template network.lane_profile must be exactly `core` or `home`")
    })?;
    Ok(lane_profile
        .derived_limits()
        .max_total_connections
        .map_or_else(
            || lane_profile.defaults().max_total_connections,
            NonZeroUsize::get,
        ))
}
fn wizard_remote_trusted_peer_count(config: &TomlValue) -> Result<usize> {
    let root = config
        .as_table()
        .ok_or_else(|| eyre!("wizard template root must be a table"))?;
    let local_public_key = root
        .get("public_key")
        .and_then(TomlValue::as_str)
        .ok_or_else(|| eyre!("wizard template public_key must be a string"))?;
    let trusted_peers = root
        .get("trusted_peers")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| eyre!("wizard template trusted_peers must be an array"))?;
    trusted_peers.iter().try_fold(0_usize, |count, peer| {
        let peer = peer
            .as_str()
            .ok_or_else(|| eyre!("wizard template trusted_peers entries must be strings"))?;
        let (public_key, _) = peer.split_once('@').ok_or_else(|| {
            eyre!("wizard template trusted peer `{peer}` must use public_key@address syntax")
        })?;
        if public_key == local_public_key {
            Ok(count)
        } else {
            count
                .checked_add(1)
                .ok_or_else(|| eyre!("wizard trusted-peer remote connection count overflowed"))
        }
    })
}
fn table(config: &TomlValue, path: &str) -> TomlTable {
    let mut table = TomlTable::new();
    let mut current = config;
    for segment in path.split('.') {
        if let TomlValue::Table(child) = current {
            if let Some(next) = child.get(segment) {
                current = next;
            } else {
                return table;
            }
        }
    }
    if let TomlValue::Table(existing) = current {
        table = existing.clone();
    }
    table
}
fn set_table(config: &mut TomlValue, path: &str, table: TomlTable) {
    let mut segments = path.split('.').collect::<Vec<_>>();
    if segments.is_empty() {
        return;
    }
    if let TomlValue::Table(root) = config {
        let last = segments.pop().expect("at least one segment");
        let mut cursor = root;
        for segment in segments {
            cursor = cursor
                .entry(segment.to_owned())
                .or_insert_with(|| TomlValue::Table(TomlTable::new()))
                .as_table_mut()
                .expect("table at path");
        }
        crate::secret_toml::insert(cursor, last.to_owned(), TomlValue::Table(table));
    }
}
fn ensure_trusted_peer_list(
    config: &mut TomlValue,
    keypair: &KeyPair,
    peers: &[String],
    host: &str,
    p2p_port: u16,
    trusted_pops: &BTreeMap<PublicKey, Vec<u8>>,
) -> Result<()> {
    let mut list = sanitize_trusted_peers(peers)?;
    let self_peer = format!("{}@{}", keypair.public_key(), addr_literal(host, p2p_port)?);
    if !trusted_peers_contain_key(&list, keypair.public_key())? {
        list.push(self_peer);
    }
    set_array(config, "trusted_peers", list);
    set_trusted_peers_pop(config, trusted_pops);
    Ok(())
}
/// Recompute a canonical listener address after overriding only its port.
fn rewrite_address_port(template: &str, port: u16) -> Result<String> {
    ensure!(port != 0, "listener port must be greater than zero");
    let mut address = parse_addr(template)?;
    match &mut address {
        SocketAddr::Ipv4(address) => address.port = port,
        SocketAddr::Ipv6(address) => address.port = port,
        SocketAddr::Host(address) => address.port = port,
    }
    validated_addr_literal(&address, "listener host")
}
/// Render a host and port as a checksummed canonical socket-address literal.
fn addr_literal(host: &str, port: u16) -> Result<String> {
    iroha_deploy::localnet::canonical_endpoint_literal(host, "address host", port)
}
/// Parse either a plain socket address or an existing canonical literal and render it canonically.
fn canonical_addr_literal(raw: &str) -> Result<String> {
    validated_addr_literal(&parse_addr(raw)?, "socket address host")
}
fn parse_addr(raw: &str) -> Result<SocketAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(eyre!("socket address must not be empty"));
    }
    if trimmed != raw {
        return Err(eyre!(
            "socket address must not contain surrounding whitespace"
        ));
    }
    if trimmed.starts_with("addr:") {
        let encoded = json::to_string(&trimmed.to_owned())
            .wrap_err("failed to encode socket address literal for validation")?;
        json::from_str::<SocketAddr>(&encoded)
            .wrap_err_with(|| format!("invalid canonical socket address literal `{raw}`"))
    } else {
        trimmed
            .parse::<SocketAddr>()
            .wrap_err_with(|| format!("invalid socket address `{raw}`"))
    }
}
fn validated_addr_literal(address: &SocketAddr, host_field: &str) -> Result<String> {
    if address.port() == 0 {
        return Err(eyre!("socket address port must be greater than zero"));
    }
    if let SocketAddr::Host(host) = address {
        return iroha_deploy::localnet::canonical_endpoint_literal(
            host.host.as_ref(),
            host_field,
            host.port,
        );
    }
    Ok(address.to_literal())
}
/// Validate trusted-peer entries and render every supplied address canonically.
fn sanitize_trusted_peers(peers: &[String]) -> Result<Vec<String>> {
    let mut normalized_by_key = BTreeMap::<PublicKey, String>::new();
    let mut normalized = Vec::with_capacity(peers.len());
    for entry in peers {
        if entry.trim() != entry {
            return Err(eyre!(
                "trusted peer entry must not contain surrounding whitespace: `{entry}`"
            ));
        }
        let peer = Peer::from_str(entry)
            .wrap_err_with(|| format!("invalid trusted peer entry: {entry}"))?;
        let rendered = if entry.contains('@') {
            format!(
                "{}@{}",
                peer.id().public_key(),
                validated_addr_literal(peer.address(), "trusted peer host")?
            )
        } else {
            peer.id().public_key().to_string()
        };
        let public_key = peer.id().public_key().clone();
        if let Some(existing) = normalized_by_key.get(&public_key) {
            if existing == &rendered {
                continue;
            }
            return Err(eyre!(
                "trusted peer public key {public_key} has conflicting entries `{existing}` and `{rendered}`"
            ));
        }
        normalized_by_key.insert(public_key, rendered.clone());
        normalized.push(rendered);
    }
    Ok(normalized)
}
fn trusted_peers_contain_key(peers: &[String], key: &PublicKey) -> Result<bool> {
    for entry in peers {
        let peer = Peer::from_str(entry)
            .wrap_err_with(|| format!("invalid trusted peer entry: {entry}"))?;
        if peer.id().public_key() == key {
            return Ok(true);
        }
    }
    Ok(false)
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::base::toml::TomlSource;
    use iroha_crypto::bls_normal_pop_prove;
    use std::fs;
    fn checked_wizard_bls_keypair() -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
            .expect("wizard BLS fixture key generation should succeed")
    }
    fn checked_wizard_transport_keypair() -> KeyPair {
        KeyPair::try_from_seed(
            b"iroha:kagami:wizard:test:soranet-transport:v1".to_vec(),
            Algorithm::Ed25519,
        )
        .expect("wizard SoraNet transport fixture key generation should succeed")
    }
    fn checked_wizard_streaming_keypair() -> KeyPair {
        KeyPair::try_from_seed(
            b"iroha:kagami:wizard:test:streaming-identity:v1".to_vec(),
            Algorithm::Ed25519,
        )
        .expect("wizard streaming identity fixture key generation should succeed")
    }
    fn nexus_non_interactive_args(output_dir: PathBuf) -> Args {
        let mut trusted_peers = Vec::new();
        let mut trusted_pops = Vec::new();
        for index in 0_u8..4 {
            let validator =
                KeyPair::try_from_seed(vec![0x80_u8.wrapping_add(index); 32], Algorithm::BlsNormal)
                    .expect("derive authoritative wizard validator fixture");
            trusted_peers.push(format!(
                "{}@127.0.0.1:{}",
                validator.public_key(),
                13_337_u16 + u16::from(index)
            ));
            trusted_pops.push(format!(
                "{}={}",
                validator.public_key(),
                hex::encode(
                    bls_normal_pop_prove(validator.private_key())
                        .expect("derive authoritative wizard validator PoP")
                )
            ));
        }
        Args {
            output_dir,
            non_interactive: true,
            p2p_host: None,
            p2p_port: None,
            torii_port: None,
            relay_mode: None,
            relay_hub_addresses: Vec::new(),
            trusted_peers: Some(trusted_peers.join(",")),
            trusted_peers_pop: Some(trusted_pops.join(",")),
        }
    }
    #[test]
    fn wizard_fixture_key_generation_preserves_bls_algorithm() {
        assert_eq!(
            checked_wizard_bls_keypair().public_key().algorithm(),
            Algorithm::BlsNormal
        );
        assert_eq!(
            checked_wizard_transport_keypair().algorithm(),
            Algorithm::Ed25519
        );
        assert_eq!(
            checked_wizard_streaming_keypair().algorithm(),
            Algorithm::Ed25519
        );
        assert_ne!(
            checked_wizard_transport_keypair().public_key(),
            checked_wizard_streaming_keypair().public_key(),
            "streaming and SoraNet transport fixture identities must be domain-separated"
        );
    }
    #[test]
    fn wizard_non_interactive_uses_nexus_observer_defaults() {
        let args = nexus_non_interactive_args(PathBuf::from("out"));
        let answers = gather_answers(&args).expect("resolve Nexus observer defaults");
        let defaults = ProfileDefaults::nexus();
        assert_eq!(answers.p2p_host, defaults.observer_public_host);
    }
    #[test]
    fn wizard_rejects_noncanonical_hosts_and_ports() {
        let base = nexus_non_interactive_args(PathBuf::from("out"));
        let mut invalid_host = base.clone();
        invalid_host.p2p_host = Some("bad host".to_owned());
        let mut padded_host = base.clone();
        padded_host.p2p_host = Some(" localhost".to_owned());
        let mut zero_p2p = base.clone();
        zero_p2p.p2p_port = Some(0);
        let mut zero_torii = base.clone();
        zero_torii.torii_port = Some(0);
        let mut hostile_relay = base.clone();
        hostile_relay.relay_mode = Some(RelayMode::Spoke);
        hostile_relay.relay_hub_addresses = vec!["/tmp/socket:1337".to_owned()];

        for (label, args, expected) in [
            ("host", invalid_host, "ASCII DNS"),
            ("whitespace", padded_host, "surrounding whitespace"),
            ("P2P port", zero_p2p, "P2P port"),
            ("Torii port", zero_torii, "Torii port"),
            ("relay host", hostile_relay, "ASCII DNS"),
        ] {
            let error = match gather_answers(&args) {
                Ok(_) => panic!("{label} fixture must be rejected"),
                Err(error) => error,
            };
            assert!(
                format!("{error:#}").contains(expected),
                "unexpected {label} diagnostic: {error:#}"
            );
        }

        let mut canonical = base;
        canonical.p2p_host = Some("EXAMPLE.COM".to_owned());
        let answers = gather_answers(&canonical).expect("canonical DNS names must be accepted");
        assert_eq!(answers.p2p_host, "example.com");
    }
    #[test]
    fn wizard_requires_a_remote_bootstrap_route() {
        let mut args = nexus_non_interactive_args(PathBuf::from("out"));
        args.trusted_peers = args.trusted_peers.as_ref().map(|peers| {
            peers
                .split(',')
                .map(|peer| peer.split_once('@').expect("addressed fixture").0)
                .collect::<Vec<_>>()
                .join(",")
        });
        let error = gather_answers(&args).expect_err("an all-key roster cannot bootstrap directly");
        assert!(
            error.to_string().contains("reachable pubkey@host:port"),
            "unexpected bootstrap diagnostic: {error:#}"
        );

        args.relay_mode = Some(RelayMode::Spoke);
        let answers = gather_answers(&args).expect("a spoke can bootstrap through its relay hub");
        assert_eq!(answers.relay_hub_addresses.len(), 1);
    }
    #[cfg(all(
        unix,
        not(any(target_os = "espidf", target_os = "horizon", target_os = "redox"))
    ))]
    #[test]
    fn wizard_refuses_to_mix_with_existing_output() {
        use std::os::unix::fs::PermissionsExt as _;

        let output = tempfile::tempdir().expect("wizard output");
        fs::set_permissions(output.path(), fs::Permissions::from_mode(0o700))
            .expect("harden wizard output directory");
        let sentinel = output.path().join("keep.txt");
        fs::write(&sentinel, b"do not overwrite").expect("write sentinel");
        let args = nexus_non_interactive_args(output.path().to_owned());
        let error = args
            .run(&mut BufWriter::new(Vec::new()))
            .expect_err("non-empty output must be rejected before publication");
        assert!(format!("{error:#}").contains("must be empty"));
        assert_eq!(
            fs::read(sentinel).expect("read sentinel"),
            b"do not overwrite"
        );
    }
    #[cfg(all(
        unix,
        not(any(target_os = "espidf", target_os = "horizon", target_os = "redox"))
    ))]
    #[test]
    fn wizard_handoff_uses_the_canonical_published_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("wizard path parent");
        let canonical_parent = temp.path().join("canonical-parent");
        fs::create_dir(&canonical_parent).expect("create canonical parent");
        let alias_parent = temp.path().join("mutable-alias");
        symlink(&canonical_parent, &alias_parent).expect("create parent alias");
        let requested = alias_parent.join("wizard-output");
        let mut output = BufWriter::new(Vec::new());
        nexus_non_interactive_args(requested.clone())
            .run(&mut output)
            .expect("generate wizard output below a symlinked parent");
        let rendered = String::from_utf8(output.into_inner().expect("flush wizard output"))
            .expect("wizard output is UTF-8");
        let published = fs::canonicalize(canonical_parent.join("wizard-output"))
            .expect("canonicalize published wizard directory");
        let quoted = crate::shell::absolute_quote_path(&published)
            .expect("quote canonical wizard directory");
        let guide = fs::read_to_string(published.join("README.md")).expect("read wizard guide");

        assert!(rendered.contains(&published.display().to_string()));
        assert!(guide.contains(&format!("cd {quoted} &&")));
        assert!(!guide.contains(&requested.display().to_string()));
    }
    #[test]
    fn invalid_wizard_request_does_not_create_output_directory() {
        let parent = tempfile::tempdir().expect("wizard validation parent");
        let output = parent.path().join("invalid-wizard");
        let args = Args {
            output_dir: output.clone(),
            non_interactive: true,
            p2p_host: None,
            p2p_port: None,
            torii_port: None,
            relay_mode: None,
            relay_hub_addresses: Vec::new(),
            trusted_peers: None,
            trusted_peers_pop: None,
        };

        let error = args
            .run(&mut BufWriter::new(Vec::new()))
            .expect_err("missing authoritative Nexus roster must fail");
        assert!(format!("{error:#}").contains("requires --trusted-peers"));
        assert!(
            !output.exists(),
            "request validation must finish before creating wizard custody"
        );
    }
    #[test]
    fn embedded_nexus_templates_are_valid_and_pinned() {
        let config: TomlValue =
            toml::from_str(NEXUS_CONFIG_TEMPLATE).expect("parse embedded config template");
        ensure_nexus_config_identity(&config).expect("embedded config identity is pinned");
        let genesis = load_genesis_template().expect("load embedded genesis template");
        assert_eq!(
            genesis.get("chain").and_then(JsonValue::as_str),
            Some(ProfileDefaults::nexus().chain)
        );
    }
    #[test]
    fn rewrite_address_port_preserves_bind_host_and_recomputes_fingerprint() {
        let rewritten = rewrite_address_port("addr:0.0.0.0:1337#BF18", 9999)
            .expect("rewritten address is valid");
        assert_eq!(
            rewritten,
            addr_literal("0.0.0.0", 9999).expect("expected address is valid")
        );
        assert_ne!(rewritten, "addr:0.0.0.0:9999#BF18");
    }
    #[test]
    fn rewrite_address_port_accepts_plain_template() {
        assert_eq!(
            rewrite_address_port("0.0.0.0:8080", 18100).expect("rewritten address is valid"),
            addr_literal("0.0.0.0", 18100).expect("expected address is valid")
        );
    }
    #[test]
    fn trusted_peer_sanitizer_collapses_exact_duplicates_and_rejects_conflicts() {
        let public_key = checked_wizard_bls_keypair().public_key().clone();
        let plain = format!("{public_key}@example.com:1337");
        let canonical = format!(
            "{public_key}@{}",
            addr_literal("example.com", 1337).expect("canonical fixture address")
        );
        assert_eq!(
            sanitize_trusted_peers(&[plain.clone(), canonical])
                .expect("equivalent peer entries should normalize"),
            vec![format!(
                "{public_key}@{}",
                addr_literal("example.com", 1337).expect("canonical fixture address")
            )]
        );
        let conflicting = format!("{public_key}@example.com:1338");
        let error = sanitize_trusted_peers(&[plain, conflicting])
            .expect_err("one public key must not map to conflicting addresses");
        assert!(
            error.to_string().contains("conflicting entries"),
            "unexpected conflict diagnostic: {error:?}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn wizard_handoff_never_treats_reference_manifest_as_signed_genesis() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("wizard README directory");
        let root = fs::canonicalize(directory.path()).expect("canonical wizard README directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("harden wizard README directory");
        let path = root.join("README.md");
        write_wizard_readme(
            &path,
            ProfileDefaults::nexus().chain,
            checked_wizard_bls_keypair().public_key(),
            Path::new("config.toml"),
            Path::new("genesis.template.json"),
            "iroha3d --sora --config config.toml",
        )
        .expect("write wizard handoff");
        let rendered = fs::read_to_string(path).expect("read wizard handoff");
        assert!(rendered.contains("genesis.signed.nrt"));
        assert!(rendered.contains("genesis.expected_hash"));
        assert!(rendered.contains("operator-authenticated validator roster"));
        assert!(rendered.contains("iroha3d --sora --config config.toml"));
        assert!(!rendered.contains("--genesis-manifest-json"));
    }
    #[test]
    fn wizard_nexus_profile_template_passes_canonical_and_cli_profile_admission() {
        let keypair = checked_wizard_bls_keypair();
        let transport_keypair = checked_wizard_transport_keypair();
        let streaming_keypair = checked_wizard_streaming_keypair();
        let mut validator_peers = Vec::new();
        let mut pops = BTreeMap::new();
        for index in 0_u8..4 {
            let validator =
                KeyPair::try_from_seed(vec![0xd0_u8.wrapping_add(index); 32], Algorithm::BlsNormal)
                    .expect("derive authoritative validator fixture");
            pops.insert(
                validator.public_key().clone(),
                bls_normal_pop_prove(validator.private_key())
                    .expect("derive authoritative validator PoP"),
            );
            validator_peers.push(validator.public_key().clone());
        }
        {
            let defaults = ProfileDefaults::nexus();
            let answers = Answers {
                p2p_host: defaults.observer_public_host.to_owned(),
                p2p_port: defaults.p2p_port,
                torii_port: defaults.torii_port,
                trusted_peers: validator_peers
                    .iter()
                    .enumerate()
                    .map(|(index, public_key)| {
                        format!(
                            "{public_key}@{}:{}",
                            defaults.relay_hub_host,
                            defaults.p2p_port
                                + u16::try_from(index).expect("fixture port offset fits")
                        )
                    })
                    .collect(),
                relay_mode: RelayMode::Disabled,
                relay_hub_addresses: Vec::new(),
                output_dir: PathBuf::from("out"),
            };
            let mut config = load_config_template(&answers, &keypair, &pops)
                .unwrap_or_else(|error| panic!("load Nexus wizard template: {error:?}"));
            apply_overrides(
                &mut config,
                &answers,
                &keypair,
                &transport_keypair,
                &streaming_keypair,
                &pops,
            )
            .unwrap_or_else(|error| panic!("apply Nexus wizard overrides: {error:?}"));
            let root = config.as_table_mut().expect("wizard config table");
            assert!(!root.contains_key("private_key_file"));
            assert!(!root.contains_key("soranet_transport_private_key_file"));
            assert_eq!(
                root.get("sumeragi")
                    .and_then(TomlValue::as_table)
                    .and_then(|sumeragi| sumeragi.get("role"))
                    .and_then(TomlValue::as_str),
                Some("observer")
            );
            let configured_pops = root
                .get("trusted_peers_pop")
                .and_then(TomlValue::as_array)
                .expect("wizard trusted-peer PoP roster");
            assert_eq!(configured_pops.len(), 4);
            assert!(configured_pops.iter().all(|entry| {
                entry
                    .as_table()
                    .and_then(|entry| entry.get("public_key"))
                    .and_then(TomlValue::as_str)
                    != Some(keypair.public_key().to_string().as_str())
            }));
            let network = root
                .get("network")
                .and_then(TomlValue::as_table)
                .expect("wizard network table");
            assert_eq!(
                network.get("address").and_then(TomlValue::as_str),
                Some(
                    addr_literal("0.0.0.0", defaults.p2p_port)
                        .expect("expected P2P listener")
                        .as_str()
                ),
                "the observer must bind locally rather than to a remote Nexus hostname"
            );
            assert_eq!(
                network.get("public_address").and_then(TomlValue::as_str),
                Some(
                    addr_literal(defaults.observer_public_host, defaults.p2p_port)
                        .expect("expected advertised P2P endpoint")
                        .as_str()
                )
            );
            assert_eq!(
                root.get("torii")
                    .and_then(TomlValue::as_table)
                    .and_then(|torii| torii.get("address"))
                    .and_then(TomlValue::as_str),
                Some(
                    addr_literal("0.0.0.0", defaults.torii_port)
                        .expect("expected Torii listener")
                        .as_str()
                ),
                "Torii must keep the template's local bind host"
            );
            let streaming = root
                .get("streaming")
                .and_then(TomlValue::as_table)
                .expect("wizard streaming table");
            assert!(!streaming.contains_key("identity_private_key_file"));
            assert_eq!(
                streaming
                    .get("identity_public_key")
                    .and_then(TomlValue::as_str),
                Some(streaming_keypair.public_key().to_string().as_str())
            );
            assert_eq!(
                root.get("sorafs")
                    .and_then(TomlValue::as_table)
                    .and_then(|sorafs| sorafs.get("storage"))
                    .and_then(TomlValue::as_table)
                    .and_then(|storage| storage.get("enabled"))
                    .and_then(TomlValue::as_bool),
                Some(false),
                "wizard must explicitly keep embedded storage disabled when `--sora` is applied"
            );
            let genesis = root
                .get_mut("genesis")
                .and_then(TomlValue::as_table_mut)
                .expect("wizard genesis table");
            assert_eq!(
                genesis
                    .get("expected_hash_file")
                    .and_then(TomlValue::as_str),
                Some("genesis.expected_hash")
            );
            genesis.remove("expected_hash_file");
            genesis.insert(
                "expected_hash".into(),
                TomlValue::String(
                    "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                        .to_owned(),
                ),
            );
            let mut actual = actual::Root::from_toml_source(TomlSource::inline(root.clone()))
                .unwrap_or_else(|error| panic!("Nexus wizard config admission: {error:?}"));
            iroha_config::sora_profile::SoraProfileSelection::from_table(root).apply(&mut actual);
            assert!(!actual.torii.sorafs_storage.enabled);
        }
    }
    #[test]
    fn genesis_template_identity_is_pinned() {
        let error = parse_nexus_genesis_template(
            br#"{"chain":"old","chain_discriminant":753,"transactions":[]}"#,
        )
        .expect_err("foreign chain must be rejected");
        assert!(error.to_string().contains("must remain pinned"));

        let raw = format!(
            r#"{{"chain":"{}","chain_discriminant":753,"transactions":[]}}"#,
            ProfileDefaults::nexus().chain
        );
        let genesis =
            parse_nexus_genesis_template(raw.as_bytes()).expect("pinned genesis template");
        assert_eq!(
            genesis
                .get("chain")
                .and_then(JsonValue::as_str)
                .unwrap_or(""),
            ProfileDefaults::nexus().chain
        );
    }
    #[test]
    fn sora_wizard_requires_authoritative_roster_and_keeps_local_peer_observer() {
        let local = checked_wizard_bls_keypair();
        let mut trusted_peers = Vec::new();
        let mut pop_entries = Vec::new();
        for index in 0_u8..4 {
            let validator =
                KeyPair::try_from_seed(vec![0xe0_u8.wrapping_add(index); 32], Algorithm::BlsNormal)
                    .expect("derive authoritative validator fixture");
            trusted_peers.push(format!(
                "{}@127.0.0.1:{}",
                validator.public_key(),
                13_337_u16 + u16::from(index)
            ));
            let pop = bls_normal_pop_prove(validator.private_key())
                .expect("derive authoritative validator PoP");
            pop_entries.push(format!("{}={}", validator.public_key(), hex::encode(pop)));
        }
        let answers = Answers {
            p2p_host: "127.0.0.1".to_owned(),
            p2p_port: 1_337,
            torii_port: 8_080,
            trusted_peers: trusted_peers.clone(),
            relay_mode: RelayMode::Disabled,
            relay_hub_addresses: Vec::new(),
            output_dir: PathBuf::from("out"),
        };
        let mut args = Args {
            output_dir: PathBuf::from("out"),
            non_interactive: true,
            p2p_host: None,
            p2p_port: None,
            torii_port: None,
            relay_mode: None,
            relay_hub_addresses: Vec::new(),
            trusted_peers: None,
            trusted_peers_pop: Some(pop_entries.join(",")),
        };
        let error = resolve_trusted_peers_pop(&args, &answers, &local)
            .expect_err("non-interactive onboarding must require an explicit peer roster");
        assert!(error.to_string().contains("--trusted-peers"));
        args.trusted_peers = Some(trusted_peers.join(","));
        let pops = resolve_trusted_peers_pop(&args, &answers, &local)
            .expect("authoritative four-validator roster");
        assert_eq!(pops.len(), 4);
        assert!(!pops.contains_key(local.public_key()));
    }
    #[test]
    fn public_taira_bundle_uses_expected_network_identity() {
        const EXPECTED_TAIRA_CHAIN_ID: &str = "fc56984b-2be7-431d-840e-21514d1883f0";
        const EXPECTED_TAIRA_CHAIN_DISCRIMINANT: i64 = 369;
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let config_path = repo_root.join("configs/soranexus/taira/config.toml");
        let config_text = fs::read_to_string(&config_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", config_path.display()));
        let config: TomlValue = toml::from_str(&config_text)
            .unwrap_or_else(|err| panic!("parse {}: {err}", config_path.display()));
        assert_eq!(
            config.get("chain").and_then(TomlValue::as_str),
            Some(EXPECTED_TAIRA_CHAIN_ID),
            "public Taira config.toml must keep the shipped live chain id"
        );
        assert_eq!(
            config
                .get("chain_discriminant")
                .and_then(TomlValue::as_integer),
            Some(EXPECTED_TAIRA_CHAIN_DISCRIMINANT),
            "public Taira config.toml must keep the shipped address discriminant"
        );
        let genesis_path = repo_root.join("configs/soranexus/taira/genesis.template.json");
        let genesis_text = fs::read_to_string(&genesis_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", genesis_path.display()));
        let genesis: JsonValue = json::from_str(&genesis_text)
            .unwrap_or_else(|err| panic!("parse {}: {err}", genesis_path.display()));
        assert_eq!(
            genesis.get("chain").and_then(JsonValue::as_str),
            Some(EXPECTED_TAIRA_CHAIN_ID),
            "public Taira genesis source template must match the shipped live chain id"
        );
        assert!(
            config_text.contains("testu"),
            "public Taira config.toml must render testnet i105 literals"
        );
        assert!(
            !config_text.contains("sorau"),
            "public Taira config.toml must not leak mainnet i105 literals"
        );
        assert!(
            genesis_text.contains("testu"),
            "public Taira genesis source template must render testnet i105 literals"
        );
        assert!(
            !genesis_text.contains("sorau"),
            "public Taira genesis source template must not leak mainnet i105 literals"
        );
        let first_tx_instructions = genesis
            .get("transactions")
            .and_then(JsonValue::as_array)
            .and_then(|items| items.first())
            .and_then(|tx| tx.get("instructions"))
            .and_then(JsonValue::as_array)
            .expect("public Taira genesis source template must include bootstrap instructions");
        let xor_asset_definition_id = first_tx_instructions
            .iter()
            .find(|instruction| {
                instruction
                    .get("SetAssetDefinitionAlias")
                    .and_then(|binding| binding.get("alias"))
                    .and_then(JsonValue::as_str)
                    == Some("xor#universal")
            })
            .and_then(|instruction| instruction.get("SetAssetDefinitionAlias"))
            .and_then(|binding| binding.get("asset_definition_id"))
            .and_then(JsonValue::as_str)
            .expect("public Taira genesis source template must bind xor#universal");
        let xor_universal = first_tx_instructions
            .iter()
            .find(|instruction| {
                instruction
                    .get("Register")
                    .and_then(|register| register.get("AssetDefinition"))
                    .and_then(|asset| asset.get("id"))
                    .and_then(JsonValue::as_str)
                    == Some(xor_asset_definition_id)
            })
            .expect("public Taira genesis source template must register the canonical xor asset");
        let confidential_policy = xor_universal
            .get("Register")
            .and_then(|register| register.get("AssetDefinition"))
            .and_then(|asset| asset.get("confidential_policy"));
        assert!(
            confidential_policy.is_none(),
            "asset registration must not bypass canonical confidential verifier activation"
        );
    }
}
