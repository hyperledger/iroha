//! Runtime-only enrollment selection on one of the four retained validators after H3.
//!
//! The controller supplies private configuration, never a credential or startup verdict.
//! Native configuration parsing and serving startup authenticate the actual dependencies.
use super::*;
use iroha_config::{
    base::{
        read::ConfigReader,
        toml::{MAX_TOML_SOURCE_BYTES, TomlSource},
    },
    parameters::user::KagemushaEnrollmentIssuer,
};
use iroha_fs::PrivateDirectory;
use std::borrow::Cow;
use toml::Table;

const CONFIG_MAX: usize = MAX_TOML_SOURCE_BYTES as usize;

/// The original in-memory node-local selection retained across the final network restart.
pub(super) struct Issuer {
    peer_index: usize,
    configuration: PathBuf,
    configuration_sha: String,
    layer: Table,
    pub(super) summary: Vec<u8>,
}

pub(super) fn require_command(command: &norito::json::Value) -> Result<()> {
    ensure!(
        command["schema"].as_str() == Some("iroha.kagemusha.real-network-command.v1")
            && command["phase"].as_str() == Some("issuer"),
        "exact issuer command schema and phase required"
    );
    digest(&command["setup_sha256"])?;
    digest(&command["previous_sha256"])?;
    let object = command
        .as_object()
        .ok_or_else(|| eyre!("issuer command object required"))?;
    ensure!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == [
                "schema",
                "phase",
                "setup_sha256",
                "previous_sha256",
                "peer_index",
                "configuration"
            ]
            .into_iter()
            .collect(),
        "exact issuer command fields required"
    );
    ensure!(
        command["peer_index"]
            .as_u64()
            .is_some_and(|index| index < 4),
        "issuer must select one of the four retained validators"
    );
    let selection = command["configuration"]
        .as_object()
        .ok_or_else(|| eyre!("private configuration selection required"))?;
    ensure!(
        selection
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == ["path", "sha256"].into_iter().collect(),
        "exact configuration reference required"
    );
    let path = command["configuration"]["path"]
        .as_str()
        .ok_or_else(|| eyre!("configuration path required"))?;
    ensure!(
        !path.is_empty() && path.len() <= 4096 && Path::new(path).is_absolute(),
        "bounded absolute configuration path required"
    );
    digest(&command["configuration"]["sha256"])?;
    Ok(())
}

fn parse_layer(
    bytes: &[u8],
    scheme: &KagemushaWalletSchemeV1,
    manifest: [u8; 32],
) -> Result<Table> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= CONFIG_MAX,
        "bounded issuer configuration required"
    );
    // Parsing diagnostics may contain source snippets. Only closed errors leave this boundary.
    let text =
        std::str::from_utf8(bytes).map_err(|_| eyre!("invalid issuer configuration text"))?;
    let layer: Table =
        toml::from_str(text).map_err(|_| eyre!("invalid issuer configuration TOML"))?;
    ensure!(
        layer.len() == 1,
        "only torii.kagemusha_enrollment may be selected"
    );
    let torii = layer
        .get("torii")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| eyre!("only torii.kagemusha_enrollment may be selected"))?;
    ensure!(
        torii.len() == 1,
        "only torii.kagemusha_enrollment may be selected"
    );
    let issuer = torii
        .get("kagemusha_enrollment")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| eyre!("issuer configuration table required"))?;
    let selected = ConfigReader::new()
        .without_env()
        .with_toml_source(TomlSource::inline(issuer.clone()))
        .read_and_complete::<KagemushaEnrollmentIssuer>()
        .map_err(|_| eyre!("invalid issuer configuration fields"))?;
    ensure!(
        !selected.providers.is_empty() && selected.providers.len() <= 128,
        "bounded nonempty issuer routes required"
    );
    let scheme_hex = hex::encode(scheme.to_canonical_bytes()?);
    let manifest_hex = hex::encode(manifest);
    ensure!(
        selected
            .providers
            .iter()
            .all(|provider| provider.scheme_hex == scheme_hex
                && provider.manifest_digest_hex == manifest_hex),
        "issuer routes must select this live owner's registered Scheme and installed pack"
    );
    Ok(layer)
}

fn read_layer(
    path: &Path,
    expected: &str,
    scheme: &KagemushaWalletSchemeV1,
    manifest: [u8; 32],
) -> Result<Table> {
    let parent = PrivateDirectory::open_exact(
        path.parent()
            .ok_or_else(|| eyre!("private configuration parent required"))?,
    )
    .map_err(|_| eyre!("private configuration custody required"))?;
    let name = path
        .file_name()
        .ok_or_else(|| eyre!("private configuration name required"))?;
    parent.read_scope(|scope| {
        scope
            .read(name, CONFIG_MAX, |bytes| {
                ensure!(hash(bytes) == expected, "issuer configuration pin differs");
                parse_layer(bytes, scheme, manifest)
            })
            .map_err(|_| eyre!("private configuration original unavailable"))?
    })
}

impl Issuer {
    fn revalidate(&self, registered: &registration::Registered) -> Result<()> {
        ensure!(
            read_layer(
                &self.configuration,
                &self.configuration_sha,
                &registered.scheme,
                registered.manifest
            )? == self.layer,
            "issuer configuration changed after selection"
        );
        Ok(())
    }

    /// Restart all original peers with the one retained issuer selection and unchanged stores.
    pub(super) fn restart_all(
        &self,
        network: &Network,
        rt: &Runtime,
        registered: &registration::Registered,
    ) -> Result<()> {
        self.revalidate(registered)?;
        ensure!(
            network.peers().len() == 4 && network.peers().iter().all(|peer| !peer.is_running()),
            "exact four stopped retained validators required"
        );
        for (index, peer) in network.peers().iter().enumerate() {
            let mut layers: Vec<_> = network.config_layers_for_peer(peer).collect();
            if index == self.peer_index {
                layers.push(Cow::Borrowed(&self.layer));
            }
            rt.block_on(async {
                tokio::time::timeout(
                    network.sync_timeout(),
                    peer.start_checked(layers.iter(), None),
                )
                .await
            })
            .map_err(|_| eyre!("retained validator startup timed out"))?
            .map_err(|_| eyre!("retained validator startup failed; inspect private node logs"))?;
        }
        self.revalidate(registered)
    }
}

pub(super) fn run(
    network: &Network,
    rt: &Runtime,
    root: &Path,
    command: &norito::json::Value,
    setup_sha: &str,
    registered: &registration::Registered,
) -> Result<Issuer> {
    ensure!(
        cfg!(target_os = "linux"),
        "the native enrollment worker requires Linux"
    );
    require_command(command)?;
    ensure!(
        network.peers().len() == 4
            && network.peers().iter().all(NetworkPeer::is_running)
            && committed_height(network)? == 3,
        "same four live validators at registration H3 required"
    );
    let peer_index = command["peer_index"].as_u64().unwrap() as usize;
    let configuration = PathBuf::from(command["configuration"]["path"].as_str().unwrap());
    let configuration_sha = command["configuration"]["sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let layer = read_layer(
        &configuration,
        &configuration_sha,
        &registered.scheme,
        registered.manifest,
    )?;
    let mut selected = Issuer {
        peer_index,
        configuration,
        configuration_sha,
        layer,
        summary: Vec::new(),
    };
    let peer = &network.peers()[peer_index];
    let identity = peer.id();
    let store = peer.kura_store_dir();
    let genesis = network.native_genesis_provisioning_bundle()?.signed_wire;
    let history = prefix(network, 3)?
        .into_iter()
        .map(|proof| proof.block_wire)
        .collect::<Vec<_>>();
    selected.revalidate(registered)?;
    rt.block_on(peer.shutdown());
    ensure!(
        network
            .peers()
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != peer_index)
            .all(|(_, other)| other.is_running()),
        "the other three retained validators must remain live"
    );
    let mut layers: Vec<_> = network.config_layers_for_peer(peer).collect();
    layers.push(Cow::Borrowed(&selected.layer));
    // None preserves the original genesis file and disables start_checked's genesis-storage
    // fallback: this call must observe ServerStarted from actual Torii /status success.
    rt.block_on(async {
        tokio::time::timeout(
            network.sync_timeout(),
            peer.start_checked(layers.iter(), None),
        )
        .await
    })
    .map_err(|_| eyre!("issuer startup timed out"))?
    .map_err(|_| eyre!("issuer startup failed; inspect private node logs"))?;
    wait_for_committed(network, 3, network.sync_timeout(), &[])?;
    ensure!(
        peer.id() == identity
            && peer.kura_store_dir() == store
            && network.peers().iter().all(NetworkPeer::is_running)
            && network.native_genesis_provisioning_bundle()?.signed_wire == genesis
            && committed_height(network)? == 3,
        "issuer restart changed the retained network identity, stores or height"
    );
    ensure!(
        prefix(network, 3)?
            .into_iter()
            .map(|proof| proof.block_wire)
            .collect::<Vec<_>>()
            == history,
        "issuer restart changed certified registration history"
    );
    selected.revalidate(registered)?;
    selected.summary = norito::json::to_vec(&norito::json!({
        "schema": "iroha.kagemusha.network-issuer-ready.v1", "setup_sha256": setup_sha,
        "registered_sha256": (hash(&registered.summary)), "configuration_sha256": (selected.configuration_sha.clone()),
        "peer_index": peer_index, "peer_id": (identity.to_string()), "torii_url": (peer.torii_url()),
        "certified_height": 3, "signed_genesis_sha256": (hash(&genesis)),
        "scope": "One retained validator restarted with the exact private issuer configuration; native Torii startup and unchanged H3 history checked. No credential, physical enrollment or latency result is asserted."
    }))?;
    publish(root, "issuer-ready.json", &selected.summary)?;
    File::open(root)?.sync_all()?;
    Ok(selected)
}

#[cfg(test)]
#[path = "issuer/tests.rs"]
mod tests;
