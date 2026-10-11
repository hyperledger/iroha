//! Explicit eight-process attachment regression through the installed native CLI.
//!
//! All authority and TLS material is independently generated in owner-private temporary
//! custody. The parent is a disposable native Global root, never public Taira. This fixture
//! establishes no release, native-platform matrix or reference-host latency qualification.

#[path = "attachment_installed_tests/timing.rs"]
mod timing;

use super::super::*;
use crate::{
    bootstrap::{
        InstalledNetworkProfile, InstalledNetworkProfiles, NetworkRelease, ReleaseCheckpointStore,
        ReleaseFaucet, ReleasePeer, SignedNetworkCheckpoint,
    },
    verify::{
        finality::{FinalitySource, FinalityVerifier, GenesisAnchor},
        http::HttpFinalitySource,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use color_eyre::eyre::{Result as TestResult, WrapErr, ensure, eyre};
use iroha::{client::Client, config::Config};
use iroha_crypto::{Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::address::ChainDiscriminantGuard,
    private_dataspace::PrivateDataspaceRecordProof,
    smart_contract::{ContractAddress, ContractArtifactId},
    sumeragi_finality::{FinalityValidator, genesis_registrations},
    transaction::SignedTransaction,
};
use iroha_fs::{PrivateDirectory, PublishMode};
use iroha_model_base::{peer::PeerId, topology::DataSpaceId};
use norito::json::{self, Value};
use std::{
    fs,
    io::Read as _,
    num::NonZeroU64,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CANARY: &str = "OWNER_PRIVATE_ATTACHMENT_CANARY_7f26d359";
const MAX_COMMAND_OUTPUT: usize = 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);
const PACKAGE: &str = r#"manifest-version = 1
[package]
namespace = "privatefixture"
name = "private-package"
version = "0.1.0"
edition = "1"
abi-version = 1
[[contract]]
name = "private-package"
path = "contract.ko"
"#;

struct Ingress {
    child: Child,
    roots: Vec<String>,
}

impl Ingress {
    fn spawn(root: &PrivateDirectory, peers: &[ManagedPeer]) -> TestResult<Self> {
        ensure!(
            peers.len() == 4,
            "ingress requires four original parent peers"
        );
        root.write_atomic(
            "ingress.py",
            include_bytes!("attachment_installed_tests/tls_proxy.py"),
            PublishMode::CreateNew,
        )?;
        root.write_atomic(
            "certificate.cnf",
            b"[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=disposable-native-attachment\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n[server]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n",
            PublishMode::CreateNew,
        )?;
        let output = Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            ])
            .arg("-config")
            .arg(root.path().join("certificate.cnf"))
            .arg("-keyout")
            .arg(root.path().join("authority-key.pem"))
            .arg("-out")
            .arg(root.path().join("authority.pem"))
            .stdin(Stdio::null())
            .output()
            .wrap_err("test controller requires openssl")?;
        ensure!(
            output.status.success(),
            "disposable TLS authority generation failed"
        );
        let request = Command::new("openssl")
            .args(["req", "-new", "-newkey", "rsa:2048", "-nodes"])
            .args(["-subj", "/CN=disposable-native-attachment-server"])
            .arg("-config")
            .arg(root.path().join("certificate.cnf"))
            .arg("-keyout")
            .arg(root.path().join("private-key.pem"))
            .arg("-out")
            .arg(root.path().join("server.csr"))
            .stdin(Stdio::null())
            .output()?;
        ensure!(
            request.status.success(),
            "disposable TLS leaf request failed"
        );
        let certificate = Command::new("openssl")
            .args(["x509", "-req", "-days", "1", "-CAcreateserial"])
            .arg("-in")
            .arg(root.path().join("server.csr"))
            .arg("-CA")
            .arg(root.path().join("authority.pem"))
            .arg("-CAkey")
            .arg(root.path().join("authority-key.pem"))
            .arg("-extfile")
            .arg(root.path().join("certificate.cnf"))
            .args(["-extensions", "server"])
            .arg("-out")
            .arg(root.path().join("certificate.pem"))
            .stdin(Stdio::null())
            .output()?;
        ensure!(
            certificate.status.success(),
            "disposable TLS leaf certification failed"
        );
        let python = [
            "python3",
            "python",
            "python3.14",
            "python3.13",
            "python3.12",
            "python3.11",
            "python3.10",
        ]
        .into_iter()
        .find(|name| {
            Command::new(name)
                .args(["-c", "import ssl,sys; assert sys.version_info >= (3,10)"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        })
        .ok_or_else(|| eyre!("test controller requires Python 3.10+ with standard ssl"))?;
        let child = Command::new(python)
            .arg(root.path().join("ingress.py"))
            .arg(root.path())
            .args(peers.iter().map(|peer| &peer.torii_url))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(root.open_append("ingress.stderr")?)
            .spawn()?;
        // No fallible work follows spawn until the harness owns this handle.
        Ok(Self {
            child,
            roots: Vec::new(),
        })
    }

    fn wait_ready(&mut self, root: &PrivateDirectory) -> TestResult<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let ports = loop {
            if root.path().join("ports").exists() {
                break fs::read_to_string(root.path().join("ports"))?;
            }
            ensure!(
                self.child.try_wait()?.is_none(),
                "disposable TLS ingress exited"
            );
            ensure!(Instant::now() < deadline, "TLS ingress readiness timed out");
            thread::sleep(Duration::from_millis(25));
        };
        let ports = ports
            .lines()
            .map(str::parse::<u16>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            ports.len() == 4 && ports.iter().all(|port| *port != 0),
            "invalid ingress port inventory"
        );
        self.roots = ports
            .into_iter()
            .map(|port| format!("https://127.0.0.1:{port}/"))
            .collect();
        Ok(())
    }
}

impl Ingress {
    fn stop(&mut self) -> TestResult<()> {
        // EOF addresses this exact child through its original lifetime pipe, never a saved PID.
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
                _ => {
                    return Err(eyre!(
                        "disposable ingress did not finish its bounded shutdown"
                    ));
                }
            }
        }
    }
}

impl Drop for Ingress {
    fn drop(&mut self) {
        if self.stop().is_err() {
            eprintln!("disposable ingress cleanup remains unconfirmed");
        }
    }
}

struct Harness {
    temporary: Option<RetainedTemporary>,
    root: PrivateDirectory,
    kagami: PathBuf,
    profiles: PathBuf,
    parent: ManagedStore,
    child: ManagedStore,
    workspace: PrivateDirectory,
    sequence: usize,
    ingress: Option<Ingress>,
    timing: Option<timing::CampaignAttempt>,
    shutdown_confirmed: bool,
    verified: bool,
}

// Preserve original custody on every early return or panic. Only the successful
// fixture path explicitly closes this owner after all native handles are dropped.
struct RetainedTemporary(Option<tempfile::TempDir>);

impl RetainedTemporary {
    fn path(&self) -> &Path {
        self.0.as_ref().expect("retained temporary owner").path()
    }

    fn close(mut self) -> std::io::Result<()> {
        self.0.take().expect("retained temporary owner").close()
    }
}

impl Drop for RetainedTemporary {
    fn drop(&mut self) {
        if let Some(temporary) = self.0.take() {
            let _ = temporary.keep();
        }
    }
}

// Keep all copied package components under retained owner-private directory custody.
fn fixture_bundle_directory(root: &PrivateDirectory, path: &Path) -> TestResult<PrivateDirectory> {
    let mut directory = PrivateDirectory::open(root.path())?;
    for component in path.strip_prefix(root.path())?.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(eyre!("fixture bundle path is not a direct child path"));
        };
        directory = directory.ensure_child(name)?;
    }
    Ok(directory)
}

impl Harness {
    fn new(installed: &Path) -> TestResult<Self> {
        InstalledRuntime::from_directory(installed)?;
        let temporary = RetainedTemporary(Some(
            tempfile::Builder::new()
                .prefix("iroha-eight-peer-attachment-")
                .tempdir()?,
        ));
        let root = PrivateDirectory::open_or_create(temporary.path().join("custody"))?;
        eprintln!("ATTACHMENT_SMOKE_STORE={}", root.path().display());
        let binaries =
            fixture_bundle_directory(&root, &KagamiBundleLayout::runtime_directory(root.path()))?;
        let profiles = crate::managed::bundle::runtime_profiles_path(binaries.path())?;
        let pins = ["kagami", "iroha3d"]
            .into_iter()
            .map(|name| {
                let filename = format!("{name}{}", std::env::consts::EXE_SUFFIX);
                admit_native_program(&mut iroha_fs::RetainedFile::open_regular(
                    installed.join(&filename),
                )?)?;
                Ok((
                    filename.clone(),
                    store::pin_binary(&installed.join(filename))?,
                ))
            })
            .collect::<TestResult<Vec<_>>>()?;
        for (filename, pin) in &pins {
            fs::copy(installed.join(&filename), binaries.path().join(&filename))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(
                    binaries.path().join(filename),
                    fs::Permissions::from_mode(0o700),
                )?;
            }
            ensure!(
                store::pin_binary(&binaries.path().join(filename))?.blake3 == pin.blake3,
                "copied runtime binary differs from original retained input"
            );
            admit_native_program(&mut iroha_fs::RetainedFile::open_regular(
                binaries.path().join(filename),
            )?)?;
        }
        for (filename, pin) in &pins {
            ensure!(
                store::pin_binary(&installed.join(filename))?.blake3 == pin.blake3,
                "runtime installation changed while the fixture copied its matching programs"
            );
        }
        InstalledRuntime::from_directory(binaries.path())?;
        let workspace = root.create_child("workspace")?;
        root.create_child("empty-path")?;
        let timing = timing::CampaignAttempt::from_environment(installed, binaries.path())?;
        Ok(Self {
            temporary: Some(temporary),
            parent: ManagedStore::open(&root.path().join("parent"))?,
            child: ManagedStore::open(&root.path().join("child"))?,
            root,
            kagami: binaries
                .path()
                .join(format!("kagami{}", std::env::consts::EXE_SUFFIX)),
            profiles,
            workspace,
            sequence: 0,
            ingress: None,
            timing,
            shutdown_confirmed: false,
            verified: false,
        })
    }

    fn command(&mut self, args: &[&str]) -> TestResult<Value> {
        let state = self.child.root().to_path_buf();
        let authority = self.root.path().join("tls/authority.pem");
        self.command_for_state(args, &state, Some(&authority))
    }

    fn command_for_state(
        &mut self,
        args: &[&str],
        state: &Path,
        tls_authority: Option<&Path>,
    ) -> TestResult<Value> {
        self.sequence += 1;
        let output = format!("cli-{}.stdout", self.sequence);
        let error = format!("cli-{}.stderr", self.sequence);
        let mut command = Command::new(&self.kagami);
        command
            .args(args)
            .arg("--state")
            .arg(state)
            .arg("--json")
            .current_dir(self.workspace.path())
            .env("PATH", self.root.path().join("empty-path"))
            .stdin(Stdio::null())
            .stdout(self.root.open_append(&output)?)
            .stderr(self.root.open_append(&error)?);
        if let Some(authority) = tls_authority {
            // Standard rustls-native-certs input, confined to the fixture's HTTPS caller.
            command.env("SSL_CERT_FILE", authority);
        }
        let mut child = command.spawn()?;
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                // Stop only this foreground invocation through its original Child handle.
                // Validators and workers are stopped through ManagedStore below, never PIDs.
                let terminated = child.kill();
                let reaped = child.wait();
                return Err(eyre!(
                    "CLI deadline; foreground termination={terminated:?}, reap={reaped:?}; retained stores require authenticated cleanup"
                ));
            }
            thread::sleep(Duration::from_millis(50));
        };
        ensure!(
            status.success(),
            "kagami {args:?} failed; inspect {}",
            self.root.path().join(error).display()
        );
        Ok(json::from_slice(
            &self.root.read(&output, MAX_COMMAND_OUTPUT)?,
        )?)
    }

    fn exercise(&mut self) -> TestResult<()> {
        let parent_state = self.parent.root().to_path_buf();
        // Both roots start through the copied installed frontend. The parent keeps
        // its normal thirty-second readiness budget and needs no fixture CA.
        let ready = parse_parent_ready(self.command_for_state(
            &["localnet", "up", "parent"],
            &parent_state,
            None,
        )?)?;
        let prepared = self.parent.prepared("parent")?;
        ensure!(
            ready.context == prepared.context && prepared.peers.len() == 4,
            "parent CLI observation differs from its retained four-validator generation"
        );
        eprintln!("ATTACHMENT_PARENT_READY peers=4");
        let parent_config = prepared.context.load_client_config()?;
        let (anchor, faucet, node_peers) = original_parent(&prepared)?;
        let mut verifier =
            independently_observed_parent(&prepared, &parent_config, &anchor, &node_peers)?;
        eprintln!(
            "ATTACHMENT_PARENT_VERIFIED height={}",
            verifier.checkpoint().height()
        );
        let initial = verifier.clone();
        let tls = self.root.create_child("tls")?;
        ensure!(self.ingress.is_none(), "TLS controller is already owned");
        let ingress = self.ingress.insert(Ingress::spawn(&tls, &prepared.peers)?);
        ingress.wait_ready(&tls)?;
        let ingress_roots = ingress.roots.clone();
        let release_key = KeyPair::random();
        let now = unix_ms()?;
        let checkpoint = verifier.checkpoint();
        let release = NetworkRelease {
            network_name: "fixture".into(),
            serial: 1,
            generation: 1,
            network_id: anchor.network_id,
            chain_id: anchor.chain_id.clone(),
            account_chain_discriminant: parent_config.account_chain_discriminant,
            native_world_schema: iroha_core::state::State::native_world_schema_hash_v1()
                .map_err(|e| eyre!(e))?,
            issued_at_ms: now.saturating_sub(1_000),
            expires_at_ms: now + 60 * 60 * 1_000,
            torii_roots: ingress_roots.clone(),
            peers: node_peers
                .iter()
                .zip(&ingress_roots)
                .map(|(peer, root)| ReleasePeer {
                    node_id: peer.clone(),
                    torii_root: root.clone(),
                })
                .collect(),
            faucet: Some(ReleaseFaucet {
                torii_root: ingress_roots[0].clone(),
                issuer: faucet.authority,
                asset_definition_id: faucet.asset_definition_id.parse()?,
                amount: faucet.amount,
                max_operation_fee: "1000".parse()?,
                max_namespace_rent: "1000".parse()?,
            }),
            build_registry: None,
            checkpoint_hash: Hash::new(checkpoint.encode_canonical()?),
            checkpoint_height: checkpoint.height(),
            checkpoint_block_hash: checkpoint.block_hash().into(),
        };
        let signed = SignedNetworkCheckpoint::sign(release, checkpoint, release_key.private_key())?;
        tls.write_atomic(
            "checkpoint.nrt",
            &signed.encode_canonical()?,
            PublishMode::CreateNew,
        )?;
        let profiles = InstalledNetworkProfiles::new(vec![InstalledNetworkProfile::new(
            "fixture".into(),
            release_key.public_key().clone(),
            1,
            format!("{}fixture/checkpoint.nrt", ingress_roots[0]),
        )?])?;
        let profile_path = &self.profiles;
        PrivateDirectory::open(profile_path.parent().unwrap())?.write_atomic(
            profile_path.file_name().unwrap(),
            &profiles.encode_installation()?,
            PublishMode::CreateNew,
        )?;
        eprintln!("ATTACHMENT_PARENT_HTTPS_READY roots=4");

        // This one call owns real funding, paid SNS, authenticated generation binding,
        // owner-private genesis, registration and independently verified parent inclusion.
        let mut attachment_timing = self
            .timing
            .as_ref()
            .map(|timing| timing.start("disposable_loopback_attachment"))
            .transpose()?;
        let up = self.command(&["dataspace", "up", "dpn", "--network", "fixture"]);
        if let Some(timing) = attachment_timing.as_mut() {
            timing.command_finished(up.is_ok());
        }
        let up = up?;
        let up: ManagedDataspaceStatus = json::from_value(up)?;
        require_attached(&up)?;
        eprintln!("ATTACHMENT_CHILD_ATTACHED peers=4");
        let child_prepared = self.child.prepared("dpn")?;
        let private_config = child_prepared.context.load_client_config()?;
        let listener_token = zeroize::Zeroizing::new(
            private_config
                .api_token
                .as_ref()
                .ok_or_else(|| eyre!("private listener has no owner credential"))?
                .expose_secret()
                .as_bytes()
                .to_vec(),
        );
        let registration = child_prepared.load_private_registration()?;
        let registered =
            self.verify_record(&prepared, &parent_config, &node_peers, &mut verifier, &up)?;
        ensure!(
            registered.record.anchor.registration() == &registration,
            "parent registered different private genesis authority"
        );
        ensure!(
            registered.record.owner == private_config.account,
            "parent owner differs from generated child owner"
        );
        ensure!(
            registered.record.alias == "dpn",
            "parent registered another SNS alias"
        );
        // Read both paid leases and resolve the owner label through native account
        // authentication. This parent has no physical `dpn` catalog or execution lane.
        let read_bootstrap =
            ReleaseCheckpointStore::open(&self.root.path().join("namespace-read-bootstrap"))?
                .authenticate(
                    profiles.select("fixture")?.release_trust(),
                    &signed.encode_canonical()?,
                    unix_ms()?,
                )?;
        let mut owner_parent = crate::provisioning::RemoteProvisioning::load_parent_config(
            &self.child.root().join("attachments/dpn/provisioning"),
            &read_bootstrap,
            &child_prepared,
            "admin",
        )?;
        // The disposable fixture's exact parent loopback listener needs no fixture CA.
        owner_parent.torii_api_url = parent_config.torii_api_url.clone();
        let owner_client = Client::builder(owner_parent)
            .build()?
            .with_request_deadline(Instant::now() + Duration::from_secs(10));
        let owner_alias = iroha_wallet::namespace::resolve_private_owner_alias("dpn", "admin")?;
        for (namespace, literal) in [
            (iroha::sns::SnsNamespacePath::Dataspace, "dpn"),
            (iroha::sns::SnsNamespacePath::AccountAlias, "admin@dpn"),
        ] {
            let lease = owner_client.sns().get_name(namespace, literal)?;
            ensure!(
                lease.owner == private_config.account
                    && matches!(lease.status, iroha_data_model::sns::NameStatus::Active)
                    && lease.ownership_generation > 0,
                "paid private namespace readback changed its active owner"
            );
        }
        let resolved = owner_client
            .resolve_account_alias_authenticated(&owner_alias.canonical_name)?
            .ok_or_else(|| eyre!("paid private owner alias did not resolve"))?;
        ensure!(
            resolved.account_id() == &private_config.account,
            "authenticated private owner alias resolved to another account"
        );
        ensure!(
            iroha::blocking::Client::from_client(owner_client)?
                .status()
                .get()?
                .dataspace_catalog
                .iter()
                .all(|entry| entry.alias != "dpn"
                    && entry.dataspace_id != owner_alias.dataspace_id.as_u64()),
            "private namespace acquisition created a physical parent catalog entry"
        );
        let generation = registered.record.ownership_generation;
        if let Some(timing) = attachment_timing {
            timing.verified()?;
        }

        // Prepare three different programs before the first upload. The .to input
        // is compiled offline and has never been deployed under another alias.
        let source_fixture = PrivateProgram::new("PrivateSecret", "source");
        let bytecode_fixture = PrivateProgram::new("PrivateBytecode", "bytecode");
        let package_fixture = PrivateProgram::new("PrivatePackage", "package");
        let (bytecode_input, bytecode_hash) =
            bytecode_fixture.compile(private_config.account_chain_discriminant)?;
        self.workspace.write_atomic(
            "secret.ko",
            source_fixture.source().as_bytes(),
            PublishMode::CreateNew,
        )?;
        self.workspace
            .write_atomic("secret.to", &bytecode_input, PublishMode::CreateNew)?;
        let mut source_timing = self
            .timing
            .as_ref()
            .map(|timing| timing.start("ready_private_source"))
            .transpose()?;
        let source = self.command(&["contract", "deploy", "secret.ko"]);
        if let Some(timing) = source_timing.as_mut() {
            timing.command_finished(source.is_ok());
        }
        let source = source?;
        let source_artifact =
            verify_private_deployment(&child_prepared, &source, &source_fixture.result())?;
        ensure!(
            source_artifact.artifact_id.code_hash != bytecode_hash
                && source_artifact.bytes != bytecode_input,
            "offline bytecode input reuses the source deployment artifact"
        );
        if let Some(timing) = source_timing {
            timing.verified()?;
        }
        let to_args = [
            "contract",
            "deploy",
            "secret.to",
            "--alias",
            "PrivateBytecode::dpn",
        ];
        let mut bytecode_timing = self
            .timing
            .as_ref()
            .map(|timing| timing.start("ready_private_bytecode"))
            .transpose()?;
        let to = self.command(&to_args);
        if let Some(timing) = bytecode_timing.as_mut() {
            timing.command_finished(to.is_ok());
        }
        let to = to?;
        let bytecode_artifact =
            verify_private_deployment(&child_prepared, &to, &bytecode_fixture.result())?;
        ensure!(
            bytecode_artifact.bytes == bytecode_input
                && bytecode_artifact.artifact_id.code_hash == bytecode_hash,
            "bytecode input changed exact artifact"
        );
        if let Some(timing) = bytecode_timing {
            timing.verified()?;
        }
        let package = self.workspace.create_child("package")?;
        package.write_atomic("Musubi.toml", PACKAGE.as_bytes(), PublishMode::CreateNew)?;
        package.write_atomic(
            "contract.ko",
            package_fixture.source().as_bytes(),
            PublishMode::CreateNew,
        )?;
        let mut package_timing = self
            .timing
            .as_ref()
            .map(|timing| timing.start("ready_private_local_package"))
            .transpose()?;
        let packaged = self.command(&["contract", "deploy", "package"]);
        if let Some(timing) = package_timing.as_mut() {
            timing.command_finished(packaged.is_ok());
        }
        let packaged = packaged?;
        let package_artifact =
            verify_private_deployment(&child_prepared, &packaged, &package_fixture.result())?;
        require_distinct_artifacts(&[&source_artifact, &bytecode_artifact, &package_artifact])?;
        if let Some(timing) = package_timing {
            timing.verified()?;
        }
        for (args, receipt) in [
            (&["contract", "deploy", "secret.ko"][..], &source),
            (&to_args[..], &to),
            (&["contract", "deploy", "package"][..], &packaged),
        ] {
            let repeated = self.command(args)?;
            ensure!(
                repeated.get("receipt") == receipt.get("receipt")
                    && repeated.get("journal") == receipt.get("journal"),
                "identical private deployment changed receipt or journal"
            );
        }
        let initialized = self.command(&[
            "contract",
            "call",
            "PrivateSecret::dpn",
            "--entrypoint",
            "hajimari",
            "--max-fee",
            "1000",
            "--readback",
            "current",
        ])?;
        let initialization_height = verify_private_call(&child_prepared, &initialized, "0")?;
        let mutated = self.command(&[
            "contract",
            "call",
            "PrivateSecret::dpn",
            "--entrypoint",
            "set",
            "--args",
            "{\"next\":\"7\"}",
            "--max-fee",
            "1000",
            "--readback",
            "current",
        ])?;
        let mutation_height = verify_private_call(&child_prepared, &mutated, "7")?;
        let call_journal = mutated
            .get("journal")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("mutable call omitted its recovery journal"))?;
        let recovered = self.command(&[
            "contract",
            "call",
            "--resume",
            call_journal,
            "--readback",
            "current",
        ])?;
        ensure!(
            recovered.get("receipt") == mutated.get("receipt")
                && recovered.get("journal") == mutated.get("journal"),
            "mutable recovery replaced its original signed call or fee authorization"
        );
        let viewed = self.command(&[
            "contract",
            "view",
            "PrivateSecret::dpn",
            "--entrypoint",
            "current",
        ])?;
        ensure!(
            viewed
                .get("result")
                .and_then(|response| response.get("result"))
                .and_then(Value::as_str)
                == Some("7"),
            "managed alias-selected view did not observe the mutable value"
        );
        let applied = [source, to, packaged]
            .iter()
            .map(deployment_height)
            .collect::<TestResult<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap()
            .max(initialization_height)
            .max(mutation_height);
        let deadline = Instant::now() + Duration::from_secs(120);
        let anchored = loop {
            let status = self
                .child
                .dataspace_status("dpn")?
                .ok_or_else(|| eyre!("private attachment disappeared"))?;
            if status
                .attachment
                .parent_confirmed
                .is_some_and(|fact| fact.child.height >= applied)
            {
                break status;
            }
            ensure!(
                Instant::now() < deadline,
                "local Applied did not gain independently verified parent inclusion"
            );
            thread::sleep(Duration::from_millis(100));
        };
        let anchored_record = self.verify_record(
            &prepared,
            &parent_config,
            &node_peers,
            &mut verifier,
            &anchored,
        )?;
        ensure!(
            anchored_record.record.ownership_generation == generation,
            "relay replaced original SNS ownership generation"
        );
        ensure!(
            anchored_record.record.anchor.cursor().height >= applied,
            "parent record trails private Applied evidence"
        );
        ensure!(
            anchored_record.record.anchor.registration() == &registration,
            "relay replaced original child authority"
        );
        ensure!(
            verifier.checkpoint().height() > initial.checkpoint().height(),
            "parent made no certified progress"
        );
        self.stop()?;
        drop(self.ingress.take());
        // Inspect exact captured parent requests and retained parent files after authenticated
        // shutdown. This is a canary/complete-artifact regression, not a universal secrecy proof.
        let needles = privacy_needles(&[
            CANARY.as_bytes(),
            &source_artifact.bytes,
            &bytecode_artifact.bytes,
            &package_artifact.bytes,
            listener_token.as_slice(),
        ]);
        let needles: Vec<&[u8]> = needles.iter().map(|bytes| bytes.as_slice()).collect();
        let captured = assert_absent(&self.root.path().join("tls/public-requests.bin"), &needles)?;
        ensure!(
            captured > 0,
            "no original parent request capture was retained"
        );
        inspect_parent_files(self.parent.root(), &needles)?;
        self.verified = true;
        eprintln!(
            "ATTACHMENT_SMOKE_PASSED={} parent_height={} private_height={}",
            self.root.path().display(),
            verifier.checkpoint().height(),
            applied
        );
        Ok(())
    }

    fn verify_record(
        &self,
        prepared: &PreparedLocalnet,
        config: &Config,
        peers: &[PeerId],
        verifier: &mut FinalityVerifier,
        status: &ManagedDataspaceStatus,
    ) -> TestResult<PrivateDataspaceRecordProof> {
        let confirmed = status
            .attachment
            .parent_confirmed
            .ok_or_else(|| eyre!("missing parent receipt"))?;
        let height =
            NonZeroU64::new(confirmed.parent_height).ok_or_else(|| eyre!("zero parent height"))?;
        let source = source_for(prepared, config, peers, verifier.checkpoint().height())?;
        let block = source.finality_proof(height)?;
        verifier.advance(&source, &block)?;
        let client = Client::builder(config.clone())
            .build()?
            .with_request_deadline(Instant::now() + Duration::from_secs(10));
        let id = DataSpaceId::new(status.local.context.dataspace_id);
        let proof = client.get_private_dataspace_record_proof(id, height)?;
        proof.verify(id, &verifier.verified_tip()?)?;
        ensure!(
            proof.record.anchor.cursor() == confirmed.child,
            "managed parent fact differs from independent native record proof"
        );
        Ok(proof)
    }

    fn stop(&mut self) -> TestResult<()> {
        self.shutdown_confirmed = false;
        let mut failures = Vec::new();
        for (store, name) in [(&self.child, "dpn"), (&self.parent, "parent")] {
            match store.down(name) {
                Ok(stopped)
                    if stopped.phase == ManagedPhase::Stopped && stopped.running_peers == 0 => {}
                Ok(status) if status.phase == ManagedPhase::Failed && status.running_peers == 0 => {
                    eprintln!(
                        "ATTACHMENT_CLEANUP {name}: authenticated zero live peers, original failure retained: {:?}",
                        status.failure
                    );
                }
                Ok(_) => failures.push(format!("{name}: authenticated shutdown was not confirmed")),
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => failures.push(format!("{name}: {error}")),
            }
        }
        if let Some(ingress) = self.ingress.as_mut() {
            if ingress.stop().is_err() {
                failures.push("TLS controller shutdown was not confirmed".into());
            }
        }
        ensure!(
            failures.is_empty(),
            "cleanup failures: {}",
            failures.join("; ")
        );
        self.shutdown_confirmed = true;
        Ok(())
    }

    fn remove_verified_custody(mut self) -> TestResult<()> {
        ensure!(
            self.verified && self.shutdown_confirmed,
            "unverified or live fixture custody must be retained"
        );
        let temporary = self
            .temporary
            .take()
            .ok_or_else(|| eyre!("fixture lost its original temporary directory owner"))?;
        // Windows directory/file pins and the retained controller Child all close
        // before TempDir removes only this fixture's original temporary directory.
        drop(self);
        temporary
            .close()
            .wrap_err("remove successful fixture custody")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if !self.shutdown_confirmed
            && let Err(error) = self.stop()
        {
            eprintln!(
                "attachment fixture cleanup did not reach Stopped at {}: {error}",
                self.root.path().display()
            );
        }
    }
}

fn parse_parent_ready(value: Value) -> TestResult<ManagedStatus> {
    let ready: ManagedStatus = json::from_value(value)?;
    ensure!(
        ready.phase == ManagedPhase::Ready
            && ready.running_peers == 4
            && ready.context.name == "parent"
            && ready.context.dataspace_id == 0
            && ready.failure.is_none(),
        "parent CLI did not report its exact Ready4 Global context"
    );
    Ok(ready)
}

fn original_parent(
    prepared: &PreparedLocalnet,
) -> TestResult<(
    GenesisAnchor,
    iroha_config::parameters::actual::ToriiFaucet,
    Vec<PeerId>,
)> {
    use iroha_config::node_config::{NodeConfigOptions, NodeFile, open_node_config};
    let profile = prepared
        .context
        .load_client_config()?
        .account_chain_discriminant;
    let _profile = ChainDiscriminantGuard::enter(profile);
    let reader = open_node_config(
        NodeFile::Path(prepared.peers[0].config_path.clone()),
        NodeConfigOptions::default(),
    )
    .map_err(|_| eyre!("original parent node configuration could not be read"))?;
    let (user, _) = reader
        .read()
        .map_err(|_| eyre!("original parent node configuration could not be resolved"))?;
    let config = user
        .parse()
        .map_err(|_| eyre!("original parent node configuration failed validation"))?;
    // The generated bundle retains its manifest beside the client configuration;
    // running validators consume the bound signed wire, not an optional manifest.
    let generation = PrivateDirectory::open(
        prepared
            .context
            .client_config
            .parent()
            .ok_or_else(|| eyre!("parent has no retained generation"))?,
    )?;
    let manifest_path = generation.path().join("genesis.json");
    let bytes = generation.read(
        "genesis.json",
        iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1,
    )?;
    let manifest =
        iroha_genesis::RawGenesisTransaction::from_json_slice_at_path(&bytes, &manifest_path)?;
    crate::genesis::staging::ensure_peer_config_matches_manifest(&config, &manifest)?;
    let signed_path = config
        .genesis
        .file
        .as_ref()
        .ok_or_else(|| eyre!("parent has no original signed genesis"))?
        .value();
    ensure!(
        signed_path == &generation.path().join("genesis.signed.nrt"),
        "parent configured signed genesis differs from its original generation"
    );
    let signed = generation.read(
        "genesis.signed.nrt",
        iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1,
    )?;
    let validated = iroha_genesis::validate_prepared_genesis_bundle(
        &signed,
        &manifest,
        &config.genesis.public_key,
        config.genesis.expected_hash,
    )?;
    let genesis = validated.block().clone();
    let registrations = genesis_registrations(&genesis)?;
    let committee = iroha_core::sumeragi::startup::genesis_committee_peers(&genesis)?;
    let validators = committee
        .into_iter()
        .map(|peer| FinalityValidator {
            public_key: peer.public_key().clone(),
            proof_of_possession: registrations[&peer].clone(),
        })
        .collect();
    let mut nodes = Vec::new();
    for peer in &prepared.peers {
        let reader = open_node_config(
            NodeFile::Path(peer.config_path.clone()),
            NodeConfigOptions::default(),
        )
        .map_err(|_| eyre!("original parent peer configuration could not be read"))?;
        let (user, _) = reader
            .read()
            .map_err(|_| eyre!("original parent peer configuration could not be resolved"))?;
        nodes.push(PeerId::new(
            user.parse()
                .map_err(|_| eyre!("original parent peer configuration failed validation"))?
                .common
                .key_pair
                .public_key()
                .clone(),
        ));
    }
    let network_id = NetworkId::from_genesis_hash(genesis.hash());
    ensure!(
        network_id.to_string() == prepared.context.network_id,
        "independent parent genesis differs from context"
    );
    Ok((
        GenesisAnchor {
            network_id,
            chain_id: prepared.context.chain_id.clone(),
            genesis,
            validators,
        },
        config
            .torii
            .faucet
            .ok_or_else(|| eyre!("disposable parent faucet absent"))?,
        nodes,
    ))
}

fn source_for(
    prepared: &PreparedLocalnet,
    config: &Config,
    peers: &[PeerId],
    height: u64,
) -> TestResult<HttpFinalitySource> {
    ensure!(
        prepared.peers.len() == 4 && peers.len() == 4,
        "parent committee endpoints differ"
    );
    let clients = prepared
        .peers
        .iter()
        .map(|peer| -> TestResult<Client> {
            let mut selected = config.clone();
            selected.torii_api_url = peer.torii_url.parse()?;
            Ok(Client::builder(selected).build()?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok(HttpFinalitySource::new(
        config.network_id,
        NonZeroU64::new(height).ok_or_else(|| eyre!("zero parent cursor"))?,
        clients.clone(),
        peers.iter().cloned().zip(clients).collect(),
        Instant::now() + Duration::from_secs(20),
    )?)
}

fn independently_observed_parent(
    prepared: &PreparedLocalnet,
    config: &Config,
    anchor: &GenesisAnchor,
    peers: &[PeerId],
) -> TestResult<FinalityVerifier> {
    let source = source_for(prepared, config, peers, 1)?;
    let mut verifier = FinalityVerifier::from_genesis(
        anchor,
        &source.finality_proof(NonZeroU64::new(1).unwrap())?,
    )?;
    let challenge: [u8; 32] = rand::random();
    let quorum = verifier.observe(&source, &challenge)?;
    ensure!(
        quorum.verified() == 4,
        "independent parent release needs all four actual HTTP attestations"
    );
    Ok(verifier)
}

#[derive(Clone, Copy)]
struct PrivateProgram {
    name: &'static str,
    suffix: &'static str,
}

impl PrivateProgram {
    fn new(name: &'static str, suffix: &'static str) -> Self {
        Self { name, suffix }
    }

    fn result(&self) -> String {
        format!("{CANARY}:{}", self.suffix)
    }

    fn source(&self) -> String {
        format!(
            "seiyaku {} {{ state int value; hajimari() {{ value = 0; }} kotoage fn set(int next) authorize(\"CanInvokeContractEntrypoint\") {{ value = next; }} view fn current() -> int {{ return value; }} view fn secret() -> string {{ return \"{}\"; }} }}",
            self.name,
            self.result()
        )
    }

    fn compile(&self, chain_discriminant: u16) -> TestResult<(Vec<u8>, Hash)> {
        let (bytes, manifest) = kotodama_lang::compiler::Compiler::new_with_options(
            kotodama_lang::compiler::CompilerOptions {
                chain_discriminant,
                ..Default::default()
            },
        )
        .compile_source_with_manifest(&self.source())
        .map_err(|error| eyre!(error))?;
        let code_hash = manifest
            .code_hash
            .ok_or_else(|| eyre!("offline compiler omitted canonical artifact hash"))?;
        Ok((bytes, code_hash))
    }
}

fn verify_private_call(
    prepared: &PreparedLocalnet,
    report: &Value,
    expected: &str,
) -> TestResult<u64> {
    let registration = prepared.load_private_registration()?;
    verify_execution_report(report, registration.child_network_id, registration.scope)?;
    ensure!(
        report.get("status").and_then(Value::as_str) == Some("applied"),
        "mutable call did not report exact Applied"
    );
    let receipt: iroha_contract_deploy::call::ContractCallReceipt = json::from_value(
        report
            .get("receipt")
            .cloned()
            .ok_or_else(|| eyre!("missing mutable call receipt"))?,
    )?;
    ensure!(
        receipt.network_id.to_string() == prepared.context.network_id
            && receipt.contract_address.dataspace_id()?.as_u64() == prepared.context.dataspace_id
            && receipt.call.terminal_kind == "Applied"
            && receipt.call.resolved_from == "state"
            && receipt.call.block_height > 1,
        "mutable call evidence changed private root or exact state completion"
    );
    ensure!(
        report.get("readback_failure").is_some_and(Value::is_null)
            && report
                .get("readback")
                .and_then(|view| view.get("result"))
                .and_then(|response| response.get("result"))
                .and_then(Value::as_str)
                == Some(expected),
        "explicit managed readback did not observe the mutable value"
    );
    let original = prepared.context.load_client_config()?;
    for peer in &prepared.peers {
        let mut selected = original.clone();
        selected.torii_api_url = peer.torii_url.parse()?;
        let client = Client::builder(selected).build()?;
        wait_for_peer_commit(
            &client,
            &receipt.call,
            Instant::now() + Duration::from_secs(20),
        )?;
        let response = client.post_contract_view_json(
            &original.account,
            Some(&receipt.contract_address),
            None,
            "current",
            None,
            1_500_000,
        )?;
        ensure!(
            response.get("result").and_then(Value::as_str) == Some(expected),
            "private mutable value did not reach every child peer"
        );
    }
    Ok(receipt.call.block_height)
}

struct VerifiedPrivateDeployment {
    artifact_id: ContractArtifactId,
    bytes: Vec<u8>,
}

fn require_distinct_artifacts(artifacts: &[&VerifiedPrivateDeployment; 3]) -> TestResult<()> {
    for (index, artifact) in artifacts.iter().enumerate() {
        for previous in &artifacts[..index] {
            ensure!(
                artifact.artifact_id.dataspace_id == previous.artifact_id.dataspace_id
                    && artifact.artifact_id.code_hash != previous.artifact_id.code_hash
                    && artifact.bytes != previous.bytes,
                "the three private input forms must deploy distinct artifacts in the same dataspace"
            );
        }
    }
    Ok(())
}

fn deployment_height(value: &Value) -> TestResult<u64> {
    ensure!(
        value.get("status").and_then(Value::as_str) == Some("applied")
            && value
                .get("journal")
                .and_then(Value::as_str)
                .is_some_and(|journal| !journal.is_empty()),
        "private deployment lacks Applied status or an exact recovery journal"
    );
    let commit = value
        .get("receipt")
        .and_then(|r| r.get("commit"))
        .ok_or_else(|| eyre!("missing local Applied evidence"))?;
    ensure!(
        commit.get("terminal_kind").and_then(Value::as_str) == Some("Applied")
            && commit.get("resolved_from").and_then(Value::as_str) == Some("state"),
        "local deployment has no state-resolved Applied evidence"
    );
    let height = commit
        .get("block_height")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("missing local Applied carrier"))?;
    ensure!(
        height > 1,
        "a private deployment cannot be a genesis effect"
    );
    Ok(height)
}

fn verify_private_deployment(
    prepared: &PreparedLocalnet,
    deployment: &Value,
    expected_result: &str,
) -> TestResult<VerifiedPrivateDeployment> {
    deployment_height(deployment)?;
    let registration = prepared.load_private_registration()?;
    verify_execution_report(
        deployment,
        registration.child_network_id,
        registration.scope,
    )?;
    let receipt = deployment
        .get("receipt")
        .ok_or_else(|| eyre!("missing private receipt"))?;
    let commit = receipt_commit(receipt)?;
    ensure!(
        receipt.get("network_id").and_then(Value::as_str) == Some(&prepared.context.network_id)
            && receipt.get("dataspace_id").and_then(Value::as_u64)
                == Some(prepared.context.dataspace_id)
            && receipt
                .get("stored_artifact_matches")
                .and_then(Value::as_bool)
                == Some(true),
        "private receipt scope or exact artifact differs"
    );
    let artifact = receipt_artifact(receipt, DataSpaceId::new(prepared.context.dataspace_id))?;
    let address: ContractAddress = json::from_value(
        receipt
            .get("contract_address")
            .cloned()
            .ok_or_else(|| eyre!("missing contract address"))?,
    )?;
    ensure!(
        address.dataspace_id()? == artifact.dataspace_id && prepared.peers.len() == 4,
        "private execution scope or peer count differs"
    );
    let config = prepared.context.load_client_config()?;
    let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    let mut bytes = None;
    for peer in &prepared.peers {
        let mut selected = config.clone();
        selected.torii_api_url = peer.torii_url.parse()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let client = Client::builder(selected)
            .build()?
            .with_request_deadline(deadline);
        wait_for_peer_commit(&client, &commit, deadline)?;
        let code = client.get_contract_code_bytes(&artifact)?;
        if let Some(original) = &bytes {
            ensure!(
                original == &code,
                "private peers returned different artifact bytes"
            );
        } else {
            bytes = Some(code);
        }
        let response = client.post_contract_view_json(
            &config.account,
            Some(&address),
            None,
            "secret",
            None,
            1_500_000,
        )?;
        ensure!(
            response.get("ok").and_then(Value::as_bool) == Some(true)
                && response.get("contract_address") == Some(&json::to_value(&address)?)
                && response.get("code_hash_hex").and_then(Value::as_str)
                    == Some(hex::encode(artifact.code_hash.as_ref()).as_str())
                && response.get("result").and_then(Value::as_str) == Some(expected_result),
            "private exact contract did not execute on every peer"
        );
    }
    Ok(VerifiedPrivateDeployment {
        artifact_id: artifact,
        bytes: bytes.ok_or_else(|| eyre!("no private artifact read"))?,
    })
}

fn receipt_commit(receipt: &Value) -> TestResult<iroha_contract_deploy::AppliedEvidence> {
    let commit: iroha_contract_deploy::AppliedEvidence = json::from_value(
        receipt
            .get("commit")
            .cloned()
            .ok_or_else(|| eyre!("missing deployment commit evidence"))?,
    )?;
    let hash: HashOf<SignedTransaction> = commit.hash.parse()?;
    ensure!(
        commit.hash == hash.to_string()
            && commit.scope == "global"
            && commit.resolved_from == "state"
            && commit.terminal_kind == "Applied"
            && commit.block_height > 1,
        "deployment commit lacks canonical selected-root Applied evidence"
    );
    Ok(commit)
}

fn wait_for_peer_commit(
    client: &Client,
    commit: &iroha_contract_deploy::AppliedEvidence,
    deadline: Instant,
) -> TestResult<()> {
    let hash: HashOf<SignedTransaction> = commit.hash.parse()?;
    let expected_hash = hex::encode(hash.as_ref());
    loop {
        ensure!(
            Instant::now() < deadline,
            "private peer did not apply the exact deployment commit before its read deadline"
        );
        // The SDK owns canonical response and absence validation. Every HTTP,
        // authorization, routing or malformed-response error fails immediately;
        // only a valid unresolved local observation may be polled again.
        let observation = client.get_transaction_status_response_local(hash)?;
        ensure!(
            Instant::now() < deadline,
            "private peer commit observation arrived after its read deadline"
        );
        if let Some(observation) = observation {
            ensure!(
                observation.hash == expected_hash && observation.scope == "local",
                "peer commit observation changed its exact hash or local scope"
            );
            if peer_commit_applied(
                commit.block_height,
                &observation.status.kind,
                &observation.resolved_from,
                observation.status.block_height,
            )? {
                return Ok(());
            }
        }
        thread::sleep(
            Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

fn peer_commit_applied(
    expected_height: u64,
    kind: &str,
    resolved_from: &str,
    observed_height: Option<u64>,
) -> TestResult<bool> {
    ensure!(
        matches!(
            kind,
            "Queued" | "Approved" | "Committed" | "Applied" | "Rejected" | "Expired"
        ) && matches!(resolved_from, "cache" | "queue" | "state"),
        "peer commit observation has an unknown kind or resolution source"
    );
    if resolved_from != "state" {
        return Ok(false);
    }
    ensure!(
        !matches!(kind, "Rejected" | "Expired"),
        "peer state rejected or expired the exact deployment commit"
    );
    if kind != "Applied" {
        return Ok(false);
    }
    ensure!(
        expected_height > 1 && observed_height == Some(expected_height),
        "peer applied the deployment commit at a different carrier height"
    );
    Ok(true)
}

fn verify_execution_report(
    deployment: &Value,
    child_network_id: NetworkId,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
) -> TestResult<()> {
    let execution: ManagedDeploymentExecution = json::from_value(
        deployment
            .get("execution")
            .cloned()
            .ok_or_else(|| eyre!("missing private execution identity"))?,
    )?;
    ensure!(
        execution.network_id == child_network_id && execution.root_scope == root_scope,
        "deployment execution differs from original signed private root"
    );
    let iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
        parent_network_id, ..
    } = root_scope
    else {
        return Err(eyre!("private fixture requires a signed private scope"));
    };
    let parent: ManagedParentReport = json::from_value(
        deployment
            .get("parent")
            .cloned()
            .ok_or_else(|| eyre!("missing separate parent observation"))?,
    )?;
    ensure!(
        parent.parent_network_id == parent_network_id
            && parent.child_network_id == child_network_id,
        "deployment parent observation differs from original signed parent/child identities"
    );
    // This confirms only a separately observed historical fact. The later exact native
    // parent record proof independently establishes coverage of the new local deployment.
    ensure!(
        matches!(parent.observation, ManagedParentObservation::Observed { status }
        if status.parent_confirmed.is_some()),
        "attached private deployment lost its historical parent observation"
    );
    Ok(())
}

fn receipt_artifact(receipt: &Value, dataspace: DataSpaceId) -> TestResult<ContractArtifactId> {
    Ok(ContractArtifactId::new(
        dataspace,
        json::from_value(
            receipt
                .get("code_hash")
                .cloned()
                .ok_or_else(|| eyre!("missing code hash"))?,
        )?,
    ))
}

fn require_attached(status: &ManagedDataspaceStatus) -> TestResult<()> {
    ensure!(
        status.local.phase == ManagedPhase::Ready && status.local.running_peers == 4,
        "private validators are not ready"
    );
    ensure!(
        status.attachment.stage == ManagedAttachmentPhase::Attached
            && status.attachment.parent_confirmed.is_some(),
        "private local readiness lacks parent inclusion"
    );
    Ok(())
}

fn assert_absent(path: &Path, needles: &[&[u8]]) -> TestResult<u64> {
    ensure!(
        !needles.is_empty() && needles.iter().all(|needle| !needle.is_empty()),
        "empty privacy canary"
    );
    let mut file = fs::File::open(path)?;
    let overlap = needles.iter().map(|needle| needle.len()).max().unwrap() - 1;
    ensure!(overlap < 16 * 1024 * 1024, "artifact privacy scan bound");
    let mut retained = Vec::new();
    let mut read = 0_u64;
    let mut chunk = [0; 64 * 1024];
    loop {
        let length = file.read(&mut chunk)?;
        if length == 0 {
            break;
        }
        read += length as u64;
        ensure!(
            read <= 256 * 1024 * 1024,
            "parent file exceeds bounded privacy scan"
        );
        retained.extend_from_slice(&chunk[..length]);
        for needle in needles {
            ensure!(
                !retained
                    .windows(needle.len())
                    .any(|window| window == *needle),
                "private canary or complete bytecode leaked into parent custody at {}",
                path.display()
            );
        }
        if retained.len() > overlap {
            retained.drain(..retained.len() - overlap);
        }
    }
    Ok(read)
}

// Canonical JSON artifact reads use standard base64, while native persisted blocks contain
// raw byte frames. Retain both exact representations and erase copied listener credentials.
fn privacy_needles(values: &[&[u8]]) -> zeroize::Zeroizing<Vec<Vec<u8>>> {
    zeroize::Zeroizing::new(
        values
            .iter()
            .flat_map(|value| [value.to_vec(), BASE64.encode(value).into_bytes()])
            .collect(),
    )
}

fn inspect_parent_files(root: &Path, needles: &[&[u8]]) -> TestResult<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut count = 0;
    let mut bytes = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            count += 1;
            ensure!(count <= 4096, "parent privacy scan entry bound");
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                bytes += assert_absent(&entry.path(), needles)?;
                ensure!(
                    bytes <= 512 * 1024 * 1024,
                    "parent privacy scan aggregate bound"
                );
            } else {
                ensure!(
                    !kind.is_symlink(),
                    "indirect parent custody cannot establish absence"
                );
            }
        }
    }
    Ok(())
}

fn unix_ms() -> TestResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

#[test]
fn fixture_temporary_custody_is_retained_unless_explicitly_closed() {
    let retained = RetainedTemporary(Some(tempfile::tempdir().unwrap()));
    let retained_path = retained.path().to_path_buf();
    let directory = PrivateDirectory::open_or_create(retained.path().join("custody")).unwrap();
    directory
        .write_atomic("evidence", b"original", PublishMode::CreateNew)
        .unwrap();
    drop(directory);
    drop(retained);
    assert_eq!(
        fs::read(retained_path.join("custody/evidence")).unwrap(),
        b"original"
    );
    fs::remove_dir_all(retained_path).unwrap();

    let success = RetainedTemporary(Some(tempfile::tempdir().unwrap()));
    let removed_path = success.path().to_path_buf();
    let directory = PrivateDirectory::open_or_create(success.path().join("custody")).unwrap();
    directory
        .write_atomic("evidence", b"verified", PublishMode::CreateNew)
        .unwrap();
    drop(directory);
    success.close().unwrap();
    assert!(!removed_path.exists());
}

#[test]
fn ingress_readiness_failure_retains_child_until_observed_eof_exit() {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("controller")).unwrap();
    root.write_atomic("ports", b"invalid-port\n", PublishMode::CreateNew)
        .unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "managed::tests::attachment_installed::ingress_lifetime_child",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env("IROHA_TEST_INGRESS_LIFETIME_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut ingress = Ingress {
        child,
        roots: Vec::new(),
    };
    assert!(ingress.wait_ready(&root).is_err());
    assert!(ingress.child.try_wait().unwrap().is_none());
    ingress.stop().unwrap();
    assert!(ingress.child.try_wait().unwrap().unwrap().success());
    ingress.stop().unwrap();
}

/// Internal portable child used only by the retained-handle shutdown regression.
#[test]
#[ignore = "internal child; the parent test owns its stdin lifetime"]
fn ingress_lifetime_child() {
    assert_eq!(
        std::env::var("IROHA_TEST_INGRESS_LIFETIME_CHILD").as_deref(),
        Ok("1")
    );
    std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink()).unwrap();
}

#[test]
fn private_peer_readback_waits_for_exact_state_applied_carrier() {
    assert!(peer_commit_applied(7, "Applied", "state", Some(7)).unwrap());
    for kind in [
        "Queued",
        "Approved",
        "Committed",
        "Applied",
        "Rejected",
        "Expired",
    ] {
        assert!(!peer_commit_applied(7, kind, "cache", Some(7)).unwrap());
    }
    for kind in ["Queued", "Approved", "Committed"] {
        assert!(!peer_commit_applied(7, kind, "state", Some(7)).unwrap());
    }
    for kind in ["Rejected", "Expired", "Unknown"] {
        assert!(peer_commit_applied(7, kind, "state", Some(7)).is_err());
    }
    for height in [None, Some(0), Some(6), Some(8)] {
        assert!(peer_commit_applied(7, "Applied", "state", height).is_err());
    }
    assert!(peer_commit_applied(0, "Applied", "state", Some(0)).is_err());
    assert!(peer_commit_applied(7, "Applied", "unknown", Some(7)).is_err());
}

#[test]
fn private_receipt_commit_requires_exact_canonical_success() {
    let commit = iroha_contract_deploy::AppliedEvidence {
        hash: Hash::new(b"private receipt transaction").to_string(),
        terminal_kind: "Applied".into(),
        block_height: 7,
        scope: "global".into(),
        resolved_from: "state".into(),
        charge: None,
    };
    let receipt = norito::json!({ "commit": (json::to_value(&commit).unwrap()) });
    assert_eq!(receipt_commit(&receipt).unwrap(), commit);
    for (field, replacement) in [
        ("hash", Value::from("invalid")),
        ("terminal_kind", Value::from("Committed")),
        ("block_height", Value::from(1_u64)),
        ("scope", Value::from("local")),
        ("resolved_from", Value::from("cache")),
    ] {
        let mut invalid = receipt.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .get_mut("commit")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(field.into(), replacement);
        assert!(receipt_commit(&invalid).is_err());
    }
    assert!(receipt_commit(&norito::json!({})).is_err());
}

#[test]
fn private_input_forms_compile_to_distinct_canary_programs() {
    let programs = [
        PrivateProgram::new("PrivateSecret", "source"),
        PrivateProgram::new("PrivateBytecode", "bytecode"),
        PrivateProgram::new("PrivatePackage", "package"),
    ];
    let mut artifacts = programs
        .iter()
        .map(|program| {
            assert!(program.result().starts_with(CANARY));
            assert!(program.source().contains(&program.result()));
            let (bytes, code_hash) = program.compile(753).unwrap();
            VerifiedPrivateDeployment {
                artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash),
                bytes,
            }
        })
        .collect::<Vec<_>>();
    assert_ne!(programs[0].result(), programs[1].result());
    assert_ne!(programs[0].result(), programs[2].result());
    assert_ne!(programs[1].result(), programs[2].result());
    require_distinct_artifacts(&[&artifacts[0], &artifacts[1], &artifacts[2]]).unwrap();

    let original_id = artifacts[1].artifact_id;
    artifacts[1].artifact_id = artifacts[0].artifact_id;
    assert!(require_distinct_artifacts(&[&artifacts[0], &artifacts[1], &artifacts[2]]).is_err());
    artifacts[1].artifact_id = original_id;
    let original_bytes = std::mem::take(&mut artifacts[1].bytes);
    artifacts[1].bytes = artifacts[0].bytes.clone();
    assert!(require_distinct_artifacts(&[&artifacts[0], &artifacts[1], &artifacts[2]]).is_err());
    artifacts[1].bytes = original_bytes;
    artifacts[1].artifact_id.dataspace_id = DataSpaceId::new(0);
    assert!(require_distinct_artifacts(&[&artifacts[0], &artifacts[1], &artifacts[2]]).is_err());
}

#[test]
fn privacy_scan_checks_chunk_boundaries_and_rejects_empty_evidence() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("public");
    let mut bytes = vec![b'x'; 64 * 1024 - 4];
    bytes.extend_from_slice(CANARY.as_bytes());
    fs::write(&file, bytes).unwrap();
    assert!(assert_absent(&file, &[CANARY.as_bytes()]).is_err());
    assert!(assert_absent(&file, &[b""]).is_err());
    assert!(assert_absent(&file, &[]).is_err());
    assert_absent(&file, &[b"not present"]).unwrap();
    let needles = privacy_needles(&[CANARY.as_bytes()]);
    let needles: Vec<&[u8]> = needles.iter().map(|bytes| bytes.as_slice()).collect();
    fs::write(&file, BASE64.encode(CANARY)).unwrap();
    assert!(assert_absent(&file, &needles).is_err());
}

#[test]
fn private_execution_report_requires_exact_separate_parent_and_child_bindings() {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope, private_dataspace::PrivateDataspaceCursor,
    };
    let child = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"private-report-child",
    )));
    let parent = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"private-report-parent",
    )));
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: parent,
        dataspace_id: DataSpaceId::new(u64::MAX),
    };
    let execution = ManagedDeploymentExecution {
        network_id: child,
        root_scope: scope,
    };
    let observation = ManagedParentReport {
        parent_network_id: parent,
        child_network_id: child,
        observation: ManagedParentObservation::Observed {
            status: ManagedAttachmentStatus {
                network: "fixture".into(),
                stage: ManagedAttachmentPhase::Attached,
                wallet_status: None,
                local_successor: None,
                failure: None,
                parent_confirmed: Some(ManagedConfirmedAnchor {
                    parent_height: 8,
                    child: PrivateDataspaceCursor {
                        height: 2,
                        consensus_hash: [1; 32],
                        result: [2; 32],
                    },
                }),
            },
        },
    };
    let report = norito::json!({ "execution": (execution), "parent": (observation) });
    verify_execution_report(&report, child, scope).unwrap();
    assert!(verify_execution_report(&report, parent, scope).is_err());
    assert!(verify_execution_report(&report, child, SumeragiRootScope::Global).is_err());
    for field in ["execution", "parent"] {
        let mut missing = report.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(verify_execution_report(&missing, child, scope).is_err());
    }
    for (field, network) in [("parent_network_id", child), ("child_network_id", parent)] {
        let mut changed = report.clone();
        changed
            .as_object_mut()
            .unwrap()
            .get_mut("parent")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(field.into(), json::to_value(&network).unwrap());
        assert!(verify_execution_report(&changed, child, scope).is_err());
    }
    let mut changed = report;
    changed
        .as_object_mut()
        .unwrap()
        .get_mut("parent")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "observation".into(),
            json::to_value(&ManagedParentObservation::NotConfigured).unwrap(),
        );
    assert!(verify_execution_report(&changed, child, scope).is_err());
}

#[test]
fn parent_cli_status_requires_exact_ready_global_context() {
    let status = ManagedStatus {
        context: ManagedContext {
            name: "parent".into(),
            chain_id: "fixture-parent".into(),
            network_id: "fixture-parent-network".into(),
            account_id: "fixture-owner".into(),
            dataspace_id: 0,
            dataspace_alias: "universal".into(),
            torii_url: "http://127.0.0.1:18080/".into(),
            client_config: "/fixture/client.toml".into(),
        },
        phase: ManagedPhase::Ready,
        running_peers: 4,
        failure: None,
    };
    let value = json::to_value(&status).unwrap();
    assert_eq!(parse_parent_ready(value.clone()).unwrap(), status);
    for (field, changed) in [
        ("phase", Value::from("stopped")),
        ("running_peers", Value::from(3_u64)),
        ("failure", Value::from("not ready")),
    ] {
        let mut invalid = value.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .insert(field.into(), changed);
        assert!(parse_parent_ready(invalid).is_err());
    }
    for (field, changed) in [
        ("name", Value::from("child")),
        ("dataspace_id", Value::from(u64::MAX)),
    ] {
        let mut invalid = value.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .get_mut("context")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(field.into(), changed);
        assert!(parse_parent_ready(invalid).is_err());
    }
    assert!(parse_parent_ready(norito::json!({"status": "ready"})).is_err());
}

#[test]
fn receipt_artifact_reads_the_canonical_typed_hash() {
    let code_hash = Hash::new(b"exact private contract bytes");
    let dataspace = DataSpaceId::new(u64::MAX);
    let receipt = norito::json!({ "code_hash": (json::to_value(&code_hash).unwrap()) });
    assert_eq!(
        receipt_artifact(&receipt, dataspace).unwrap(),
        ContractArtifactId::new(dataspace, code_hash)
    );
    assert!(receipt_artifact(&norito::json!({}), dataspace).is_err());
    assert!(receipt_artifact(&norito::json!({ "code_hash": 7 }), dataspace).is_err());
}

#[test]
fn deployment_evidence_requires_state_applied_height_and_exact_journal() {
    let evidence = norito::json!({
        "status": "applied", "journal": "original",
        "receipt": {"commit": {"terminal_kind": "Applied", "resolved_from": "state", "block_height": 5}},
    });
    assert_eq!(deployment_height(&evidence).unwrap(), 5);
    for field in ["status", "journal", "receipt"] {
        let mut missing = evidence.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(deployment_height(&missing).is_err());
    }
    for (field, replacement) in [
        ("terminal_kind", Value::from("Pending")),
        ("resolved_from", Value::from("cache")),
        ("block_height", Value::from(1_u64)),
    ] {
        let mut changed = evidence.clone();
        changed
            .as_object_mut()
            .unwrap()
            .get_mut("receipt")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("commit")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(field.into(), replacement);
        assert!(deployment_height(&changed).is_err());
    }
}

/// Explicit eight-validator installed-runtime regression; no public network is contacted.
#[test]
#[ignore = "requires matching IROHA_TEST_RUNTIME_DIRECTORY, Python/OpenSSL controller tools, and resources for eight native validators"]
fn installed_parent_attachment_private_contracts_and_payload_isolation() {
    let _resources = super::super::native_test_guard();
    let installed = PathBuf::from(
        std::env::var_os("IROHA_TEST_RUNTIME_DIRECTORY")
            .expect("set matching native runtime installation"),
    );
    let mut harness = Harness::new(&installed).expect("disposable installed runtime custody");
    let result = harness.exercise();
    let stopped = harness.stop();
    if let Some(timing) = &harness.timing {
        timing
            .cleanup(stopped.is_ok())
            .expect("typed diagnostic cleanup observation");
    }
    stopped.expect("authenticated zero owned peers after attachment fixture");
    result.expect("genuine parent attachment and private payload isolation");
    harness
        .remove_verified_custody()
        .expect("remove only successful, authenticated-stopped fixture custody");
}

#[test]
fn installed_fixture_uses_one_canonical_bundle_runtime_and_resource_directory() {
    for layout in [
        NativeBundleLayout::MacOs,
        NativeBundleLayout::Linux,
        NativeBundleLayout::Windows,
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let root = PrivateDirectory::open_or_create(temporary.path().join("custody")).unwrap();
        let runtime =
            fixture_bundle_directory(&root, &layout.runtime_directory(root.path())).unwrap();
        let resources =
            fixture_bundle_directory(&root, &layout.resources_directory(root.path())).unwrap();
        assert_eq!(runtime.path(), layout.runtime_directory(root.path()));
        let profile = layout.profiles_path(root.path());
        assert_eq!(profile.parent().unwrap(), resources.path());
        resources
            .write_atomic(
                profile.file_name().unwrap(),
                b"fixture",
                PublishMode::CreateNew,
            )
            .unwrap();
        assert_eq!(
            resources
                .read(profile.file_name().unwrap(), 16)
                .unwrap()
                .as_slice(),
            b"fixture"
        );
        if layout == NativeBundleLayout::MacOs {
            assert!(!root.path().join("bin").exists());
            assert!(!runtime.path().join(profile.file_name().unwrap()).exists());
        }
        assert!(fixture_bundle_directory(&root, &root.path().join("../escape")).is_err());
        assert!(fixture_bundle_directory(&root, temporary.path()).is_err());
    }
}

#[test]
fn installed_cli_fixture_admits_only_two_programs_and_colocated_profiles() {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("custody")).unwrap();
    let runtime =
        fixture_bundle_directory(&root, &KagamiBundleLayout::runtime_directory(root.path()))
            .unwrap();
    for program in ["kagami", "iroha3d"] {
        std::fs::copy(
            std::env::current_exe().unwrap(),
            runtime
                .path()
                .join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
        )
        .unwrap();
    }
    let installed = InstalledRuntime::from_directory(runtime.path()).unwrap();
    let profiles = InstalledNetworkProfiles::new(Vec::new()).unwrap();
    runtime
        .write_atomic(
            crate::bootstrap::NETWORK_PROFILES_FILENAME,
            &profiles.encode_installation().unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    assert_eq!(installed.network_profiles().unwrap().names().len(), 0);
    assert_eq!(
        crate::managed::bundle::runtime_profiles_path(runtime.path()).unwrap(),
        KagamiBundleLayout::profiles_path(root.path())
    );
    assert!(!runtime.path().join("mochi").exists());
    assert!(!root.path().join("Mochi.app").exists());
}
