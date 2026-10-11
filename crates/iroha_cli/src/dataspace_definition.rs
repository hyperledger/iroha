//! Build a dataspace runtime directly from one definition and an explicit public trust profile.
//!
//! Public input is admitted before either runtime credential is opened. The owner is selected
//! only by `dataspace.owner_key`; operator authorization is a separate explicit CLI credential.

use std::{io::Write, path::Path, time::Duration};

use eyre::{Result, WrapErr as _, bail};
use iroha_deploy::definition::{CommitteeSource, DataspaceDefinition, NetworkRef};

use crate::{
    Args, ChainDiscriminantGuard, Command, FeePayerArg, FeePaymentArgs, Localizer,
    PrintJsonContext, client_config, client_config_with_defaults, effective_output,
    load_runtime_operator_key, operator_key,
    taira_dataspace_deploy::{self, DeploymentTrustV1},
};

/// Dispatch definition commands before the general CLI considers `client.toml`.
#[cfg(unix)]
pub(crate) fn run(
    args: &Args,
    output: impl Write,
    errors: impl Write,
    i18n: Localizer,
) -> Result<()> {
    use taira_dataspace_deploy::{Command as DataspaceCommand, PublicInput};

    reject_runtime_globals(args)?;
    let Command::Dataspace(command) = &args.command else {
        bail!("expected a dataspace definition command");
    };
    let command_args = match command {
        DataspaceCommand::Plan(args)
        | DataspaceCommand::Apply(args)
        | DataspaceCommand::Status(args) => args,
        DataspaceCommand::ExportProfile(_) | DataspaceCommand::VerifyAuthority(_) => {
            bail!("profile export must use the credential-free dispatcher")
        }
    };
    if command_args.timeout_ms == 0 {
        bail!("dataspace command timeout must be greater than zero");
    }
    let definition_input =
        PublicInput::read(&command_args.definition).wrap_err("cannot read dataspace definition")?;
    let definition = parse_definition(&definition_input.bytes, &command_args.definition)?;
    let endpoint = definition_endpoint(&definition)?;
    let trust_input = PublicInput::read(&command_args.trust)
        .wrap_err("cannot read independently selected public trust profile")?;
    let trust: DeploymentTrustV1 =
        norito::json::from_slice(&trust_input.bytes).wrap_err("invalid public trust profile")?;
    let network_id = trusted_network(&trust)?;
    command.verification_origins(&trust)?;
    if definition
        .dataspace
        .network_id
        .is_some_and(|pin| pin != network_id)
    {
        bail!(
            "dataspace.network_id differs from the signed genesis in the selected public trust profile"
        );
    }
    if args.operator_private_key_file.is_none() && args.operator_private_key_fd.is_none() {
        bail!(
            "dataspace commands require an explicit --operator-private-key-file or --operator-private-key-fd for authenticated network reads"
        );
    }
    // Parsing and public trust checks must finish before opening either secret.
    definition_input.revalidate()?;
    trust_input.revalidate()?;
    let owner = operator_key::load_owner_key_pair(&definition.dataspace.owner_key)?;
    let operator_key_pair = load_runtime_operator_key(args)?;
    let _address_profile = ChainDiscriminantGuard::enter(trust.account_chain_discriminant);
    let config = client_config_with_defaults(
        trust.chain.clone(),
        network_id,
        owner,
        trust.account_chain_discriminant,
        endpoint,
    );
    let selection = effective_output(args);
    let mut context = PrintJsonContext {
        write: output,
        err_write: errors,
        config,
        filesystem_config: client_config::FilesystemConfig::default(),
        offline_fallback: false,
        operator_key_pair,
        transaction_metadata: None,
        fee_payment: FeePaymentArgs {
            fee_payer: Some(FeePayerArg::Authority),
            ..FeePaymentArgs::default()
        },
        input_instructions: false,
        output_instructions: false,
        output_format: selection.format,
        json_lines: selection.json_lines,
        i18n,
    };
    definition_input.revalidate()?;
    trust_input.revalidate()?;
    taira_dataspace_deploy::run_definition(&mut context, command, &definition, trust)
}

/// Fail closed on platforms without the required direct-file custody primitives.
#[cfg(not(unix))]
pub(crate) fn run(_: &Args, _: impl Write, _: impl Write, _: Localizer) -> Result<()> {
    bail!("dataspace definition commands require Unix filesystem custody")
}

fn reject_runtime_globals(args: &Args) -> Result<()> {
    if args.config.is_some()
        || args.config_fd.is_some()
        || args.config_source_path.is_some()
        || args.verbose
        || args.metadata.is_some()
        || args.stdin_instructions
        || args.emit_instructions
        || args.fee_payment.fee_payer.is_some()
        || args.fee_payment.fee_program.is_some()
        || args.fee_payment.fee_program_revision.is_some()
    {
        bail!(
            "dataspace definitions supply the owner, network, and fee budget; config, verbose, metadata, stdin/emit-instruction, and fee-selection globals are not accepted"
        );
    }
    Ok(())
}

fn parse_definition(bytes: &[u8], path: &Path) -> Result<DataspaceDefinition> {
    let text = std::str::from_utf8(bytes).wrap_err("dataspace definition must be UTF-8 TOML")?;
    let table: toml::Table = text.parse().wrap_err("invalid dataspace definition TOML")?;
    if table.contains_key("monitor") {
        bail!(
            "[monitor] is not supported by dataspace plan/apply/status; remove it before deployment"
        );
    }
    let definition = DataspaceDefinition::parse(text, path, std::env::home_dir().as_deref())?;
    definition_endpoint(&definition)?;
    Ok(definition)
}

fn definition_endpoint(definition: &DataspaceDefinition) -> Result<url::Url> {
    let NetworkRef::Url(endpoint) = &definition.dataspace.network else {
        bail!(
            "dataspace.network must be an explicit HTTPS URL; network definitions and card anchors are not supported by this runtime"
        );
    };
    if definition.committee.source != CommitteeSource::Network {
        bail!("dataspace deployment currently supports committee.source = \"network\" only");
    }
    if definition.ssh.is_some() || definition.edge.is_some() {
        bail!("[ssh] and [edge] require owner-committee deployment, which is not implemented");
    }
    if definition.monitor.webhook_file.is_some()
        || definition.monitor.interval.get() != Duration::from_secs(300)
    {
        bail!("dataspace monitoring is not implemented by plan/apply/status");
    }
    if definition.dataspace.max_fee.is_zero() {
        bail!(
            "dataspace.max_fee must be greater than zero to budget the registration and alias transactions"
        );
    }
    endpoint
        .as_str()
        .parse()
        .wrap_err("invalid dataspace network endpoint")
}

fn trusted_network(trust: &DeploymentTrustV1) -> Result<iroha_data_model::NetworkId> {
    // Bound hexadecimal before allocation. Full canonical encoding and signature verification
    // remain owned by the existing deployment trust validator.
    if trust.genesis_signed_wire_hex.len() > 8 * 1024 * 1024 {
        bail!("public genesis exceeds the deployment profile bound");
    }
    let wire =
        hex::decode(&trust.genesis_signed_wire_hex).wrap_err("invalid signed genesis hex")?;
    let (hash, _) =
        iroha_core::release_identity::genesis_identity(&wire, &trust.genesis_public_key)?;
    let network =
        iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(hash));
    taira_dataspace_deploy::validate_deployment_trust(trust, network)?;
    Ok(network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use iroha_crypto::{Algorithm, KeyPair};

    fn definition(network: &str) -> String {
        format!(
            "[dataspace]\nname = \"acme\"\nnetwork = {network:?}\nowner_key = \"owner.key\"\nmax_fee = \"20\"\n"
        )
    }

    #[test]
    fn admits_one_definition_and_resolves_only_its_owner_path() {
        let definition = parse_definition(
            definition("https://EXAMPLE.com/").as_bytes(),
            Path::new("/definitions/acme.toml"),
        )
        .unwrap();
        assert_eq!(
            definition.dataspace.owner_key,
            Path::new("/definitions/owner.key")
        );
        assert_eq!(
            definition_endpoint(&definition).unwrap().as_str(),
            "https://example.com/"
        );
        assert_eq!(definition.committee.source, CommitteeSource::Network);
    }

    #[test]
    fn rejects_unsupported_definitions_before_reading_any_referenced_file() {
        for network in ["../network.toml", "../network.card.toml"] {
            let error = parse_definition(
                definition(network).as_bytes(),
                Path::new("/absent/definition.toml"),
            )
            .unwrap_err();
            assert!(error.to_string().contains("explicit HTTPS URL"));
        }
        for monitor in ["[monitor]\n", "[monitor]\ninterval = \"5m\"\n"] {
            let text = definition("https://example.com") + monitor;
            assert!(
                parse_definition(text.as_bytes(), Path::new("/absent/definition.toml"))
                    .unwrap_err()
                    .to_string()
                    .contains("[monitor]")
            );
        }
        let text = definition("https://example.com").replace("max_fee = \"20\"", "max_fee = \"0\"");
        assert!(
            parse_definition(text.as_bytes(), Path::new("/absent/definition.toml"))
                .unwrap_err()
                .to_string()
                .contains("max_fee must be greater than zero")
        );
    }

    #[test]
    fn definition_surface_rejects_redundant_globals_and_retired_commands() {
        for command in ["plan", "apply", "status"] {
            let parsed = Args::try_parse_from([
                "iroha",
                "dataspace",
                command,
                "dataspaces/acme.toml",
                "--trust",
                "network.json",
            ])
            .unwrap();
            reject_runtime_globals(&parsed).unwrap();
            assert!(!parsed.command.allows_fallback_config());
        }
        for globals in [
            vec!["--config", "/must-not-read"],
            vec![
                "--config-fd",
                "999",
                "--config-source-path",
                "/must-not-read",
            ],
            vec!["--metadata", "/must-not-read"],
            vec!["--stdin-instructions"],
            vec!["--emit-instructions"],
            vec!["--verbose"],
            vec!["--fee-payer", "authority"],
        ] {
            let mut argv = vec!["iroha"];
            argv.extend(globals);
            argv.extend([
                "dataspace",
                "plan",
                "definition.toml",
                "--trust",
                "trust.json",
            ]);
            assert!(reject_runtime_globals(&Args::try_parse_from(argv).unwrap()).is_err());
        }
        assert!(Args::try_parse_from(["iroha", "taira", "dataspace-deploy", "plan"]).is_err());
        assert!(Args::try_parse_from(["iroha", "dataspace", "init"]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unsupported_input_fails_before_trust_and_credential_io() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("dataspace.toml");
        for text in [
            definition("missing.card.toml"),
            definition("https://example.com") + "[monitor]\n",
            definition("https://example.com").replace("max_fee = \"20\"", "max_fee = \"0\""),
        ] {
            std::fs::write(&source, text).unwrap();
            let args = Args::try_parse_from([
                "iroha",
                "--operator-private-key-file",
                "/must-not-read-operator",
                "dataspace",
                "plan",
                source.to_str().unwrap(),
                "--trust",
                "/must-not-read-trust",
            ])
            .unwrap();
            let error = run(
                &args,
                Vec::new(),
                Vec::new(),
                Localizer::new(iroha_i18n::Bundle::Cli, iroha_i18n::Language::English),
            )
            .unwrap_err();
            let message = format!("{error:#}");
            assert!(!message.contains("cannot read independently selected public trust profile"));
            assert!(!message.contains("private-key file"));
            assert!(
                message.contains("explicit HTTPS URL")
                    || message.contains("[monitor]")
                    || message.contains("max_fee must be greater than zero")
            );
        }
    }

    #[test]
    fn network_identity_comes_from_validated_public_genesis() {
        use norito::codec::Encode as _;
        let (genesis, signer) = crate::taira_public_reset::deployment_genesis_fixture();
        let peers = iroha_genesis::signed_genesis_validator_pops(&genesis)
            .unwrap()
            .into_keys()
            .enumerate()
            .map(|(index, key)| {
                let peer_id = iroha_model_base::peer::PeerId::new(key);
                taira_dataspace_deploy::DeploymentPeerV1 {
                    torii_origin: format!("http://127.0.0.1:{}/", 8080 + index),
                    node_fingerprint: iroha_crypto::Hash::new(peer_id.encode()),
                    peer_id,
                    build_fingerprint: iroha_crypto::Hash::new([1]),
                    config_fingerprint: iroha_crypto::Hash::new([2]),
                }
            })
            .collect();
        let mut trust = DeploymentTrustV1 {
            chain: "explicit-selected-chain".into(),
            account_chain_discriminant: 901,
            genesis_public_key: signer.public_key().clone(),
            genesis_signed_wire_hex: hex::encode(genesis.encode_wire().unwrap()),
            peers,
        };
        assert_eq!(
            trusted_network(&trust).unwrap(),
            iroha_data_model::NetworkId::from_genesis_hash(genesis.hash())
        );
        trust.genesis_signed_wire_hex.push_str("00");
        assert!(trusted_network(&trust).is_err());
    }

    #[test]
    fn client_defaults_preserve_explicit_identity_and_separate_operator_selection() {
        let owner = KeyPair::try_from_seed(vec![3; 32], Algorithm::Ed25519).unwrap();
        let network = iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                b"selected-network",
            )),
        );
        let config = client_config_with_defaults(
            "selected-chain".into(),
            network,
            owner.clone(),
            901,
            "https://example.com/".parse().unwrap(),
        );
        assert_eq!(config.chain.as_str(), "selected-chain");
        assert_eq!(config.network_id, network);
        assert_eq!(config.account_chain_discriminant, 901);
        assert_eq!(
            config.account,
            iroha_data_model::account::AccountId::new(owner.public_key().clone())
        );
        assert_eq!(config.key_pair.public_key(), owner.public_key());
    }
}
