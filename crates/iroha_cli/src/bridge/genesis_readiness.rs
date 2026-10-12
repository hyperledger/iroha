//! One bounded signed-genesis readiness probe; callers own retries and deadlines.
use crate::{CliOutputFormat, RunContext};
use base64::Engine as _;
use eyre::{Result, ensure};
use iroha::{
    client::GenesisFinalityReadiness,
    crypto::{Hash, HashOf, PublicKey},
    data_model::{
        block::BlockHeader,
        id::NetworkId,
        sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier},
    },
};
use iroha_model_base::peer::PeerId;
use std::{
    io::Read as _,
    path::PathBuf,
    time::{Duration, Instant},
};

const MAX_OUTPUT_BYTES: usize = 24 * 1024 * 1024;
const MAX_ATTESTATION_BYTES: usize = 16 * 1024 * 1024;

/// Original process identities and one finite overall HTTP probe budget.
#[derive(clap::Args, Debug)]
pub struct Args {
    /// Fresh unpredictable 32-byte challenge as exactly 64 lowercase hexadecimal characters.
    #[arg(long)]
    challenge: String,
    /// BLS public key independently retained for this original validator process.
    #[arg(long)]
    node_public_key: PublicKey,
    /// Canonical genesis hash retained from original generated inputs.
    #[arg(long)]
    genesis_hash: Hash,
    /// Independently retained canonical signed genesis file.
    #[arg(long)]
    signed_genesis: PathBuf,
    /// Original genesis manifest, checked against the signed genesis semantics.
    #[arg(long)]
    genesis_manifest: PathBuf,
    /// Independently retained genesis verification key.
    #[arg(long)]
    genesis_public_key: PublicKey,
    /// Total HTTP budget for compatibility and attestation, within the launcher's deadline.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=60_000))]
    request_timeout_ms: u64,
}

#[derive(norito::derive::JsonSerialize)]
struct Report {
    version: u8,
    state: &'static str,
    reason: Option<&'static str>,
    challenge: String,
    node_id: PeerId,
    network_id: NetworkId,
    genesis_hash: HashOf<BlockHeader>,
    consensus_instance: String,
    genesis_execution_hash: Option<String>,
    attestation_norito_base64: Option<String>,
}

fn parse_challenge(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "challenge must be exactly 64 lowercase hexadecimal characters"
    );
    let mut challenge = [0; 32];
    hex::decode_to_slice(value, &mut challenge)?;
    ensure!(
        challenge.iter().any(|byte| *byte != 0),
        "challenge must be nonzero"
    );
    Ok(challenge)
}

fn genesis_execution_hash(block: &iroha::data_model::block::SignedBlock) -> Result<String> {
    use iroha::data_model::sumeragi_finality::{
        CertifiedResultScope, CertifiedResultV1, result_of_preimage,
    };
    let certificate = block
        .commit_certificate()
        .ok_or_else(|| eyre::eyre!("verified genesis certificate missing"))?;
    // The readiness client already authenticated this genesis and its scope. Recheck the
    // complete structural carrier and C5 before rendering its exact signed result hash.
    let certified = CertifiedResultV1::decode(
        certificate.result_preimage(),
        CertifiedResultScope::TairaGlobal,
    )?;
    certified.check_block(
        block.header().height().get(),
        block.header().creation_time_ms,
    )?;
    Ok(hex::encode(
        result_of_preimage(certificate.result_preimage())
            .ok_or_else(|| eyre::eyre!("verified genesis result preimage is malformed"))?
            .0,
    ))
}

fn report(
    args: &Args,
    network_id: NetworkId,
    instance: [u8; 32],
    outcome: GenesisFinalityReadiness,
) -> Result<Report> {
    let (state, reason, attestation_norito_base64, genesis_execution_hash) = match outcome {
        GenesisFinalityReadiness::Ready(attestation) => {
            let block = iroha::data_model::block::decode_framed_signed_block(
                &attestation.body.finality_proof.block_wire,
            )?;
            let execution_hash = genesis_execution_hash(&block)?;
            let bytes = norito::to_bytes(attestation.as_ref())?;
            ensure!(
                bytes.len() <= MAX_ATTESTATION_BYTES,
                "verified attestation exceeds the canonical wire limit"
            );
            (
                "ready",
                None,
                Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
                Some(execution_hash),
            )
        }
        GenesisFinalityReadiness::NotReady(reason) => {
            (reason.readiness_state(), Some(reason.as_str()), None, None)
        }
    };
    Ok(Report {
        version: 1,
        state,
        reason,
        challenge: args.challenge.clone(),
        node_id: PeerId::new(args.node_public_key.clone()),
        network_id,
        genesis_hash: HashOf::from_untyped_unchecked(args.genesis_hash),
        consensus_instance: hex::encode(instance),
        genesis_execution_hash,
        attestation_norito_base64,
    })
}

fn render_report(report: &Report) -> Result<String> {
    let output = norito::json::to_json(report)?;
    ensure!(
        output.len() < MAX_OUTPUT_BYTES,
        "genesis readiness output exceeds 24 MiB including its newline"
    );
    Ok(output)
}

/// Send the bounded protocol result to stdout, independently of the diagnostic stream.
fn write_report(context: &mut impl RunContext, report: &Report) -> Result<()> {
    context.println_data(render_report(report)?)
}

pub(super) fn run(context: &mut impl RunContext, args: Args) -> Result<()> {
    ensure!(
        context.output_format() == CliOutputFormat::Json,
        "genesis-readiness requires --output-format json"
    );
    ensure!(
        (1..=60_000).contains(&args.request_timeout_ms),
        "request timeout must be 1..=60000 milliseconds"
    );
    let deadline = Instant::now() + Duration::from_millis(args.request_timeout_ms);
    let challenge = parse_challenge(&args.challenge)?;
    let node_id = PeerId::new(args.node_public_key.clone());
    let genesis_hash = HashOf::<BlockHeader>::from_untyped_unchecked(args.genesis_hash);
    iroha_genesis::init_instruction_registry();
    let bounded_read = |path: &PathBuf, maximum: usize| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            !bytes.is_empty() && bytes.len() <= maximum,
            "genesis input exceeds its finite bound"
        );
        Ok(bytes)
    };
    let wire = bounded_read(&args.signed_genesis, 32 * 1024 * 1024)?;
    let manifest_bytes = bounded_read(&args.genesis_manifest, 16 * 1024 * 1024)?;
    let manifest: iroha_genesis::RawGenesisTransaction = norito::json::from_slice(&manifest_bytes)?;
    let genesis = iroha_genesis::validate_prepared_genesis_bundle(
        &wire,
        &manifest,
        &args.genesis_public_key,
        genesis_hash,
    )?;
    let mut validators: Vec<_> = genesis
        .validator_pops()
        .iter()
        .map(|(key, pop)| FinalityValidator {
            public_key: key.clone(),
            proof_of_possession: pop.clone(),
        })
        .collect();
    validators.sort_by_key(|validator| {
        validator
            .public_key
            .try_to_bytes()
            .expect("validated key")
            .1
            .to_vec()
    });
    let verifier = SumeragiFinalityVerifier::new(
        genesis.block(),
        &manifest.chain_id().to_string(),
        validators,
    )?;
    let network_id = context.config().network_id;
    ensure!(
        network_id == NetworkId::from_genesis_hash(genesis_hash),
        "client and original genesis network differ"
    );
    let mut builder = context.client_from_config()?.to_builder();
    builder.torii_request_timeout = Duration::from_millis(args.request_timeout_ms);
    let client = builder.build()?;
    let outcome =
        client.poll_sumeragi_genesis_readiness(challenge, &node_id, &verifier, deadline)?;
    write_report(
        context,
        &report(&args, network_id, verifier.instance().0, outcome)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use iroha::crypto::{Algorithm, KeyPair};
    use iroha_torii_shared::bridge_attestation::FinalityAttestationFailureReason as Reason;
    #[derive(clap::Parser)]
    struct Probe {
        #[command(flatten)]
        args: Args,
    }
    fn args() -> Args {
        Args {
            challenge: "47".repeat(32),
            node_public_key: KeyPair::try_from_seed(vec![14; 32], Algorithm::BlsNormal)
                .expect("BLS fixture")
                .public_key()
                .clone(),
            genesis_hash: Hash::new(b"original genesis"),
            signed_genesis: PathBuf::from("genesis.signed.nrt"),
            genesis_manifest: PathBuf::from("genesis.json"),
            genesis_public_key: KeyPair::from_seed(vec![15; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
            request_timeout_ms: 1000,
        }
    }
    #[test]
    fn challenge_rejects_zero_noncanonical_and_truncated_inputs() {
        assert_eq!(parse_challenge(&"47".repeat(32)).unwrap(), [71; 32]);
        for value in [
            "00".repeat(32),
            "AA".repeat(32),
            "4g".repeat(32),
            "47".repeat(31),
            "47".repeat(33),
            format!(" {}", "47".repeat(32)),
        ] {
            assert!(parse_challenge(&value).is_err(), "{value:?}");
        }
    }
    #[test]
    fn reported_genesis_hash_requires_the_complete_certified_result_and_original_time() {
        use iroha_data_model::{
            block::{CommitCertificate, decode_framed_signed_block},
            sumeragi_finality::{
                CertifiedResultError, CertifiedResultScope, CertifiedResultV1,
                SccpFinalityHeaderV1, certified_result::X_LEN,
                test_fixtures::NativeFinalityFixture,
            },
        };
        let fixture = NativeFinalityFixture::new();
        let mut block = decode_framed_signed_block(&fixture.genesis_proof().block_wire).unwrap();
        let original = block.commit_certificate().unwrap().clone();
        let certified =
            CertifiedResultV1::decode(original.result_preimage(), CertifiedResultScope::NonGlobal)
                .unwrap();
        assert_eq!(
            genesis_execution_hash(&block).unwrap(),
            hex::encode(certified.result().unwrap().0)
        );
        for bytes in [
            original.result_preimage()[X_LEN..].to_vec(),
            original.result_preimage()[..original.result_preimage().len() - 1].to_vec(),
        ] {
            block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
                Vec::new(),
                Vec::new(),
                bytes,
                Vec::new(),
            )));
            assert!(genesis_execution_hash(&block).is_err());
        }
        let (header, body) = certified.into_parts();
        let wrong_time = SccpFinalityHeaderV1::inactive(
            body.schedule.current.network_id.as_bytes().to_owned(),
            header.height(),
            header.timestamp_ms() + 1,
        )
        .unwrap();
        let changed =
            CertifiedResultV1::new(wrong_time, body, CertifiedResultScope::NonGlobal).unwrap();
        block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
            Vec::new(),
            Vec::new(),
            changed.preimage().unwrap(),
            Vec::new(),
        )));
        assert!(matches!(
            genesis_execution_hash(&block)
                .unwrap_err()
                .downcast_ref::<CertifiedResultError>(),
            Some(CertifiedResultError::BlockMismatch)
        ));
        block.set_commit_certificate(None);
        assert!(genesis_execution_hash(&block).is_err());
    }
    #[test]
    fn cli_requires_finite_timeout_and_all_independent_anchors() {
        let original = args();
        let argv = vec![
            "probe".to_owned(),
            "--challenge".to_owned(),
            original.challenge.clone(),
            "--node-public-key".to_owned(),
            original.node_public_key.to_string(),
            "--genesis-hash".to_owned(),
            original.genesis_hash.to_string(),
            "--signed-genesis".to_owned(),
            original.signed_genesis.display().to_string(),
            "--genesis-manifest".to_owned(),
            original.genesis_manifest.display().to_string(),
            "--genesis-public-key".to_owned(),
            original.genesis_public_key.to_string(),
            "--request-timeout-ms".to_owned(),
            "1000".to_owned(),
        ];
        let parsed = Probe::try_parse_from(argv.clone()).expect("complete probe");
        assert_eq!(parsed.args.signed_genesis, original.signed_genesis);
        for value in ["0", "60001"] {
            let mut changed = argv.clone();
            *changed.last_mut().unwrap() = value.to_owned();
            assert!(Probe::try_parse_from(changed).is_err());
        }
        for index in [1, 3, 5, 7, 9, 11, 13] {
            let mut changed = argv.clone();
            changed.drain(index..index + 2);
            assert!(Probe::try_parse_from(changed).is_err());
        }
    }
    #[test]
    fn report_never_claims_ready_or_emits_evidence_for_failure() {
        let args = args();
        let network =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(args.genesis_hash));
        for (reason, state) in [
            (Reason::ConsensusUninitialized, "pending"),
            (Reason::GenesisUncommitted, "pending"),
            (Reason::RestartRequired, "restart_required"),
            (Reason::TipChanged, "conflict"),
            (Reason::ConflictingState, "conflict"),
            (Reason::FinalityUnavailable, "unavailable"),
            (Reason::InternalFailure, "unavailable"),
        ] {
            let value = report(
                &args,
                network,
                [7; 32],
                GenesisFinalityReadiness::NotReady(reason),
            )
            .unwrap();
            assert_eq!(value.state, state);
            assert!(value.attestation_norito_base64.is_none());
            assert_eq!(value.challenge, args.challenge);
            assert_eq!(value.network_id, network);
            let output = render_report(&value).unwrap();
            assert!(output.contains("\"attestation_norito_base64\":null"));
            assert!(output.len() < MAX_OUTPUT_BYTES);
        }
    }
    #[test]
    fn renderer_rejects_output_at_its_hard_limit() {
        let args = args();
        let network =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(args.genesis_hash));
        let mut value = report(
            &args,
            network,
            [7; 32],
            GenesisFinalityReadiness::NotReady(Reason::GenesisUncommitted),
        )
        .unwrap();
        value.challenge = "a".repeat(MAX_OUTPUT_BYTES);
        assert!(render_report(&value).is_err());
    }

    #[test]
    fn machine_report_uses_stdout_and_never_the_diagnostic_stream() {
        let args = args();
        let network =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(args.genesis_hash));
        let mut value = report(
            &args,
            network,
            [7; 32],
            GenesisFinalityReadiness::NotReady(Reason::GenesisUncommitted),
        )
        .unwrap();
        let mut context = crate::tests::test_context(CliOutputFormat::Json);
        write_report(&mut context, &value).unwrap();
        assert_eq!(
            context.write,
            format!("{}\n", render_report(&value).unwrap()).as_bytes()
        );
        assert!(context.err_write.is_empty());
        let parsed: norito::json::Value = norito::json::from_slice(&context.write).unwrap();
        assert_eq!(parsed["state"].as_str(), Some("pending"));
        context.write.clear();
        value.challenge = "a".repeat(MAX_OUTPUT_BYTES);
        assert!(write_report(&mut context, &value).is_err());
        assert!(context.write.is_empty());
        assert!(context.err_write.is_empty());
    }
}
