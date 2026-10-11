//! Generates deterministic provider admission fixtures for SoraFS tests.
use ed25519_dalek::{Signer, SigningKey};
use hex::FromHex;
use iroha_crypto::{BlsNormal, KeyGenOption, KeyPair};
use norito::json::{Map, Value, to_string_pretty};
use sorafs_car::set_no_follow_flag;
use sorafs_car::{CarBuildPlan, fetch_plan::try_chunk_fetch_plan_to_json};
use sorafs_chunker::ChunkProfile;
use sorafs_manifest::provider_admission::ProviderAdmissionSerializationContext;
use sorafs_manifest::{
    AdmissionRecord, AdvertEndpoint, AdvertSignature, AvailabilityTier, CapabilityTlv,
    CapabilityType, CouncilSignature, ENDPOINT_ATTESTATION_VERSION_V1, EndpointAdmissionV1,
    EndpointAttestationKind, EndpointAttestationV1, EndpointKind,
    PROVIDER_ADMISSION_RENEWAL_VERSION_V1, PROVIDER_ADMISSION_REVOCATION_VERSION_V1,
    PathDiversityPolicy, ProviderAdmissionCouncilPolicy, ProviderAdmissionEnvelopeError,
    ProviderAdmissionEnvelopeV1, ProviderAdmissionProposalV1, ProviderAdmissionRenewalV1,
    ProviderAdmissionRevocationV1, ProviderAdvertBodyV1, ProviderAdvertV1,
    ProviderCapabilityRangeV1, ProviderVrfPublicKeyV1, QosHints, RendezvousTopic,
    SignatureAlgorithm, StakePointer, StreamBudgetV1, TransportHintV1, TransportProtocol,
    XorQuantity, chunker_registry, compute_advert_body_digest,
    compute_envelope_authorization_digest, compute_envelope_digest, compute_proposal_digest,
    verify_advert_against_record, verify_envelope, verify_revocation_signatures,
};
use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
const DEFAULT_OUTPUT_DIR: &str = "fixtures/sorafs_manifest/provider_admission";
const PROVIDER_ID_HEX: &str = "0a0b0c0d0e0f0011223344556677889900aa0bb0ccddeeff1122334455667788";
const STAKE_POOL_ID_HEX: &str = "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa";
const PROVIDER_ENDPOINT_TORII: &str = "torii:cluster.primary.svc.local";
const PROVIDER_ENDPOINT_QUIC: &str = "quic:cluster.primary.svc.local";
const RENDEZVOUS_TOPIC: &str = "sorafs.sf1.primary";
const RENDEZVOUS_REGION: &str = "global";
const LEAF_CERT: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
const INTERMEDIATE_CERT: &[u8] = &[0x11, 0x22, 0x33, 0x44];
const QUIC_REPORT: &[u8] = &[0x10, 0x20, 0x30];
const COUNCIL_KEY_BYTES: [u8; 32] = [0x45; 32];
const PROVIDER_SIGNING_KEY_BYTES: [u8; 32] = [0x21; 32];
// Synthetic fixture identity only; production tools require the exact genesis hash as input.
const FIXTURE_NETWORK_ID: [u8; 32] = [0xA1; 32];
#[derive(Debug)]
struct Options {
    out_dir: PathBuf,
}
#[derive(Debug, Clone)]
struct FixtureSummary {
    proposal_v1_digest: [u8; 32],
    envelope_v1_digest: [u8; 32],
    renewal_envelope_digest: [u8; 32],
    revocation_digest: [u8; 32],
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_args(env::args().skip(1))?;
    let summary = generate_fixtures(&options.out_dir)?;
    println!(
        "provider admission fixtures refreshed under {} (proposal digest {}, envelope digest {}, \
         renewal envelope digest {}, revocation digest {})",
        options.out_dir.display(),
        hex_lower(summary.proposal_v1_digest),
        hex_lower(summary.envelope_v1_digest),
        hex_lower(summary.renewal_envelope_digest),
        hex_lower(summary.revocation_digest)
    );
    Ok(())
}
fn parse_args<I>(args: I) -> Result<Options, Box<dyn std::error::Error>>
where
    I: Iterator<Item = String>,
{
    let mut out_dir = PathBuf::from(DEFAULT_OUTPUT_DIR);
    for arg in args {
        if arg == "-h" || arg == "--help" {
            println!("usage: provider_admission_fixtures [--out-dir=<path>]");
            println!("       Regenerates deterministic SoraFS provider admission fixtures.");
            std::process::exit(0);
        } else if let Some(value) = arg.strip_prefix("--out-dir=") {
            out_dir = PathBuf::from(value);
        } else {
            return Err(format!("unknown argument: {arg}").into());
        }
    }
    Ok(Options { out_dir })
}
fn generate_fixtures(out_dir: &Path) -> Result<FixtureSummary, Box<dyn std::error::Error>> {
    let descriptor = chunker_registry::lookup_by_handle("sorafs.sf1@1.0.0").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "required chunker registry handle sorafs.sf1@1.0.0 is unavailable",
        )
    })?;
    let provider_id = decode_hex_array(PROVIDER_ID_HEX)?;
    let stake_pool_id = decode_hex_array(STAKE_POOL_ID_HEX)?;
    let provider_signing_key = SigningKey::from_bytes(&PROVIDER_SIGNING_KEY_BYTES);
    let council_key = SigningKey::from_bytes(&COUNCIL_KEY_BYTES);
    let advert_key = *provider_signing_key.verifying_key().as_bytes();
    let council_policy =
        ProviderAdmissionCouncilPolicy::new([*council_key.verifying_key().as_bytes()], 1)?;
    let proposal_v1 = build_proposal(ProposalParams {
        namespace: descriptor.namespace,
        name: descriptor.name,
        semver: descriptor.semver,
        aliases: descriptor.aliases,
        provider_id,
        stake_pool_id,
        advert_key,
        stake_amount: XorQuantity::try_from_micro(5_000).expect("fixture stake is representable"),
        attested_at: 1_700_000_000,
        expires_at: 1_700_003_600,
    })?;
    let advert_v1 = build_advert(&proposal_v1, &provider_signing_key, 120, 600, 1_500, 32)?;
    let envelope_v1 = build_envelope(
        proposal_v1.clone(),
        advert_v1.body.clone(),
        120,
        600,
        &council_key,
        None,
    )?;
    let record_v1 = AdmissionRecord::new(envelope_v1.clone(), &council_policy)?;
    verify_advert_against_record(&advert_v1, &record_v1)?;
    write_binary(out_dir, "proposal_v1.to", &norito::to_bytes(&proposal_v1)?)?;
    write_json(
        out_dir,
        "proposal_v1.json",
        Value::Object(build_proposal_summary(&proposal_v1)),
    )?;
    write_binary(out_dir, "advert_v1.to", &norito::to_bytes(&advert_v1)?)?;
    write_json(
        out_dir,
        "advert_v1.json",
        Value::Object(build_advert_summary(&advert_v1)),
    )?;
    write_binary(out_dir, "envelope_v1.to", &norito::to_bytes(&envelope_v1)?)?;
    write_json(
        out_dir,
        "envelope_v1.json",
        Value::Object(build_envelope_summary(&envelope_v1, &record_v1)?),
    )?;
    let renewed_proposal_v1 = build_proposal(ProposalParams {
        namespace: descriptor.namespace,
        name: descriptor.name,
        semver: descriptor.semver,
        aliases: descriptor.aliases,
        provider_id,
        stake_pool_id,
        advert_key,
        stake_amount: XorQuantity::try_from_micro(7_000).expect("fixture stake is representable"),
        attested_at: 1_700_000_000,
        expires_at: 1_700_007_200,
    })?;
    let renewed_advert_v1 = build_advert(
        &renewed_proposal_v1,
        &provider_signing_key,
        220,
        900,
        1_400,
        32,
    )?;
    let renewed_envelope_v1 = build_envelope(
        renewed_proposal_v1.clone(),
        renewed_advert_v1.body.clone(),
        220,
        900,
        &council_key,
        Some(&record_v1),
    )?;
    let renewed_envelope_v1_digest = compute_envelope_digest(&renewed_envelope_v1)?;
    let renewal = ProviderAdmissionRenewalV1 {
        version: PROVIDER_ADMISSION_RENEWAL_VERSION_V1,
        provider_id,
        previous_envelope_digest: *record_v1.envelope_digest(),
        envelope_digest: renewed_envelope_v1_digest,
        envelope: renewed_envelope_v1.clone(),
        notes: Some("stake top-up 2025-03".into()),
    };
    // Ensure renewal respects invariants.
    let renewed_record = record_v1.apply_renewal(&renewal, &council_policy)?;
    verify_advert_against_record(&renewed_advert_v1, &renewed_record)?;
    write_binary(
        out_dir,
        "proposal_renewed_v1.to",
        &norito::to_bytes(&renewed_proposal_v1)?,
    )?;
    write_json(
        out_dir,
        "proposal_renewed_v1.json",
        Value::Object(build_proposal_summary(&renewed_proposal_v1)),
    )?;
    write_binary(
        out_dir,
        "advert_renewed_v1.to",
        &norito::to_bytes(&renewed_advert_v1)?,
    )?;
    write_json(
        out_dir,
        "advert_renewed_v1.json",
        Value::Object(build_advert_summary(&renewed_advert_v1)),
    )?;
    write_binary(
        out_dir,
        "envelope_renewed_v1.to",
        &norito::to_bytes(&renewed_envelope_v1)?,
    )?;
    write_json(
        out_dir,
        "envelope_renewed_v1.json",
        Value::Object(build_envelope_summary(
            &renewed_envelope_v1,
            &renewed_record,
        )?),
    )?;
    write_binary(out_dir, "renewal_v1.to", &norito::to_bytes(&renewal)?)?;
    write_json(
        out_dir,
        "renewal_v1.json",
        Value::Object(build_renewal_summary(&renewal)),
    )?;
    let mut revocation = ProviderAdmissionRevocationV1 {
        version: PROVIDER_ADMISSION_REVOCATION_VERSION_V1,
        network_id: FIXTURE_NETWORK_ID,
        policy_id: record_v1.envelope().policy_id,
        policy_revision: record_v1.envelope().policy_revision,
        policy_digest: record_v1.envelope().policy_digest,
        transition_revision: record_v1.envelope().admission_revision + 1,
        expected_current_event_digest: *record_v1.envelope_digest(),
        provider_id,
        envelope_digest: *record_v1.envelope_digest(),
        revoked_at: 970,
        reason: "endpoint compromise".into(),
        council_signatures: Vec::new(),
        notes: Some("incident-456".into()),
    };
    let revocation_digest = revocation.digest()?;
    let revocation_signature = council_key.sign(&revocation_digest);
    revocation.council_signatures.push(CouncilSignature {
        signer: *council_key.verifying_key().as_bytes(),
        signature: revocation_signature.to_bytes().to_vec(),
    });
    verify_revocation_signatures(&revocation, &council_policy)?;
    record_v1.verify_revocation(&revocation, &council_policy)?;
    write_binary(out_dir, "revocation_v1.to", &norito::to_bytes(&revocation)?)?;
    write_json(
        out_dir,
        "revocation_v1.json",
        Value::Object(build_revocation_summary(&revocation, &revocation_digest)),
    )?;
    write_json(
        out_dir,
        "metadata.json",
        Value::Object(build_metadata_summary(
            &proposal_v1,
            &renewal,
            &revocation_digest,
            &record_v1,
        )?),
    )?;
    let plan_payload: Vec<u8> = (0..(64 * 1024)).map(|idx| (idx % 251) as u8).collect();
    let plan = CarBuildPlan::single_file_with_profile(&plan_payload, ChunkProfile::DEFAULT)?;
    write_json(
        out_dir,
        "multi_fetch_plan.json",
        try_chunk_fetch_plan_to_json(&plan)?,
    )?;
    write_readme(out_dir)?;
    Ok(FixtureSummary {
        proposal_v1_digest: compute_proposal_digest(&proposal_v1)?,
        envelope_v1_digest: *record_v1.envelope_digest(),
        renewal_envelope_digest: renewed_envelope_v1_digest,
        revocation_digest,
    })
}
struct ProposalParams<'a> {
    namespace: &'a str,
    name: &'a str,
    semver: &'a str,
    aliases: &'a [&'a str],
    provider_id: [u8; 32],
    stake_pool_id: [u8; 32],
    advert_key: [u8; 32],
    stake_amount: XorQuantity,
    attested_at: u64,
    expires_at: u64,
}
fn build_proposal(
    params: ProposalParams<'_>,
) -> Result<ProviderAdmissionProposalV1, Box<dyn std::error::Error>> {
    let canonical_handle = format!("{}.{}@{}", params.namespace, params.name, params.semver);
    let mut alias_list: Vec<String> = params
        .aliases
        .iter()
        .map(|alias| alias.to_string())
        .collect();
    alias_list.retain(|alias| alias != &canonical_handle);
    alias_list.insert(0, canonical_handle.clone());
    let range_payload = ProviderCapabilityRangeV1 {
        max_chunk_span: 32,
        min_granularity: 8,
        supports_sparse_offsets: true,
        requires_alignment: false,
        supports_merkle_proof: true,
    }
    .to_bytes()?;
    let (vrf_public, vrf_private) =
        BlsNormal::try_keypair(KeyGenOption::UseSeed(params.provider_id.to_vec()))?;
    let vrf_pair: KeyPair = (vrf_public, vrf_private).into();
    Ok(ProviderAdmissionProposalV1 {
        version: 1,
        provider_id: params.provider_id,
        profile_id: canonical_handle,
        profile_aliases: Some(alias_list),
        stake: StakePointer {
            pool_id: params.stake_pool_id,
            stake_amount: params.stake_amount,
        },
        capabilities: vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            CapabilityTlv {
                cap_type: CapabilityType::ChunkRangeFetch,
                payload: range_payload,
            },
        ],
        endpoints: vec![
            EndpointAdmissionV1 {
                endpoint: AdvertEndpoint {
                    kind: EndpointKind::Torii,
                    host_pattern: PROVIDER_ENDPOINT_TORII.into(),
                    metadata: Vec::new(),
                },
                attestation: EndpointAttestationV1 {
                    version: ENDPOINT_ATTESTATION_VERSION_V1,
                    kind: EndpointAttestationKind::Tls,
                    attested_at: params.attested_at,
                    expires_at: params.expires_at,
                    leaf_certificate: LEAF_CERT.to_vec(),
                    intermediate_certificates: vec![INTERMEDIATE_CERT.to_vec()],
                    alpn_ids: vec!["h2".into()],
                    report: QUIC_REPORT.to_vec(),
                },
            },
            EndpointAdmissionV1 {
                endpoint: AdvertEndpoint {
                    kind: EndpointKind::Quic,
                    host_pattern: PROVIDER_ENDPOINT_QUIC.into(),
                    metadata: Vec::new(),
                },
                attestation: EndpointAttestationV1 {
                    version: ENDPOINT_ATTESTATION_VERSION_V1,
                    kind: EndpointAttestationKind::Quic,
                    attested_at: params.attested_at,
                    expires_at: params.expires_at,
                    leaf_certificate: LEAF_CERT.to_vec(),
                    intermediate_certificates: Vec::new(),
                    alpn_ids: vec!["h3".into()],
                    report: QUIC_REPORT.to_vec(),
                },
            },
        ],
        advert_key: params.advert_key,
        por_vrf_key: ProviderVrfPublicKeyV1::BlsNormal(
            vrf_pair.public_key().to_bytes().1.try_into()?,
        ),
        jurisdiction_code: "US".into(),
        contact_uri: Some("mailto:ops@example.com".into()),
        stream_budget: Some(StreamBudgetV1 {
            max_in_flight: 8,
            max_bytes_per_sec: 9_000_000,
            burst_bytes: Some(4_500_000),
        }),
        transport_hints: Some(vec![
            TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 0,
            },
            TransportHintV1 {
                protocol: TransportProtocol::QuicStream,
                priority: 1,
            },
        ]),
    })
}
fn build_advert(
    proposal: &ProviderAdmissionProposalV1,
    provider_key: &SigningKey,
    issued_at: u64,
    retention_epoch: u64,
    max_latency_ms: u32,
    max_streams: u16,
) -> Result<ProviderAdvertV1, Box<dyn std::error::Error>> {
    let body = ProviderAdvertBodyV1 {
        provider_id: proposal.provider_id,
        profile_id: proposal.profile_id.clone(),
        profile_aliases: proposal.profile_aliases.clone(),
        stake: proposal.stake.clone(),
        qos: QosHints {
            availability: AvailabilityTier::Hot,
            max_retrieval_latency_ms: max_latency_ms,
            max_concurrent_streams: max_streams,
        },
        capabilities: proposal.capabilities.clone(),
        endpoints: proposal
            .endpoints
            .iter()
            .map(|entry| entry.endpoint.clone())
            .collect(),
        rendezvous_topics: vec![RendezvousTopic {
            topic: RENDEZVOUS_TOPIC.into(),
            region: RENDEZVOUS_REGION.into(),
        }],
        path_policy: PathDiversityPolicy {
            min_guard_weight: 10,
            max_same_asn_per_path: 1,
            max_same_pool_per_path: 1,
        },
        notes: None,
        stream_budget: proposal.stream_budget,
        transport_hints: proposal.transport_hints.clone(),
    };
    let mut advert = ProviderAdvertV1 {
        version: 1,
        network_id: FIXTURE_NETWORK_ID,
        issued_at,
        expires_at: retention_epoch,
        body,
        signature: AdvertSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: provider_key.verifying_key().as_bytes().to_vec(),
            signature: vec![0; 64],
        },
        signature_strict: true,
        allow_unknown_capabilities: false,
    };
    let payload = advert.signature_payload_bytes()?;
    advert.signature.signature = provider_key.sign(&payload).to_bytes().to_vec();
    advert.verify_signature()?;
    Ok(advert)
}
fn build_envelope(
    proposal: ProviderAdmissionProposalV1,
    advert_body: ProviderAdvertBodyV1,
    issued_at: u64,
    retention_epoch: u64,
    council_key: &SigningKey,
    predecessor: Option<&AdmissionRecord>,
) -> Result<ProviderAdmissionEnvelopeV1, Box<dyn std::error::Error>> {
    let admission_revision = match predecessor {
        Some(record) => record
            .envelope()
            .admission_revision
            .checked_add(1)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "admission revision overflow")
            })?,
        None => 1,
    };
    let proposal_digest = compute_proposal_digest(&proposal).map_err(|source| {
        ProviderAdmissionEnvelopeError::Serialization {
            context: ProviderAdmissionSerializationContext::Proposal,
            source,
        }
    })?;
    let advert_digest = compute_advert_body_digest(&advert_body).map_err(|source| {
        ProviderAdmissionEnvelopeError::Serialization {
            context: ProviderAdmissionSerializationContext::AdvertBody,
            source,
        }
    })?;
    let mut envelope = ProviderAdmissionEnvelopeV1 {
        version: 1,
        network_id: FIXTURE_NETWORK_ID,
        policy_id: [0xC1; 32],
        policy_revision: 1,
        policy_digest: [0xD1; 32],
        admission_revision,
        expected_current_event_digest: predecessor.map(|record| *record.envelope_digest()),
        proposal,
        proposal_digest,
        advert_body,
        advert_body_digest: advert_digest,
        issued_at,
        retention_epoch,
        council_signatures: Vec::new(),
        notes: None,
    };
    let authorization_digest =
        compute_envelope_authorization_digest(&envelope).map_err(|source| {
            ProviderAdmissionEnvelopeError::Serialization {
                context: ProviderAdmissionSerializationContext::EnvelopeAuthorization,
                source,
            }
        })?;
    let signature = council_key.sign(&authorization_digest);
    envelope.council_signatures.push(CouncilSignature {
        signer: *council_key.verifying_key().as_bytes(),
        signature: signature.to_bytes().to_vec(),
    });
    let policy = ProviderAdmissionCouncilPolicy::new([*council_key.verifying_key().as_bytes()], 1)?;
    verify_envelope(&envelope, &policy)?;
    Ok(envelope)
}
fn build_proposal_summary(proposal: &ProviderAdmissionProposalV1) -> Map {
    let mut map = Map::new();
    map.insert(
        "provider_id_hex".into(),
        Value::from(hex_lower(proposal.provider_id)),
    );
    map.insert(
        "profile_id".into(),
        Value::from(proposal.profile_id.clone()),
    );
    map.insert(
        "profile_aliases".into(),
        Value::Array(
            proposal
                .profile_aliases
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(Value::from)
                .collect(),
        ),
    );
    map.insert(
        "stake_amount".into(),
        Value::from(proposal.stake.stake_amount.to_string()),
    );
    map.insert(
        "capabilities".into(),
        Value::from(proposal.capabilities.len() as u64),
    );
    map.insert(
        "endpoints".into(),
        Value::from(proposal.endpoints.len() as u64),
    );
    map.insert(
        "stream_budget".into(),
        match proposal.stream_budget.as_ref() {
            Some(budget) => stream_budget_summary(budget),
            None => Value::Null,
        },
    );
    map.insert(
        "transport_hints".into(),
        match proposal.transport_hints.as_ref() {
            Some(hints) => transport_hints_summary(hints),
            None => Value::Null,
        },
    );
    map
}
fn build_advert_summary(advert: &ProviderAdvertV1) -> Map {
    let mut map = Map::new();
    map.insert(
        "network_id_hex".into(),
        Value::from(hex_lower(advert.network_id)),
    );
    map.insert("issued_at".into(), Value::from(advert.issued_at));
    map.insert("expires_at".into(), Value::from(advert.expires_at));
    map.insert(
        "signature_hex".into(),
        Value::from(hex_lower(&advert.signature.signature)),
    );
    map.insert(
        "public_key_hex".into(),
        Value::from(hex_lower(&advert.signature.public_key)),
    );
    map.insert(
        "capabilities".into(),
        Value::from(advert.body.capabilities.len() as u64),
    );
    map.insert(
        "endpoint_count".into(),
        Value::from(advert.body.endpoints.len() as u64),
    );
    map.insert(
        "stream_budget".into(),
        match advert.body.stream_budget.as_ref() {
            Some(budget) => stream_budget_summary(budget),
            None => Value::Null,
        },
    );
    map.insert(
        "transport_hints".into(),
        match advert.body.transport_hints.as_ref() {
            Some(hints) => transport_hints_summary(hints),
            None => Value::Null,
        },
    );
    map
}
fn build_envelope_summary(
    envelope: &ProviderAdmissionEnvelopeV1,
    record: &AdmissionRecord,
) -> Result<Map, Box<dyn std::error::Error>> {
    let mut map = Map::new();
    map.insert(
        "network_id_hex".into(),
        Value::from(hex_lower(envelope.network_id)),
    );
    map.insert(
        "policy_id_hex".into(),
        Value::from(hex_lower(envelope.policy_id)),
    );
    map.insert(
        "policy_revision".into(),
        Value::from(envelope.policy_revision),
    );
    map.insert(
        "policy_digest_hex".into(),
        Value::from(hex_lower(envelope.policy_digest)),
    );
    map.insert(
        "admission_revision".into(),
        Value::from(envelope.admission_revision),
    );
    if let Some(predecessor) = envelope.expected_current_event_digest {
        map.insert(
            "expected_current_event_digest_hex".into(),
            Value::from(hex_lower(predecessor)),
        );
    }
    let authorization_digest = compute_envelope_authorization_digest(envelope)?;
    map.insert(
        "proposal_digest_hex".into(),
        Value::from(hex_lower(envelope.proposal_digest)),
    );
    map.insert(
        "advert_body_digest_hex".into(),
        Value::from(hex_lower(envelope.advert_body_digest)),
    );
    map.insert(
        "envelope_digest_hex".into(),
        Value::from(hex_lower(record.envelope_digest())),
    );
    map.insert(
        "authorization_digest_hex".into(),
        Value::from(hex_lower(authorization_digest)),
    );
    map.insert(
        "trusted_council_keys_hex".into(),
        Value::Array(
            envelope
                .council_signatures
                .iter()
                .map(|signature| Value::from(hex_lower(signature.signer)))
                .collect(),
        ),
    );
    map.insert("signature_threshold".into(), Value::from(1_u64));
    map.insert(
        "council_signature_count".into(),
        Value::from(envelope.council_signatures.len() as u64),
    );
    Ok(map)
}
fn build_renewal_summary(renewal: &ProviderAdmissionRenewalV1) -> Map {
    let mut map = Map::new();
    map.insert(
        "previous_envelope_digest_hex".into(),
        Value::from(hex_lower(renewal.previous_envelope_digest)),
    );
    map.insert(
        "admission_revision".into(),
        Value::from(renewal.envelope.admission_revision),
    );
    map.insert(
        "expected_current_event_digest_hex".into(),
        Value::from(hex_lower(
            renewal
                .envelope
                .expected_current_event_digest
                .expect("validated renewal has signed predecessor"),
        )),
    );
    map.insert(
        "envelope_digest_hex".into(),
        Value::from(hex_lower(renewal.envelope_digest)),
    );
    map.insert(
        "retention_epoch".into(),
        Value::from(renewal.envelope.retention_epoch),
    );
    map
}
fn build_revocation_summary(
    revocation: &ProviderAdmissionRevocationV1,
    revocation_digest: &[u8; 32],
) -> Map {
    let mut map = Map::new();
    map.insert(
        "network_id_hex".into(),
        Value::from(hex_lower(revocation.network_id)),
    );
    map.insert(
        "policy_id_hex".into(),
        Value::from(hex_lower(revocation.policy_id)),
    );
    map.insert(
        "policy_revision".into(),
        Value::from(revocation.policy_revision),
    );
    map.insert(
        "policy_digest_hex".into(),
        Value::from(hex_lower(revocation.policy_digest)),
    );
    map.insert(
        "transition_revision".into(),
        Value::from(revocation.transition_revision),
    );
    map.insert(
        "expected_current_event_digest_hex".into(),
        Value::from(hex_lower(revocation.expected_current_event_digest)),
    );
    map.insert(
        "envelope_digest_hex".into(),
        Value::from(hex_lower(revocation.envelope_digest)),
    );
    map.insert(
        "revocation_digest_hex".into(),
        Value::from(hex_lower(revocation_digest)),
    );
    map.insert("revoked_at".into(), Value::from(revocation.revoked_at));
    map.insert("reason".into(), Value::from(revocation.reason.clone()));
    map.insert(
        "council_signature_count".into(),
        Value::from(revocation.council_signatures.len() as u64),
    );
    map
}
fn build_metadata_summary(
    proposal: &ProviderAdmissionProposalV1,
    renewal: &ProviderAdmissionRenewalV1,
    revocation_digest: &[u8; 32],
    record: &AdmissionRecord,
) -> Result<Map, Box<dyn std::error::Error>> {
    let mut map = Map::new();
    map.insert(
        "network_id_hex".into(),
        Value::from(hex_lower(record.envelope().network_id)),
    );
    let proposal_digest = compute_proposal_digest(proposal)?;
    map.insert(
        "proposal_digest_hex".into(),
        Value::from(hex_lower(proposal_digest)),
    );
    map.insert(
        "envelope_digest_hex".into(),
        Value::from(hex_lower(record.envelope_digest())),
    );
    map.insert(
        "renewal_envelope_digest_hex".into(),
        Value::from(hex_lower(renewal.envelope_digest)),
    );
    map.insert(
        "revocation_digest_hex".into(),
        Value::from(hex_lower(revocation_digest)),
    );
    map.insert(
        "notes".into(),
        Value::from("Deterministic fixtures for tests"),
    );
    Ok(map)
}
fn write_binary(
    out_dir: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let path = out_dir.join(name);
    let mut file = open_output_file(&path, "binary fixture")?;
    file.write_all(bytes)?;
    Ok(())
}
fn write_json(out_dir: &Path, name: &str, value: Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut json_string = to_string_pretty(&value)?;
    json_string.push('\n');
    let path = out_dir.join(name);
    let mut file = open_output_file(&path, "JSON fixture")?;
    file.write_all(json_string.as_bytes())?;
    Ok(())
}
fn write_readme(out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = out_dir.join("README.md");
    let content = String::from(
        "# Provider Admission Fixtures\n\n\
These files are generated via `cargo run -p sorafs_car --features manifest,dev-tools --bin provider_admission_fixtures`.\n\
They provide deterministic governance proposals, adverts, envelopes, renewals, and revocations for\n\
integration tests across Rust, Torii, and CLI tooling. Every admission object uses the first-release\n\
V1 schema. Files named `*_renewed_v1` contain the V1 proposal, advert, and envelope carried by\n\
`renewal_v1`; `renewed` describes lifecycle state, not a new schema version.\n\n\
The generator uses test-only Ed25519 seeds `[0x21; 32]` for the provider and `[0x45; 32]` for\n\
the one-member council. These keys are public fixture material and must never be used by a live\n\
provider or governance council. Binary `.to` files are canonical Norito; matching `.json` files\n\
are human-readable summaries, not alternative wire payloads.\n\n\
Additional artifacts include a payload-bound `sorafs.chunk_fetch_plan.v1` multi-source plan for\n\
isolated SDK scheduling tests. Standalone plans are strict V1 envelopes; the retired bare-array\n\
representation is not an accepted interchange format. These fixtures do not provide or qualify\n\
authenticated multi-provider transport, a governance-aware external software completion signer,\n\
a sealed-CAS retention backend, or four-validator deployment evidence.\n\n\
Do not edit manually; rerun the generator if data changes.\n",
    );
    let mut file = open_output_file(&path, "README fixture")?;
    file.write_all(content.as_bytes())?;
    Ok(())
}
fn open_output_file(path: &Path, label: &str) -> Result<fs::File, Box<dyn std::error::Error>> {
    validate_output_path(path)?;
    ensure_parent_dir(path)?;
    validate_output_path(path)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    set_no_follow_flag(&mut options);
    let file = options
        .open(path)
        .map_err(|err| format!("failed to open {label} `{}`: {err}", path.display()))?;
    let metadata = file.metadata().map_err(|err| {
        format!(
            "failed to inspect {label} `{}` after open: {err}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "failed to write {label} `{}`: output must be a regular file",
            path.display()
        )
        .into());
    }
    Ok(file)
}
fn ensure_parent_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create output parent `{}`: {err}",
                parent.display()
            )
        })?;
    }
    Ok(())
}
fn validate_output_path(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!("output `{}` must not be a symlink", path.display()).into());
            }
            if metadata.is_dir() {
                return Err(format!("output `{}` must not be a directory", path.display()).into());
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!("failed to inspect output `{}`: {err}", path.display()).into());
        }
    }
    if let Some(parent) = path.parent() {
        for ancestor in std::iter::once(parent).chain(parent.ancestors().skip(1)) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            match fs::symlink_metadata(ancestor) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(format!(
                            "output parent `{}` must not be a symlink",
                            ancestor.display()
                        )
                        .into());
                    }
                    if !metadata.is_dir() {
                        return Err(format!(
                            "output parent `{}` must be a directory",
                            ancestor.display()
                        )
                        .into());
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(format!(
                        "failed to inspect output parent `{}`: {err}",
                        ancestor.display()
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}
fn decode_hex_array(input: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut out = [0u8; 32];
    let bytes = Vec::from_hex(input)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte hex string, got {}", bytes.len()).into());
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}
fn hex_lower<T: AsRef<[u8]>>(bytes: T) -> String {
    hex::encode(bytes)
}
fn stream_budget_summary(budget: &StreamBudgetV1) -> Value {
    let mut map = Map::new();
    map.insert(
        "max_in_flight".into(),
        Value::from(budget.max_in_flight as u64),
    );
    map.insert(
        "max_bytes_per_sec".into(),
        Value::from(budget.max_bytes_per_sec),
    );
    map.insert(
        "burst_bytes".into(),
        match budget.burst_bytes {
            Some(burst) => Value::from(burst),
            None => Value::Null,
        },
    );
    Value::Object(map)
}
fn transport_hints_summary(hints: &[TransportHintV1]) -> Value {
    Value::Array(
        hints
            .iter()
            .map(|hint| {
                let mut map = Map::new();
                map.insert(
                    "protocol".into(),
                    Value::from(transport_protocol_label(hint.protocol)),
                );
                map.insert("priority".into(), Value::from(hint.priority as u64));
                Value::Object(map)
            })
            .collect(),
    )
}
fn transport_protocol_label(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::ToriiHttpRange => "torii_http_range",
        TransportProtocol::QuicStream => "quic_stream",
        TransportProtocol::SoraNetRelay => "soranet_relay",
        TransportProtocol::VendorReserved => "vendor_reserved",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tempfile::{TempDir, tempdir};
    const EXPECTED_FIXTURE_NAMES: &[&str] = &[
        "README.md",
        "advert_renewed_v1.json",
        "advert_renewed_v1.to",
        "advert_v1.json",
        "advert_v1.to",
        "envelope_renewed_v1.json",
        "envelope_renewed_v1.to",
        "envelope_v1.json",
        "envelope_v1.to",
        "metadata.json",
        "multi_fetch_plan.json",
        "proposal_renewed_v1.json",
        "proposal_renewed_v1.to",
        "proposal_v1.json",
        "proposal_v1.to",
        "renewal_v1.json",
        "renewal_v1.to",
        "revocation_v1.json",
        "revocation_v1.to",
    ];
    fn canonical_tempdir() -> (TempDir, PathBuf) {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().canonicalize().expect("canonical tempdir");
        (temp, path)
    }
    #[test]
    fn generate_fixtures_produces_expected_artifacts() {
        let (_dir, dir_path) = canonical_tempdir();
        let summary = generate_fixtures(&dir_path).expect("fixtures");
        assert_eq!(
            hex_lower(summary.proposal_v1_digest),
            "8ebd7463b2c6c72bdf50eea5536420ada3540a056956dec00b0a0ca36a7952df"
        );
        assert_eq!(
            hex_lower(summary.envelope_v1_digest),
            "6583a44c4ca5fec411ea83207f8bec48b97de9d835a595d98f655e823b9e54a2"
        );
        assert_eq!(
            hex_lower(summary.renewal_envelope_digest),
            "beef94ab215a87cafe92743cd7b8a37afbe24fcfcd50476a93cc64ac77b080a6"
        );
        assert_eq!(
            hex_lower(summary.revocation_digest),
            "0c286de308fee9a436442ab1382c3e1fcda28da5033da1e0d663e640b9f5651d"
        );
        let generated_names: BTreeSet<String> = fs::read_dir(&dir_path)
            .expect("read generated fixture directory")
            .map(|entry| {
                entry
                    .expect("read generated fixture entry")
                    .file_name()
                    .into_string()
                    .expect("fixture name is UTF-8")
            })
            .collect();
        let expected_names: BTreeSet<String> = EXPECTED_FIXTURE_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        assert_eq!(
            generated_names, expected_names,
            "generator artifact set drifted"
        );
        let committed_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/sorafs_manifest/provider_admission");
        for name in EXPECTED_FIXTURE_NAMES {
            let generated = fs::read(dir_path.join(name))
                .unwrap_or_else(|error| panic!("read generated fixture {name}: {error}"));
            let committed = fs::read(committed_dir.join(name))
                .unwrap_or_else(|error| panic!("read committed fixture {name}: {error}"));
            assert_eq!(
                generated, committed,
                "committed fixture {name} is stale; rerun provider_admission_fixtures"
            );
        }
    }
    #[test]
    fn write_binary_creates_parent_and_writes_all_bytes() {
        let (_temp, temp_path) = canonical_tempdir();
        let out_dir = temp_path.join("nested");
        write_binary(&out_dir, "payload.to", b"provider-admission").expect("write binary fixture");
        assert_eq!(
            fs::read(out_dir.join("payload.to")).expect("read output"),
            b"provider-admission"
        );
    }
    #[cfg(unix)]
    #[test]
    fn write_json_rejects_symlink_output() {
        let (_temp, temp_path) = canonical_tempdir();
        let target_path = temp_path.join("target.json");
        fs::write(&target_path, b"unchanged\n").expect("write target");
        let output_path = temp_path.join("metadata.json");
        std::os::unix::fs::symlink(&target_path, &output_path).expect("create symlink");
        let err = write_json(&temp_path, "metadata.json", Value::Object(Map::new()))
            .expect_err("reject symlink output");
        let message = err.to_string();
        assert!(
            message.contains("must not be a symlink"),
            "unexpected error: {message}"
        );
        assert_eq!(fs::read(&target_path).expect("read target"), b"unchanged\n");
    }
    #[cfg(unix)]
    #[test]
    fn write_readme_rejects_symlink_parent() {
        let (_temp, temp_path) = canonical_tempdir();
        let real_dir = temp_path.join("real");
        fs::create_dir(&real_dir).expect("create real dir");
        let linked_dir = temp_path.join("linked");
        std::os::unix::fs::symlink(&real_dir, &linked_dir).expect("create symlink");
        let err = write_readme(&linked_dir).expect_err("reject symlink parent");
        let message = err.to_string();
        assert!(
            message.contains("parent") && message.contains("must not be a symlink"),
            "unexpected error: {message}"
        );
        assert!(
            !real_dir.join("README.md").exists(),
            "symlink parent should not receive output"
        );
    }
    #[cfg(unix)]
    #[test]
    fn generate_fixtures_rejects_output_symlink_without_touching_target() {
        let (_temp, temp_path) = canonical_tempdir();
        let target_path = temp_path.join("outside.to");
        fs::write(&target_path, b"unchanged").expect("write target");
        std::os::unix::fs::symlink(&target_path, temp_path.join("proposal_v1.to"))
            .expect("create fixture output symlink");
        let err = generate_fixtures(&temp_path).expect_err("reject fixture output symlink");
        assert!(
            err.to_string().contains("must not be a symlink"),
            "unexpected error: {err}"
        );
        assert_eq!(fs::read(&target_path).expect("read target"), b"unchanged");
        assert!(
            temp_path.join("proposal_v1.to").is_symlink(),
            "rejected symlink must not be removed"
        );
    }
}
