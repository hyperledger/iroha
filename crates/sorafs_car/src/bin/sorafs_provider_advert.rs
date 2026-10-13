//! Production CLI for constructing and verifying SoraFS provider advertisements.
use ed25519_dalek::VerifyingKey;
use iroha_crypto::sha256;
use norito::json::{Map, Value, to_string_pretty};
use sorafs_car::chunker_registry;
use sorafs_car::set_no_follow_flag;
use sorafs_manifest::{
    AdvertEndpoint, AvailabilityTier, CapabilityTlv, CapabilityType, EndpointKind,
    EndpointMetadata, EndpointMetadataKey, MAX_ADVERT_TTL_SECS, ProviderAdvertBuildError,
    ProviderAdvertV1, ProviderCapabilityRangeV1, REFRESH_RECOMMENDATION_SECS, RendezvousTopic,
    SignatureAlgorithm, StreamBudgetV1, TransportHintV1, TransportProtocol, deal::XorQuantity,
    decode_provider_advert_v1, provider_advert::ProviderCapabilitySoranetPqV1,
};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process,
};
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const PREPARE_SIGNATURE_PLACEHOLDER: [u8; ED25519_SIGNATURE_BYTES] =
    [0xA6; ED25519_SIGNATURE_BYTES];
const PROVIDER_ADVERT_MAX_BYTES: u64 = 1024 * 1024;
const SIGNING_PAYLOAD_MAX_BYTES: u64 = 1024 * 1024;
fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = match args.next() {
        Some(flag) if flag == "--prepare" || flag == "--emit" => {
            let prepare = flag == "--prepare";
            let mut opts = EmitOptions::default();
            for arg in args {
                let (key, value) = arg
                    .split_once('=')
                    .ok_or_else(|| format!("expected key=value option, got: {arg}"))?;
                match key {
                    "--network-id" => opts.network_id = Some(parse_hex_fixed::<32>(value)?),
                    "--chunker-profile" => {
                        if opts.profile_handle.is_some() {
                            return Err("--chunker-profile may only be specified once".into());
                        }
                        opts.profile_handle = Some(value.to_string());
                    }
                    "--provider-id" => opts.provider_id = Some(parse_hex_fixed::<32>(value)?),
                    "--stake-pool-id" => opts.stake_pool_id = Some(parse_hex_fixed::<32>(value)?),
                    "--stake-amount" => opts.stake_amount = Some(parse_xor_quantity(value)?),
                    "--availability" => opts.availability = Some(parse_availability(value)?),
                    "--max-latency-ms" => opts.max_latency_ms = Some(parse_u32(value)?),
                    "--max-streams" => opts.max_streams = Some(parse_u16(value)?),
                    "--range-capability" => {
                        if opts.range_capability.is_some() {
                            return Err("only one --range-capability entry may be specified".into());
                        }
                        opts.range_capability = Some(parse_range_capability(value)?);
                    }
                    "--soranet-pq" => {
                        if opts.soranet_pq.is_some() {
                            return Err("only one --soranet-pq entry may be specified".into());
                        }
                        opts.soranet_pq = Some(parse_soranet_pq(value)?);
                    }
                    "--stream-budget" => {
                        if opts.stream_budget.is_some() {
                            return Err("only one --stream-budget entry may be specified".into());
                        }
                        opts.stream_budget = Some(parse_stream_budget(value)?);
                    }
                    "--transport-hint" => {
                        let hint = parse_transport_hint(value)?;
                        opts.transport_hints.push(hint);
                    }
                    "--capability" => opts.capabilities.push(parse_capability(value)?),
                    "--endpoint" => opts.endpoints.push(parse_endpoint(value)?),
                    "--endpoint-meta" => parse_endpoint_metadata(value, &mut opts)?,
                    "--topic" => opts.topics.push(parse_topic(value)?),
                    "--min-guard-weight" => opts.min_guard_weight = Some(parse_u16(value)?),
                    "--max-same-asn" => opts.max_same_asn = Some(parse_u8(value)?),
                    "--max-same-pool" => opts.max_same_pool = Some(parse_u8(value)?),
                    "--notes" => opts.notes = Some(value.to_string()),
                    "--issued-at" => opts.issued_at = Some(parse_u64(value)?),
                    "--allow-unknown-capabilities" => {
                        opts.allow_unknown_capabilities = parse_bool(value)?;
                    }
                    "--ttl-secs" => opts.ttl_secs = Some(parse_u64(value)?),
                    "--public-key-file" => {
                        set_unique_path(&mut opts.public_key_file, value, "--public-key-file")?
                    }
                    "--public-key-fingerprint-sha256" => {
                        if opts.public_key_fingerprint_sha256.is_some() {
                            return Err(
                                "--public-key-fingerprint-sha256 may only be specified once".into(),
                            );
                        }
                        opts.public_key_fingerprint_sha256 =
                            Some(parse_reviewed_fingerprint(value)?);
                    }
                    "--signature-file" => {
                        set_unique_path(&mut opts.signature_file, value, "--signature-file")?
                    }
                    "--signing-payload-file" => set_unique_path(
                        &mut opts.signing_payload_file,
                        value,
                        "--signing-payload-file",
                    )?,
                    "--signing-payload-out" => set_unique_path(
                        &mut opts.signing_payload_out,
                        value,
                        "--signing-payload-out",
                    )?,
                    "--advert-out" => opts.advert_out = Some(PathBuf::from(value)),
                    "--json-out" => opts.json_out = Some(PathBuf::from(value)),
                    _ => return Err(format!("unknown option: {key}")),
                }
            }
            if prepare {
                Command::Prepare(Box::new(opts))
            } else {
                Command::Emit(Box::new(opts))
            }
        }
        Some(flag) if flag == "--verify" => {
            let mut opts = VerifyOptions::default();
            for arg in args {
                let (key, value) = arg
                    .split_once('=')
                    .ok_or_else(|| format!("expected key=value option, got: {arg}"))?;
                match key {
                    "--network-id" => opts.network_id = Some(parse_hex_fixed::<32>(value)?),
                    "--advert" => opts.advert_path = Some(PathBuf::from(value)),
                    "--json-out" => opts.json_out = Some(PathBuf::from(value)),
                    "--now" => opts.now = Some(parse_u64(value)?),
                    "--public-key-file" => {
                        set_unique_path(&mut opts.public_key_file, value, "--public-key-file")?
                    }
                    "--public-key-fingerprint-sha256" => {
                        if opts.public_key_fingerprint_sha256.is_some() {
                            return Err(
                                "--public-key-fingerprint-sha256 may only be specified once".into(),
                            );
                        }
                        opts.public_key_fingerprint_sha256 =
                            Some(parse_reviewed_fingerprint(value)?);
                    }
                    _ => return Err(format!("unknown option: {key}")),
                }
            }
            Command::Verify(opts)
        }
        _ => return Err(usage().to_string()),
    };
    match command {
        Command::Prepare(opts) => handle_prepare(*opts),
        Command::Emit(opts) => handle_emit(*opts),
        Command::Verify(opts) => handle_verify(opts),
    }
}
fn handle_prepare(opts: EmitOptions) -> Result<(), String> {
    if opts.signature_file.is_some() || opts.signing_payload_file.is_some() {
        return Err("--prepare does not accept --signature-file or --signing-payload-file".into());
    }
    if opts.advert_out.is_some() {
        return Err("--prepare does not write an advert; remove --advert-out".into());
    }
    let signing_payload_out = opts.signing_payload_out.as_ref().ok_or_else(|| {
        "--prepare requires --signing-payload-out=<path> for the external Ed25519 signer"
            .to_string()
    })?;
    let public_key_path = required_public_key_path(&opts)?;
    ensure_distinct_paths(&[
        (
            public_key_path,
            "--public-key-file",
            signing_payload_out.as_path(),
            "--signing-payload-out",
        ),
        (
            public_key_path,
            "--public-key-file",
            opts.json_out.as_deref().unwrap_or(Path::new("-")),
            "--json-out",
        ),
        (
            signing_payload_out.as_path(),
            "--signing-payload-out",
            opts.json_out.as_deref().unwrap_or(Path::new("-")),
            "--json-out",
        ),
    ])?;
    let (public_key, fingerprint) =
        load_reviewed_public_key(public_key_path, opts.public_key_fingerprint_sha256.as_ref())?;
    // Signature bytes are excluded from the signed payload and this advert is never emitted.
    // Use a non-inert placeholder so strict advert validation remains enabled during preparation.
    let advert = build_advert(
        &opts,
        public_key.to_vec(),
        PREPARE_SIGNATURE_PLACEHOLDER.to_vec(),
    )?;
    let signing_payload = advert
        .signature_payload_bytes()
        .map_err(|err| format!("encode advert signing payload: {err}"))?;
    write_bytes(signing_payload_out, &signing_payload)?;
    let report = build_signing_request_report(&advert, &signing_payload, &fingerprint);
    write_report(&report, opts.json_out.as_deref())
}
fn handle_emit(opts: EmitOptions) -> Result<(), String> {
    if opts.signing_payload_out.is_some() {
        return Err("--emit does not accept --signing-payload-out; use --prepare first".into());
    }
    let advert_out = opts.advert_out.as_ref().ok_or_else(|| {
        "--emit requires --advert-out=<path>; unsigned or report-only production output is forbidden"
            .to_string()
    })?;
    let public_key_path = required_public_key_path(&opts)?;
    let signature_path = opts.signature_file.as_ref().ok_or_else(|| {
        "--emit requires --signature-file=<raw-64-byte-path> from an external Ed25519 signer"
            .to_string()
    })?;
    let signing_payload_path = opts.signing_payload_file.as_ref().ok_or_else(|| {
        "--emit requires --signing-payload-file=<path> created by --prepare".to_string()
    })?;
    ensure_distinct_paths(&[
        (
            public_key_path,
            "--public-key-file",
            signature_path,
            "--signature-file",
        ),
        (
            public_key_path,
            "--public-key-file",
            signing_payload_path,
            "--signing-payload-file",
        ),
        (
            signature_path,
            "--signature-file",
            signing_payload_path,
            "--signing-payload-file",
        ),
        (
            advert_out,
            "--advert-out",
            signing_payload_path,
            "--signing-payload-file",
        ),
        (
            advert_out,
            "--advert-out",
            public_key_path,
            "--public-key-file",
        ),
        (
            advert_out,
            "--advert-out",
            signature_path,
            "--signature-file",
        ),
        (
            advert_out,
            "--advert-out",
            opts.json_out.as_deref().unwrap_or(Path::new("-")),
            "--json-out",
        ),
        (
            public_key_path,
            "--public-key-file",
            opts.json_out.as_deref().unwrap_or(Path::new("-")),
            "--json-out",
        ),
        (
            signature_path,
            "--signature-file",
            opts.json_out.as_deref().unwrap_or(Path::new("-")),
            "--json-out",
        ),
        (
            signing_payload_path,
            "--signing-payload-file",
            opts.json_out.as_deref().unwrap_or(Path::new("-")),
            "--json-out",
        ),
    ])?;
    let (public_key, fingerprint) =
        load_reviewed_public_key(public_key_path, opts.public_key_fingerprint_sha256.as_ref())?;
    let signature = read_trusted_regular_file(
        signature_path,
        "provider advert signature",
        ED25519_SIGNATURE_BYTES as u64,
        Some(ED25519_SIGNATURE_BYTES as u64),
    )?;
    if signature.iter().all(|byte| *byte == 0) {
        return Err("provider advert signature must not be all zero".into());
    }
    let advert = build_advert(&opts, public_key.to_vec(), signature)?;
    let generated_signing_payload = advert
        .signature_payload_bytes()
        .map_err(|err| format!("encode advert signing payload: {err}"))?;
    let reviewed_signing_payload = read_trusted_regular_file(
        signing_payload_path,
        "provider advert signing payload",
        SIGNING_PAYLOAD_MAX_BYTES,
        None,
    )?;
    if reviewed_signing_payload != generated_signing_payload {
        return Err(
            "provider advert fields do not match the reviewed external signing payload".into(),
        );
    }
    verify_advert_signature(&advert)
        .map_err(|err| format!("signature validation failed: {err}"))?;
    let bytes = norito::to_bytes(&advert).map_err(|err| err.to_string())?;
    write_bytes(advert_out, &bytes)?;
    let report = build_report(&advert, &bytes, true, &fingerprint);
    write_report(&report, opts.json_out.as_deref())
}
fn handle_verify(opts: VerifyOptions) -> Result<(), String> {
    let network_id = opts
        .network_id
        .ok_or_else(|| "--verify requires --network-id=<genesis-block-hash-hex32>".to_string())?;
    let advert_path = opts
        .advert_path
        .ok_or_else(|| "missing required option: --advert=<path>".to_string())?;
    let public_key_path = opts
        .public_key_file
        .as_ref()
        .ok_or_else(|| "--verify requires --public-key-file=<raw-32-byte-path>".to_string())?;
    ensure_distinct_paths(&[(
        advert_path.as_path(),
        "--advert",
        public_key_path.as_path(),
        "--public-key-file",
    )])?;
    let (public_key, fingerprint) =
        load_reviewed_public_key(public_key_path, opts.public_key_fingerprint_sha256.as_ref())?;
    let bytes = read_trusted_regular_file(
        &advert_path,
        "provider advert",
        PROVIDER_ADVERT_MAX_BYTES,
        None,
    )?;
    let advert = decode_provider_advert_v1(&bytes).map_err(|err| err.to_string())?;
    if advert.network_id != network_id {
        return Err("provider advert network id differs from --network-id".into());
    }
    if advert.signature.algorithm != SignatureAlgorithm::Ed25519 {
        return Err("provider advert must use Ed25519 in V1".into());
    }
    if advert.signature.public_key.as_slice() != public_key.as_slice() {
        return Err("provider advert signer does not match the reviewed public key".into());
    }
    let now = opts.now.unwrap_or(advert.issued_at);
    advert
        .validate_with_body(now)
        .map_err(|err| err.to_string())?;
    verify_advert_signature(&advert)
        .map_err(|err| format!("signature validation failed: {err}"))?;
    let report = build_report(&advert, &bytes, true, &fingerprint);
    write_report(&report, opts.json_out.as_deref())
}
fn usage() -> &'static str {
    "usage: sorafs_provider_advert <--prepare|--emit|--verify> \
     --prepare|--emit \
     --network-id=genesis_block_hash_hex32 \
     --chunker-profile=namespace.name@semver \
     --provider-id=hex32 \
     --stake-pool-id=hex32 \
     --stake-amount=canonical_xor_quantity \
     --availability=hot|warm|cold \
     --max-latency-ms=value \
     --max-streams=value \
     --capability=kind \
     [--soranet-pq=guard|majority|strict] \
     [--range-capability=max_span=...,min_granularity=...[,sparse=bool,...]] \
     [--stream-budget=max_in_flight=...,max_bytes_per_sec=...[,burst=...]] \
     [--transport-hint=protocol:priority] \
     --endpoint=kind:host \
     --topic=name:region \
     --public-key-file=path \
     --public-key-fingerprint-sha256=lowercase_hex32 \
     --prepare: --signing-payload-out=path \
     --emit: --signing-payload-file=path --signature-file=path --advert-out=path \
      [--notes=text] \
      [--min-guard-weight=number] \
      [--max-same-asn=number] \
      [--max-same-pool=number] \
      [--allow-unknown-capabilities=true|false] \
      [--ttl-secs=seconds] \
     --issued-at=unix \
     [--endpoint-meta=key:value] \
     [--json-out=path] \
     --verify \
     --network-id=genesis_block_hash_hex32 \
     --advert=path \
     --public-key-file=path \
     --public-key-fingerprint-sha256=lowercase_hex32 \
     [--now=unix] \
     [--json-out=path]"
}
fn build_advert(
    opts: &EmitOptions,
    public_key_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
) -> Result<ProviderAdvertV1, String> {
    chunker_registry::ensure_charter_compliance()
        .map_err(|err| format!("registry charter violation: {err}"))?;
    let profile_handle = opts
        .profile_handle
        .as_deref()
        .ok_or_else(|| "missing required option: --chunker-profile".to_string())
        .and_then(resolve_profile_handle)?;
    let profile_aliases = chunker_registry::lookup_by_handle(&profile_handle)
        .map(|descriptor| {
            let mut aliases: Vec<String> = descriptor
                .aliases
                .iter()
                .map(|alias| alias.to_string())
                .collect();
            if !aliases.iter().any(|alias| alias == &profile_handle) {
                aliases.insert(0, profile_handle.clone());
            } else if aliases.first().map(String::as_str) != Some(profile_handle.as_str()) {
                // Ensure canonical handle is first for deterministic negotiation.
                aliases.retain(|alias| alias != &profile_handle);
                aliases.insert(0, profile_handle.clone());
            }
            aliases
        })
        .unwrap_or_else(|| vec![profile_handle.clone()]);
    let issued_at = opts
        .issued_at
        .ok_or_else(|| "missing required option: --issued-at".to_string())?;
    let ttl = opts
        .ttl_secs
        .unwrap_or(REFRESH_RECOMMENDATION_SECS * 2)
        .min(MAX_ADVERT_TTL_SECS);
    if ttl == 0 {
        return Err("ttl-secs must be greater than zero".into());
    }
    let provider_id = opts
        .provider_id
        .ok_or_else(|| "missing required option: --provider-id".to_string())?;
    let network_id = opts
        .network_id
        .ok_or_else(|| "missing required option: --network-id".to_string())?;
    let stake_pool_id = opts
        .stake_pool_id
        .ok_or_else(|| "missing required option: --stake-pool-id".to_string())?;
    let stake_amount = opts
        .stake_amount
        .clone()
        .ok_or_else(|| "missing required option: --stake-amount".to_string())?;
    let availability = opts
        .availability
        .ok_or_else(|| "missing required option: --availability".to_string())?;
    let max_latency_ms = opts
        .max_latency_ms
        .ok_or_else(|| "missing required option: --max-latency-ms".to_string())?;
    let max_streams = opts
        .max_streams
        .ok_or_else(|| "missing required option: --max-streams".to_string())?;
    let capability_count = opts.capabilities.len()
        + usize::from(opts.range_capability.is_some())
        + usize::from(opts.soranet_pq.is_some());
    if capability_count == 0 {
        return Err(
            "at least one capability is required (--capability or --range-capability)".into(),
        );
    }
    if opts.endpoints.is_empty() {
        return Err("at least one --endpoint entry is required".into());
    }
    if opts.topics.is_empty() {
        return Err("at least one --topic entry is required".into());
    }
    if opts.stream_budget.is_some() && opts.range_capability.is_none() {
        return Err("--stream-budget requires --range-capability".into());
    }
    if !opts.transport_hints.is_empty() && opts.range_capability.is_none() {
        return Err("--transport-hint requires --range-capability".into());
    }
    if opts
        .transport_hints
        .iter()
        .any(|hint| hint.protocol == TransportProtocol::SoraNetRelay)
        && !(opts
            .capabilities
            .iter()
            .any(|cap| cap.cap_type == CapabilityType::SoraNetHybridPq)
            || opts.soranet_pq.is_some())
    {
        return Err("--transport-hint=soranet requires --soranet-pq".into());
    }
    let mut builder = ProviderAdvertV1::builder();
    let _ = builder
        .network_id(network_id)
        .profile_id(profile_handle.clone())
        .profile_aliases(profile_aliases)
        .provider_id(provider_id)
        .stake_pool_id(stake_pool_id)
        .stake_amount(stake_amount)
        .availability(availability)
        .max_retrieval_latency_ms(max_latency_ms)
        .max_concurrent_streams(max_streams)
        .issued_at(issued_at)
        .ttl_secs(ttl)
        .allow_unknown_capabilities(opts.allow_unknown_capabilities)
        .path_policy_min_guard_weight(opts.min_guard_weight.unwrap_or(10))
        .path_policy_max_same_asn_per_path(opts.max_same_asn.unwrap_or(1))
        .path_policy_max_same_pool_per_path(opts.max_same_pool.unwrap_or(1));
    if let Some(notes) = &opts.notes {
        let _ = builder.notes(notes.clone());
    }
    for capability in &opts.capabilities {
        let _ = builder.add_capability(capability.clone());
    }
    if let Some(range_capability) = &opts.range_capability {
        builder
            .add_range_capability(*range_capability)
            .map_err(|err| format!("invalid range capability: {err}"))?;
    }
    if let Some(pq_capability) = &opts.soranet_pq {
        let payload = pq_capability
            .to_bytes()
            .map_err(|err| format!("invalid soranet-pq capability: {err}"))?;
        let _ = builder.add_capability(CapabilityTlv {
            cap_type: CapabilityType::SoraNetHybridPq,
            payload,
        });
    }
    if let Some(budget) = &opts.stream_budget {
        let _ = builder.stream_budget(*budget);
    }
    if !opts.transport_hints.is_empty() {
        let _ = builder.transport_hints(opts.transport_hints.clone());
    }
    for endpoint in &opts.endpoints {
        let _ = builder.add_endpoint(endpoint.clone());
    }
    for topic in &opts.topics {
        let _ = builder.add_topic(topic.clone());
    }
    let _ = builder.signature(
        SignatureAlgorithm::Ed25519,
        public_key_bytes,
        signature_bytes,
    );
    builder.build().map_err(|err| match err {
        ProviderAdvertBuildError::MissingField(field) => {
            let option = match field {
                "profile_id" => "--chunker-profile",
                "provider_id" => "--provider-id",
                "stake_pool_id" => "--stake-pool-id",
                "stake_amount" => "--stake-amount",
                "availability" => "--availability",
                "max_retrieval_latency_ms" => "--max-latency-ms",
                "max_concurrent_streams" => "--max-streams",
                "capabilities" => "--capability/--range-capability",
                "endpoints" => "--endpoint",
                "rendezvous_topics" => "--topic",
                "public_key" => "--public-key-file",
                "signature" => "--signature-file",
                other => other,
            };
            format!("missing required option: {option}")
        }
        ProviderAdvertBuildError::Validation(validation) => validation.to_string(),
    })
}
fn build_report(
    advert: &ProviderAdvertV1,
    bytes: &[u8],
    signature_verified: bool,
    public_key_fingerprint_sha256: &[u8; 32],
) -> Value {
    let mut advert_obj = Map::new();
    advert_obj.insert("version".into(), Value::from(advert.version));
    advert_obj.insert(
        "network_id_hex".into(),
        Value::from(hex::encode(advert.network_id)),
    );
    advert_obj.insert("issued_at".into(), Value::from(advert.issued_at));
    advert_obj.insert("expires_at".into(), Value::from(advert.expires_at));
    advert_obj.insert("ttl_secs".into(), Value::from(advert.ttl()));
    advert_obj.insert(
        "refresh_recommended_at".into(),
        Value::from(advert.refresh_deadline()),
    );
    advert_obj.insert(
        "allow_unknown_capabilities".into(),
        Value::from(advert.allow_unknown_capabilities),
    );
    let mut body_obj = Map::new();
    body_obj.insert(
        "provider_id_hex".into(),
        Value::from(hex::encode(advert.body.provider_id)),
    );
    body_obj.insert(
        "profile_id".into(),
        Value::from(advert.body.profile_id.clone()),
    );
    if let Some(aliases) = &advert.body.profile_aliases {
        body_obj.insert(
            "profile_aliases".into(),
            Value::Array(aliases.iter().cloned().map(Value::from).collect()),
        );
    }
    let descriptor_opt =
        chunker_registry::lookup_by_handle(&advert.body.profile_id).or_else(|| {
            resolve_profile_handle(&advert.body.profile_id)
                .ok()
                .and_then(|handle| chunker_registry::lookup_by_handle(&handle))
        });
    if let Some(descriptor) = descriptor_opt {
        body_obj.insert(
            "profile_handle".into(),
            Value::from(format!(
                "{}.{}@{}",
                descriptor.namespace, descriptor.name, descriptor.semver
            )),
        );
        body_obj.insert(
            "profile_namespace".into(),
            Value::from(descriptor.namespace),
        );
        body_obj.insert("profile_name".into(), Value::from(descriptor.name));
        body_obj.insert("profile_semver".into(), Value::from(descriptor.semver));
    }
    body_obj.insert(
        "stake_pool_id_hex".into(),
        Value::from(hex::encode(advert.body.stake.pool_id)),
    );
    body_obj.insert(
        "stake_amount".into(),
        Value::from(advert.body.stake.stake_amount.to_string()),
    );
    body_obj.insert(
        "availability".into(),
        Value::from(availability_name(advert.body.qos.availability)),
    );
    body_obj.insert(
        "max_retrieval_latency_ms".into(),
        Value::from(advert.body.qos.max_retrieval_latency_ms),
    );
    body_obj.insert(
        "max_concurrent_streams".into(),
        Value::from(advert.body.qos.max_concurrent_streams),
    );
    let capabilities: Vec<Value> = advert
        .body
        .capabilities
        .iter()
        .map(|cap| {
            let mut obj = Map::new();
            obj.insert("type".into(), Value::from(capability_name(cap.cap_type)));
            obj.insert("payload_hex".into(), Value::from(hex::encode(&cap.payload)));
            if cap.cap_type == CapabilityType::ChunkRangeFetch {
                match ProviderCapabilityRangeV1::from_bytes(&cap.payload) {
                    Ok(range) => {
                        let mut range_obj = Map::new();
                        range_obj
                            .insert("max_chunk_span".into(), Value::from(range.max_chunk_span));
                        range_obj
                            .insert("min_granularity".into(), Value::from(range.min_granularity));
                        range_obj.insert(
                            "supports_sparse_offsets".into(),
                            Value::from(range.supports_sparse_offsets),
                        );
                        range_obj.insert(
                            "requires_alignment".into(),
                            Value::from(range.requires_alignment),
                        );
                        range_obj.insert(
                            "supports_merkle_proof".into(),
                            Value::from(range.supports_merkle_proof),
                        );
                        obj.insert("range".into(), Value::Object(range_obj));
                    }
                    Err(err) => {
                        obj.insert("range_decode_error".into(), Value::from(format!("{err}")));
                    }
                }
            } else if cap.cap_type == CapabilityType::SoraNetHybridPq {
                match ProviderCapabilitySoranetPqV1::from_bytes(&cap.payload) {
                    Ok(pq) => {
                        let mut pq_obj = Map::new();
                        pq_obj.insert("supports_guard".into(), Value::from(pq.supports_guard));
                        pq_obj.insert(
                            "supports_majority".into(),
                            Value::from(pq.supports_majority),
                        );
                        pq_obj.insert("supports_strict".into(), Value::from(pq.supports_strict));
                        obj.insert("soranet_pq".into(), Value::Object(pq_obj));
                    }
                    Err(err) => {
                        obj.insert(
                            "soranet_pq_decode_error".into(),
                            Value::from(format!("{err}")),
                        );
                    }
                }
            }
            Value::Object(obj)
        })
        .collect();
    body_obj.insert("capabilities".into(), Value::Array(capabilities));
    if let Some(budget) = &advert.body.stream_budget {
        let mut budget_obj = Map::new();
        budget_obj.insert(
            "max_in_flight".into(),
            Value::from(budget.max_in_flight as u64),
        );
        budget_obj.insert(
            "max_bytes_per_sec".into(),
            Value::from(budget.max_bytes_per_sec),
        );
        if let Some(burst) = budget.burst_bytes {
            budget_obj.insert("burst_bytes".into(), Value::from(burst));
        }
        body_obj.insert("stream_budget".into(), Value::Object(budget_obj));
    }
    if let Some(hints) = &advert.body.transport_hints {
        let hint_values: Vec<Value> = hints
            .iter()
            .map(|hint| {
                let mut hint_obj = Map::new();
                hint_obj.insert(
                    "protocol".into(),
                    Value::from(transport_protocol_name(hint.protocol)),
                );
                hint_obj.insert("priority".into(), Value::from(hint.priority as u64));
                Value::Object(hint_obj)
            })
            .collect();
        body_obj.insert("transport_hints".into(), Value::Array(hint_values));
    }
    let endpoints: Vec<Value> = advert
        .body
        .endpoints
        .iter()
        .map(|endpoint| {
            let mut obj = Map::new();
            obj.insert(
                "kind".into(),
                Value::from(endpoint_kind_name(endpoint.kind)),
            );
            obj.insert(
                "host_pattern".into(),
                Value::from(endpoint.host_pattern.clone()),
            );
            let meta: Vec<Value> = endpoint
                .metadata
                .iter()
                .map(|entry| {
                    let mut mobj = Map::new();
                    mobj.insert("key".into(), Value::from(endpoint_metadata_name(entry.key)));
                    mobj.insert("value_hex".into(), Value::from(hex::encode(&entry.value)));
                    Value::Object(mobj)
                })
                .collect();
            obj.insert("metadata".into(), Value::Array(meta));
            Value::Object(obj)
        })
        .collect();
    body_obj.insert("endpoints".into(), Value::Array(endpoints));
    let topics: Vec<Value> = advert
        .body
        .rendezvous_topics
        .iter()
        .map(|topic| {
            let mut obj = Map::new();
            obj.insert("topic".into(), Value::from(topic.topic.clone()));
            obj.insert("region".into(), Value::from(topic.region.clone()));
            Value::Object(obj)
        })
        .collect();
    body_obj.insert("rendezvous_topics".into(), Value::Array(topics));
    let mut path_obj = Map::new();
    path_obj.insert(
        "min_guard_weight".into(),
        Value::from(advert.body.path_policy.min_guard_weight as u64),
    );
    path_obj.insert(
        "max_same_asn_per_path".into(),
        Value::from(advert.body.path_policy.max_same_asn_per_path as u64),
    );
    path_obj.insert(
        "max_same_pool_per_path".into(),
        Value::from(advert.body.path_policy.max_same_pool_per_path as u64),
    );
    body_obj.insert("path_policy".into(), Value::Object(path_obj));
    if let Some(notes) = &advert.body.notes {
        body_obj.insert("notes".into(), Value::from(notes.clone()));
    }
    advert_obj.insert("body".into(), Value::Object(body_obj));
    let mut sig_obj = Map::new();
    sig_obj.insert(
        "algorithm".into(),
        Value::from(signature_alg_name(advert.signature.algorithm)),
    );
    sig_obj.insert(
        "public_key_hex".into(),
        Value::from(hex::encode(&advert.signature.public_key)),
    );
    sig_obj.insert(
        "public_key_fingerprint_sha256".into(),
        Value::from(hex::encode(public_key_fingerprint_sha256)),
    );
    sig_obj.insert(
        "signature_hex".into(),
        Value::from(hex::encode(&advert.signature.signature)),
    );
    advert_obj.insert("signature".into(), Value::Object(sig_obj));
    advert_obj.insert("signature_verified".into(), Value::from(signature_verified));
    advert_obj.insert("norito_len".into(), Value::from(bytes.len() as u64));
    advert_obj.insert("norito_hex".into(), Value::from(hex::encode(bytes)));
    Value::Object(advert_obj)
}
fn build_signing_request_report(
    advert: &ProviderAdvertV1,
    signing_payload: &[u8],
    public_key_fingerprint_sha256: &[u8; 32],
) -> Value {
    let mut report = Map::new();
    report.insert(
        "mode".into(),
        Value::from("external_ed25519_signing_request"),
    );
    report.insert("signature_algorithm".into(), Value::from("ed25519"));
    report.insert(
        "network_id_hex".into(),
        Value::from(hex::encode(advert.network_id)),
    );
    report.insert(
        "public_key_hex".into(),
        Value::from(hex::encode(&advert.signature.public_key)),
    );
    report.insert(
        "public_key_fingerprint_sha256".into(),
        Value::from(hex::encode(public_key_fingerprint_sha256)),
    );
    report.insert(
        "signing_payload_sha256".into(),
        Value::from(hex::encode(sha256(signing_payload))),
    );
    report.insert(
        "signing_payload_len".into(),
        Value::from(signing_payload.len() as u64),
    );
    report.insert(
        "provider_id_hex".into(),
        Value::from(hex::encode(advert.body.provider_id)),
    );
    report.insert("issued_at".into(), Value::from(advert.issued_at));
    report.insert("expires_at".into(), Value::from(advert.expires_at));
    report.insert("signature_required".into(), Value::from(true));
    Value::Object(report)
}
fn write_report(report: &Value, json_out: Option<&Path>) -> Result<(), String> {
    let mut report_string =
        to_string_pretty(report).map_err(|err| format!("failed to serialise JSON: {err}"))?;
    report_string.push('\n');
    let wrote_stdout = if let Some(path) = json_out {
        write_text(path, &report_string)?
    } else {
        false
    };
    if !wrote_stdout {
        print!("{report_string}");
    }
    Ok(())
}
enum Command {
    Prepare(Box<EmitOptions>),
    Emit(Box<EmitOptions>),
    Verify(VerifyOptions),
}
#[derive(Default)]
struct EmitOptions {
    network_id: Option<[u8; 32]>,
    profile_handle: Option<String>,
    provider_id: Option<[u8; 32]>,
    stake_pool_id: Option<[u8; 32]>,
    stake_amount: Option<XorQuantity>,
    availability: Option<AvailabilityTier>,
    max_latency_ms: Option<u32>,
    max_streams: Option<u16>,
    capabilities: Vec<CapabilityTlv>,
    endpoints: Vec<AdvertEndpoint>,
    topics: Vec<RendezvousTopic>,
    min_guard_weight: Option<u16>,
    max_same_asn: Option<u8>,
    max_same_pool: Option<u8>,
    notes: Option<String>,
    issued_at: Option<u64>,
    ttl_secs: Option<u64>,
    public_key_file: Option<PathBuf>,
    public_key_fingerprint_sha256: Option<[u8; 32]>,
    signature_file: Option<PathBuf>,
    signing_payload_file: Option<PathBuf>,
    signing_payload_out: Option<PathBuf>,
    advert_out: Option<PathBuf>,
    json_out: Option<PathBuf>,
    allow_unknown_capabilities: bool,
    range_capability: Option<ProviderCapabilityRangeV1>,
    soranet_pq: Option<ProviderCapabilitySoranetPqV1>,
    stream_budget: Option<StreamBudgetV1>,
    transport_hints: Vec<TransportHintV1>,
}
#[derive(Default)]
struct VerifyOptions {
    network_id: Option<[u8; 32]>,
    advert_path: Option<PathBuf>,
    public_key_file: Option<PathBuf>,
    public_key_fingerprint_sha256: Option<[u8; 32]>,
    json_out: Option<PathBuf>,
    now: Option<u64>,
}
fn parse_availability(value: &str) -> Result<AvailabilityTier, String> {
    match value {
        "hot" => Ok(AvailabilityTier::Hot),
        "warm" => Ok(AvailabilityTier::Warm),
        "cold" => Ok(AvailabilityTier::Cold),
        other => Err(format!("unknown availability tier: {other}")),
    }
}
fn parse_capability(value: &str) -> Result<CapabilityTlv, String> {
    let (head, payload_str) = value
        .split_once(':')
        .map_or((value, None), |(h, rest)| (h, Some(rest)));
    let cap_type = match head {
        "torii" => CapabilityType::ToriiGateway,
        "quic" => CapabilityType::QuicNoise,
        "potr-mldsa" => CapabilityType::PotrMlDsa,
        "range" => {
            return Err(
                "use --range-capability=<key=value,...> to describe chunk-range support".into(),
            );
        }
        "soranet" | "soranet-pq" => {
            return Err("use --soranet-pq=<guard|majority|strict>".into());
        }
        "vendor" => CapabilityType::VendorReserved,
        other => {
            return Err(format!(
                "unknown capability type: {other} (expected torii|quic|potr-mldsa|vendor; use --range-capability or --soranet-pq for structured capabilities)"
            ));
        }
    };
    let payload = match (cap_type, payload_str) {
        (CapabilityType::VendorReserved, Some(rest)) => parse_hex_vec(rest)?,
        (CapabilityType::PotrMlDsa, Some(rest)) => parse_hex_vec(rest)?,
        (CapabilityType::PotrMlDsa, None) => {
            return Err("potr-mldsa capability requires a hex ML-DSA-65 public key".into());
        }
        (_, Some(rest)) => parse_hex_vec(rest)?,
        _ => Vec::new(),
    };
    Ok(CapabilityTlv { cap_type, payload })
}
fn parse_soranet_pq(value: &str) -> Result<ProviderCapabilitySoranetPqV1, String> {
    let capability = match value {
        "guard" => ProviderCapabilitySoranetPqV1 {
            supports_guard: true,
            supports_majority: false,
            supports_strict: false,
        },
        "majority" => ProviderCapabilitySoranetPqV1 {
            supports_guard: true,
            supports_majority: true,
            supports_strict: false,
        },
        "strict" => ProviderCapabilitySoranetPqV1 {
            supports_guard: true,
            supports_majority: true,
            supports_strict: true,
        },
        other => {
            return Err(format!(
                "unknown soranet-pq level `{other}` (expected exactly guard|majority|strict)"
            ));
        }
    };
    capability
        .validate()
        .map_err(|err| format!("invalid soranet-pq capability: {err}"))?;
    Ok(capability)
}
fn parse_range_capability(value: &str) -> Result<ProviderCapabilityRangeV1, String> {
    let mut max_span = None;
    let mut min_granularity = None;
    let mut sparse = None;
    let mut alignment = None;
    let mut merkle = None;
    for part in value.split(',') {
        if part.is_empty() {
            return Err("range-capability must not contain empty entries".to_string());
        }
        require_no_ascii_whitespace(part, "range-capability entry")?;
        let (key, raw) = part
            .split_once('=')
            .ok_or_else(|| format!("range-capability requires key=value entries, got: {part}"))?;
        match key {
            "max_span" => {
                if max_span.is_some() {
                    return Err("range-capability field max_span specified multiple times".into());
                }
                let span = parse_u32(raw)?;
                max_span = Some(span);
            }
            "min_granularity" => {
                if min_granularity.is_some() {
                    return Err(
                        "range-capability field min_granularity specified multiple times".into(),
                    );
                }
                let granularity = parse_u32(raw)?;
                min_granularity = Some(granularity);
            }
            "sparse" => {
                if sparse.is_some() {
                    return Err("range-capability field sparse specified multiple times".into());
                }
                sparse = Some(parse_bool(raw)?);
            }
            "alignment" => {
                if alignment.is_some() {
                    return Err("range-capability field alignment specified multiple times".into());
                }
                alignment = Some(parse_bool(raw)?);
            }
            "merkle" => {
                if merkle.is_some() {
                    return Err("range-capability field merkle specified multiple times".into());
                }
                merkle = Some(parse_bool(raw)?);
            }
            other => {
                return Err(format!(
                    "unknown range-capability field: {other} (expected max_span|min_granularity|sparse|alignment|merkle)"
                ));
            }
        }
    }
    let capability = ProviderCapabilityRangeV1 {
        max_chunk_span: max_span
            .ok_or_else(|| "range-capability requires max_span=<u32>".to_string())?,
        min_granularity: min_granularity
            .ok_or_else(|| "range-capability requires min_granularity=<u32>".to_string())?,
        supports_sparse_offsets: sparse.unwrap_or(false),
        requires_alignment: alignment.unwrap_or(false),
        supports_merkle_proof: merkle.unwrap_or(false),
    };
    capability
        .validate()
        .map_err(|err| format!("invalid range capability: {err}"))?;
    Ok(capability)
}
fn parse_stream_budget(value: &str) -> Result<StreamBudgetV1, String> {
    let mut max_in_flight = None;
    let mut max_bytes_per_sec = None;
    let mut burst_bytes = None;
    for part in value.split(',') {
        if part.is_empty() {
            return Err("stream-budget must not contain empty entries".to_string());
        }
        require_no_ascii_whitespace(part, "stream-budget entry")?;
        let (key, raw) = part
            .split_once('=')
            .ok_or_else(|| format!("stream-budget requires key=value entries, got: {part}"))?;
        match key {
            "max_in_flight" => {
                if max_in_flight.is_some() {
                    return Err("stream-budget field max_in_flight specified multiple times".into());
                }
                let inflight = parse_u16(raw)?;
                max_in_flight = Some(inflight);
            }
            "max_bytes_per_sec" => {
                if max_bytes_per_sec.is_some() {
                    return Err(
                        "stream-budget field max_bytes_per_sec specified multiple times".into(),
                    );
                }
                let rate = parse_u64(raw)?;
                max_bytes_per_sec = Some(rate);
            }
            "burst" => {
                if burst_bytes.is_some() {
                    return Err("stream-budget field burst specified multiple times".into());
                }
                let burst = parse_u64(raw)?;
                burst_bytes = Some(burst);
            }
            other => {
                return Err(format!(
                    "unknown stream-budget field: {other} (expected max_in_flight|max_bytes_per_sec|burst)"
                ));
            }
        }
    }
    let budget = StreamBudgetV1 {
        max_in_flight: max_in_flight
            .ok_or_else(|| "stream-budget requires max_in_flight=<u16>".to_string())?,
        max_bytes_per_sec: max_bytes_per_sec
            .ok_or_else(|| "stream-budget requires max_bytes_per_sec=<u64>".to_string())?,
        burst_bytes,
    };
    budget
        .validate()
        .map_err(|err| format!("invalid stream budget: {err}"))?;
    Ok(budget)
}
fn parse_transport_hint(value: &str) -> Result<TransportHintV1, String> {
    let (protocol_str, priority_str) = value
        .split_once(':')
        .ok_or_else(|| "transport-hint requires protocol:priority".to_string())?;
    require_no_ascii_whitespace(protocol_str, "transport-hint protocol")?;
    require_no_ascii_whitespace(priority_str, "transport-hint priority")?;
    let protocol = parse_transport_protocol(protocol_str)?;
    let priority = parse_u8(priority_str)?;
    let hint = TransportHintV1 { protocol, priority };
    hint.validate()
        .map_err(|err| format!("invalid transport hint: {err}"))?;
    Ok(hint)
}
fn parse_transport_protocol(value: &str) -> Result<TransportProtocol, String> {
    match value {
        "torii" => Ok(TransportProtocol::ToriiHttpRange),
        "quic" => Ok(TransportProtocol::QuicStream),
        "soranet" => Ok(TransportProtocol::SoraNetRelay),
        "vendor" => Ok(TransportProtocol::VendorReserved),
        other => Err(format!(
            "unknown transport protocol: {other} (expected torii|quic|soranet|vendor)"
        )),
    }
}
fn parse_endpoint(value: &str) -> Result<AdvertEndpoint, String> {
    let (kind_str, host) = value
        .split_once(':')
        .ok_or_else(|| "endpoint requires kind:host".to_string())?;
    let kind = match kind_str {
        "torii" => EndpointKind::Torii,
        "quic" => EndpointKind::Quic,
        "norito-rpc" => EndpointKind::NoritoRpc,
        other => return Err(format!("unknown endpoint kind: {other}")),
    };
    Ok(AdvertEndpoint {
        kind,
        host_pattern: host.to_string(),
        metadata: Vec::new(),
    })
}
fn parse_endpoint_metadata(value: &str, opts: &mut EmitOptions) -> Result<(), String> {
    let (key_str, data) = value
        .split_once(':')
        .ok_or_else(|| "endpoint-meta requires key:value".to_string())?;
    let endpoint = opts
        .endpoints
        .last_mut()
        .ok_or_else(|| "endpoint-meta requires at least one --endpoint before it".to_string())?;
    let key = match key_str {
        "tls_fingerprint" => EndpointMetadataKey::TlsFingerprint,
        "alpn" => EndpointMetadataKey::Alpn,
        "region" => EndpointMetadataKey::Region,
        other => return Err(format!("unknown endpoint metadata key: {other}")),
    };
    let value_bytes = match key {
        EndpointMetadataKey::Region => data.as_bytes().to_vec(),
        _ => parse_hex_vec(data)?,
    };
    endpoint.metadata.push(EndpointMetadata {
        key,
        value: value_bytes,
    });
    Ok(())
}
fn parse_topic(value: &str) -> Result<RendezvousTopic, String> {
    let (topic, region) = value
        .split_once(':')
        .ok_or_else(|| "topic requires name:region".to_string())?;
    Ok(RendezvousTopic {
        topic: topic.to_string(),
        region: region.to_string(),
    })
}
fn set_unique_path(target: &mut Option<PathBuf>, value: &str, flag: &str) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} may only be specified once"));
    }
    if value.is_empty() {
        return Err(format!("{flag} requires a non-empty path"));
    }
    *target = Some(PathBuf::from(value));
    Ok(())
}
fn parse_reviewed_fingerprint(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(
            "--public-key-fingerprint-sha256 must be exactly 32 bytes of lowercase SHA-256 hex without prefixes or whitespace"
                .into(),
        );
    }
    let decoded = parse_hex_vec(value)?;
    Ok(decoded
        .try_into()
        .expect("reviewed fingerprint length checked above"))
}
fn required_public_key_path(opts: &EmitOptions) -> Result<&Path, String> {
    opts.public_key_file
        .as_deref()
        .ok_or_else(|| "--public-key-file=<raw-32-byte-path> is required".to_string())
}
fn load_reviewed_public_key(
    path: &Path,
    reviewed_fingerprint: Option<&[u8; 32]>,
) -> Result<([u8; 32], [u8; 32]), String> {
    let reviewed_fingerprint = reviewed_fingerprint.ok_or_else(|| {
        "--public-key-fingerprint-sha256=<lowercase-hex32> is required".to_string()
    })?;
    let bytes = read_trusted_regular_file(
        path,
        "provider advert public key",
        ED25519_PUBLIC_KEY_BYTES as u64,
        Some(ED25519_PUBLIC_KEY_BYTES as u64),
    )?;
    let public_key: [u8; ED25519_PUBLIC_KEY_BYTES] = bytes
        .try_into()
        .expect("exact public key length checked above");
    if public_key.iter().all(|byte| *byte == 0) {
        return Err("provider advert public key must not be all zero".into());
    }
    let actual_fingerprint = sha256(public_key);
    if &actual_fingerprint != reviewed_fingerprint {
        return Err("provider advert public key does not match the reviewed fingerprint".into());
    }
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| "provider advert public key is not valid Ed25519".to_string())?;
    if verifying_key.is_weak() {
        return Err("provider advert public key must not be weak or small-order".into());
    }
    Ok((public_key, actual_fingerprint))
}
fn ensure_distinct_paths(pairs: &[(&Path, &str, &Path, &str)]) -> Result<(), String> {
    let current_dir =
        env::current_dir().map_err(|err| format!("failed to resolve current directory: {err}"))?;
    for (left, left_label, right, right_label) in pairs {
        if *left == Path::new("-") || *right == Path::new("-") {
            continue;
        }
        let left = lexical_absolute_path(&current_dir, left)?;
        let right = lexical_absolute_path(&current_dir, right)?;
        if left == right {
            return Err(format!(
                "{left_label} and {right_label} must use distinct paths"
            ));
        }
    }
    Ok(())
}
fn resolve_profile_handle(input: &str) -> Result<String, String> {
    if input.is_empty() {
        return Err("chunker profile cannot be empty".into());
    }
    require_no_ascii_whitespace(input, "chunker profile")?;
    if let Some(descriptor) = chunker_registry::lookup_by_handle(input) {
        let canonical = format!(
            "{}.{}@{}",
            descriptor.namespace, descriptor.name, descriptor.semver
        );
        if input == canonical {
            return Ok(canonical);
        }
        return Err(format!(
            "chunker profile handle `{input}` is not canonical; expected `{canonical}`"
        ));
    }
    Err(format!(
        "unknown chunker profile handle '{input}'. expected namespace.name@semver"
    ))
}
fn parse_hex_vec(value: &str) -> Result<Vec<u8>, String> {
    require_canonical_hex(value, "hex input")?;
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let high = decode_hex(bytes[idx])?;
        let low = decode_hex(bytes[idx + 1])?;
        out.push((high << 4) | low);
        idx += 2;
    }
    Ok(out)
}
fn parse_hex_fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let vec = parse_hex_vec(value)?;
    if vec.len() != N {
        return Err(format!("expected exactly {N} hex bytes, got {}", vec.len()));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&vec);
    Ok(arr)
}
fn parse_u64(value: &str) -> Result<u64, String> {
    if let Some(stripped) = value.strip_prefix("0x") {
        require_canonical_hex_unsigned(stripped, "u64")?;
        u64::from_str_radix(stripped, 16).map_err(|err| err.to_string())
    } else {
        require_canonical_unsigned_decimal(value, "u64")?;
        value.parse::<u64>().map_err(|err| err.to_string())
    }
}
fn parse_xor_quantity(value: &str) -> Result<XorQuantity, String> {
    let quantity = value
        .parse::<XorQuantity>()
        .map_err(|err| format!("invalid XOR quantity `{value}`: {err}"))?;
    if quantity.to_string() != value {
        return Err(format!(
            "XOR quantity `{value}` must use the canonical decimal spelling"
        ));
    }
    Ok(quantity)
}
fn parse_u32(value: &str) -> Result<u32, String> {
    if let Some(stripped) = value.strip_prefix("0x") {
        require_canonical_hex_unsigned(stripped, "u32")?;
        u32::from_str_radix(stripped, 16).map_err(|err| err.to_string())
    } else {
        require_canonical_unsigned_decimal(value, "u32")?;
        value.parse::<u32>().map_err(|err| err.to_string())
    }
}
fn parse_u16(value: &str) -> Result<u16, String> {
    if let Some(stripped) = value.strip_prefix("0x") {
        require_canonical_hex_unsigned(stripped, "u16")?;
        u16::from_str_radix(stripped, 16).map_err(|err| err.to_string())
    } else {
        require_canonical_unsigned_decimal(value, "u16")?;
        value.parse::<u16>().map_err(|err| err.to_string())
    }
}
fn parse_u8(value: &str) -> Result<u8, String> {
    if let Some(stripped) = value.strip_prefix("0x") {
        require_canonical_hex_unsigned(stripped, "u8")?;
        u8::from_str_radix(stripped, 16).map_err(|err| err.to_string())
    } else {
        require_canonical_unsigned_decimal(value, "u8")?;
        value.parse::<u8>().map_err(|err| err.to_string())
    }
}
fn is_canonical_unsigned_decimal(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.iter().all(u8::is_ascii_digit)
        && (bytes.len() == 1 || bytes[0] != b'0')
}
fn require_canonical_unsigned_decimal(value: &str, ty: &str) -> Result<(), String> {
    if is_canonical_unsigned_decimal(value) {
        Ok(())
    } else {
        Err(format!(
            "{ty} value must be a canonical unsigned decimal integer or lowercase 0x-prefixed hex"
        ))
    }
}
fn require_canonical_hex_unsigned(value: &str, ty: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        && (bytes.len() == 1 || bytes[0] != b'0')
    {
        Ok(())
    } else {
        Err(format!(
            "{ty} value must be a canonical unsigned decimal integer or lowercase 0x-prefixed hex"
        ))
    }
}
fn require_no_ascii_whitespace(value: &str, label: &str) -> Result<(), String> {
    if value.as_bytes().iter().any(u8::is_ascii_whitespace) {
        Err(format!("{label} must not contain ASCII whitespace"))
    } else {
        Ok(())
    }
}
fn require_canonical_hex(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.starts_with("0x")
        || value.starts_with("0X")
        || value
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_whitespace())
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        Err(format!(
            "{label} must be lowercase even-length hex without a 0x prefix or whitespace"
        ))
    } else {
        Ok(())
    }
}
fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("expected boolean true|false, got {other}")),
    }
}
fn decode_hex(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(format!("invalid hex digit: {}", byte as char)),
    }
}
fn read_trusted_regular_file(
    path: &Path,
    label: &str,
    maximum_bytes: u64,
    exact_bytes: Option<u64>,
) -> Result<Vec<u8>, String> {
    let direct_path = trusted_direct_path(path, label)?;
    let before = fs::symlink_metadata(&direct_path)
        .map_err(|err| format!("failed to inspect {label}: {err}"))?;
    validate_trusted_input_metadata(label, &before, maximum_bytes)?;
    let mut options = OpenOptions::new();
    options.read(true);
    set_no_follow_flag(&mut options);
    let mut file = options
        .open(&direct_path)
        .map_err(|err| format!("failed to open {label}: {err}"))?;
    let opened = file
        .metadata()
        .map_err(|err| format!("failed to inspect open {label}: {err}"))?;
    validate_trusted_input_metadata(label, &opened, maximum_bytes)?;
    if !trusted_metadata_matches(&before, &opened) {
        return Err(format!("{label} changed while being opened"));
    }
    let capacity =
        usize::try_from(opened.len()).map_err(|_| format!("{label} exceeds host size limits"))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| format!("failed to read {label}: {err}"))?;
    let after = fs::symlink_metadata(&direct_path)
        .map_err(|err| format!("failed to re-inspect {label}: {err}"))?;
    validate_trusted_input_metadata(label, &after, maximum_bytes)?;
    trusted_direct_path(path, label)?;
    if bytes.len() as u64 != opened.len()
        || !trusted_metadata_matches(&opened, &after)
        || !trusted_metadata_matches(&before, &after)
    {
        return Err(format!("{label} changed while being read"));
    }
    if let Some(expected) = exact_bytes
        && bytes.len() as u64 != expected
    {
        return Err(format!("{label} must contain exactly {expected} raw bytes"));
    }
    Ok(bytes)
}
fn trusted_direct_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    let current_dir =
        env::current_dir().map_err(|err| format!("failed to resolve {label} path: {err}"))?;
    let direct_path = lexical_absolute_path(&current_dir, path).map_err(|_| {
        format!("{label} must use a non-empty direct path without `.` or `..` components")
    })?;
    validate_direct_parent_path(&direct_path, label)?;
    Ok(direct_path)
}
fn lexical_absolute_path(current_dir: &Path, path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err("path must be non-empty and direct".into());
    }
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir.join(path)
    })
}
fn validate_direct_parent_path(path: &Path, label: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        for ancestor in parent.ancestors() {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            let metadata = fs::symlink_metadata(ancestor)
                .map_err(|err| format!("failed to inspect {label} parent: {err}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!("{label} parent must be a real directory"));
            }
        }
    }
    Ok(())
}
fn validate_trusted_input_metadata(
    label: &str,
    metadata: &fs::Metadata,
    maximum_bytes: u64,
) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} must be a direct regular file"));
    }
    if metadata.len() == 0 || metadata.len() > maximum_bytes {
        return Err(format!("{label} size is outside the supported range"));
    }
    #[cfg(unix)]
    {
        if metadata.nlink() != 1 {
            return Err(format!("{label} must have exactly one hard link"));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(format!("{label} must not be group- or world-writable"));
        }
    }
    Ok(())
}
#[cfg(unix)]
fn trusted_metadata_matches(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(not(unix))]
fn trusted_metadata_matches(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}
fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path == Path::new("-") {
        return Err("binary outputs do not support '-'".into());
    }
    let output_path = trusted_output_path(path, "binary output")?;
    let mut file = open_output_file(&output_path, "binary output")?;
    file.write_all(bytes)
        .map_err(|err| format!("failed to write {path:?}: {err}"))?;
    file.sync_all()
        .map_err(|err| format!("failed to sync {path:?}: {err}"))?;
    validate_open_output_identity(&output_path, &file, "binary output")
}
fn write_text(path: &Path, text: &str) -> Result<bool, String> {
    if path == Path::new("-") {
        io::stdout()
            .write_all(text.as_bytes())
            .map_err(|err| format!("failed to write to stdout: {err}"))?;
        return Ok(true);
    }
    write_bytes(path, text.as_bytes()).map(|_| false)
}
fn open_output_file(path: &Path, label: &str) -> Result<fs::File, String> {
    validate_output_path(path)?;
    ensure_parent_dir(path)?;
    validate_output_path(path)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    set_no_follow_flag(&mut options);
    let file = options
        .open(path)
        .map_err(|err| format!("failed to open {label} {path:?}: {err}"))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to inspect {label} {path:?} after open: {err}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "failed to write {label} {path:?}: output must be a regular file"
        ));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err(format!(
            "failed to write {label} {path:?}: output must have exactly one hard link"
        ));
    }
    Ok(file)
}
fn trusted_output_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    let current_dir =
        env::current_dir().map_err(|err| format!("failed to resolve {label} path: {err}"))?;
    let direct_path = lexical_absolute_path(&current_dir, path).map_err(|_| {
        format!("{label} must use a non-empty direct path without `.` or `..` components")
    })?;
    ensure_parent_dir(&direct_path)?;
    validate_direct_parent_path(&direct_path, label)?;
    Ok(direct_path)
}
fn validate_open_output_identity(path: &Path, file: &fs::File, label: &str) -> Result<(), String> {
    validate_direct_parent_path(path, label)?;
    let opened = file
        .metadata()
        .map_err(|err| format!("failed to inspect open {label} {path:?}: {err}"))?;
    let linked = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to re-inspect {label} {path:?}: {err}"))?;
    if linked.file_type().is_symlink()
        || !linked.is_file()
        || !trusted_metadata_matches(&opened, &linked)
    {
        return Err(format!("{label} {path:?} changed while being written"));
    }
    #[cfg(unix)]
    if opened.nlink() != 1 || linked.nlink() != 1 {
        return Err(format!("{label} {path:?} must have exactly one hard link"));
    }
    Ok(())
}
fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|err| format!("failed to create {parent:?}: {err}"))?;
    }
    Ok(())
}
fn validate_output_path(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!("output {path:?} must not be a symlink"));
            }
            if metadata.is_dir() {
                return Err(format!("output {path:?} must not be a directory"));
            }
            return Err(format!(
                "output {path:?} already exists; production outputs are no-clobber"
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("failed to inspect output {path:?}: {err}")),
    }
    if let Some(parent) = path.parent() {
        for ancestor in std::iter::once(parent).chain(parent.ancestors().skip(1)) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            match fs::symlink_metadata(ancestor) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(format!("output parent {ancestor:?} must not be a symlink"));
                    }
                    if !metadata.is_dir() {
                        return Err(format!("output parent {ancestor:?} must be a directory"));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(format!(
                        "failed to inspect output parent {ancestor:?}: {err}"
                    ));
                }
            }
        }
    }
    Ok(())
}
fn capability_name(cap: CapabilityType) -> &'static str {
    match cap {
        CapabilityType::ToriiGateway => "torii_gateway",
        CapabilityType::QuicNoise => "quic_noise",
        CapabilityType::ChunkRangeFetch => "chunk_range_fetch",
        CapabilityType::SoraNetHybridPq => "soranet_pq",
        CapabilityType::PotrMlDsa => "potr_mldsa",
        CapabilityType::RegisteredAccountRead => "registered_account_read",
        CapabilityType::VendorReserved => "vendor_reserved",
    }
}
fn availability_name(availability: AvailabilityTier) -> &'static str {
    match availability {
        AvailabilityTier::Hot => "hot",
        AvailabilityTier::Warm => "warm",
        AvailabilityTier::Cold => "cold",
    }
}
fn verify_advert_signature(advert: &ProviderAdvertV1) -> Result<(), String> {
    advert.verify_signature().map_err(|err| err.to_string())
}
fn endpoint_kind_name(kind: EndpointKind) -> &'static str {
    match kind {
        EndpointKind::Torii => "torii",
        EndpointKind::Quic => "quic",
        EndpointKind::NoritoRpc => "norito-rpc",
    }
}
fn endpoint_metadata_name(key: EndpointMetadataKey) -> &'static str {
    match key {
        EndpointMetadataKey::TlsFingerprint => "tls_fingerprint",
        EndpointMetadataKey::Alpn => "alpn",
        EndpointMetadataKey::Region => "region",
    }
}
fn transport_protocol_name(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::ToriiHttpRange => "torii_http_range",
        TransportProtocol::QuicStream => "quic_stream",
        TransportProtocol::SoraNetRelay => "soranet_relay",
        TransportProtocol::VendorReserved => "vendor_reserved",
    }
}
fn signature_alg_name(alg: SignatureAlgorithm) -> &'static str {
    match alg {
        SignatureAlgorithm::Ed25519 => "ed25519",
        SignatureAlgorithm::MultiSig => "multi-sig",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;
    fn externally_sign_advert(opts: &EmitOptions, signing_key: &SigningKey) -> ProviderAdvertV1 {
        let public_key = signing_key.verifying_key().to_bytes();
        let mut advert = build_advert(
            opts,
            public_key.to_vec(),
            PREPARE_SIGNATURE_PLACEHOLDER.to_vec(),
        )
        .expect("advert builds");
        let payload = advert
            .signature_payload_bytes()
            .expect("encode advert signing payload");
        advert.signature.signature = signing_key.sign(&payload).to_bytes().to_vec();
        advert
    }
    #[test]
    fn write_bytes_creates_parent_and_writes_all_bytes() {
        let temp = tempdir().expect("tempdir");
        let temp_path = temp.path().canonicalize().expect("canonical tempdir");
        let output_path = temp_path.join("nested").join("advert.to");
        write_bytes(&output_path, b"provider-advert").expect("write bytes");
        assert_eq!(
            fs::read(&output_path).expect("read output"),
            b"provider-advert"
        );
    }
    #[cfg(unix)]
    #[test]
    fn write_text_rejects_symlink_output() {
        let temp = tempdir().expect("tempdir");
        let temp_path = temp.path().canonicalize().expect("canonical tempdir");
        let target_path = temp_path.join("target.json");
        fs::write(&target_path, b"unchanged\n").expect("write target");
        let output_path = temp_path.join("report.json");
        std::os::unix::fs::symlink(&target_path, &output_path).expect("create symlink");
        let err = write_text(&output_path, "changed\n").expect_err("reject symlink output");
        assert!(
            err.contains("must not be a symlink"),
            "unexpected error: {err}"
        );
        assert_eq!(fs::read(&target_path).expect("read target"), b"unchanged\n");
    }
    #[cfg(unix)]
    #[test]
    fn write_bytes_rejects_symlink_parent() {
        let temp = tempdir().expect("tempdir");
        let temp_path = temp.path().canonicalize().expect("canonical tempdir");
        let real_dir = temp_path.join("real");
        fs::create_dir(&real_dir).expect("create real dir");
        let linked_dir = temp_path.join("linked");
        std::os::unix::fs::symlink(&real_dir, &linked_dir).expect("create symlink");
        let output_path = linked_dir.join("advert.to");
        let err = write_bytes(&output_path, b"changed").expect_err("reject symlink parent");
        assert!(
            err.contains("parent") && err.contains("must be a real directory"),
            "unexpected error: {err}"
        );
        assert!(
            !real_dir.join("advert.to").exists(),
            "symlink parent should not receive output"
        );
    }
    #[test]
    fn parse_range_capability_success() {
        let capability = parse_range_capability(
            "max_span=16,min_granularity=4,sparse=true,alignment=false,merkle=true",
        )
        .expect("range capability parses");
        assert_eq!(capability.max_chunk_span, 16);
        assert_eq!(capability.min_granularity, 4);
        assert!(capability.supports_sparse_offsets);
        assert!(!capability.requires_alignment);
        assert!(capability.supports_merkle_proof);
    }
    #[test]
    fn usage_uses_cargo_binary_name() {
        let text = usage();
        assert!(text.contains("sorafs_provider_advert <--prepare|--emit|--verify>"));
        assert!(!text.contains("signing-key"));
        assert!(!text.contains("--public-key=hex"));
        assert!(!text.contains("--profile-id"));
        assert!(text.contains("--chunker-profile=namespace.name@semver"));
        assert!(text.contains("--public-key-fingerprint-sha256"));
    }
    #[test]
    fn parse_range_capability_missing_field() {
        let err = parse_range_capability("min_granularity=4,sparse=false")
            .expect_err("missing max_span rejected");
        assert!(err.contains("max_span"), "unexpected error message: {err}");
    }
    #[test]
    fn parse_stream_budget_success() {
        let budget =
            parse_stream_budget("max_in_flight=5,max_bytes_per_sec=1000,burst=200").unwrap();
        assert_eq!(budget.max_in_flight, 5);
        assert_eq!(budget.max_bytes_per_sec, 1000);
        assert_eq!(budget.burst_bytes, Some(200));
    }
    #[test]
    fn numeric_parsers_reject_noncanonical_unsigned_tokens() {
        for value in [
            "", " 1", "1 ", "+1", "01", "1_000", "0Xff", "0x0f", "0xFF", "-1",
        ] {
            let err = parse_u64(value).expect_err("noncanonical u64 token must fail");
            assert!(
                err.contains("canonical unsigned"),
                "unexpected u64 error for {value:?}: {err}"
            );
        }
        assert_eq!(parse_u64("0").expect("canonical zero"), 0);
        assert_eq!(parse_u64("0x0").expect("canonical hex zero"), 0);
        assert_eq!(parse_u64("0xff").expect("canonical lowercase hex"), 255);
        assert_eq!(
            parse_xor_quantity("0.000000001")
                .expect("canonical sub-micro XOR quantity")
                .to_string(),
            "0.000000001"
        );
        assert_eq!(
            parse_xor_quantity("340282366920938463463374607431768211456")
                .expect("canonical XOR quantity wider than u128")
                .to_string(),
            "340282366920938463463374607431768211456"
        );
        for value in ["", "01", "1.0", "+1", "-1", " 1", "1 ", "0x1"] {
            parse_xor_quantity(value).expect_err("noncanonical XOR quantity must fail");
        }
        assert_eq!(parse_u32("42").expect("canonical u32"), 42);
        assert_eq!(parse_u16("7").expect("canonical u16"), 7);
        assert_eq!(parse_u8("15").expect("canonical u8"), 15);
        let err = parse_u16("70000").expect_err("u16 overflow must still fail");
        assert!(
            err.contains("number too large"),
            "unexpected overflow error: {err}"
        );
    }
    #[test]
    fn hex_parsers_reject_noncanonical_material() {
        assert_eq!(
            parse_hex_vec("00ff10").expect("canonical lowercase hex"),
            vec![0x00, 0xff, 0x10]
        );
        for value in ["", "f", "0x00", "0X00", "00 ", " 00", "AA", "aA", "gg"] {
            let err = parse_hex_vec(value).expect_err("noncanonical hex must fail");
            assert!(
                err.contains("lowercase even-length hex"),
                "unexpected error for {value:?}: {err}"
            );
        }
    }
    #[test]
    fn fixed_hex_parser_requires_exact_width() {
        let exact = "11".repeat(32);
        assert_eq!(
            parse_hex_fixed::<32>(&exact).expect("exact provider id"),
            [0x11; 32]
        );
        for (value, expected) in [
            ("11".repeat(31), "expected exactly 32 hex bytes"),
            ("11".repeat(33), "expected exactly 32 hex bytes"),
            ("AA".repeat(32), "lowercase even-length hex"),
        ] {
            let err = parse_hex_fixed::<32>(&value).expect_err("fixed hex must fail");
            assert!(
                err.contains(expected),
                "expected {expected:?} for {value:?}, got: {err}"
            );
        }
    }
    #[test]
    fn structured_hex_payloads_reject_noncanonical_forms() {
        for (value, expected) in [
            ("vendor:ABCDEF", "lowercase even-length hex"),
            ("vendor:abc", "lowercase even-length hex"),
            ("vendor:0xabcdef", "lowercase even-length hex"),
            ("torii: aa", "lowercase even-length hex"),
        ] {
            let err = parse_capability(value).expect_err("noncanonical capability payload fails");
            assert!(
                err.contains(expected),
                "expected {expected:?} for {value:?}, got: {err}"
            );
        }
        let mut opts = EmitOptions {
            endpoints: vec![AdvertEndpoint {
                kind: EndpointKind::Torii,
                host_pattern: "localhost".into(),
                metadata: Vec::new(),
            }],
            ..EmitOptions::default()
        };
        let err = parse_endpoint_metadata("tls_fingerprint:AA", &mut opts)
            .expect_err("noncanonical endpoint metadata hex fails");
        assert!(
            err.contains("lowercase even-length hex"),
            "unexpected endpoint metadata error: {err}"
        );
    }
    #[test]
    fn parse_range_capability_rejects_noncanonical_numeric_fields() {
        for value in [
            "max_span=016,min_granularity=4",
            "max_span=16,min_granularity=04",
            "max_span=16, min_granularity=4",
            "max_span=16,min_granularity=4,",
        ] {
            let err =
                parse_range_capability(value).expect_err("noncanonical range capability must fail");
            assert!(
                err.contains("canonical")
                    || err.contains("whitespace")
                    || err.contains("empty entries"),
                "unexpected range capability error for {value:?}: {err}"
            );
        }
    }
    #[test]
    fn parse_stream_budget_rejects_noncanonical_numeric_fields() {
        for value in [
            "max_in_flight=05,max_bytes_per_sec=1000",
            "max_in_flight=5,max_bytes_per_sec=01000",
            "max_in_flight=5,max_bytes_per_sec=1000,burst=0x0f",
            "max_in_flight=5, max_bytes_per_sec=1000",
            "max_in_flight=5,max_bytes_per_sec=1000,",
        ] {
            let err = parse_stream_budget(value).expect_err("noncanonical stream budget must fail");
            assert!(
                err.contains("canonical")
                    || err.contains("whitespace")
                    || err.contains("empty entries"),
                "unexpected stream budget error for {value:?}: {err}"
            );
        }
    }
    #[test]
    fn parse_transport_hint_enforces_priority() {
        let hint = parse_transport_hint("torii:0").expect("valid hint parses");
        assert_eq!(hint.protocol, TransportProtocol::ToriiHttpRange);
        assert_eq!(hint.priority, 0);
        let err = parse_transport_hint("quic:32").expect_err("priority above 15 rejected");
        assert!(
            err.contains("invalid transport hint"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn parse_transport_hint_rejects_noncanonical_priority() {
        for value in ["torii:01", "torii:+1", "torii: 1", " torii:1"] {
            let err =
                parse_transport_hint(value).expect_err("noncanonical transport hint must fail");
            assert!(
                err.contains("canonical") || err.contains("whitespace"),
                "unexpected transport hint error for {value:?}: {err}"
            );
        }
    }
    #[test]
    fn v1_selector_parsers_reject_compatibility_aliases() {
        for value in ["HOT", "Hot", " hot", "hot "] {
            parse_availability(value).expect_err("availability aliases must fail");
        }
        for value in [
            "torii-gateway",
            "quic-noise",
            "potr_mldsa",
            "TORII",
            " torii",
            "torii ",
            "chunk-range",
            "chunk_range",
            "soranet_pq",
            "soranet-hybrid-pq",
        ] {
            parse_capability(value).expect_err("capability aliases must fail");
        }
        for value in [
            "",
            "Guard",
            " guard",
            "guard ",
            "stage-a",
            "stagea",
            "guard+strict",
            "guard,strict",
            "guard|strict",
        ] {
            parse_soranet_pq(value).expect_err("SoraNet PQ aliases must fail");
        }
        for value in [
            "max-chunk-span=16,min_granularity=4",
            "max_chunk_span=16,min_granularity=4",
            "max_span=16,min-granularity=4",
            "max_span=16,min_granularity=4,supports_sparse_offsets=true",
            "max_span=16,min_granularity=4,requires_alignment=true",
            "max_span=16,min_granularity=4,supports_merkle_proof=true",
            "MAX_SPAN=16,min_granularity=4",
        ] {
            parse_range_capability(value).expect_err("range field aliases must fail");
        }
        for value in [
            "max-in-flight=2,max_bytes_per_sec=1024",
            "inflight=2,max_bytes_per_sec=1024",
            "max_in_flight=2,max-bytes-per-sec=1024",
            "max_in_flight=2,max_rate=1024",
            "max_in_flight=2,max_bytes_per_sec=1024,burst_bytes=512",
            "MAX_IN_FLIGHT=2,max_bytes_per_sec=1024",
        ] {
            parse_stream_budget(value).expect_err("stream-budget field aliases must fail");
        }
        for value in [
            "torii-http",
            "torii_http",
            "torii-range",
            "quic-stream",
            "quic_stream",
            "relay",
            "soranet-relay",
            "soranet_relay",
            "vendor-reserved",
            "vendor_reserved",
            "TORII",
        ] {
            parse_transport_protocol(value).expect_err("transport aliases must fail");
        }
        for value in [
            "noritorpc:storage.example",
            "TORII:storage.example",
            " torii:storage.example",
        ] {
            parse_endpoint(value).expect_err("endpoint aliases must fail");
        }
        for value in ["tls:11", "tls-fingerprint:11", "TLS_FINGERPRINT:11"] {
            let mut opts = EmitOptions {
                endpoints: vec![
                    parse_endpoint("torii:storage.example").expect("canonical endpoint"),
                ],
                ..EmitOptions::default()
            };
            parse_endpoint_metadata(value, &mut opts).expect_err("metadata alias must fail");
        }
        for value in ["1", "0", "yes", "no", "TRUE", "False", " true"] {
            parse_bool(value).expect_err("boolean aliases must fail");
        }
    }
    #[test]
    fn v1_selector_parsers_accept_exact_canonical_tokens() {
        for value in ["hot", "warm", "cold"] {
            let availability = parse_availability(value).expect("canonical availability");
            assert_eq!(availability_name(availability), value);
        }
        for (selector, label) in [
            ("torii", "torii_gateway"),
            ("quic", "quic_noise"),
            ("vendor", "vendor_reserved"),
        ] {
            let capability = parse_capability(selector).expect("canonical payload-free capability");
            assert_eq!(capability_name(capability.cap_type), label);
        }
        parse_capability(&format!("potr-mldsa:{}", "11".repeat(1_952)))
            .expect("canonical PoTR capability");
        for value in ["guard", "majority", "strict"] {
            parse_soranet_pq(value).expect("canonical SoraNet PQ level");
        }
        parse_range_capability(
            "max_span=16,min_granularity=4,sparse=true,alignment=false,merkle=true",
        )
        .expect("canonical range capability");
        parse_stream_budget("max_in_flight=2,max_bytes_per_sec=1024,burst=512")
            .expect("canonical stream budget");
        for (selector, label) in [
            ("torii", "torii_http_range"),
            ("quic", "quic_stream"),
            ("soranet", "soranet_relay"),
            ("vendor", "vendor_reserved"),
        ] {
            let protocol = parse_transport_protocol(selector).expect("canonical transport");
            assert_eq!(transport_protocol_name(protocol), label);
        }
        for value in [
            "torii:storage.example",
            "quic:storage.example",
            "norito-rpc:storage.example",
        ] {
            parse_endpoint(value).expect("canonical endpoint kind");
        }
        let mut opts = EmitOptions {
            endpoints: vec![parse_endpoint("torii:storage.example").expect("canonical endpoint")],
            ..EmitOptions::default()
        };
        for value in ["tls_fingerprint:11", "alpn:11", "region:global"] {
            parse_endpoint_metadata(value, &mut opts).expect("canonical endpoint metadata");
        }
        assert!(parse_bool("true").expect("canonical true"));
        assert!(!parse_bool("false").expect("canonical false"));
    }
    #[test]
    fn structured_selectors_reject_duplicate_fields() {
        for value in [
            "max_span=16,max_span=16,min_granularity=4",
            "max_span=16,min_granularity=4,sparse=true,sparse=false",
            "max_span=16,min_granularity=4,alignment=true,alignment=false",
            "max_span=16,min_granularity=4,merkle=true,merkle=false",
        ] {
            let err = parse_range_capability(value).expect_err("duplicate range field must fail");
            assert!(err.contains("multiple times"), "unexpected error: {err}");
        }
        for value in [
            "max_in_flight=2,max_in_flight=3,max_bytes_per_sec=1024",
            "max_in_flight=2,max_bytes_per_sec=1024,max_bytes_per_sec=2048",
            "max_in_flight=2,max_bytes_per_sec=1024,burst=512,burst=256",
        ] {
            let err = parse_stream_budget(value).expect_err("duplicate budget field must fail");
            assert!(err.contains("multiple times"), "unexpected error: {err}");
        }
    }
    #[test]
    fn reviewed_fingerprint_requires_exact_lowercase_sha256_hex() {
        let fingerprint =
            parse_reviewed_fingerprint(&"ab".repeat(32)).expect("canonical reviewed fingerprint");
        assert_eq!(fingerprint, [0xAB; 32]);
        for value in [
            "",
            "ab",
            &"AB".repeat(32),
            &format!("0x{}", "ab".repeat(32)),
        ] {
            let err = parse_reviewed_fingerprint(value)
                .expect_err("noncanonical reviewed fingerprint must fail");
            assert!(
                err.contains("lowercase SHA-256 hex"),
                "unexpected fingerprint error: {err}"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn trusted_input_rejects_hardlinks() {
        let temp = tempdir().expect("tempdir");
        let temp_path = temp.path().canonicalize().expect("canonical tempdir");
        let original = temp_path.join("provider.pub");
        let linked = temp_path.join("provider-copy.pub");
        fs::write(&original, [0xA5; ED25519_PUBLIC_KEY_BYTES]).expect("write public key");
        fs::hard_link(&original, &linked).expect("create hard link");
        let err = read_trusted_regular_file(
            &original,
            "provider advert public key",
            ED25519_PUBLIC_KEY_BYTES as u64,
            Some(ED25519_PUBLIC_KEY_BYTES as u64),
        )
        .expect_err("hard-linked input must fail closed");
        assert!(
            err.contains("exactly one hard link"),
            "unexpected hard-link error: {err}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn trusted_metadata_detects_path_replacement() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("provider.pub");
        let displaced = temp.path().join("provider.displaced");
        fs::write(&path, [0xA5; ED25519_PUBLIC_KEY_BYTES]).expect("write original");
        let before = fs::symlink_metadata(&path).expect("inspect original");
        fs::rename(&path, &displaced).expect("displace original");
        fs::write(&path, [0xA5; ED25519_PUBLIC_KEY_BYTES]).expect("write replacement");
        let after = fs::symlink_metadata(&path).expect("inspect replacement");
        assert!(
            !trusted_metadata_matches(&before, &after),
            "same-sized path replacement must not retain trusted identity"
        );
    }
    #[cfg(unix)]
    #[test]
    fn write_bytes_rejects_existing_hardlinked_output_without_mutation() {
        let temp = tempdir().expect("tempdir");
        let temp_path = temp.path().canonicalize().expect("canonical tempdir");
        let output = temp_path.join("advert.to");
        let alias = temp_path.join("advert.alias");
        fs::write(&output, b"existing").expect("write existing output");
        fs::hard_link(&output, &alias).expect("create output hard link");
        let err = write_bytes(&output, b"replacement").expect_err("reject existing hard link");
        assert!(
            err.contains("already exists"),
            "unexpected output error: {err}"
        );
        assert_eq!(fs::read(&output).expect("read output"), b"existing");
        assert_eq!(fs::read(&alias).expect("read alias"), b"existing");
    }
    #[test]
    fn verify_advert_signature_rejects_all_zero_signature_material() {
        let opts = EmitOptions {
            network_id: Some([0xA1; 32]),
            profile_handle: Some("sorafs.sf1@1.0.0".into()),
            provider_id: Some([0x11; 32]),
            stake_pool_id: Some([0x22; 32]),
            stake_amount: Some(
                XorQuantity::try_from_micro(1_000_000)
                    .expect("test micro-XOR amount is representable"),
            ),
            availability: Some(AvailabilityTier::Hot),
            max_latency_ms: Some(500),
            max_streams: Some(5),
            capabilities: vec![CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            }],
            endpoints: vec![AdvertEndpoint {
                kind: EndpointKind::Torii,
                host_pattern: "localhost".into(),
                metadata: Vec::new(),
            }],
            topics: vec![RendezvousTopic {
                topic: "sorafs.zero-signature.primary".into(),
                region: "global".into(),
            }],
            issued_at: Some(1_700_000_000),
            ..EmitOptions::default()
        };
        let signing_key = SigningKey::from_bytes(&[0xAB; 32]);
        let mut advert = externally_sign_advert(&opts, &signing_key);
        advert.signature.signature.fill(0);
        let err = verify_advert_signature(&advert)
            .expect_err("all-zero signature material must be rejected");
        assert!(err.contains("all zero"), "unexpected error: {err}");
    }
    #[test]
    fn verify_advert_signature_rejects_malformed_signature_r() {
        const SMALL_ORDER_R: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_R: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let opts = EmitOptions {
            network_id: Some([0xA1; 32]),
            profile_handle: Some("sorafs.sf1@1.0.0".into()),
            provider_id: Some([0x11; 32]),
            stake_pool_id: Some([0x22; 32]),
            stake_amount: Some(
                XorQuantity::try_from_micro(1_000_000)
                    .expect("test micro-XOR amount is representable"),
            ),
            availability: Some(AvailabilityTier::Hot),
            max_latency_ms: Some(500),
            max_streams: Some(5),
            capabilities: vec![CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            }],
            endpoints: vec![AdvertEndpoint {
                kind: EndpointKind::Torii,
                host_pattern: "localhost".into(),
                metadata: Vec::new(),
            }],
            topics: vec![RendezvousTopic {
                topic: "sorafs.invalid-r.primary".into(),
                region: "global".into(),
            }],
            issued_at: Some(1_700_000_000),
            ..EmitOptions::default()
        };
        let signing_key = SigningKey::from_bytes(&[0xAB; 32]);
        for (label, replacement_r, expected) in [
            ("small-order", SMALL_ORDER_R, "small-order"),
            ("noncanonical", NONCANONICAL_R, "not a canonical"),
        ] {
            let mut advert = externally_sign_advert(&opts, &signing_key);
            advert.signature.signature[..32].copy_from_slice(&replacement_r);
            let err = verify_advert_signature(&advert)
                .expect_err("malformed signature R must be rejected");
            assert!(
                err.contains(expected),
                "{label} signature R produced unexpected error: {err}"
            );
        }
    }
    #[test]
    fn resolves_canonical_handle() {
        let handle = resolve_profile_handle("sorafs.sf1@1.0.0").expect("handle resolves");
        assert_eq!(handle, "sorafs.sf1@1.0.0");
    }
    #[test]
    fn rejects_whitespace_padded_profile_handle() {
        let err = resolve_profile_handle(" sorafs.sf1@1.0.0")
            .expect_err("whitespace-padded handle must fail");
        assert!(err.contains("whitespace"), "unexpected error: {err}");
    }
    #[test]
    fn rejects_profile_selector_aliases() {
        for value in [
            "1",
            "01",
            "99",
            "sorafs-sf1",
            "sorafs/sf1@1.0.0",
            "SORAFS.SF1@1.0.0",
        ] {
            resolve_profile_handle(value).expect_err("profile selector alias must fail");
        }
    }
    #[test]
    fn rejects_empty_input() {
        let err = resolve_profile_handle("").expect_err("empty input");
        assert!(err.contains("cannot be empty"));
    }
}
