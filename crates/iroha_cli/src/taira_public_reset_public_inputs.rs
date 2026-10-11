//! Complete public genesis and canary inputs for native reset assembly.
//!
//! This command verifies public identity and signatures, not executed genesis results or
//! release qualification. It never opens private keys or contacts a network. The whole
//! public bundle is published atomically; the same inputs can be retried without replacement.
//! Preparation refuses a generated network whose validator `[gov]`/`[torii.faucet]` profile and
//! genesis citizens cannot seat the SORA Parliament, or whose citizenship escrow is controlled by
//! a key published in this repository (`specs/sccp.md` §4.14.5).

use super::*;
use iroha_data_model::NetworkId;

const SCHEMA: &str = "iroha.taira.public-reset.public-inputs.v1";
const MAX_GENESIS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IDENTITY_BYTES: u64 = 1024;
const OUTPUT_FILES: [&str; 6] = [
    "genesis.signed.nrt",
    "nexus-amx-context.v1.bin",
    "genesis.json",
    "genesis.hash",
    "canary-onboarding-request.json",
    "public-inputs.json",
];

/// Derive all public identity inputs directly from native generator output.
#[derive(clap::Args, Debug)]
pub(super) struct PreparePublicInputs {
    /// Native localnet output containing signed genesis and its public identity files.
    #[arg(long, value_name = "DIR")]
    localnet_dir: PathBuf,
    /// Canonical public key file for the reset's separately generated canary account.
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present = "intent",
        conflicts_with = "intent"
    )]
    canary_public_key: Option<PathBuf>,
    /// Explicit topology intent; native account parsing derives its public canary key.
    #[arg(long, value_name = "PATH", conflicts_with = "canary_public_key")]
    intent: Option<PathBuf>,
    /// Atomic public bundle under an existing owner-only parent directory.
    /// Repeating the same request verifies and reuses an identical completed bundle.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
}

/// Typed public identities consumed by reset assembly without manual conversion.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct PublicInputsV1 {
    pub(super) schema: String,
    pub(super) network_id: NetworkId,
    /// Consensus genesis identity; distinct from the SHA256 of the signed wire file.
    pub(super) genesis_hash: String,
    pub(super) signed_genesis_sha256: String,
    pub(super) nexus_amx_context_sha256: String,
    pub(super) raw_manifest_sha256: String,
    pub(super) genesis_public_key: PublicKey,
    pub(super) canary_public_key: PublicKey,
    pub(super) canary_onboarding_request: AccountOnboardingPlanRequestV1,
}

fn require(condition: bool, message: &'static str) -> Result<()> {
    if !condition {
        return Err(eyre!(message));
    }
    Ok(())
}

fn canonical_line(bytes: &[u8]) -> Result<&str> {
    require(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_IDENTITY_BYTES,
        "public identity text is empty or exceeds its bound",
    )?;
    let text = std::str::from_utf8(bytes).wrap_err("public identity text is not UTF-8")?;
    let value = text
        .strip_suffix('\n')
        .ok_or_else(|| eyre!("public identity requires one terminating newline"))?;
    require(
        !value.is_empty() && !value.chars().any(char::is_whitespace),
        "public identity must be one canonical unpadded line",
    )?;
    Ok(value)
}

fn canonical_public_key(bytes: &[u8]) -> Result<PublicKey> {
    let value = canonical_line(bytes)?;
    let key: PublicKey = value.parse().wrap_err("invalid native public key")?;
    require(
        key.to_string() == value,
        "public key spelling is not canonical",
    )?;
    Ok(key)
}

fn derive(
    wire: &[u8],
    manifest_bytes: &[u8],
    network_bytes: &[u8],
    genesis_key_bytes: &[u8],
    canary_key_bytes: &[u8],
    nexus_context: &[u8],
) -> Result<PublicInputsV1> {
    let _guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
    require(
        !wire.is_empty() && wire.len() as u64 <= MAX_GENESIS_BYTES,
        "signed genesis is empty or exceeds its byte bound",
    )?;
    let network_text = canonical_line(network_bytes)?;
    let network: NetworkId = network_text.parse().wrap_err("invalid checked NetworkId")?;
    require(
        network.to_string() == network_text,
        "NetworkId spelling is not canonical",
    )?;
    let genesis_key = canonical_public_key(genesis_key_bytes)?;
    let canary_key = canonical_public_key(canary_key_bytes)?;
    require(
        canary_key.try_to_bytes()?.0 == Algorithm::Ed25519,
        "canary public key must use Ed25519",
    )?;
    let (genesis_hash, metadata) =
        iroha_core::release_identity::genesis_identity(wire, &genesis_key)
            .wrap_err("generated signed genesis failed native identity validation")?;
    require(
        genesis_hash == Hash::from(network.into_genesis_hash()),
        "signed genesis hash differs from checked network identity",
    )?;
    inputs::validate_taira_genesis_mode(metadata.mode)?;
    require(
        !nexus_context.is_empty()
            && nexus_context.len() <= iroha_data_model::nexus::MAX_NEXUS_AMX_CONTEXT_BYTES_V1
            && Hash::new(nexus_context)
                == Hash::prehashed(metadata.sumeragi_context.nexus_amx_context_hash),
        "Nexus AMX context differs from signed genesis",
    )?;
    iroha_data_model::nexus::decode_nexus_amx_context_v1(nexus_context)
        .map_err(|error| eyre!("invalid Nexus AMX context: {error:?}"))?;
    require(
        !manifest_bytes.is_empty() && manifest_bytes.len() as u64 <= MAX_JSON_BYTES,
        "public raw genesis manifest exceeds its bound",
    )?;
    let manifest: iroha_genesis::RawGenesisTransaction = json::from_slice(manifest_bytes)?;
    iroha_genesis::validate_prepared_genesis_bundle(
        wire,
        &manifest,
        &genesis_key,
        network.into_genesis_hash(),
    )
    .wrap_err("raw genesis manifest differs from signed genesis")?;
    let account = AccountId::new(canary_key.clone());
    let request = AccountOnboardingPlanRequestV1::try_new(
        crate::taira::canary_alias(&canary_key),
        &account,
        std::iter::empty(),
    )?;
    Ok(PublicInputsV1 {
        schema: SCHEMA.to_owned(),
        network_id: network,
        genesis_hash: genesis_hash.to_string(),
        signed_genesis_sha256: sha256_hex(wire),
        nexus_amx_context_sha256: sha256_hex(nexus_context),
        raw_manifest_sha256: sha256_hex(manifest_bytes),
        genesis_public_key: genesis_key,
        canary_public_key: canary_key,
        canary_onboarding_request: request,
    })
}

fn json_line<T: JsonSerialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn public_file(path: &Path, maximum: u64) -> Result<(PinnedInput, Vec<u8>)> {
    let (file, snapshot) = open_pinned_regular(path, "public reset input")?;
    let bytes = read_pinned_bytes(
        path,
        "public reset input",
        file.try_clone()?,
        &snapshot,
        maximum,
    )?;
    Ok((
        PinnedInput {
            path: path.to_path_buf(),
            file,
            snapshot,
        },
        bytes,
    ))
}

/// Revalidate a complete retained bundle before its values enter an inventory.
pub(super) fn load(directory: &Path) -> Result<PublicInputsV1> {
    validate_absolute_normal_path(directory, "public input bundle")?;
    validate_owner_private_dir(directory, "public input bundle")?;
    let mut actual: Vec<_> = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<_>>()?;
    actual.sort();
    let mut expected: Vec<_> = OUTPUT_FILES
        .iter()
        .map(|name| std::ffi::OsString::from(*name))
        .collect();
    expected.sort();
    require(
        actual == expected,
        "public input bundle has missing or unexpected files",
    )?;
    let (record_pin, record_bytes) =
        public_file(&directory.join("public-inputs.json"), MAX_JSON_BYTES)?;
    let record: PublicInputsV1 = json::from_slice(&record_bytes)?;
    let (wire_pin, wire) = public_file(&directory.join("genesis.signed.nrt"), MAX_GENESIS_BYTES)?;
    let (manifest_pin, manifest) = public_file(&directory.join("genesis.json"), MAX_JSON_BYTES)?;
    let (context_pin, context) = public_file(
        &directory.join("nexus-amx-context.v1.bin"),
        iroha_data_model::nexus::MAX_NEXUS_AMX_CONTEXT_BYTES_V1 as u64,
    )?;
    let derived = derive(
        &wire,
        &manifest,
        format!("{}\n", record.network_id).as_bytes(),
        format!("{}\n", record.genesis_public_key).as_bytes(),
        format!("{}\n", record.canary_public_key).as_bytes(),
        &context,
    )?;
    require(
        record == derived && record_bytes == json_line(&derived)?,
        "public input bundle identity differs",
    )?;
    for (name, expected) in [
        (
            "genesis.hash",
            format!("{}\n", derived.genesis_hash).into_bytes(),
        ),
        (
            "canary-onboarding-request.json",
            json_line(&derived.canary_onboarding_request)?,
        ),
    ] {
        let (pin, bytes) = public_file(&directory.join(name), MAX_JSON_BYTES)?;
        require(
            bytes == expected,
            "public input bundle artifact differs from its identity",
        )?;
        #[cfg(unix)]
        require(
            pin.snapshot.mode & 0o7777 == 0o644,
            "public bundle artifacts must use mode0644",
        )?;
        revalidate_pinned(&pin, "public input bundle artifact")?;
    }
    for pin in [&record_pin, &wire_pin, &manifest_pin, &context_pin] {
        #[cfg(unix)]
        require(
            pin.snapshot.mode & 0o7777 == 0o644,
            "public bundle artifacts must use mode0644",
        )?;
        revalidate_pinned(pin, "public input bundle")?;
    }
    Ok(derived)
}

/// Atomically produce a bundle, or verify an identical completed prior invocation.
#[cfg(unix)]
pub(super) fn prepare(args: &PreparePublicInputs, output: &mut impl Write) -> Result<()> {
    let _guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
    validate_absolute_normal_path(&args.localnet_dir, "generated network directory")?;
    validate_owner_private_dir(&args.localnet_dir, "generated network directory")?;
    validate_absolute_normal_path(&args.output_dir, "public input output")?;
    let parent = args
        .output_dir
        .parent()
        .ok_or_else(|| eyre!("public input output has no parent"))?;
    validate_owner_private_dir(parent, "public input output parent")?;
    let mut retained = Vec::new();
    for (path, maximum) in [
        (
            args.localnet_dir.join("genesis.signed.nrt"),
            MAX_GENESIS_BYTES,
        ),
        (
            args.localnet_dir.join("genesis.expected_hash"),
            MAX_IDENTITY_BYTES,
        ),
        (
            args.localnet_dir.join("genesis.public_key"),
            MAX_IDENTITY_BYTES,
        ),
        (args.localnet_dir.join("genesis.json"), MAX_JSON_BYTES),
        (
            args.localnet_dir.join("nexus-amx-context.v1.bin"),
            iroha_data_model::nexus::MAX_NEXUS_AMX_CONTEXT_BYTES_V1 as u64,
        ),
    ] {
        retained.push(public_file(&path, maximum)?);
    }
    let (canary_bytes, draft_request) = match (&args.canary_public_key, &args.intent) {
        (Some(path), None) => {
            let input = public_file(path, MAX_IDENTITY_BYTES)?;
            let bytes = input.1.clone();
            retained.push(input);
            (bytes, None)
        }
        (None, Some(path)) => {
            let pin = pin_owner_private_file(path, "reset topology intent")?;
            let bytes = read_pinned_bytes(
                path,
                "reset topology intent",
                pin.file.try_clone()?,
                &pin.snapshot,
                MAX_JSON_BYTES,
            )?;
            let request = inputs::topology_canary_request(&bytes)?;
            let account = AccountId::parse_encoded(&request.account_id)?;
            if account.to_string() != request.account_id {
                return Err(eyre!("draft canary account is not canonical"));
            }
            let key = account
                .try_signatory()
                .ok_or_else(|| eyre!("draft canary requires one native signatory"))?;
            let key_bytes = format!("{key}\n").into_bytes();
            retained.push((pin, bytes));
            (key_bytes, Some(request))
        }
        _ => {
            return Err(eyre!(
                "select exactly one canary public key file or reset topology intent"
            ));
        }
    };
    let record = derive(
        &retained[0].1,
        &retained[3].1,
        &retained[1].1,
        &retained[2].1,
        &canary_bytes,
        &retained[4].1,
    )?;
    if draft_request
        .as_ref()
        .is_some_and(|request| request != &record.canary_onboarding_request)
    {
        return Err(eyre!(
            "draft canary request differs from its canonical native public identity"
        ));
    }
    // The Parliament is the only SCCP governance authority: refuse a network whose validator
    // profile and genesis citizens cannot seat it (specs/sccp.md §4.14.5, §4.18).
    let manifest: iroha_genesis::RawGenesisTransaction = json::from_slice(&retained[3].1)?;
    crate::taira::parliament_seating::require_seated_localnet(&args.localnet_dir, &manifest)?;
    if args.output_dir.try_exists()? {
        require(
            load(&args.output_dir)? == record,
            "output already contains a different public input bundle",
        )?;
    } else {
        let temporary = tempfile::Builder::new()
            .prefix(".public-inputs-")
            .tempdir_in(parent)?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        for (name, bytes) in [
            ("genesis.signed.nrt", retained[0].1.clone()),
            ("genesis.json", retained[3].1.clone()),
            ("nexus-amx-context.v1.bin", retained[4].1.clone()),
            (
                "genesis.hash",
                format!("{}\n", record.genesis_hash).into_bytes(),
            ),
            (
                "canary-onboarding-request.json",
                json_line(&record.canary_onboarding_request)?,
            ),
            ("public-inputs.json", json_line(&record)?),
        ] {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(temporary.path().join(name))?;
            file.write_all(&bytes)?;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
        }
        File::open(temporary.path())?.sync_all()?;
        for (pin, _) in &retained {
            revalidate_pinned(pin, "generated public input")?;
        }
        validate_owner_private_dir(parent, "public input output parent")?;
        match rustix::fs::renameat_with(
            rustix::fs::CWD,
            temporary.path(),
            rustix::fs::CWD,
            &args.output_dir,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                require(
                    load(&args.output_dir)? == record,
                    "concurrent output contains a different public input bundle",
                )?;
            }
            Err(error) => {
                return Err(error).wrap_err("publish public input bundle without replacement");
            }
        }
    }
    File::open(parent)?.sync_all()?;
    for (pin, _) in &retained {
        revalidate_pinned(pin, "generated public input")?;
    }
    require(
        load(&args.output_dir)? == record,
        "published public input bundle differs",
    )?;
    output.write_all(&json_line(&record)?)?;
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn prepare(_args: &PreparePublicInputs, _output: &mut impl Write) -> Result<()> {
    Err(eyre!(
        "public Taira reset input preparation requires a Unix operator host"
    ))
}

#[cfg(test)]
#[path = "taira_public_reset_public_inputs_tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn deployment_genesis_fixture()
-> (iroha_data_model::block::SignedBlock, iroha_crypto::KeyPair) {
    tests::deployment_genesis_fixture()
}

/// Exact executed genesis retained with its validated native manifest binding.
#[cfg(test)]
pub(super) fn deployment_validated_genesis_fixture() -> iroha_genesis::ValidatedGenesisBundle {
    tests::deployment_validated_genesis_fixture()
}

/// Native signed genesis with explicitly registered and activated validator accounts.
#[cfg(test)]
pub(super) fn deployment_lane_genesis_fixture()
-> (iroha_data_model::block::SignedBlock, iroha_crypto::KeyPair) {
    tests::deployment_lane_genesis_fixture()
}
