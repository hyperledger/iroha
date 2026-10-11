//! Signed-genesis trust root and one-owner beacon DKG for exact 4-through-31-seat committees.

use super::*;

const REQUEST_SCHEMA: &str = "iroha.global-beacon.bootstrap.request.v1";
const BUNDLE_SCHEMA: &str = "iroha.global-beacon.bootstrap.bundle.v1";

/// Pin a fresh network to one genesis beacon transcript identity (Core's canonical one).
pub(super) fn canonical_genesis_session_id(network: NetworkId) -> [u8; 32] {
    iroha_core::beacon::ceremony::global_beacon_genesis_session_id_v1(network)
}

/// Pin the network's only genesis dealer attempt across crash recovery (Core's canonical one).
pub(super) fn canonical_genesis_attempt_id(network: NetworkId) -> [u8; 32] {
    iroha_core::beacon::ceremony::global_beacon_genesis_attempt_id_v1(network)
}

/// Reject a rerolled session under the same signed genesis or attempt root.
pub(super) fn genesis_session_identity_is_canonical(
    network: NetworkId,
    session: GlobalThresholdBeaconDkgSessionV1,
) -> bool {
    session.network_id == network
        && session.session_id == canonical_genesis_session_id(network)
        && session.attempt_id == canonical_genesis_attempt_id(network)
        && session.authority_generation == 0
}

#[derive(Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct GenesisRequest {
    schema: String,
    dkg_session: GlobalThresholdBeaconDkgSessionV1,
    target_roster: Vec<PeerId>,
    authorization_roster: Vec<PeerId>,
    provider_handles: Vec<String>,
    provider_revision: u64,
}

#[derive(Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct GenesisProof {
    manifest: iroha_genesis::RawGenesisTransaction,
    signed_wire: Vec<u8>,
    public_key: PublicKey,
}

#[derive(Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct GenesisPublicBundle {
    schema: String,
    request: GenesisRequest,
    genesis: GenesisProof,
    phase_proofs: Vec<NativeFinalityJournal>,
    finalized_observed_height: u64,
    record: FinalizedGlobalThresholdBeaconKeySessionRecordV1,
    finalization_draft: ThresholdKeyLifecycleCertificateV1,
    providers: Vec<Provider>,
}

fn read_genesis_proof(
    manifest_path: &Path,
    wire_path: &Path,
    key_path: &Path,
) -> Result<GenesisProof> {
    iroha_genesis::init_instruction_registry();
    let text = read_public_bytes_bounded(key_path, 512)?;
    let literal = std::str::from_utf8(&text)
        .map_err(|_| Error::InvalidInput)?
        .strip_suffix('\n')
        .ok_or(Error::InvalidInput)?;
    let public_key = literal
        .parse::<PublicKey>()
        .map_err(|_| Error::InvalidInput)?;
    if public_key.to_string() != literal {
        return Err(Error::InvalidInput);
    }
    Ok(GenesisProof {
        manifest: read_json(manifest_path)?,
        signed_wire: read_public_bytes(wire_path)?,
        public_key,
    })
}

fn first_required_pulse_height(genesis: &GenesisProof) -> Result<u64> {
    let parameters = genesis
        .manifest
        .effective_parameters()
        .map_err(|_| Error::InvalidInput)?;
    parameters
        .sumeragi()
        .epoch_length_blocks
        .get()
        .checked_sub(1)
        .ok_or(Error::Height)
}

/// Derive DKG and certificate thresholds from the complete canonical voting roster.
fn genesis_roster_geometry(roster: &[PeerId]) -> Result<(u16, u16, u16)> {
    let seats = roster.len();
    if !is_valid_committee_size(seats) || roster.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::InvalidInput);
    }
    let committee_size = u16::try_from(seats).map_err(|_| Error::InvalidInput)?;
    let faults = (committee_size - 1) / 3;
    Ok((committee_size, faults + 1, committee_size - faults))
}

/// Bind public ceremony inputs to the already authenticated exact genesis roster.
fn validate_genesis_request(
    network: NetworkId,
    request: &GenesisRequest,
    roster: &[PeerId],
) -> Result<()> {
    let session = request.dkg_session;
    let (committee_size, threshold, _) = genesis_roster_geometry(roster)?;
    if request.schema != REQUEST_SCHEMA
        || request.target_roster.as_slice() != roster
        || request.authorization_roster.as_slice() != roster
        || request.provider_handles.len() != roster.len()
        || request
            .provider_handles
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != roster.len()
        || request.provider_handles.iter().any(|handle| {
            iroha_config::parameters::validate_production_runtime_handle(handle).is_err()
        })
        || request.provider_revision == 0
        || !genesis_session_identity_is_canonical(network, session)
        || session.roster_hash != global_threshold_beacon_roster_hash_v1(roster)
        || session.committee_size != committee_size
        || session.threshold != threshold
        || session.start_height != 1
        || session.commitments_end_height != 2
        || session.deliveries_end_height != 3
        || session.acceptances_end_height != 4
    {
        return Err(Error::InvalidInput);
    }
    GlobalThresholdBeaconDkgStateV1::validate_session(
        &session,
        &AdaptiveGlobalThresholdBeaconDkgCryptoV1,
    )
    .map_err(|_| Error::Crypto)?;
    Ok(())
}

fn verify_signed_genesis_attempt(
    chain_id: &ChainId,
    limits: NativeFinalityLimits,
    network: NetworkId,
    chain_discriminant: u16,
    request: &GenesisRequest,
    genesis: &GenesisProof,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<(
    Vec<PeerId>,
    NativeJournalCursor,
    u64,
    iroha_core::beacon::AuthenticatedGlobalBeaconDkgAttemptV1,
)> {
    iroha_genesis::init_instruction_registry();
    let session = request.dkg_session;
    let validated = iroha_genesis::validate_prepared_genesis_bundle(
        &genesis.signed_wire,
        &genesis.manifest,
        &genesis.public_key,
        network.into_genesis_hash(),
    )
    .map_err(Error::GenesisBundle)?;
    if genesis.manifest.consensus_mode()
        != iroha_data_model::parameter::system::SumeragiConsensusMode::Npos
        || genesis.manifest.chain_discriminant() != chain_discriminant
        || genesis.manifest.chain_id() != chain_id
    {
        return Err(Error::InvalidInput);
    }
    let (signed_genesis, epoch) =
        authenticate_signed_genesis(&genesis.signed_wire, network, limits)?;
    if signed_genesis.hash() != validated.block().hash() {
        return Err(Error::Crypto);
    }
    let roster = epoch
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<Vec<_>>();
    validate_genesis_request(network, request, &roster)?;
    let cutoff = first_required_pulse_height(genesis)?;
    if session.acceptances_end_height >= cutoff {
        return Err(Error::Height);
    }
    // This cursor has no finalized tip until a genuine H2 journal authenticates
    // the signed genesis result through its native parent-result commitment.
    let verifier = NativeJournalCursor::new(
        chain_id.clone(),
        network,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits,
        budget,
    )?;
    let authority = iroha_core::beacon::AuthenticatedGlobalBeaconDkgAttemptV1::signed_genesis(
        &signed_genesis,
        network,
        chain_id,
    )?;
    if authority.session() != session || authority.cutoff() != cutoff {
        return Err(Error::InvalidInput);
    }
    Ok((roster, verifier, cutoff, authority))
}

#[allow(
    unsafe_code,
    reason = "the supervisor passes separate inherited public DKG and finality-proof FIFOs"
)]
/// Provision exactly one genesis voting seat under a signed-genesis trust root.
pub(super) fn provision_genesis_seat_command(
    chain_id: &ChainId,
    finality_limits: FinalityLimitsArgs,
    network: NetworkId,
    chain_discriminant: u16,
    request_path: &Path,
    manifest_path: &Path,
    wire_path: &Path,
    key_path: &Path,
    signer_index: u16,
    key_fd: Option<i32>,
    config_fd: Option<i32>,
    public_fd: i32,
    finality_fd: i32,
    attempt_root: &Path,
    timeout_ms: u64,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<()> {
    let limits = finality_limits.checked()?;
    let _profile =
        iroha_data_model::account::address::ChainDiscriminantGuard::enter(chain_discriminant);
    let (key_descriptor, from_config) = match (key_fd, config_fd) {
        (Some(198), None) => (198, false),
        (None, Some(198)) => (198, true),
        _ => return Err(Error::InvalidInput),
    };
    if public_fd < 3
        || finality_fd < 3
        || public_fd == finality_fd
        || matches!(public_fd, 198 | 199 | 200)
        || matches!(finality_fd, 198 | 199 | 200)
        || timeout_ms == 0
        || timeout_ms > MAX_TIMEOUT_MS
    {
        return Err(Error::InvalidInput);
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or(Error::Deadline)?;
    let public_input = unsafe { BorrowedFd::borrow_raw(public_fd) };
    let finality_input = unsafe { BorrowedFd::borrow_raw(finality_fd) };
    for fd in [public_input, finality_input] {
        let metadata = rustix::fs::fstat(fd).map_err(|_| Error::InvalidInput)?;
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Fifo {
            return Err(Error::InvalidInput);
        }
    }
    let request: GenesisRequest = read_json(request_path)?;
    let genesis = read_genesis_proof(manifest_path, wire_path, key_path)?;
    let (roster, verifier, _cutoff, authority) = verify_signed_genesis_attempt(
        chain_id,
        limits,
        network,
        chain_discriminant,
        &request,
        &genesis,
        budget,
    )?;
    if signer_index == 0 || usize::from(signer_index) > roster.len() {
        return Err(Error::InvalidInput);
    }
    let file = crate::taira_runtime_signer::take_inherited_private_file(key_descriptor)
        .map_err(|_| Error::InvalidCustody)?;
    let signer = if from_config {
        load_lifecycle_config(file, &network)?
    } else {
        load_lifecycle_key(file)?
    };
    if signer.public_key() != roster[usize::from(signer_index - 1)].public_key() {
        return Err(Error::InvalidCustody);
    }
    let handle = &request.provider_handles[usize::from(signer_index - 1)];
    // SAFETY: distinct inherited FIFO sources were validated above and are
    // moved once, never duplicated or reacquired on a retained attempt retry.
    use std::os::fd::FromRawFd as _;
    let attempt = seat_attempt::SeatDkgAttempt::new(
        authority,
        &roster,
        signer_index,
        signer,
        unsafe { File::from_raw_fd(public_fd) },
        unsafe { File::from_raw_fd(finality_fd) },
        verifier,
        handle,
        request.provider_revision,
        attempt_root,
        deadline,
        budget,
    )?;
    attempt.resume().map_err(Error::PendingAttempt)
}

fn validate_genesis_phase_chain(
    chain_id: &ChainId,
    limits: NativeFinalityLimits,
    network: NetworkId,
    chain_discriminant: u16,
    request: &GenesisRequest,
    genesis: &GenesisProof,
    phases: &[NativeFinalityJournal],
    budget: &iroha_allocation::AllocationBudget,
) -> Result<Vec<PeerId>> {
    let (roster, mut verifier, cutoff, _authority) = verify_signed_genesis_attempt(
        chain_id,
        limits,
        network,
        chain_discriminant,
        request,
        genesis,
        budget,
    )?;
    if phases.len() != 3 {
        return Err(Error::Height);
    }
    let mut last = 1;
    for phase in phases {
        advance_phase_journal(&mut verifier, phase, &mut last, cutoff)?;
    }
    if last != request.dkg_session.acceptances_end_height {
        return Err(Error::Height);
    }
    Ok(roster)
}

fn draft_genesis_certificate(
    roster: &[PeerId],
    record: &FinalizedGlobalThresholdBeaconKeySessionRecordV1,
    effective_height: u64,
) -> Result<ThresholdKeyLifecycleCertificateV1> {
    let (committee_size, _, quorum) = genesis_roster_geometry(roster)?;
    if effective_height <= record.session.adaptive_dkg.finalized_at_height {
        return Err(Error::Height);
    }
    Ok(ThresholdKeyLifecycleCertificateV1 {
        version: THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
        action: ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
        expected_active_session_id: None,
        effective_height,
        network_id: record.session.network_id,
        roster_hash: global_threshold_beacon_roster_hash_v1(roster),
        committee_size,
        quorum,
        session_id: record.session.session_id,
        transcript_hash: record.session.transcript_hash,
        public_state: norito::encode_canonical(record).map_err(|_| Error::Crypto)?,
        signatures: Vec::new(),
    })
}

fn validate_genesis_bundle(
    bundle: &GenesisPublicBundle,
    chain_id: &ChainId,
    limits: NativeFinalityLimits,
    network: NetworkId,
    chain_discriminant: u16,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<Vec<PeerId>> {
    let roster = validate_genesis_phase_chain(
        chain_id,
        limits,
        network,
        chain_discriminant,
        &bundle.request,
        &bundle.genesis,
        &bundle.phase_proofs,
        budget,
    )?;
    let session = bundle.request.dkg_session;
    bundle.record.validate(budget).map_err(Error::from)?;
    if bundle.schema != BUNDLE_SCHEMA
        || bundle.record.session.adaptive_dkg.session != session
        || bundle.record.session.adaptive_dkg.finalized_at_height != session.acceptances_end_height
        || bundle.finalized_observed_height != session.acceptances_end_height
        || bundle.record.activated_at_height.is_some()
        || bundle.record.retired_at_height.is_some()
        || bundle.finalization_draft.effective_height
            >= first_required_pulse_height(&bundle.genesis)?
        || bundle.finalization_draft
            != draft_genesis_certificate(
                &roster,
                &bundle.record,
                bundle.finalization_draft.effective_height,
            )?
        || bundle.providers.len() != roster.len()
    {
        return Err(Error::InvalidInput);
    }
    for (offset, provider) in bundle.providers.iter().enumerate() {
        let seat = u16::try_from(offset + 1).map_err(|_| Error::InvalidInput)?;
        if provider.signer_index != seat
            || provider.validator != roster[offset]
            || provider.handle != bundle.request.provider_handles[offset]
            || provider.revision != bundle.request.provider_revision
            || provider.policy_digest
                != global_beacon_partial_signer_public_inventory_digest_v1(
                    network,
                    &[(&bundle.record.session, seat)],
                )
                .map_err(|_| Error::Crypto)?
        {
            return Err(Error::InvalidInput);
        }
    }
    Ok(roster)
}

/// Assemble the complete public genesis transcript after native H2–H4 finality.
/// Signed H1 supplies body authority only; H2 authenticates its result.
pub(super) fn assemble_genesis_dkg_command(
    chain_id: &ChainId,
    finality_limits: FinalityLimitsArgs,
    network: NetworkId,
    chain_discriminant: u16,
    request_path: &Path,
    manifest_path: &Path,
    wire_path: &Path,
    key_path: &Path,
    phase_paths: &[PathBuf],
    public_session_path: &Path,
    provider_paths: &[PathBuf],
    certificate_height: u64,
    output: &Path,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<()> {
    let limits = finality_limits.checked()?;
    let _profile =
        iroha_data_model::account::address::ChainDiscriminantGuard::enter(chain_discriminant);
    let request: GenesisRequest = read_json(request_path)?;
    let genesis = read_genesis_proof(manifest_path, wire_path, key_path)?;
    let phase_proofs = phase_paths
        .iter()
        .map(|path| {
            let bytes = read_public_bytes_bounded(path, limits.journal_bytes)?;
            NativeFinalityJournal::decode(&bytes, limits).map_err(Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    let roster = validate_genesis_phase_chain(
        chain_id,
        limits,
        network,
        chain_discriminant,
        &request,
        &genesis,
        &phase_proofs,
        budget,
    )?;
    let bytes = read_public_bytes(public_session_path)?;
    let public: GlobalThresholdBeaconKeySessionV1 =
        norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
            .map_err(|_| Error::Crypto)?;
    let record = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(public, budget)
        .map_err(Error::from)?;
    let mut providers = provider_paths
        .iter()
        .map(|path| read_json::<Provider>(path))
        .collect::<Result<Vec<_>>>()?;
    providers.sort_by_key(|provider| provider.signer_index);
    let draft = draft_genesis_certificate(&roster, &record, certificate_height)?;
    let bundle = GenesisPublicBundle {
        schema: BUNDLE_SCHEMA.into(),
        request,
        genesis,
        phase_proofs,
        finalized_observed_height: record.session.adaptive_dkg.finalized_at_height,
        record,
        finalization_draft: draft,
        providers,
    };
    validate_genesis_bundle(
        &bundle,
        chain_id,
        limits,
        network,
        chain_discriminant,
        budget,
    )?;
    write_new(output, &json_bytes(&bundle)?, false)
}

/// Sign the exact genesis-roster installation draft with one native identity.
pub(super) fn sign_genesis_install_command(
    chain_id: &ChainId,
    finality_limits: FinalityLimitsArgs,
    network: NetworkId,
    chain_discriminant: u16,
    bundle_path: &Path,
    signer_index: u16,
    key_fd: Option<i32>,
    config_fd: Option<i32>,
    output: &Path,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<()> {
    let limits = finality_limits.checked()?;
    let _profile =
        iroha_data_model::account::address::ChainDiscriminantGuard::enter(chain_discriminant);
    iroha_genesis::init_instruction_registry();
    let (fd, config) = match (key_fd, config_fd) {
        (Some(198), None) => (198, false),
        (None, Some(198)) => (198, true),
        _ => return Err(Error::InvalidInput),
    };
    let bundle: GenesisPublicBundle = read_json(bundle_path)?;
    let roster = validate_genesis_bundle(
        &bundle,
        chain_id,
        limits,
        network,
        chain_discriminant,
        budget,
    )?;
    let file = crate::taira_runtime_signer::take_inherited_private_file(fd)
        .map_err(|_| Error::InvalidCustody)?;
    let key = if config {
        load_lifecycle_config(file, &network)?
    } else {
        load_lifecycle_key(file)?
    };
    let signed = sign_rotation_draft(&bundle.finalization_draft, &roster, signer_index, &key)?;
    write_new(output, &json_bytes(&signed)?, false)
}

/// Emit an install instruction only after the exact genesis quorum signs.
pub(super) fn assemble_genesis_install_command(
    chain_id: &ChainId,
    finality_limits: FinalityLimitsArgs,
    network: NetworkId,
    chain_discriminant: u16,
    bundle_path: &Path,
    signature_paths: &[PathBuf],
    output: &Path,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<()> {
    let limits = finality_limits.checked()?;
    let _profile =
        iroha_data_model::account::address::ChainDiscriminantGuard::enter(chain_discriminant);
    iroha_genesis::init_instruction_registry();
    let bundle: GenesisPublicBundle = read_json(bundle_path)?;
    let roster = validate_genesis_bundle(
        &bundle,
        chain_id,
        limits,
        network,
        chain_discriminant,
        budget,
    )?;
    let signatures = signature_paths
        .iter()
        .map(|path| read_json(path))
        .collect::<Result<Vec<_>>>()?;
    let certificate = assemble_rotation_draft(&bundle.finalization_draft, &roster, signatures)?;
    let instructions = vec![InstructionBox::from(
        ApplyThresholdKeyLifecycleCertificateV1 { certificate },
    )];
    write_new(output, &json_bytes(&instructions)?, false)
}

#[cfg(test)]
mod tests {
    //! Genesis provisioning geometry and real all-edge certificate authorization controls.

    use super::*;
    use iroha_core::beacon::ceremony::{
        GlobalBeaconCeremonyPlanV1, deal_global_beacon_at_logical_clock_v1,
        global_beacon_genesis_dkg_session_v1,
    };

    fn roster_keys(seats: usize) -> Vec<KeyPair> {
        let mut keys = (0..seats)
            .map(|index| {
                KeyPair::from_seed(
                    vec![u8::try_from(index + 1).expect("test committee fits u8"); 32],
                    Algorithm::BlsNormal,
                )
            })
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        keys
    }

    fn roster(keys: &[KeyPair]) -> Vec<PeerId> {
        keys.iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect()
    }

    fn request(roster: &[PeerId]) -> GenesisRequest {
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(Hash::new(
            b"genesis-provisioning-committee-network",
        )));
        GenesisRequest {
            schema: REQUEST_SCHEMA.into(),
            dkg_session: global_beacon_genesis_dkg_session_v1(network, roster)
                .expect("canonical genesis session"),
            target_roster: roster.to_vec(),
            authorization_roster: roster.to_vec(),
            provider_handles: (1..=roster.len())
                .map(|seat| format!("genesis-beacon-seat-{seat}"))
                .collect(),
            provider_revision: 1,
        }
    }

    #[test]
    fn genesis_request_binds_every_seat_at_four_seven_and_thirty_one() {
        for seats in [4, 7, 31] {
            let roster = roster(&roster_keys(seats));
            let request = request(&roster);
            let network = request.dkg_session.network_id;
            validate_genesis_request(network, &request, &roster)
                .expect("all exact authenticated genesis seats");
            let mut wrong = request.clone();
            wrong.dkg_session.committee_size -= 1;
            assert!(matches!(
                validate_genesis_request(network, &wrong, &roster),
                Err(Error::InvalidInput)
            ));
            wrong = request.clone();
            wrong.dkg_session.threshold += 1;
            assert!(matches!(
                validate_genesis_request(network, &wrong, &roster),
                Err(Error::InvalidInput)
            ));
            wrong = request.clone();
            wrong.target_roster.pop();
            assert!(matches!(
                validate_genesis_request(network, &wrong, &roster),
                Err(Error::InvalidInput)
            ));
            wrong = request.clone();
            wrong.authorization_roster.swap(0, 1);
            assert!(matches!(
                validate_genesis_request(network, &wrong, &roster),
                Err(Error::InvalidInput)
            ));
            wrong = request.clone();
            wrong.provider_handles.pop();
            assert!(matches!(
                validate_genesis_request(network, &wrong, &roster),
                Err(Error::InvalidInput)
            ));
            wrong = request.clone();
            wrong.provider_handles[1] = wrong.provider_handles[0].clone();
            assert!(matches!(
                validate_genesis_request(network, &wrong, &roster),
                Err(Error::InvalidInput)
            ));
        }
    }

    #[test]
    fn genesis_roster_rejects_noncommittees_duplicate_and_reordered_seats() {
        let roster = roster(&roster_keys(34));
        for seats in 0..=34 {
            if (4..=31).contains(&seats) && (seats - 1) % 3 == 0 {
                let (count, threshold, quorum) = genesis_roster_geometry(&roster[..seats])
                    .expect("exact canonical committee geometry");
                assert_eq!(usize::from(count), seats);
                assert_eq!(usize::from(threshold), (seats - 1) / 3 + 1);
                assert_eq!(usize::from(quorum), seats - (seats - 1) / 3);
            } else {
                assert!(matches!(
                    genesis_roster_geometry(&roster[..seats]),
                    Err(Error::InvalidInput)
                ));
            }
        }
        let mut duplicate = roster[..7].to_vec();
        duplicate[1] = duplicate[0].clone();
        assert!(matches!(
            genesis_roster_geometry(&duplicate),
            Err(Error::InvalidInput)
        ));
        let mut reordered = roster[..7].to_vec();
        reordered.swap(0, 1);
        assert!(matches!(
            genesis_roster_geometry(&reordered),
            Err(Error::InvalidInput)
        ));
    }

    #[test]
    fn genesis_install_requires_exact_quorum_at_four_seven_and_thirty_one() {
        for seats in [4, 7, 31] {
            let keys = roster_keys(seats);
            let roster = roster(&keys);
            let request = request(&roster);
            let plan = GlobalBeaconCeremonyPlanV1::new(
                request.dkg_session,
                roster.clone(),
                request.provider_handles,
                request.provider_revision,
            )
            .expect("exact genesis ceremony plan");
            let dealt = deal_global_beacon_at_logical_clock_v1(
                &plan,
                &keys.iter().collect::<Vec<_>>(),
                &test_credential_budget(),
            )
            .expect("real signed all-edge genesis DKG");
            // Exercise the actual public DTO boundary after the ceremony has
            // retained its single authenticated graph; no second runtime owner.
            let encoded =
                norito::encode_canonical(&dealt.record).expect("canonical retained record");
            let record: FinalizedGlobalThresholdBeaconKeySessionRecordV1 =
                norito::decode_canonical(&encoded).expect("public wire record");
            let draft = draft_genesis_certificate(&roster, &record, 5)
                .expect("complete genesis install draft");
            assert_eq!(usize::from(draft.committee_size), seats);
            assert_eq!(draft.expected_active_session_id, None);
            let quorum = seats - (seats - 1) / 3;
            assert_eq!(usize::from(draft.quorum), quorum);
            assert!(matches!(
                draft_genesis_certificate(&roster, &record, 4),
                Err(Error::Height)
            ));
            let signatures = keys
                .iter()
                .enumerate()
                .map(|(index, key)| {
                    sign_rotation_draft(&draft, &roster, u16::try_from(index).unwrap(), key)
                        .expect("original genesis seat signature")
                })
                .collect::<Vec<_>>();
            assemble_rotation_draft(&draft, &roster, signatures[..quorum].to_vec())
                .expect("exact n-f genesis authorization");
            assert!(matches!(
                assemble_rotation_draft(&draft, &roster, signatures[..quorum - 1].to_vec()),
                Err(Error::Crypto)
            ));
            assert!(matches!(
                assemble_rotation_draft(&draft, &roster, signatures[..quorum + 1].to_vec()),
                Err(Error::Crypto)
            ));
        }
    }
}
