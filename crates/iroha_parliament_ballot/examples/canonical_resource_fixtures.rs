//! Generate public canonical ballot fixtures using real candidate proofs and 28-bit stamps.
//!
//! Usage: `canonical_resource_fixtures OUTPUT_DIR SEATS THREADS [valid|late-invalid]`,
//! where SEATS is 3, 500 or 1000 and OUTPUT_DIR must not exist. Inputs and proving tapes
//! are deterministic public fixture material. Parallel stamp search may select different
//! valid nonces and attempt counts on different runs. These files carry no qualification.

use std::{
    error::Error,
    fs,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use iroha_data_model::{
    NetworkId,
    block::BlockHeader,
    governance::{
        anonymous_ballot::{
            AdmissionNonceV1, AdmissionStampV1, AnonymousBallotAuthorizationV1,
            AnonymousBallotEnvelopeV1, AnonymousBallotV1, BallotBodyContextV1, BallotChoiceV1,
            BallotProofBytesV1, CredentialCommitmentV1, Digest512, FrozenBallotPolicyV1,
            FrozenParliamentAttemptPolicyV1, ParliamentBallotParametersV1,
            ParliamentLifecycleParametersV1, ProofProfileIdV1, SealedCredentialListV1,
            digests::verify_stamp_v1, framing::enc,
        },
        types::{
            BodyElectionAttemptId, BodyInstanceId, GovernanceAttemptId, ParliamentBody, RiskTierV1,
        },
    },
    prelude::{Hash, HashOf},
};
use iroha_parliament_ballot::{
    PROOF_ROW_V1,
    ballot::{BallotProofErrorV1, verify_ballot_proof_v1},
    context::ScopedBallotContextV1,
    inputs::{ProofValueV1, body_digest_v1, proof_list_v1, proof_profile_v1},
    stamp::StampTargetV1,
};
use iroha_parliament_ballot_proof::{
    credential::CredentialSecret,
    profile::{Profile, ProofField, Role},
    proving::ProvingTape,
    vote::{self, VoteRelation, VoteStatement},
};
use iroha_zkp_vole::{
    field::Gf256,
    proof::{self, ProofError},
};
use norito::json::JsonSerialize;

/// Errors remain visible to the caller; partial output is retained.
type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USAGE: &str =
    "usage: canonical_resource_fixtures OUTPUT_DIR SEATS(3|500|1000) THREADS [valid|late-invalid]";

/// Whether the encoded proof is honest or has the qualification coefficient mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    Valid,
    LateInvalid,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::LateInvalid => "late-invalid",
        }
    }
}

/// Explicit fixture inputs; no process environment changes protocol parameters.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    output: PathBuf,
    seats: u16,
    threads: NonZeroUsize,
    variant: Variant,
}

fn options(args: &[String]) -> Result<Options> {
    if !(3..=4).contains(&args.len()) {
        return Err(USAGE.into());
    }
    let seats = args[1].parse::<u16>()?;
    if !matches!(seats, 3 | 500 | 1000) {
        return Err("SEATS must be 3, 500 or 1000".into());
    }
    let threads = args[2].parse::<NonZeroUsize>()?;
    let variant = match args.get(3).map(String::as_str).unwrap_or("valid") {
        "valid" => Variant::Valid,
        "late-invalid" => Variant::LateInvalid,
        _ => return Err("variant must be valid or late-invalid".into()),
    };
    Ok(Options {
        output: PathBuf::from(&args[0]),
        seats,
        threads,
        variant,
    })
}

fn network_id(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([seed; Hash::LENGTH]),
    ))
}

/// The first two bytes encode the complete roster index, including indices above 255.
fn public_secret(member: u16) -> [u8; 48] {
    let mut bytes = [0x40; 48];
    bytes[..2].copy_from_slice(&member.to_le_bytes());
    bytes
}

fn public_tape(seats: u16) -> [u8; 112] {
    let mut bytes = [0x72; 112];
    bytes[..2].copy_from_slice(&seats.to_le_bytes());
    bytes
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
}

fn standard_policy(body_role: ParliamentBody) -> Result<FrozenBallotPolicyV1> {
    let pipeline = [
        ParliamentBody::RulesCommittee,
        ParliamentBody::AgendaCouncil,
        ParliamentBody::InterestPanel,
        ParliamentBody::ReviewPanel,
        ParliamentBody::CoordinationCouncil,
        ParliamentBody::FmaCommittee,
        ParliamentBody::OversightCommittee,
        ParliamentBody::PolicyJury,
        ParliamentBody::ConfirmationJury,
    ];
    let attempt = FrozenParliamentAttemptPolicyV1::freeze_v1(
        &pipeline,
        &ParliamentLifecycleParametersV1::default(),
        Some(&ParliamentBallotParametersV1::default()),
        1_000,
        3_600,
    )?;
    let policy = attempt.ballot_policy(RiskTierV1::Standard, body_role)?;
    if policy.binding.stamp_difficulty_bits != 28 {
        return Err("the default standard-tier policy no longer has 28-bit stamps".into());
    }
    Ok(policy)
}

/// A genuine typed statement over a synthetic public authenticated-context fixture.
struct Prepared {
    context: ScopedBallotContextV1,
    profile: Profile,
    statement: VoteStatement,
    secret: CredentialSecret,
    roster_member: u16,
    position: u16,
}

fn prepare(seats: u16) -> Result<Prepared> {
    if !matches!(seats, 3 | 500 | 1000) {
        return Err("unsupported fixture roster".into());
    }
    let body_role = if seats == 1000 {
        ParliamentBody::ConfirmationJury
    } else {
        ParliamentBody::PolicyJury
    };
    let body = BallotBodyContextV1 {
        network_id: network_id(0x5a),
        governance_attempt_id: GovernanceAttemptId::new([0x11; 32]),
        election_attempt_id: BodyElectionAttemptId::new([0x22; 32]),
        body_role,
    };
    let body_digest = body_digest_v1(&body)?;
    let commitments = (0..seats)
        .map(|member| {
            CredentialCommitmentV1::from_proof(
                &CredentialSecret::from_bytes(&public_secret(member))
                    .commitment(&body_digest.to_proof()),
            )
        })
        .collect();
    let list =
        SealedCredentialListV1::from_unsorted(ProofProfileIdV1::V1, body_digest, commitments)?;
    let context = ScopedBallotContextV1::build(
        body,
        Digest512::new([0x33; 64]),
        BodyInstanceId::new([0x03; 32]),
        &list,
        standard_policy(body_role)?,
    )?;
    let profile = proof_profile_v1()?;
    let roster_member = seats - 1;
    let secret = CredentialSecret::from_bytes(&public_secret(roster_member));
    let proof_list = proof_list_v1(&list)?;
    let statement = VoteStatement::for_secret(
        &profile,
        &secret,
        body_digest.to_proof(),
        context.scope().to_proof(),
        &proof_list,
        BallotChoiceV1::Aye.to_proof(),
        context.policy_hash().to_proof(),
    )?;
    let position = proof_list
        .position(&secret.commitment(&body_digest.to_proof()))
        .ok_or("fixture voter is missing from the sealed list")?;
    Ok(Prepared {
        context,
        profile,
        statement,
        secret,
        roster_member,
        position,
    })
}

/// Exactly the qualification runner's first canonical coefficient-byte mutation.
fn mutate_coefficient(bytes: &mut [u8]) -> Result<usize> {
    if bytes.len() != PROOF_ROW_V1.proof_bytes(Role::Vote) {
        return Err("coefficient mutation requires the exact candidate vote-proof length".into());
    }
    let field = PROOF_ROW_V1
        .proof_layout(Role::Vote)
        .into_iter()
        .find(|segment| segment.field == ProofField::Coefficients)
        .ok_or("candidate vote proof has no coefficients segment")?;
    if field.len == 0 {
        return Err("candidate coefficients segment is empty".into());
    }
    bytes[field.offset] ^= 1;
    Ok(field.offset)
}

fn envelope(
    authorization: &AnonymousBallotAuthorizationV1,
    stamp: AdmissionStampV1,
) -> AnonymousBallotEnvelopeV1 {
    AnonymousBallotEnvelopeV1 {
        network_id: authorization.network_id,
        ballot: AnonymousBallotV1 {
            scope: authorization.scope,
            vote: authorization.vote,
            nullifier: authorization.nullifier,
            auth_v: authorization.auth_v,
            profile_id: authorization.profile_id,
            stamp,
            proof: authorization.proof.clone(),
        },
    }
}

/// The manifest distinguishes deterministic proof inputs from scheduled nonce search.
#[derive(JsonSerialize)]
struct Manifest {
    schema: &'static str,
    status: &'static str,
    variant: &'static str,
    seats: u16,
    threads: usize,
    network_id: String,
    alternate_network_id: String,
    body_instance_id: String,
    body_role: Option<ParliamentBody>,
    target_seats: Option<u16>,
    roster_member_index: u16,
    sealed_position: Option<u16>,
    public_secret_encoding: &'static str,
    selected_public_secret_hex: String,
    public_proving_tape_hex: String,
    deterministic_proof_inputs: bool,
    deterministic_stamp_nonce: bool,
    context_bytes: Option<usize>,
    authorization_bytes: Option<usize>,
    envelope_bytes: Option<usize>,
    proof_bytes: Option<usize>,
    scope_hex: Option<String>,
    profile_id_hex: String,
    stamp_nonce_hex: Option<String>,
    stamp_payload_digest_hex: Option<String>,
    stamp_difficulty_bits: u8,
    stamp_work_bits: Option<u32>,
    stamp_attempts: Option<u64>,
    honest_proof_verified: bool,
    mutation_offset_in_proof: Option<usize>,
    mutation_xor_mask: Option<u8>,
    mutation_reference: Option<&'static str>,
    observed_backend_stage: Option<&'static str>,
    typed_verifier_result: Option<&'static str>,
    stamp_verified: bool,
    canonical_envelope_roundtrip_checked: bool,
    public_fixture_only: bool,
    authenticated_chain_evidence: bool,
    native_execution_qualified: bool,
    current_candidate_qualified: bool,
    complete_64_mib_certificate: bool,
    full_profile_proved: bool,
    profile_qualified: bool,
    independent_external_cryptographic_review: bool,
    production_qualified: bool,
    error: Option<String>,
}

impl Manifest {
    fn new(options: &Options) -> Self {
        Self {
            schema: "parliament-canonical-resource-fixture-v1",
            status: "preparing",
            variant: options.variant.name(),
            seats: options.seats,
            threads: options.threads.get(),
            network_id: network_id(0x5a).to_string(),
            alternate_network_id: network_id(0x5b).to_string(),
            body_instance_id: hex(&[0x03; 32]),
            body_role: None,
            target_seats: None,
            roster_member_index: options.seats - 1,
            sealed_position: None,
            public_secret_encoding: "48 bytes: u16 little-endian roster index followed by 46 bytes of 0x40",
            selected_public_secret_hex: hex(&public_secret(options.seats - 1)),
            public_proving_tape_hex: hex(&public_tape(options.seats)),
            deterministic_proof_inputs: true,
            deterministic_stamp_nonce: false,
            context_bytes: None,
            authorization_bytes: None,
            envelope_bytes: None,
            proof_bytes: None,
            scope_hex: None,
            profile_id_hex: hex(ProofProfileIdV1::V1.as_bytes()),
            stamp_nonce_hex: None,
            stamp_payload_digest_hex: None,
            stamp_difficulty_bits: 28,
            stamp_work_bits: None,
            stamp_attempts: None,
            honest_proof_verified: false,
            mutation_offset_in_proof: None,
            mutation_xor_mask: None,
            mutation_reference: None,
            observed_backend_stage: None,
            typed_verifier_result: None,
            stamp_verified: false,
            canonical_envelope_roundtrip_checked: false,
            public_fixture_only: true,
            authenticated_chain_evidence: false,
            native_execution_qualified: false,
            current_candidate_qualified: false,
            complete_64_mib_certificate: false,
            full_profile_proved: false,
            profile_qualified: false,
            independent_external_cryptographic_review: false,
            production_qualified: false,
            error: None,
        }
    }

    fn record_context(&mut self, prepared: &Prepared) -> Result<()> {
        let target_seats = prepared
            .context
            .policy()
            .body_target_seats()
            .ok_or("fixture context has no frozen body target")?;
        self.body_role = Some(prepared.context.body_context().body_role);
        self.target_seats = Some(target_seats);
        self.roster_member_index = prepared.roster_member;
        self.sealed_position = Some(prepared.position);
        self.scope_hex = Some(hex(prepared.context.scope().as_bytes()));
        Ok(())
    }

    fn save(&self, output: &Path) -> Result<()> {
        fs::write(
            output.join("manifest.json"),
            format!("{}\n", norito::json::to_json(self)?),
        )?;
        Ok(())
    }
}

fn generate(options: &Options, manifest: &mut Manifest) -> Result<()> {
    let prepared = prepare(options.seats)?;
    manifest.record_context(&prepared)?;
    let context_bytes = enc(prepared.context.context())?;
    if context_bytes != prepared.context.encoded_context().as_bytes() {
        return Err("context encoding disagrees with the stamp context".into());
    }
    manifest.context_bytes = Some(context_bytes.len());
    fs::write(options.output.join("context.norito"), context_bytes)?;
    manifest.status = "proving";
    manifest.save(&options.output)?;
    eprintln!(
        "Proving candidate vote for {} seats (public roster member {}, sealed position {})",
        options.seats, prepared.roster_member, prepared.position
    );
    let mut proof_bytes = vote::prove(
        PROOF_ROW_V1,
        &prepared.statement,
        &prepared.secret,
        prepared.position,
        ProvingTape::from_bytes(&public_tape(options.seats)),
    )?;
    vote::verify(PROOF_ROW_V1, &prepared.statement, &proof_bytes)?;
    manifest.honest_proof_verified = true;
    manifest.proof_bytes = Some(proof_bytes.len());
    if options.variant == Variant::LateInvalid {
        let offset = mutate_coefficient(&mut proof_bytes)?;
        let instance = prepared.statement.instance(&prepared.profile)?;
        let diagnostic = proof::verify::<Gf256, _>(
            &prepared.profile.context(Role::Vote)?,
            &VoteRelation,
            instance.public(),
            instance.mu(),
            &proof_bytes,
        );
        if diagnostic != Err(ProofError::ChallengeMismatch) {
            return Err(format!(
                "coefficient mutation did not reach ChallengeMismatch: {diagnostic:?}"
            )
            .into());
        }
        manifest.mutation_offset_in_proof = Some(offset);
        manifest.mutation_xor_mask = Some(1);
        manifest.mutation_reference = Some(
            "iroha_parliament_ballot_proof/examples/qualification/mod.rs: first ProofField::Coefficients byte XOR 1",
        );
        manifest.observed_backend_stage = Some("ProofError::ChallengeMismatch");
    }
    let authorization = AnonymousBallotAuthorizationV1 {
        network_id: *prepared.context.network_id(),
        scope: *prepared.context.scope(),
        vote: BallotChoiceV1::Aye,
        nullifier: ProofValueV1::from_proof(&prepared.statement.nullifier),
        auth_v: ProofValueV1::from_proof(&prepared.statement.auth_v),
        profile_id: ProofProfileIdV1::V1,
        proof: BallotProofBytesV1::new(proof_bytes)?,
    };
    // This retained canonical authorization permits inspection after a mining failure.
    let authorization_bytes = enc(&authorization)?;
    manifest.authorization_bytes = Some(authorization_bytes.len());
    fs::write(
        options.output.join("authorization.norito"),
        authorization_bytes,
    )?;
    let target = StampTargetV1::for_ballot(&authorization, prepared.context.context())?;
    if target.difficulty_bits() != 28 {
        return Err("fixture stamp target must retain the frozen 28-bit difficulty".into());
    }
    manifest.stamp_payload_digest_hex = Some(hex(target.payload_digest().as_bytes()));
    manifest.status = "mining";
    manifest.save(&options.output)?;
    eprintln!(
        "Mining a genuine 28-bit stamp using {} threads for {}",
        options.threads,
        options.variant.name()
    );
    let mined = target.mine_parallel(
        AdmissionNonceV1::new([0; 32]),
        options.threads,
        &AtomicBool::new(false),
    )?;
    manifest.stamp_nonce_hex = Some(hex(mined.stamp.nonce.as_bytes()));
    manifest.stamp_work_bits = Some(mined.work_bits);
    manifest.stamp_attempts = Some(mined.attempts);
    if !verify_stamp_v1(
        &authorization,
        prepared.context.context(),
        &mined.stamp.nonce,
    )? {
        return Err("mined nonce failed the protocol stamp verifier".into());
    }
    manifest.stamp_verified = true;
    let envelope = envelope(&authorization, mined.stamp);
    let verdict = verify_ballot_proof_v1(&prepared.context, &envelope);
    match (options.variant, verdict) {
        (Variant::Valid, Ok(())) => manifest.typed_verifier_result = Some("Ok(())"),
        (Variant::LateInvalid, Err(BallotProofErrorV1::Rejected)) => {
            manifest.typed_verifier_result = Some("BallotProofErrorV1::Rejected");
        }
        (_, other) => {
            return Err(format!("unexpected genuine typed verifier result: {other:?}").into());
        }
    }
    let canonical = envelope.encode_canonical_bounded()?;
    if AnonymousBallotEnvelopeV1::decode_canonical_bounded(&canonical)? != envelope {
        return Err("canonical envelope failed its exact roundtrip".into());
    }
    manifest.canonical_envelope_roundtrip_checked = true;
    manifest.envelope_bytes = Some(canonical.len());
    fs::write(options.output.join("envelope.norito"), canonical)?;
    manifest.status = "complete";
    manifest.save(&options.output)?;
    println!(
        "{}: seats={}, proof={} bytes, envelope={} bytes, stamp={} bits/{} attempts, verifier={}",
        options.output.display(),
        options.seats,
        manifest.proof_bytes.unwrap_or_default(),
        manifest.envelope_bytes.unwrap_or_default(),
        mined.work_bits,
        mined.attempts,
        manifest.typed_verifier_result.unwrap_or("unavailable")
    );
    Ok(())
}

fn run(options: &Options) -> Result<()> {
    // create_dir refuses existing files, directories and symlinks; no overwrite or cleanup.
    fs::create_dir(&options.output)?;
    let mut manifest = Manifest::new(options);
    manifest.save(&options.output)?;
    if let Err(error) = generate(options, &mut manifest) {
        manifest.status = "failed";
        manifest.error = Some(error.to_string());
        if let Err(write_error) = manifest.save(&options.output) {
            eprintln!("Could not record fixture failure: {write_error}");
        }
        return Err(error);
    }
    Ok(())
}

fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    run(&options(&arguments)?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn command_line_is_closed_and_defaults_to_valid() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        };
        let default = options(&args(&["out", "3", "2"])).expect("valid arguments");
        assert_eq!(default.variant, Variant::Valid);
        assert_eq!(default.variant.name(), "valid");
        let late = options(&args(&["out", "1000", "4", "late-invalid"])).expect("late fixture");
        assert_eq!(late.variant.name(), "late-invalid");
        assert_eq!(late.seats, 1000);
        for invalid in [
            vec!["out", "2", "1"],
            vec!["out", "3", "0"],
            vec!["out", "3", "1", "bad"],
            vec!["out", "3"],
            vec!["out", "500", "1", "valid", "extra"],
        ] {
            assert!(options(&args(&invalid)).is_err());
        }
    }

    #[test]
    fn public_roster_indices_do_not_wrap_at_256() {
        let roster: BTreeSet<_> = (0..1000).map(public_secret).collect();
        assert_eq!(roster.len(), 1000);
        assert_eq!(&public_secret(999)[..2], &999_u16.to_le_bytes());
        assert_ne!(public_secret(0), public_secret(256));
        assert_eq!(public_tape(500), public_tape(500));
        assert_ne!(public_tape(500), public_tape(1000));
        assert_eq!(hex(&[0, 3, 0xff]), "0003ff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn coefficient_mutation_changes_one_byte_and_preserves_layout() {
        let mut bytes = vec![0x5a; PROOF_ROW_V1.proof_bytes(Role::Vote)];
        let original = bytes.clone();
        let offset = mutate_coefficient(&mut bytes).expect("exact candidate layout");
        assert_eq!(bytes.len(), original.len());
        assert_eq!(bytes[offset], 0x5b);
        assert_eq!(
            bytes.iter().zip(&original).filter(|(a, b)| a != b).count(),
            1
        );
        assert_eq!(&bytes[bytes.len() - 4..], &original[original.len() - 4..]);
        assert!(mutate_coefficient(&mut bytes[..10]).is_err());
    }

    #[test]
    fn context_and_manifest_keep_protocol_policy_and_false_qualification() {
        let prepared = prepare(3).expect("real checked fixture context");
        assert_eq!(prepared.context.seats(), 3);
        assert_eq!(prepared.context.policy().binding.stamp_difficulty_bits, 28);
        assert_eq!(*prepared.context.network_id(), network_id(0x5a));
        assert_eq!(
            *prepared.context.body_instance_id(),
            BodyInstanceId::new([3; 32])
        );
        assert!(prepared.position < 3);
        assert_eq!(
            enc(prepared.context.context()).expect("canonical context"),
            prepared.context.encoded_context().as_bytes()
        );
        assert!(prepare(2).is_err());
        let options = Options {
            output: PathBuf::from("unused"),
            seats: 3,
            threads: NonZeroUsize::MIN,
            variant: Variant::Valid,
        };
        let mut manifest = Manifest::new(&options);
        manifest.record_context(&prepared).expect("checked context");
        assert_eq!(manifest.body_role, Some(ParliamentBody::PolicyJury));
        assert_eq!(manifest.target_seats, Some(500));
        assert!(manifest.public_fixture_only);
        assert!(
            !manifest.production_qualified
                && !manifest.current_candidate_qualified
                && !manifest.complete_64_mib_certificate
                && !manifest.profile_qualified
        );
        assert!(!manifest.stamp_verified && !manifest.honest_proof_verified);
        assert_eq!(manifest.network_id, network_id(0x5a).to_string());
        assert_eq!(manifest.alternate_network_id, network_id(0x5b).to_string());
        assert_ne!(manifest.network_id, manifest.alternate_network_id);
        assert_eq!(manifest.body_instance_id, "03".repeat(32));
        assert!(norito::json::to_json(&manifest).is_ok());
        let authorization = AnonymousBallotAuthorizationV1 {
            network_id: *prepared.context.network_id(),
            scope: *prepared.context.scope(),
            vote: BallotChoiceV1::Aye,
            nullifier: ProofValueV1::from_proof(&prepared.statement.nullifier),
            auth_v: ProofValueV1::from_proof(&prepared.statement.auth_v),
            profile_id: ProofProfileIdV1::V1,
            proof: BallotProofBytesV1::new(vec![0; PROOF_ROW_V1.proof_bytes(Role::Vote)])
                .expect("test-only exact-length placeholder"),
        };
        let stamp = AdmissionStampV1 {
            nonce: AdmissionNonceV1::new([7; 32]),
        };
        let wrapped = envelope(&authorization, stamp);
        assert_eq!(wrapped.authorization(), authorization);
        assert_eq!(wrapped.ballot.stamp, stamp);
    }

    #[test]
    fn thousand_seats_use_the_unchanged_default_confirmation_jury_policy() {
        let prepared = prepare(1000).expect("default confirmation jury accepts 1000 seats");
        let policy = prepared.context.policy();
        assert_eq!(prepared.context.seats(), 1000);
        assert_eq!(
            prepared.context.body_context().body_role,
            ParliamentBody::ConfirmationJury
        );
        assert_eq!(policy.body_role, ParliamentBody::ConfirmationJury);
        assert_eq!(policy.body_target_seats(), Some(1000));
        assert_eq!(policy.risk_tier, RiskTierV1::Standard);
        assert_eq!(policy.binding.stamp_difficulty_bits, 28);
        assert_eq!(
            policy,
            &standard_policy(ParliamentBody::ConfirmationJury).expect("unchanged defaults")
        );
        assert!(prepared.position < 1000);
        let options = Options {
            output: PathBuf::from("unused"),
            seats: 1000,
            threads: NonZeroUsize::MIN,
            variant: Variant::Valid,
        };
        let mut manifest = Manifest::new(&options);
        manifest.record_context(&prepared).expect("checked context");
        assert_eq!(manifest.body_role, Some(ParliamentBody::ConfirmationJury));
        assert_eq!(manifest.target_seats, Some(1000));
        let json = norito::json::to_json(&manifest).expect("manifest JSON");
        assert!(json.contains("\"body_role\":\"confirmation-jury\""));
        assert!(json.contains("\"target_seats\":1000"));
    }

    #[test]
    fn an_existing_output_directory_is_preserved_without_proving_or_mining() {
        let root = std::env::temp_dir().join(format!(
            "parliament-canonical-fixture-refusal-{}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("fresh test directory");
        fs::write(root.join("existing.txt"), b"preserve").expect("sentinel");
        let options = Options {
            output: root.clone(),
            seats: 3,
            threads: NonZeroUsize::MIN,
            variant: Variant::Valid,
        };
        assert!(run(&options).is_err());
        assert_eq!(
            fs::read(root.join("existing.txt")).expect("sentinel"),
            b"preserve"
        );
        assert!(!root.join("manifest.json").exists());
        fs::remove_file(root.join("existing.txt")).expect("test sentinel cleanup");
        fs::remove_dir(root).expect("test directory cleanup");
    }
}
