//! Typed source owner for the shared Musubi V1 signed fixtures.
//!
//! This module is compiled by the release-only generator and included directly by
//! the grouped integration tests. Generated JSON is never read while constructing
//! either fixture.
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, SignatureOf};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    isi::{
        InstructionBox, decode_instruction_from_pair, framed_instruction_payload,
        instruction_wire_id,
        musubi::{
            AcceptMusubiPackageMaintainerV1, AddMusubiArchiveLocationV1, AdvanceMusubiPinOutboxV1,
            AssertMusubiReleaseDigestV1, CheckMusubiPinOutboxV1, InviteMusubiPackageMaintainerV1,
            PublishMusubiReleaseV1, RecoverMusubiPackageV1, RegisterMusubiAliasV1,
            RegisterMusubiArchiveV1, RegisterMusubiNamespaceBindingV1,
            RegisterMusubiProviderBundleAttestationV1, RemoveMusubiPackageMaintainerV1,
            RetargetMusubiAliasV1, RetireMusubiArchiveLocationV1,
            RevokeMusubiPackageMaintainerInvitationV1, SetMusubiArtifactTakedownV1,
            SetMusubiPackageMaintainerRoleV1, SetMusubiPackageMetadataV1,
            SetMusubiRegistryPolicyV1, SetMusubiReleaseYankV1,
        },
    },
    musubi::{
        ArchiveId, MUSUBI_MAX_CAR_BYTES_V1, MUSUBI_MAX_CHUNKS_V1, MUSUBI_MAX_FILES_V1,
        MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1, MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1,
        MusubiAliasNameV1, MusubiAliasPricingPolicyV1, MusubiArchiveCommitmentV1,
        MusubiArchiveLocationIdV1, MusubiContentDigestV1, MusubiDependencyKindV1,
        MusubiDependencyReqV1, MusubiDescriptionV1, MusubiDocumentRefV1,
        MusubiExactDependencyEdgeV1, MusubiGovernanceDecisionV1, MusubiInviteIdV1, MusubiKeywordV1,
        MusubiKotodamaEditionV1, MusubiMaintainerPermissionsV1, MusubiNamespaceBindingV1,
        MusubiNamespaceDelegationApprovalV1, MusubiNamespaceDelegationPayloadV1,
        MusubiNamespaceDelegationV1, MusubiNamespaceV1, MusubiPackageIdV1, MusubiPackageNameV1,
        MusubiPackageRoleV1, MusubiPackageScopeV1, MusubiParliamentActionV1,
        MusubiProviderBundleAttestationRefV1, MusubiProviderBundleVerificationApprovalV1,
        MusubiProviderBundleVerificationAttestationV1, MusubiProviderBundleVerificationBindingV1,
        MusubiProviderBundleVerificationPayloadV1, MusubiPublicationV1, MusubiReasonV1,
        MusubiRecoverPackageOwnersV1, MusubiRegistryAdmissionModeV1, MusubiRegistryPolicyV1,
        MusubiRegistrySnapshotV1, MusubiReleaseDigestV1, MusubiReleaseIdV1,
        MusubiReleaseManifestV1, MusubiReleaseMetadataV1, MusubiResolutionProofV1,
        MusubiRetargetAliasV1, MusubiSeedIngressReceiptApprovalV1,
        MusubiSeedIngressReceiptBindingV1, MusubiSeedIngressReceiptPayloadV1,
        MusubiSeedIngressReceiptV1, MusubiSetRegistryPolicyActionV1,
        MusubiTakedownArtifactActionV1, MusubiVerificationLockV1, MusubiVerificationNodeV1,
        MusubiVersionReqV1, MusubiVersionV1, musubi_provider_bundle_attestation_set_digest_v1,
    },
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ChunkerProfileHandle, ManifestDigest, ManifestRootCid,
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
            ProviderIngestFinalizedAnchorV1, ReplicationOrderId,
        },
    },
};
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use norito::{
    NoritoDeserialize, NoritoSerialize,
    core::{DecodeFlagsGuard, DecodeFromSlice},
    json::{self, JsonDeserialize, JsonSerialize, Value},
};
use std::{
    any::type_name,
    collections::BTreeSet,
    fmt::{Debug, Write as _},
};
/// Odd network marker used by both V1 fixture documents.
///
/// The final byte is deliberately odd so every network-bound model exercises the
/// first-release anti-sentinel validation path.
const FIXTURE_NETWORK_MARKER: u8 = 0xA5;
// These non-zero Ed25519 seeds are public test material, never production keys.
// Each role has a distinct seed so authority substitution cannot pass unnoticed.
const INSTRUCTION_NAMESPACE_OWNER_SEED: u8 = 0x80;
const INSTRUCTION_PUBLISHER_SEED: u8 = 0x81;
const INSTRUCTION_RECEIPT_BROKER_SEED: u8 = 0x82;
const INSTRUCTION_PROVIDER_1_SEED: u8 = 0x90;
const INSTRUCTION_PROVIDER_2_SEED: u8 = 0x91;
const INSTRUCTION_PROVIDER_3_SEED: u8 = 0x92;
#[cfg_attr(test, allow(dead_code))]
pub const MUSUBI_FIXTURE_OUTPUTS: [&str; 2] = [
    "fixtures/musubi/instructions_v1.json",
    "fixtures/musubi/sdk_v1.json",
];
pub fn fixture_network_id() -> NetworkId {
    let network_id = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([FIXTURE_NETWORK_MARKER; Hash::LENGTH]),
    ));
    assert_eq!(
        network_id.as_bytes()[Hash::LENGTH - 1] & 1,
        1,
        "fixture NetworkId must retain the odd deployment marker"
    );
    network_id
}
/// Synthetic Musubi-purpose order, outside the reserved automatic-order namespace.
pub fn fixture_replication_order() -> ReplicationOrderId {
    let order = ReplicationOrderId::new([0x42; 32]);
    assert!(
        !order.is_auto(),
        "Musubi fixtures require a purpose-issued order"
    );
    order
}

#[test]
fn musubi_fixture_order_uses_the_purpose_issued_namespace() {
    let order = fixture_replication_order();
    assert_eq!(order.as_bytes(), &[0x42; 32]);
    assert!(!order.is_auto());
}

pub fn keypair(seed: u8) -> KeyPair {
    assert_ne!(seed, 0, "fixture signing seeds must be non-zero");
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("fixed fixture seed derives an Ed25519 keypair")
}
pub fn account(seed: u8) -> AccountId {
    AccountId::new(keypair(seed).public_key().clone())
}
fn package(home_dataspace: u64, scope: MusubiPackageScopeV1, name: &str) -> MusubiPackageIdV1 {
    MusubiPackageIdV1::new(
        DataSpaceId::new(home_dataspace),
        scope,
        MusubiPackageNameV1::new(name).expect("fixture package name"),
    )
}
fn metadata(
    description: &str,
    readme: &str,
    license: &str,
    repository: &str,
    keywords: &[&str],
) -> MusubiReleaseMetadataV1 {
    let value = MusubiReleaseMetadataV1 {
        description: Some(
            description
                .parse::<MusubiDescriptionV1>()
                .expect("fixture description"),
        ),
        readme: Some(
            readme
                .parse::<MusubiDocumentRefV1>()
                .expect("fixture readme"),
        ),
        license: Some(
            license
                .parse::<MusubiDocumentRefV1>()
                .expect("fixture license"),
        ),
        repository: Some(
            repository
                .parse::<MusubiDocumentRefV1>()
                .expect("fixture repository"),
        ),
        keywords: keywords
            .iter()
            .map(|keyword| keyword.parse::<MusubiKeywordV1>().expect("fixture keyword"))
            .collect(),
    };
    value.validate().expect("fixture metadata is canonical");
    value
}
fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}
// These instructions expose their canonical JSON boundary but no public constructor.
// Keep the fixture inputs independently typed; never read generated fixture output.
// Raw pin-outbox bytes use the declared fixed_bytes numeric-array adapter,
// rather than the generic [u8; N] hex-string JSON representation.
fn fixture_instruction<T: JsonDeserialize>(fields: Value) -> T {
    json::from_value(fields).expect("typed first-release Musubi instruction fixture fields")
}

fn render_instruction_case<T>(id: &str, value: T) -> Value
where
    T: Clone
        + Debug
        + Eq
        + Into<InstructionBox>
        + JsonDeserialize
        + JsonSerialize
        + NoritoSerialize
        + 'static,
    for<'a> T: NoritoDeserialize<'a>,
{
    let semantic = json::to_value(&value).expect("encode typed instruction semantic JSON");
    let semantic_decoded: T =
        json::from_value(semantic.clone()).expect("decode typed instruction semantic JSON");
    assert_eq!(semantic_decoded, value);
    let (bare_payload, header_flags) = norito::codec::encode_with_header_flags(&value);
    let concrete_frame =
        norito::core::frame_bare_with_header_flags::<T>(&bare_payload, header_flags)
            .expect("frame concrete instruction");
    let concrete_decoded: T =
        norito::decode_from_bytes(&concrete_frame).expect("decode concrete instruction frame");
    assert_eq!(concrete_decoded, value);
    assert_eq!(
        norito::core::to_bytes(&concrete_decoded).expect("re-encode concrete instruction frame"),
        concrete_frame
    );
    let boxed: InstructionBox = value.clone().into();
    let wire_id = instruction_wire_id(&boxed)
        .expect("every fixture instruction must be registered")
        .to_owned();
    let (embedded_wire_id, embedded_concrete_frame) =
        framed_instruction_payload(&boxed).expect("render registered instruction payload");
    assert_eq!(embedded_wire_id, wire_id);
    assert_eq!(embedded_concrete_frame, concrete_frame);
    let registered_decoded = decode_instruction_from_pair(&wire_id, &concrete_frame)
        .expect("decode registered concrete instruction");
    assert_eq!(
        registered_decoded
            .as_any()
            .downcast_ref::<T>()
            .expect("registered instruction concrete type"),
        &value
    );
    let (instruction_box_pair, pair_flags) = norito::codec::encode_with_header_flags(&boxed);
    assert_eq!(pair_flags, header_flags);
    let pair_decoded = {
        let _guard = DecodeFlagsGuard::enter(pair_flags);
        let (decoded, used) = InstructionBox::decode_from_slice(&instruction_box_pair)
            .expect("decode bare InstructionBox pair");
        assert_eq!(used, instruction_box_pair.len());
        decoded
    };
    assert_eq!(
        pair_decoded
            .as_any()
            .downcast_ref::<T>()
            .expect("bare pair concrete type"),
        &value
    );
    let (reencoded_pair, reencoded_pair_flags) =
        norito::codec::encode_with_header_flags(&pair_decoded);
    assert_eq!(reencoded_pair_flags, pair_flags);
    assert_eq!(reencoded_pair, instruction_box_pair);
    let standalone_instruction_box_frame = norito::core::frame_bare_with_header_flags::<
        InstructionBox,
    >(&instruction_box_pair, pair_flags)
    .expect("frame standalone InstructionBox");
    let standalone_decoded: InstructionBox =
        norito::decode_from_bytes(&standalone_instruction_box_frame)
            .expect("decode standalone InstructionBox frame");
    assert_eq!(
        standalone_decoded
            .as_any()
            .downcast_ref::<T>()
            .expect("standalone frame concrete type"),
        &value
    );
    assert_eq!(
        norito::core::to_bytes(&standalone_decoded)
            .expect("re-encode standalone InstructionBox frame"),
        standalone_instruction_box_frame
    );
    norito::json!({
        "id": id,
        "wire_id": wire_id,
        "concrete_schema_name": (type_name::<T>()),
        "concrete_schema_hash": (encode_hex(&norito::schema::identity::frame_hash::<T>())),
        "header_flags": header_flags,
        "semantic": semantic,
        "bare_payload_hex": (encode_hex(&bare_payload)),
        "concrete_frame_hex": (encode_hex(&concrete_frame)),
        "instruction_box_pair_hex": (encode_hex(&instruction_box_pair)),
        "standalone_instruction_box_frame_hex": (encode_hex(&standalone_instruction_box_frame)),
    })
}
/// Concrete Musubi instruction values shared with generated-record captures.
#[allow(
    dead_code,
    reason = "the generator and grouped tests render JSON; library identity tests read these fields"
)]
pub struct MusubiGeneratedIdentityValues {
    /// Namespace-binding registration fixture.
    pub(crate) register_namespace: RegisterMusubiNamespaceBindingV1,
    /// Archive-registration fixture with a verified seed-ingress receipt.
    pub(crate) register_archive: RegisterMusubiArchiveV1,
    /// Signed provider-bundle attestation with its explicit completion signer.
    pub(crate) register_provider_attestation: RegisterMusubiProviderBundleAttestationV1,
    /// Archive-location retirement fixture.
    pub(crate) retire_archive_location: RetireMusubiArchiveLocationV1,
    /// Package-metadata replacement fixture.
    pub(crate) set_package_metadata: SetMusubiPackageMetadataV1,
    /// Package-maintainer invitation fixture.
    pub(crate) invite_package_maintainer: InviteMusubiPackageMaintainerV1,
    /// Package-maintainer invitation acceptance fixture.
    pub(crate) accept_package_maintainer: AcceptMusubiPackageMaintainerV1,
    /// Package-maintainer role replacement fixture.
    pub(crate) set_package_maintainer_role: SetMusubiPackageMaintainerRoleV1,
    /// Package-maintainer removal fixture.
    pub(crate) remove_package_maintainer: RemoveMusubiPackageMaintainerV1,
    /// Alias-registration fixture.
    pub(crate) register_alias: RegisterMusubiAliasV1,
    /// Parliament-authorized package recovery fixture.
    pub(crate) recover_package: RecoverMusubiPackageV1,
    /// Parliament-authorized alias-retarget fixture.
    pub(crate) retarget_alias: RetargetMusubiAliasV1,
    /// Parliament-authorized artifact-takedown fixture.
    pub(crate) set_artifact_takedown: SetMusubiArtifactTakedownV1,
    /// Parliament-authorized registry-policy replacement fixture.
    pub(crate) set_registry_policy: SetMusubiRegistryPolicyV1,
}

/// Construct the complete instruction fixture from concrete Rust values.
#[must_use]
pub fn instruction_document() -> Value {
    instruction_document_and_generated_identity_values().0
}

/// Both closed native pin-outbox Check variants from typed first-release values.
pub fn pin_outbox_checks() -> [CheckMusubiPinOutboxV1; 2] {
    use iroha_data_model::{
        block::consensus::HeightContextId,
        musubi::{
            MusubiPinOutboxCheckExpectationV1, MusubiPinOutboxCheckFloorV1,
            MusubiPinOutboxHighWaterV1,
        },
    };
    let absent = {
        let network_id: NetworkId = fixture_network_id();
        let pin_authority: AccountId = account(INSTRUCTION_PUBLISHER_SEED);
        let session_id: [u8; 32] = [0xb7; 32];
        let inventory_digest: [u8; 32] = [0xb8; 32];
        let challenge: [u8; 32] = [0xb9; 32];
        let floor: MusubiPinOutboxCheckFloorV1 = MusubiPinOutboxCheckFloorV1 {
            height: 93,
            block_hash: [0xba; 32],
            context_id: HeightContextId(HashOf::from_untyped_unchecked(Hash::new([0xbb; 32]))),
        };
        let expected: MusubiPinOutboxCheckExpectationV1 = MusubiPinOutboxCheckExpectationV1::Absent;
        fixture_instruction::<CheckMusubiPinOutboxV1>(norito::json!({
            "network_id": network_id,
            "pin_authority": pin_authority,
            "session_id": (session_id.to_vec()),
            "inventory_digest": (inventory_digest.to_vec()),
            "challenge": (challenge.to_vec()),
            "floor": floor,
            "expected": expected,
        }))
    };
    let present = {
        let network_id: NetworkId = *absent.network_id();
        let pin_authority: AccountId = absent.pin_authority().clone();
        let session_id: [u8; 32] = *absent.session_id();
        let inventory_digest: [u8; 32] = *absent.inventory_digest();
        let challenge: [u8; 32] = [0xbc; 32];
        let floor: MusubiPinOutboxCheckFloorV1 = *absent.floor();
        let expected: MusubiPinOutboxCheckExpectationV1 =
            MusubiPinOutboxCheckExpectationV1::Present(MusubiPinOutboxHighWaterV1 {
                version: 1,
                network_id: *absent.network_id(),
                pin_authority: absent.pin_authority().clone(),
                session_id: *absent.session_id(),
                revision: 17,
                inventory_digest: *absent.inventory_digest(),
                recorded_at_height: 81,
                transaction_hash: [0xbd; 32],
            });
        fixture_instruction::<CheckMusubiPinOutboxV1>(norito::json!({
            "network_id": network_id,
            "pin_authority": pin_authority,
            "session_id": (session_id.to_vec()),
            "inventory_digest": (inventory_digest.to_vec()),
            "challenge": (challenge.to_vec()),
            "floor": floor,
            "expected": expected,
        }))
    };
    for check in [&absent, &present] {
        check.validate().expect("typed Check fixture");
    }
    [absent, present]
}

#[test]
fn musubi_pin_outbox_json_construction_preserves_declared_byte_arrays() {
    for check in pin_outbox_checks() {
        let semantic = json::to_value(&check).expect("encode declared Check JSON");
        for (field, bytes) in [
            ("session_id", check.session_id()),
            ("inventory_digest", check.inventory_digest()),
            ("challenge", check.challenge()),
        ] {
            assert_eq!(semantic[field], norito::json!(bytes.to_vec()));
        }
        let decoded: CheckMusubiPinOutboxV1 =
            json::from_value(semantic.clone()).expect("decode declared Check JSON");
        assert_eq!(decoded, check);
        let mut generic_array_json = semantic;
        *generic_array_json
            .as_object_mut()
            .expect("Check JSON object")
            .get_mut("challenge")
            .expect("Check challenge field") =
            json::to_value(check.challenge()).expect("encode generic byte-array JSON");
        assert!(matches!(
            json::from_value::<CheckMusubiPinOutboxV1>(generic_array_json),
            Err(json::Error::ExpectedArrayStart { .. })
        ));
    }
}

/// Construct the typed values needed by the generated-record identity capture.
#[allow(
    dead_code,
    reason = "only library identity tests need typed values from this shared fixture module"
)]
#[must_use]
pub fn generated_identity_values() -> MusubiGeneratedIdentityValues {
    instruction_document_and_generated_identity_values().1
}

// Constructed instructions retain one ordered owner until rendering consumes them.
struct FixtureInstructions {
    accept: AcceptMusubiPackageMaintainerV1,
    revoke: RevokeMusubiPackageMaintainerInvitationV1,
    alias: RegisterMusubiAliasV1,
    assertion: AssertMusubiReleaseDigestV1,
    retire: RetireMusubiArchiveLocationV1,
    unyank: SetMusubiReleaseYankV1,
    remove: RemoveMusubiPackageMaintainerV1,
    register_namespace: RegisterMusubiNamespaceBindingV1,
    invite: InviteMusubiPackageMaintainerV1,
    promote: SetMusubiPackageMaintainerRoleV1,
    recover: RecoverMusubiPackageV1,
    retarget: RetargetMusubiAliasV1,
    takedown: SetMusubiArtifactTakedownV1,
    register_archive: RegisterMusubiArchiveV1,
    advance_pin_outbox: AdvanceMusubiPinOutboxV1,
    register_provider_attestation: RegisterMusubiProviderBundleAttestationV1,
    add_location: AddMusubiArchiveLocationV1,
    publish: PublishMusubiReleaseV1,
    set_metadata: SetMusubiPackageMetadataV1,
    set_policy: SetMusubiRegistryPolicyV1,
}

fn instruction_document_and_generated_identity_values() -> (Value, MusubiGeneratedIdentityValues) {
    let accept = fixture_maintainer_acceptance();
    let revoke = fixture_invitation_revocation();
    let alias = fixture_alias_registration();
    let assertion = fixture_prerelease_assertion();
    let retire = fixture_archive_location_retirement();
    let unyank = fixture_release_unyank();
    let remove = fixture_maintainer_removal();
    let register_namespace = fixture_namespace_registration();
    let invite = fixture_maintainer_invitation();
    let promote = fixture_maintainer_promotion();
    let (recovery_action, recover) = fixture_package_recovery();
    let (retarget_action, retarget) = fixture_alias_retarget();
    let (takedown_action, takedown) = fixture_artifact_takedown();
    let commitment = fixture_archive_commitment();
    let (root_package, publication) = fixture_publication_graph(&commitment);
    let publisher = account(INSTRUCTION_PUBLISHER_SEED);
    let (receipt_binding, register_archive) =
        fixture_archive_registration(&commitment, &publication, &publisher);
    let advance_pin_outbox = {
        let network_id: NetworkId = fixture_network_id();
        let pin_authority: AccountId = publisher.clone();
        let session_id: [u8; 32] = [0xb7; 32];
        let expected_revision: u64 = 0;
        let expected_inventory_digest: [u8; 32] = [0; 32];
        let inventory_digest: [u8; 32] = [0xb8; 32];
        fixture_instruction::<AdvanceMusubiPinOutboxV1>(norito::json!({
            "network_id": network_id,
            "pin_authority": pin_authority,
            "session_id": (session_id.to_vec()),
            "expected_revision": expected_revision,
            "expected_inventory_digest": (expected_inventory_digest.to_vec()),
            "inventory_digest": (inventory_digest.to_vec()),
        }))
    };
    advance_pin_outbox
        .validate()
        .expect("canonical signed pin-outbox inventory fixture");
    let replication_order = fixture_replication_order();
    let provider_attestations = fixture_provider_attestations(
        &commitment,
        &publication,
        &receipt_binding,
        replication_order,
    );
    let (provider_attestation_references, register_provider_attestation, add_location) =
        fixture_provider_location(&commitment, replication_order, &provider_attestations);
    let (namespace_binding, namespace_owner, publish) =
        fixture_delegated_publication(&root_package, publication, &publisher);
    let set_metadata = fixture_package_metadata(root_package);
    let (current_policy, policy_action, set_policy) = fixture_registry_policy();
    verify_revision_and_distinctness_fixtures(
        &accept, &revoke, &assertion, &retire, &unyank, &remove,
    );
    verify_namespace_and_maintainer_fixtures(&register_namespace, &invite, &promote);
    verify_governance_decision_fixtures(&recover, &retarget, &takedown, &set_policy);
    verify_governance_action_bindings(
        &recover,
        &retarget,
        &takedown,
        &recovery_action,
        &retarget_action,
        &takedown_action,
    );
    verify_archive_publication_binding(
        &register_archive,
        &add_location,
        &publish,
        &receipt_binding,
    );
    verify_provider_location_bindings(
        &provider_attestations,
        &register_provider_attestation,
        &provider_attestation_references,
        &add_location,
        &receipt_binding,
        &publish,
        &register_archive,
    );
    verify_delegated_publication_binding(
        &publish,
        &namespace_binding,
        &namespace_owner,
        &publisher,
        &receipt_binding,
    );
    verify_metadata_and_policy_fixtures(
        &set_metadata,
        &set_policy,
        &current_policy,
        &policy_action,
    );
    FixtureInstructions {
        accept,
        revoke,
        alias,
        assertion,
        retire,
        unyank,
        remove,
        register_namespace,
        invite,
        promote,
        recover,
        retarget,
        takedown,
        register_archive,
        advance_pin_outbox,
        register_provider_attestation,
        add_location,
        publish,
        set_metadata,
        set_policy,
    }
    .into_document()
}

fn fixture_maintainer_acceptance() -> AcceptMusubiPackageMaintainerV1 {
    {
        let package: MusubiPackageIdV1 =
            package(7, MusubiPackageScopeV1::DataspaceRoot, "math-utils");
        let invite_id: MusubiInviteIdV1 = MusubiInviteIdV1::new([0x11; 32]);
        let expected_governance_revision: u64 = u64::MAX;
        fixture_instruction::<AcceptMusubiPackageMaintainerV1>(norito::json!({
            "package": package,
            "invite_id": invite_id,
            "expected_governance_revision": expected_governance_revision,
        }))
    }
}

fn fixture_invitation_revocation() -> RevokeMusubiPackageMaintainerInvitationV1 {
    {
        let package: MusubiPackageIdV1 = package(
            42,
            MusubiPackageScopeV1::Domain("finance".parse::<Name>().expect("domain name")),
            "oracle-kit",
        );
        let invite_id: MusubiInviteIdV1 = MusubiInviteIdV1::new([0x22; 32]);
        let expected_governance_revision: u64 = 9;
        fixture_instruction::<RevokeMusubiPackageMaintainerInvitationV1>(norito::json!({
            "package": package,
            "invite_id": invite_id,
            "expected_governance_revision": expected_governance_revision,
        }))
    }
}

fn fixture_alias_registration() -> RegisterMusubiAliasV1 {
    RegisterMusubiAliasV1::new(
        "oracle-tools".parse::<MusubiAliasNameV1>().expect("alias"),
        package(
            u64::MAX,
            MusubiPackageScopeV1::Domain("defi".parse::<Name>().expect("domain name")),
            "price-feed",
        ),
        17,
    )
}

fn fixture_prerelease_assertion() -> AssertMusubiReleaseDigestV1 {
    AssertMusubiReleaseDigestV1::new(
        MusubiReleaseIdV1::new(
            package(99, MusubiPackageScopeV1::DataspaceRoot, "compiler-core"),
            "1.2.3-rc.7"
                .parse::<MusubiVersionV1>()
                .expect("prerelease version"),
        ),
        MusubiReleaseDigestV1::new([0x33; 32]),
    )
}

fn fixture_archive_location_retirement() -> RetireMusubiArchiveLocationV1 {
    {
        let archive_id: ArchiveId = ArchiveId::new([0xA5; 32]);
        let location_id: MusubiArchiveLocationIdV1 = MusubiArchiveLocationIdV1::new([0x5A; 32]);
        let expected_location_revision: u64 = u64::MAX;
        let reason: MusubiReasonV1 = MusubiReasonV1::new(
            "Provider lease retired after cross-provider readback failed at epoch 9.",
        )
        .expect("retirement reason");
        fixture_instruction::<RetireMusubiArchiveLocationV1>(norito::json!({
            "archive_id": archive_id,
            "location_id": location_id,
            "expected_location_revision": expected_location_revision,
            "reason": reason,
        }))
    }
}

fn fixture_release_unyank() -> SetMusubiReleaseYankV1 {
    SetMusubiReleaseYankV1::new(
        MusubiReleaseIdV1::new(
            package(
                u64::MAX - 1,
                MusubiPackageScopeV1::Domain("operations".parse::<Name>().expect("domain name")),
                "ledger-proof",
            ),
            "0.0.1-alpha.0"
                .parse::<MusubiVersionV1>()
                .expect("prerelease version"),
        ),
        false,
        MusubiReasonV1::new("Replica quorum restored after independent bundle verification.")
            .expect("unyank reason"),
        u64::MAX - 1,
    )
}

fn fixture_maintainer_removal() -> RemoveMusubiPackageMaintainerV1 {
    {
        let package: MusubiPackageIdV1 =
            package(0, MusubiPackageScopeV1::DataspaceRoot, "access-control");
        let account: AccountId = AccountId::new(
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
                .parse()
                .expect("public key"),
        );
        let expected_governance_revision: u64 = u64::MAX - 2;
        fixture_instruction::<RemoveMusubiPackageMaintainerV1>(norito::json!({
            "package": package,
            "account": account,
            "expected_governance_revision": expected_governance_revision,
        }))
    }
}

fn fixture_namespace_registration() -> RegisterMusubiNamespaceBindingV1 {
    RegisterMusubiNamespaceBindingV1::new(
        MusubiNamespaceBindingV1 {
            namespace: "governance.universal"
                .parse::<MusubiNamespaceV1>()
                .expect("domain namespace"),
            home_dataspace: DataSpaceId::new(u64::MAX - 6),
            scope: MusubiPackageScopeV1::Domain("governance".parse::<Name>().expect("domain name")),
            generation: u64::MAX,
        },
        u64::MAX - 5,
    )
}

fn fixture_maintainer_invitation() -> InviteMusubiPackageMaintainerV1 {
    {
        let package: MusubiPackageIdV1 = package(
            5_124_095_576_030_430,
            MusubiPackageScopeV1::Domain("security".parse::<Name>().expect("domain name")),
            "key-rotation",
        );
        let invite_id: MusubiInviteIdV1 = MusubiInviteIdV1::new(core::array::from_fn(|index| {
            u8::try_from(index).expect("invite-id index fits u8")
        }));
        let invited_account: AccountId = AccountId::new(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                .parse()
                .expect("public key"),
        );
        let role: MusubiPackageRoleV1 =
            MusubiPackageRoleV1::Maintainer(MusubiMaintainerPermissionsV1 {
                publish: true,
                yank: false,
                metadata: true,
                archive_locations: false,
            });
        let expires_at_height: u64 = u64::MAX;
        let expected_governance_revision: u64 = u64::MAX - 3;
        fixture_instruction::<InviteMusubiPackageMaintainerV1>(norito::json!({
            "package": package,
            "invite_id": invite_id,
            "invited_account": invited_account,
            "role": role,
            "expires_at_height": expires_at_height,
            "expected_governance_revision": expected_governance_revision,
        }))
    }
}

fn fixture_maintainer_promotion() -> SetMusubiPackageMaintainerRoleV1 {
    {
        let package: MusubiPackageIdV1 =
            package(1, MusubiPackageScopeV1::DataspaceRoot, "consensus-tools");
        let account: AccountId = AccountId::new(
            "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
                .parse()
                .expect("public key"),
        );
        let role: MusubiPackageRoleV1 = MusubiPackageRoleV1::Owner;
        let expected_governance_revision: u64 = u64::MAX - 4;
        fixture_instruction::<SetMusubiPackageMaintainerRoleV1>(norito::json!({
            "package": package,
            "account": account,
            "role": role,
            "expected_governance_revision": expected_governance_revision,
        }))
    }
}

fn fixture_package_recovery() -> (MusubiParliamentActionV1, RecoverMusubiPackageV1) {
    let recovery_package = package(
        u64::MAX,
        MusubiPackageScopeV1::Domain("recovery".parse::<Name>().expect("domain name")),
        "registry-guard",
    );
    let mut recovery_owners = vec![
        AccountId::new(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                .parse()
                .expect("public key"),
        ),
        AccountId::new(
            "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
                .parse()
                .expect("public key"),
        ),
        AccountId::new(
            "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016"
                .parse()
                .expect("public key"),
        ),
    ];
    recovery_owners.sort();
    recovery_owners.dedup();
    let recovery_action =
        MusubiParliamentActionV1::RecoverPackageOwners(MusubiRecoverPackageOwnersV1 {
            package: recovery_package.clone(),
            owners: recovery_owners.clone(),
            expected_revision: u64::MAX - 6,
        });
    let recover = {
        let decision: MusubiGovernanceDecisionV1 = MusubiGovernanceDecisionV1 {
            decision_id: [0xC1; 32],
            action_digest: recovery_action.action_digest(),
            enacted_at_height: 1,
            execute_after_height: 2,
        };
        let package: MusubiPackageIdV1 = recovery_package;
        let owners: Vec<AccountId> = recovery_owners;
        let expected_governance_revision: u64 = u64::MAX - 6;
        fixture_instruction::<RecoverMusubiPackageV1>(norito::json!({
            "decision": decision,
            "package": package,
            "owners": owners,
            "expected_governance_revision": expected_governance_revision,
        }))
    };
    (recovery_action, recover)
}

fn fixture_alias_retarget() -> (MusubiParliamentActionV1, RetargetMusubiAliasV1) {
    let retarget_alias = "x".parse::<MusubiAliasNameV1>().expect("global alias");
    let retarget_target = package(
        0,
        MusubiPackageScopeV1::Domain("parliament".parse::<Name>().expect("domain name")),
        "emergency-target",
    );
    let retarget_action = MusubiParliamentActionV1::RetargetAlias(MusubiRetargetAliasV1 {
        alias: retarget_alias.clone(),
        target: retarget_target.clone(),
        expected_revision: u64::MAX - 7,
    });
    let retarget = {
        let decision: MusubiGovernanceDecisionV1 = MusubiGovernanceDecisionV1 {
            decision_id: core::array::from_fn(|index| {
                0x40_u8 + u8::try_from(index).expect("decision-id index fits u8")
            }),
            action_digest: retarget_action.action_digest(),
            enacted_at_height: u64::MAX - 2,
            execute_after_height: u64::MAX - 1,
        };
        let alias: MusubiAliasNameV1 = retarget_alias;
        let target: MusubiPackageIdV1 = retarget_target;
        let expected_history_revision: u64 = u64::MAX - 7;
        fixture_instruction::<RetargetMusubiAliasV1>(norito::json!({
            "decision": decision,
            "alias": alias,
            "target": target,
            "expected_history_revision": expected_history_revision,
        }))
    };
    (retarget_action, retarget)
}

fn fixture_artifact_takedown() -> (MusubiParliamentActionV1, SetMusubiArtifactTakedownV1) {
    let takedown_release = MusubiReleaseIdV1::new(
        package(
            u64::MAX - 9,
            MusubiPackageScopeV1::DataspaceRoot,
            "supply-chain",
        ),
        "18446744073709551615.0.0-incident.1"
            .parse::<MusubiVersionV1>()
            .expect("maximum-major prerelease version"),
    );
    let takedown_reason = MusubiReasonV1::new(
        "Parliament ordered takedown after reproducible signature-forgery evidence.",
    )
    .expect("takedown reason");
    let takedown_action =
        MusubiParliamentActionV1::TakedownArtifact(MusubiTakedownArtifactActionV1 {
            release: takedown_release.clone(),
            reason: takedown_reason.clone(),
            expected_artifact_governance_revision: u64::MAX - 8,
        });
    let takedown = {
        let decision: MusubiGovernanceDecisionV1 = MusubiGovernanceDecisionV1 {
            decision_id: [0xFE; 32],
            action_digest: takedown_action.action_digest(),
            enacted_at_height: u64::MAX - 1,
            execute_after_height: u64::MAX,
        };
        let release: MusubiReleaseIdV1 = takedown_release;
        let reason: MusubiReasonV1 = takedown_reason;
        let expected_artifact_governance_revision: u64 = u64::MAX - 8;
        fixture_instruction::<SetMusubiArtifactTakedownV1>(norito::json!({
            "decision": decision,
            "release": release,
            "reason": reason,
            "expected_artifact_governance_revision": expected_artifact_governance_revision,
        }))
    };
    (takedown_action, takedown)
}

fn fixture_archive_commitment() -> MusubiArchiveCommitmentV1 {
    let commitment = MusubiArchiveCommitmentV1 {
        root_cid: ManifestRootCid::from_blake3_digest([0x61; 32]).expect("root CID"),
        chunker: ChunkerProfileHandle {
            profile_id: u32::MAX,
            namespace: "sorafs".to_owned(),
            name: "musubi-v1".to_owned(),
            semver: "1.0.0".to_owned(),
            multihash_code: 0x1f,
        },
        chunk_plan_digest: MusubiContentDigestV1::new([0x62; 32]),
        por_root: MusubiContentDigestV1::new([0x63; 32]),
        content_length: MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1,
        car_digest: MusubiContentDigestV1::new([0x64; 32]),
        car_size: MUSUBI_MAX_CAR_BYTES_V1,
        bundle_digest: MusubiContentDigestV1::new([0x65; 32]),
        source_tree_digest: MusubiContentDigestV1::new([0x66; 32]),
        descriptor_digest: MusubiContentDigestV1::new([0x67; 32]),
        file_count: MUSUBI_MAX_FILES_V1,
        chunk_count: MUSUBI_MAX_CHUNKS_V1,
    };
    commitment
        .validate()
        .expect("fixture archive commitment is valid");
    commitment
}

fn fixture_publication_graph(
    commitment: &MusubiArchiveCommitmentV1,
) -> (MusubiPackageIdV1, MusubiPublicationV1) {
    let root_package = package(
        0x0123_4567_89AB_CDEF,
        MusubiPackageScopeV1::Domain("fixture".parse::<Name>().expect("domain name")),
        "deterministic-publisher",
    );
    let root_release = MusubiReleaseIdV1::new(
        root_package.clone(),
        "2.5.8-beta.13"
            .parse::<MusubiVersionV1>()
            .expect("fixture root version"),
    );
    let dependency_package = package(17, MusubiPackageScopeV1::DataspaceRoot, "vector-math");
    let dependency_release = MusubiReleaseIdV1::new(
        dependency_package.clone(),
        "1.4.2"
            .parse::<MusubiVersionV1>()
            .expect("fixture dependency version"),
    );
    let dependency_requirement = ">=1.2.0,<2.0.0"
        .parse::<MusubiVersionReqV1>()
        .expect("fixture dependency requirement");
    let exact_dependency = MusubiExactDependencyEdgeV1 {
        alias: "math".parse().expect("dependency alias"),
        kind: MusubiDependencyKindV1::Normal,
        package: dependency_package.clone(),
        requirement: dependency_requirement.clone(),
        selected: dependency_release.clone(),
    };
    let verification_lock = MusubiVerificationLockV1 {
        schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
        version: MUSUBI_REGISTRY_VERSION_V1,
        root: root_release.clone(),
        root_dependencies: vec![exact_dependency],
        nodes: vec![MusubiVerificationNodeV1 {
            release: dependency_release,
            release_digest: MusubiReleaseDigestV1::new([0x91; 32]),
            archive_id: ArchiveId::new([0x92; 32]),
            source_digest: MusubiContentDigestV1::new([0x93; 32]),
            interface_digest: MusubiContentDigestV1::new([0x94; 32]),
            abi: MusubiAbiBindingV1::new([0x95; 32]).expect("dependency ABI"),
            dependencies: Vec::new(),
        }],
    };
    verification_lock
        .validate()
        .expect("fixture verification lock is valid");
    let release_manifest = MusubiReleaseManifestV1 {
        release: root_release,
        edition: MusubiKotodamaEditionV1::V1,
        abi: MusubiAbiBindingV1::new([0xA1; 32]).expect("root ABI"),
        dependencies: vec![MusubiDependencyReqV1 {
            alias: "math".parse().expect("dependency alias"),
            package: dependency_package,
            requirement: dependency_requirement,
        }],
        exports: vec![
            "compile".parse().expect("export name"),
            "verify".parse().expect("export name"),
        ],
        interface_digest: MusubiContentDigestV1::new([0xA2; 32]),
        metadata: metadata(
            "Deterministic publication fixture with a signed namespace delegation.",
            "README.md",
            "Apache-2.0",
            "https://example.invalid/musubi/deterministic-publisher",
            &["deterministic", "kotodama", "registry"],
        ),
        archive_id: commitment.archive_id(),
        verification_lock_digest: verification_lock.digest(),
    };
    let publication = MusubiPublicationV1 {
        manifest: release_manifest,
        resolution: MusubiResolutionProofV1 {
            snapshot: MusubiRegistrySnapshotV1 {
                finalized_height: u64::MAX - 20,
                finalized_block_hash: [0xA3; 32],
                index_revision: u64::MAX - 21,
            },
            lock: verification_lock,
        },
    };
    publication
        .validate()
        .expect("fixture publication binds its exact graph");
    (root_package, publication)
}

fn fixture_archive_registration(
    commitment: &MusubiArchiveCommitmentV1,
    publication: &MusubiPublicationV1,
    publisher: &AccountId,
) -> (MusubiSeedIngressReceiptBindingV1, RegisterMusubiArchiveV1) {
    let broker_keypair = keypair(INSTRUCTION_RECEIPT_BROKER_SEED);
    let receipt_binding = MusubiSeedIngressReceiptBindingV1 {
        network_id: fixture_network_id(),
        publisher: publisher.clone(),
        ingress_broker: AccountId::new(broker_keypair.public_key().clone()),
        seed_provider: ProviderId::new([0xB2; 32]),
        semantic_release_manifest_digest: publication.manifest.semantic_digest(),
        archive_id: commitment.archive_id(),
        car_body_digest: commitment.car_digest,
        car_body_length: commitment.car_size,
        nonce: core::array::from_fn(|index| {
            0xC0_u8 + u8::try_from(index).expect("nonce index fits u8")
        }),
    };
    let receipt_payload = MusubiSeedIngressReceiptPayloadV1 {
        version: MUSUBI_REGISTRY_VERSION_V1,
        binding: receipt_binding.clone(),
        issued_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_086_400_000,
    };
    let staging_receipt = MusubiSeedIngressReceiptV1 {
        approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
            public_key: broker_keypair.public_key().clone(),
            signature: SignatureOf::try_from_hash(
                broker_keypair.private_key(),
                receipt_payload.signing_hash(),
            )
            .expect("sign staging receipt"),
        }],
        payload: receipt_payload,
    };
    staging_receipt
        .verify(&receipt_binding, 1_700_000_000_001)
        .expect("fixture staging receipt verifies");
    let register_archive =
        RegisterMusubiArchiveV1::new(commitment.clone(), staging_receipt, u64::MAX - 30);
    (receipt_binding, register_archive)
}

fn fixture_provider_attestations(
    commitment: &MusubiArchiveCommitmentV1,
    publication: &MusubiPublicationV1,
    receipt_binding: &MusubiSeedIngressReceiptBindingV1,
    replication_order: ReplicationOrderId,
) -> Vec<MusubiProviderBundleVerificationAttestationV1> {
    [
        (0xD1, INSTRUCTION_PROVIDER_1_SEED, 0xE1, 0xF1, 0x71),
        (0xD2, INSTRUCTION_PROVIDER_2_SEED, 0xE2, 0xF2, 0x72),
        (0xD3, INSTRUCTION_PROVIDER_3_SEED, 0xE3, 0xF3, 0x73),
    ]
    .into_iter()
    .enumerate()
    .map(
        |(index, (provider_byte, key_seed, policy_byte, digest_byte, block_byte))| {
            let owner_keypair = keypair(key_seed);
            let provider_id = ProviderId::new([provider_byte; 32]);
            let owner = AccountId::new(owner_keypair.public_key().clone());
            let binding = MusubiProviderBundleVerificationBindingV1 {
                network_id: receipt_binding.network_id,
                provider_id,
                completed_by: owner.clone(),
                completion_authority: ProviderIngestCompletionAuthorityV1::new(
                    owner.clone(),
                    owner,
                    ProviderIngestCompletionSignerPolicyV1 {
                        policy_id: [policy_byte; 32],
                        revision: 2,
                        predecessor_digest: Some([policy_byte.wrapping_add(8); 32]),
                        policy_digest: [digest_byte; 32],
                    },
                ),
                replication_order,
                assignment_revision: u64::MAX
                    - 40
                    - u64::try_from(index).expect("provider index fits u64"),
                completion_epoch: 600 + u64::try_from(index).expect("provider index fits u64"),
                finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                    height: 700 + u64::try_from(index).expect("provider index fits u64"),
                    block_hash: [block_byte; 32],
                },
                archive_id: commitment.archive_id(),
                bundle_digest: commitment.bundle_digest,
                descriptor_digest: commitment.descriptor_digest,
                semantic_release_manifest_digest: publication.manifest.semantic_digest(),
                verification_lock_digest: publication.manifest.verification_lock_digest,
                source_tree_digest: commitment.source_tree_digest,
            };
            let payload = MusubiProviderBundleVerificationPayloadV1 {
                version: MUSUBI_REGISTRY_VERSION_V1,
                binding: binding.clone(),
            };
            let attestation = MusubiProviderBundleVerificationAttestationV1 {
                approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
                    public_key: owner_keypair.public_key().clone(),
                    signature: SignatureOf::try_from_hash(
                        owner_keypair.private_key(),
                        payload.signing_hash(),
                    )
                    .expect("sign provider attestation"),
                }],
                payload,
            };
            attestation
                .verify(&binding)
                .expect("fixture provider attestation verifies");
            attestation
        },
    )
    .collect::<Vec<_>>()
}

fn fixture_provider_location(
    commitment: &MusubiArchiveCommitmentV1,
    replication_order: ReplicationOrderId,
    provider_attestations: &[MusubiProviderBundleVerificationAttestationV1],
) -> (
    Vec<MusubiProviderBundleAttestationRefV1>,
    RegisterMusubiProviderBundleAttestationV1,
    AddMusubiArchiveLocationV1,
) {
    let provider_attestation_references = provider_attestations
        .iter()
        .map(MusubiProviderBundleVerificationAttestationV1::reference)
        .collect::<Vec<_>>();
    let register_provider_attestation = RegisterMusubiProviderBundleAttestationV1::new(
        provider_attestations[0].clone(),
        u64::MAX - 31,
    );
    let provider_attestation_set_digest = musubi_provider_bundle_attestation_set_digest_v1(
        commitment.archive_id(),
        replication_order,
        &provider_attestation_references,
    )
    .expect("fixture provider attestation set is canonical");
    let add_location = {
        let archive_id: ArchiveId = commitment.archive_id();
        let location_id: MusubiArchiveLocationIdV1 = MusubiArchiveLocationIdV1::new([0xC3; 32]);
        let pin_manifest: ManifestDigest = ManifestDigest::new([0xC1; 32]);
        let replication_order: ReplicationOrderId = replication_order;
        let provider_attestation_set_digest: iroha_data_model::musubi::MusubiProviderBundleAttestationSetDigestV1 = provider_attestation_set_digest;
        let renew_after_epoch: u64 = 1_000;
        let expires_at_epoch: u64 = 2_000;
        let expected_location_revision: u64 = u64::MAX - 31;
        fixture_instruction::<AddMusubiArchiveLocationV1>(norito::json!({
            "archive_id": archive_id,
            "location_id": location_id,
            "pin_manifest": pin_manifest,
            "replication_order": replication_order,
            "provider_attestation_set_digest": provider_attestation_set_digest,
            "renew_after_epoch": renew_after_epoch,
            "expires_at_epoch": expires_at_epoch,
            "expected_location_revision": expected_location_revision,
        }))
    };
    (
        provider_attestation_references,
        register_provider_attestation,
        add_location,
    )
}

fn fixture_delegated_publication(
    root_package: &MusubiPackageIdV1,
    publication: MusubiPublicationV1,
    publisher: &AccountId,
) -> (MusubiNamespaceBindingV1, AccountId, PublishMusubiReleaseV1) {
    let namespace_binding = MusubiNamespaceBindingV1 {
        namespace: "fixture.universal"
            .parse::<MusubiNamespaceV1>()
            .expect("fixture namespace"),
        home_dataspace: root_package.home_dataspace,
        scope: root_package.scope.clone(),
        generation: u64::MAX - 50,
    };
    let namespace_owner_keypair = keypair(INSTRUCTION_NAMESPACE_OWNER_SEED);
    let namespace_owner = AccountId::new(namespace_owner_keypair.public_key().clone());
    let delegation_payload = MusubiNamespaceDelegationPayloadV1 {
        version: MUSUBI_REGISTRY_VERSION_V1,
        namespace_binding: namespace_binding.digest(),
        owner_generation: namespace_binding.generation,
        owner: namespace_owner.clone(),
        delegate: publisher.clone(),
        expires_at_height: u64::MAX - 1,
    };
    let namespace_delegation = MusubiNamespaceDelegationV1 {
        approvals: vec![MusubiNamespaceDelegationApprovalV1 {
            public_key: namespace_owner_keypair.public_key().clone(),
            signature: SignatureOf::try_from_hash(
                namespace_owner_keypair.private_key(),
                delegation_payload.signing_hash(),
            )
            .expect("sign namespace delegation"),
        }],
        payload: delegation_payload,
    };
    namespace_delegation
        .verify(
            &namespace_binding,
            &namespace_owner,
            namespace_binding.generation,
            publisher,
            u64::MAX - 2,
        )
        .expect("fixture namespace delegation verifies");
    let publish = PublishMusubiReleaseV1::new(
        namespace_binding.namespace.clone(),
        publication,
        Some(namespace_delegation),
        u64::MAX - 29,
        None,
    );
    (namespace_binding, namespace_owner, publish)
}

fn fixture_package_metadata(root_package: MusubiPackageIdV1) -> SetMusubiPackageMetadataV1 {
    {
        let package: MusubiPackageIdV1 = root_package;
        let metadata: MusubiReleaseMetadataV1 = metadata(
            "Package metadata replaced after independent source and interface review.",
            "docs/overview.md",
            "LICENSES/Apache-2.0.txt",
            "https://example.invalid/musubi/reviewed-package",
            &["audit-ready", "sorafs", "supply-chain"],
        );
        let expected_metadata_revision: u64 = u64::MAX - 28;
        fixture_instruction::<SetMusubiPackageMetadataV1>(norito::json!({
            "package": package,
            "metadata": metadata,
            "expected_metadata_revision": expected_metadata_revision,
        }))
    }
}

fn fixture_registry_policy() -> (
    MusubiRegistryPolicyV1,
    MusubiParliamentActionV1,
    SetMusubiRegistryPolicyV1,
) {
    let current_policy = MusubiRegistryPolicyV1::default();
    let replacement_policy = MusubiRegistryPolicyV1 {
        version: MUSUBI_REGISTRY_VERSION_V1,
        revision: 2,
        mode: MusubiRegistryAdmissionModeV1::Allowlisted,
        allowlisted_dataspaces: vec![
            DataSpaceId::new(0),
            DataSpaceId::new(0x0123_4567_89AB_CDEF),
            DataSpaceId::new(u64::MAX),
        ],
        alias_pricing: MusubiAliasPricingPolicyV1 {
            revision: 2,
            length_1_xor: 2_000,
            length_2_xor: 400,
            length_3_xor: 80,
            length_4_xor: 16,
            length_5_to_32_xor: 2,
        },
    };
    replacement_policy
        .validate_successor(&current_policy)
        .expect("fixture policy is the exact successor");
    let policy_action =
        MusubiParliamentActionV1::SetRegistryPolicy(MusubiSetRegistryPolicyActionV1 {
            policy: replacement_policy.clone(),
            expected_revision: current_policy.revision,
        });
    policy_action
        .validate()
        .expect("fixture policy action is valid");
    let set_policy = {
        let decision: MusubiGovernanceDecisionV1 = MusubiGovernanceDecisionV1 {
            decision_id: [0xF7; 32],
            action_digest: policy_action.action_digest(),
            enacted_at_height: u64::MAX - 1,
            execute_after_height: u64::MAX,
        };
        let policy: MusubiRegistryPolicyV1 = replacement_policy;
        let expected_policy_revision: u64 = current_policy.revision;
        fixture_instruction::<SetMusubiRegistryPolicyV1>(norito::json!({
            "decision": decision,
            "policy": policy,
            "expected_policy_revision": expected_policy_revision,
        }))
    };
    (current_policy, policy_action, set_policy)
}

fn verify_revision_and_distinctness_fixtures(
    accept: &AcceptMusubiPackageMaintainerV1,
    revoke: &RevokeMusubiPackageMaintainerInvitationV1,
    assertion: &AssertMusubiReleaseDigestV1,
    retire: &RetireMusubiArchiveLocationV1,
    unyank: &SetMusubiReleaseYankV1,
    remove: &RemoveMusubiPackageMaintainerV1,
) {
    assert_ne!(*accept.invite_id(), *revoke.invite_id());
    assert_ne!(
        accept.invite_id().as_bytes(),
        assertion.expected_digest().as_bytes()
    );
    assert_ne!(
        revoke.invite_id().as_bytes(),
        assertion.expected_digest().as_bytes()
    );
    assert!(assertion.release().version.is_prerelease());
    assert!(!*unyank.yanked());
    assert_eq!(*retire.expected_location_revision(), u64::MAX);
    assert_eq!(*unyank.expected_yank_revision(), u64::MAX - 1);
    assert_eq!(*remove.expected_governance_revision(), u64::MAX - 2);
}

fn verify_namespace_and_maintainer_fixtures(
    register_namespace: &RegisterMusubiNamespaceBindingV1,
    invite: &InviteMusubiPackageMaintainerV1,
    promote: &SetMusubiPackageMaintainerRoleV1,
) {
    register_namespace
        .binding()
        .validate_authority_generation(u64::MAX)
        .expect("namespace binding generation is current");
    assert_eq!(
        register_namespace.binding().namespace.domain_segment(),
        Some("governance")
    );
    assert_eq!(*register_namespace.expected_policy_revision(), u64::MAX - 5);
    assert!(!invite.invite_id().is_zero());
    assert_eq!(*invite.expires_at_height(), u64::MAX);
    assert_eq!(*invite.expected_governance_revision(), u64::MAX - 3);
    let MusubiPackageRoleV1::Maintainer(permissions) = *invite.role() else {
        panic!("fixture invitation offers a maintainer role");
    };
    assert!(!permissions.is_empty());
    assert!(permissions.publish);
    assert!(!permissions.yank);
    assert!(permissions.metadata);
    assert!(!permissions.archive_locations);
    assert_ne!(*invite.invited_account(), *promote.account());
    assert_eq!(*promote.role(), MusubiPackageRoleV1::Owner);
    assert_eq!(*promote.expected_governance_revision(), u64::MAX - 4);
}

fn verify_governance_decision_fixtures(
    recover: &RecoverMusubiPackageV1,
    retarget: &RetargetMusubiAliasV1,
    takedown: &SetMusubiArtifactTakedownV1,
    set_policy: &SetMusubiRegistryPolicyV1,
) {
    for decision in [
        *recover.decision(),
        *retarget.decision(),
        *takedown.decision(),
        *set_policy.decision(),
    ] {
        decision.validate().expect("valid enacted decision anchors");
        assert!(decision.enacted_at_height < decision.execute_after_height);
    }
    assert_eq!(
        BTreeSet::from([
            recover.decision().decision_id,
            retarget.decision().decision_id,
            takedown.decision().decision_id,
            set_policy.decision().decision_id,
        ])
        .len(),
        4
    );
}

fn verify_governance_action_bindings(
    recover: &RecoverMusubiPackageV1,
    retarget: &RetargetMusubiAliasV1,
    takedown: &SetMusubiArtifactTakedownV1,
    recovery_action: &MusubiParliamentActionV1,
    retarget_action: &MusubiParliamentActionV1,
    takedown_action: &MusubiParliamentActionV1,
) {
    assert_eq!(recover.owners().len(), 3);
    assert!(recover.owners().windows(2).all(|pair| pair[0] < pair[1]));
    recovery_action
        .validate()
        .expect("valid package recovery action");
    retarget_action
        .validate()
        .expect("valid alias retarget action");
    takedown_action
        .validate()
        .expect("valid artifact takedown action");
    let MusubiParliamentActionV1::RecoverPackageOwners(recovery_payload) = recovery_action else {
        panic!("fixture recovery action has the expected variant");
    };
    assert_eq!(recovery_payload.package, *recover.package());
    assert_eq!(recovery_payload.owners, *recover.owners());
    assert_eq!(
        recovery_payload.expected_revision,
        *recover.expected_governance_revision()
    );
    assert_eq!(
        recover.decision().action_digest,
        recovery_action.action_digest()
    );
    let MusubiParliamentActionV1::RetargetAlias(retarget_payload) = retarget_action else {
        panic!("fixture alias action has the expected variant");
    };
    assert_eq!(retarget_payload.alias, *retarget.alias());
    assert_eq!(retarget_payload.target, *retarget.target());
    assert_eq!(
        retarget_payload.expected_revision,
        *retarget.expected_history_revision()
    );
    assert_eq!(
        retarget.decision().action_digest,
        retarget_action.action_digest()
    );
    let MusubiParliamentActionV1::TakedownArtifact(takedown_payload) = takedown_action else {
        panic!("fixture takedown action has the expected variant");
    };
    assert_eq!(takedown_payload.release, *takedown.release());
    assert_eq!(takedown_payload.reason, *takedown.reason());
    assert_eq!(
        takedown_payload.expected_artifact_governance_revision,
        *takedown.expected_artifact_governance_revision()
    );
    assert_eq!(
        takedown.decision().action_digest,
        takedown_action.action_digest()
    );
    assert_eq!(*recover.expected_governance_revision(), u64::MAX - 6);
    assert_eq!(*retarget.expected_history_revision(), u64::MAX - 7);
    assert_eq!(
        *takedown.expected_artifact_governance_revision(),
        u64::MAX - 8
    );
    assert!(takedown.release().version.is_prerelease());
}

fn verify_archive_publication_binding(
    register_archive: &RegisterMusubiArchiveV1,
    add_location: &AddMusubiArchiveLocationV1,
    publish: &PublishMusubiReleaseV1,
    receipt_binding: &MusubiSeedIngressReceiptBindingV1,
) {
    register_archive
        .commitment()
        .validate()
        .expect("fixture archive commitment remains valid");
    register_archive
        .staging_receipt()
        .verify(receipt_binding, 1_700_000_000_001)
        .expect("fixture staging receipt remains bound and signed");
    assert_eq!(
        register_archive.commitment().archive_id(),
        *add_location.archive_id()
    );
    assert_eq!(
        register_archive.commitment().archive_id(),
        publish.publication().manifest.archive_id
    );
    assert_eq!(
        register_archive
            .staging_receipt()
            .payload
            .binding
            .archive_id,
        *add_location.archive_id()
    );
    assert_eq!(
        register_archive
            .staging_receipt()
            .payload
            .binding
            .semantic_release_manifest_digest,
        publish.publication().manifest.semantic_digest()
    );
    assert_eq!(*register_archive.expected_policy_revision(), u64::MAX - 30);
}

fn verify_provider_location_bindings(
    provider_attestations: &[MusubiProviderBundleVerificationAttestationV1],
    register_provider_attestation: &RegisterMusubiProviderBundleAttestationV1,
    provider_attestation_references: &[MusubiProviderBundleAttestationRefV1],
    add_location: &AddMusubiArchiveLocationV1,
    receipt_binding: &MusubiSeedIngressReceiptBindingV1,
    publish: &PublishMusubiReleaseV1,
    register_archive: &RegisterMusubiArchiveV1,
) {
    assert_eq!(provider_attestations.len(), 3);
    assert!(
        provider_attestations
            .windows(2)
            .all(|pair| pair[0].payload.binding.provider_id < pair[1].payload.binding.provider_id)
    );
    assert!(*add_location.renew_after_epoch() < *add_location.expires_at_epoch());
    assert_eq!(*add_location.expected_location_revision(), u64::MAX - 31);
    register_provider_attestation
        .validate()
        .expect("fixture registered provider attestation remains valid");
    assert_eq!(
        *register_provider_attestation.expected_location_revision(),
        *add_location.expected_location_revision()
    );
    assert_eq!(
        register_provider_attestation.attestation().reference(),
        provider_attestation_references[0]
    );
    assert_eq!(
        *add_location.provider_attestation_set_digest(),
        musubi_provider_bundle_attestation_set_digest_v1(
            *add_location.archive_id(),
            *add_location.replication_order(),
            provider_attestation_references,
        )
        .expect("fixture provider attestation references remain canonical")
    );
    for attestation in provider_attestations {
        let binding = &attestation.payload.binding;
        attestation
            .verify(binding)
            .expect("fixture provider attestation remains bound and signed");
        assert_eq!(binding.archive_id, *add_location.archive_id());
        assert_eq!(binding.replication_order, *add_location.replication_order());
        assert_eq!(binding.network_id, receipt_binding.network_id);
        assert_eq!(
            binding.semantic_release_manifest_digest,
            publish.publication().manifest.semantic_digest()
        );
        assert_eq!(
            binding.verification_lock_digest,
            publish.publication().manifest.verification_lock_digest
        );
        assert_eq!(
            binding.bundle_digest,
            register_archive.commitment().bundle_digest
        );
        assert_eq!(
            binding.descriptor_digest,
            register_archive.commitment().descriptor_digest
        );
        assert_eq!(
            binding.source_tree_digest,
            register_archive.commitment().source_tree_digest
        );
    }
}

fn verify_delegated_publication_binding(
    publish: &PublishMusubiReleaseV1,
    namespace_binding: &MusubiNamespaceBindingV1,
    namespace_owner: &AccountId,
    publisher: &AccountId,
    receipt_binding: &MusubiSeedIngressReceiptBindingV1,
) {
    publish
        .publication()
        .validate()
        .expect("fixture publication remains bound to its exact graph");
    assert_eq!(*publish.namespace(), namespace_binding.namespace);
    assert_eq!(*publish.expected_policy_revision(), u64::MAX - 29);
    assert_eq!(*publish.expected_governance_revision(), None);
    let delegation = publish
        .namespace_delegation()
        .as_ref()
        .expect("fixture publication carries a namespace delegation");
    delegation
        .verify(
            namespace_binding,
            namespace_owner,
            namespace_binding.generation,
            publisher,
            u64::MAX - 2,
        )
        .expect("fixture namespace delegation remains bound and signed");
    assert_eq!(delegation.payload.delegate, receipt_binding.publisher);
}

fn verify_metadata_and_policy_fixtures(
    set_metadata: &SetMusubiPackageMetadataV1,
    set_policy: &SetMusubiRegistryPolicyV1,
    current_policy: &MusubiRegistryPolicyV1,
    policy_action: &MusubiParliamentActionV1,
) {
    set_metadata
        .metadata()
        .validate()
        .expect("fixture replacement metadata remains canonical");
    assert_eq!(*set_metadata.expected_metadata_revision(), u64::MAX - 28);
    set_policy
        .policy()
        .validate_successor(current_policy)
        .expect("fixture replacement policy remains the exact successor");
    let MusubiParliamentActionV1::SetRegistryPolicy(policy_payload) = policy_action else {
        panic!("fixture registry policy action has the expected variant");
    };
    assert_eq!(policy_payload.policy, *set_policy.policy());
    assert_eq!(
        policy_payload.expected_revision,
        *set_policy.expected_policy_revision()
    );
    assert_eq!(
        *set_policy.expected_policy_revision(),
        current_policy.revision
    );
    assert_eq!(
        set_policy.decision().action_digest,
        policy_action.action_digest()
    );
}

impl FixtureInstructions {
    fn into_document(self) -> (Value, MusubiGeneratedIdentityValues) {
        let Self {
            accept,
            revoke,
            alias,
            assertion,
            retire,
            unyank,
            remove,
            register_namespace,
            invite,
            promote,
            recover,
            retarget,
            takedown,
            register_archive,
            advance_pin_outbox,
            register_provider_attestation,
            add_location,
            publish,
            set_metadata,
            set_policy,
        } = self;
        let generated_identity_values = MusubiGeneratedIdentityValues {
            register_namespace: register_namespace.clone(),
            register_archive: register_archive.clone(),
            register_provider_attestation: register_provider_attestation.clone(),
            retire_archive_location: retire.clone(),
            set_package_metadata: set_metadata.clone(),
            invite_package_maintainer: invite.clone(),
            accept_package_maintainer: accept.clone(),
            set_package_maintainer_role: promote.clone(),
            remove_package_maintainer: remove.clone(),
            register_alias: alias.clone(),
            recover_package: recover.clone(),
            retarget_alias: retarget.clone(),
            set_artifact_takedown: takedown.clone(),
            set_registry_policy: set_policy.clone(),
        };
        let cases = vec![
            render_instruction_case("accept-root-max-revision", accept),
            render_instruction_case("revoke-domain-invitation", revoke),
            render_instruction_case("register-alias-domain-target", alias),
            render_instruction_case("assert-prerelease-digest", assertion),
            render_instruction_case("retire-location-max-revision", retire),
            render_instruction_case("unyank-domain-release-high-revision", unyank),
            render_instruction_case("remove-root-maintainer-high-revision", remove),
            render_instruction_case(
                "register-domain-namespace-max-generation",
                register_namespace,
            ),
            render_instruction_case("invite-domain-maintainer-max-expiry", invite),
            render_instruction_case("promote-root-member-to-owner-high-revision", promote),
            render_instruction_case("recover-domain-package-three-owners", recover),
            render_instruction_case("retarget-one-character-alias-high-revision", retarget),
            render_instruction_case("takedown-max-major-prerelease", takedown),
            render_instruction_case(
                "register-archive-max-bounds-signed-receipt",
                register_archive,
            ),
            render_instruction_case("advance-signed-pin-outbox-inventory", advance_pin_outbox),
            render_instruction_case(
                "check-authority-wide-pin-outbox-absent",
                pin_outbox_checks()[0].clone(),
            ),
            render_instruction_case(
                "check-complete-pin-outbox-present",
                pin_outbox_checks()[1].clone(),
            ),
            render_instruction_case(
                "register-provider-bundle-attestation",
                register_provider_attestation,
            ),
            render_instruction_case("add-location-three-signed-providers", add_location),
            render_instruction_case("publish-delegated-domain-release", publish),
            render_instruction_case("replace-domain-metadata-high-revision", set_metadata),
            render_instruction_case("set-allowlisted-policy-repriced-aliases", set_policy),
        ];
        (
            norito::json!({
                "format": "iroha-musubi-instructions-v1",
                "fixture_version": 1,
                "rust_owner": "iroha_data_model::isi::musubi",
                "instruction_box_schema_name": (<InstructionBox as norito::NoritoSchema>::frame_name()),
                "instruction_box_schema_hash": (encode_hex(
                    &norito::schema::identity::frame_hash::<InstructionBox>(),
                )),
                "cases": cases,
            }),
            generated_identity_values,
        )
    }
}
