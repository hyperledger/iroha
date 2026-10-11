#[cfg(feature = "governance")]
use crate::isi::governance;
mod wire_ids;

#[cfg(test)]
mod native_capture;
use crate::{
    isi::{
        InstructionRegistry, account_recovery, alias_setup, asset_alias, asset_transfer_control,
        bridge, confidential, consensus_keys, content, contract_alias, defi, endorsement, escrow,
        game, identifier, kaigi, ministry, musubi, nexus, nft_market, oracle, privacy, ram_lfe,
        repo, runtime_upgrade, rwa, sccp, settlement, smart_contract_code, social, soracloud,
        soradns, sorafs, space_directory,
        transparent::{
            AddSignatory, InvalidInstruction, RemoveAssetKeyValue, RemoveSignatory,
            SetAccountQuorum, SetAssetKeyValue,
        },
        verifying_keys, vpn, zk,
    },
    prelude::*,
};
/// Signature of helper functions that register instructions into [`InstructionRegistry`].
type Registrar = fn(InstructionRegistry) -> InstructionRegistry;
/// Create an [`InstructionRegistry`] populated with all instructions supported
/// by Iroha out of the box.
pub fn default() -> InstructionRegistry {
    wire_ids::register_all()
}
/// Read the sole built-in encoding inventory without constructing the decoder registry.
pub(super) fn default_encoding_entry(
    type_name: &'static str,
) -> Option<super::InstructionEncodingEntry> {
    wire_ids::encoding_entry(type_name)
}
/// Return whether `wire_id` identifies a built-in instruction accepted by the default registry.
///
/// Sponsor-program revision validation uses this fail-closed lookup before an
/// immutable native-instruction selector can be staged.
#[must_use]
pub fn is_instruction_wire_id_registered(wire_id: &str) -> bool {
    static DEFAULT_REGISTRY: std::sync::OnceLock<InstructionRegistry> = std::sync::OnceLock::new();
    DEFAULT_REGISTRY.get_or_init(default).contains(wire_id)
}
#[cfg(test)]
pub(super) fn encoding_inventory_for_tests() -> impl Iterator<Item = (&'static str, &'static str)> {
    wire_ids::ALL
        .iter()
        .map(|record| ((record.type_name)(), record.wire_id))
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::numeric::{Numeric, Quantity};
    #[test]
    fn citizen_bond_operations_are_not_production_instructions() {
        // Commitment-only bond records do not establish native custody or authorization.
        // Production admission requires a complete, qualified native lifecycle first.
        let registry = default();
        for operation in [
            "RegisterSorafsCitizenBond",
            "RotateSorafsCitizenBondAuthorization",
            "RequestSorafsCitizenBondExit",
        ] {
            let wire_id = format!("iroha.instruction.v1::sorafs::{operation}");
            assert!(!registry.contains(&wire_id));
            assert!(registry.decode(&wire_id, &[]).is_none());
        }
    }

    fn xor_quantity_nanos(value: u128) -> Quantity {
        Quantity::from_canonical_numeric(Numeric::new(
            value,
            crate::sorafs::pricing::XOR_QUANTITY_SCALE,
        ))
        .expect("u128 nano-XOR registry fixture fits Quantity")
    }
    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked ISI registry fixture account keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn domain_id() -> DomainId {
        DomainId::try_new("wonderland", "universal").expect("domain id")
    }
    fn asset_definition_id() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(domain_id(), "rose".parse().expect("asset name"))
    }
    fn asset_id() -> AssetId {
        AssetId::of(asset_definition_id(), account(0xA1))
    }
    fn trigger_id() -> TriggerId {
        "registry_tick".parse().expect("trigger id")
    }
    fn role_id() -> RoleId {
        "registry_auditor".parse().expect("role id")
    }
    fn assert_default_registry_decodes<T>(value: T)
    where
        T: crate::isi::Instruction
            + norito::codec::Encode
            + 'static
            + norito::core::NoritoSerialize,
        for<'de> T: norito::core::NoritoDeserialize<'de>,
    {
        let registry = default();
        let wire_id = registry
            .wire_id(std::any::type_name::<T>())
            .expect("instruction type has an explicit V1 wire identifier");
        let (payload, flags) = norito::codec::encode_with_header_flags(&value);
        let framed = norito::core::frame_bare_with_header_flags::<T>(&payload, flags)
            .expect("frame instruction payload");
        let decoded = registry
            .decode(wire_id, &framed)
            .expect("registered instruction")
            .expect("decode instruction");
        assert_eq!(crate::isi::Instruction::dyn_encode(&*decoded), payload);
    }
    fn framed_instruction_payload<T>(value: &T) -> Vec<u8>
    where
        T: crate::isi::Instruction
            + norito::codec::Encode
            + 'static
            + norito::core::NoritoSerialize,
    {
        let (payload, flags) = norito::codec::encode_with_header_flags(value);
        norito::core::frame_bare_with_header_flags::<T>(&payload, flags)
            .expect("frame instruction payload")
    }
    fn raw_instruction_payload<T>(value: &T) -> Vec<u8>
    where
        T: crate::isi::Instruction + norito::codec::Encode,
    {
        let (payload, _) = norito::codec::encode_with_header_flags(value);
        payload
    }
    fn framed_instruction_payload_with_tag<T>(value: &T, tag: u32) -> Vec<u8>
    where
        T: crate::isi::Instruction
            + norito::codec::Encode
            + 'static
            + norito::core::NoritoSerialize,
    {
        let (mut payload, flags) = norito::codec::encode_with_header_flags(value);
        payload
            .get_mut(..4)
            .expect("boxed instruction payload starts with a variant tag")
            .copy_from_slice(&tag.to_le_bytes());
        norito::core::frame_bare_with_header_flags::<T>(&payload, flags)
            .expect("frame instruction payload")
    }
    fn assert_default_registry_rejects_payload<T>(wire_id: &str, value: T)
    where
        T: crate::isi::Instruction
            + norito::codec::Encode
            + 'static
            + norito::core::NoritoSerialize,
    {
        let registry = default();
        let framed = framed_instruction_payload(&value);
        let decoded = registry
            .decode(wire_id, &framed)
            .expect("canonical wire id remains registered");
        assert!(
            decoded.is_err(),
            "{wire_id} must reject payload encoded for {}",
            std::any::type_name::<T>()
        );
    }
    fn assert_default_registry_rejects_framed_payload(wire_id: &str, framed: &[u8], source: &str) {
        let registry = default();
        let decoded = registry
            .decode(wire_id, framed)
            .expect("canonical wire id remains registered");
        assert!(
            decoded.is_err(),
            "{wire_id} must reject framed payload encoded for {source}"
        );
    }
    fn settlement_leg(from: AccountId, to: AccountId, quantity: u32) -> settlement::SettlementLeg {
        settlement::SettlementLeg::new(asset_definition_id(), quantity, from, to)
    }
    fn assert_instruction_box_uses_wire_id(
        instruction: InstructionBox,
        expected_wire_id: &str,
        expected_type_name: &'static str,
    ) {
        let (wire_id, framed) = super::super::encoded_instruction_pair_payload(&instruction)
            .expect("instruction is registered for pair encoding");
        assert_eq!(
            wire_id, expected_wire_id,
            "InstructionBox conversion must use canonical boxed wire id"
        );
        let decoded = default()
            .decode(wire_id, &framed)
            .expect("encoded wire id is registered")
            .expect("encoded payload decodes");
        assert_eq!(
            crate::isi::Instruction::id(&*decoded),
            expected_type_name,
            "pair payload should decode back into the canonical boxed family"
        );
    }
    #[cfg(feature = "governance")]
    #[test]
    fn parliament_registry_contains_only_current_lifecycle_and_standalone_ballots() {
        let registry = default();
        for active in [
            crate::isi::governance::CreateParliamentGovernanceAttemptV1::WIRE_ID,
            crate::isi::governance::SubmitParliamentLifecycleTransitionV1::WIRE_ID,
            "iroha.instruction.v1::governance::CastZkBallot",
            "iroha.instruction.v1::governance::CastPlainBallot",
            "iroha.instruction.v1::governance::UpdatePlainConviction",
        ] {
            assert!(
                registry.contains(active),
                "active Parliament or standalone referendum wire id is missing: {active}"
            );
        }
        for retired in [
            "iroha_data_model::isi::governance::ApproveGovernanceProposal",
            "iroha_data_model::isi::governance::CastParliamentBallot",
            "iroha_data_model::isi::governance::FinalizeReferendum",
            "iroha_data_model::isi::governance::EnactReferendum",
        ] {
            assert!(
                !registry.contains(retired),
                "retired proposal-backed governance wire id remains registered: {retired}"
            );
            assert!(
                !is_instruction_wire_id_registered(retired),
                "retired proposal-backed governance wire id remains publicly accepted: {retired}"
            );
        }
    }
    #[test]
    fn default_registry_registers_signed_public_lane_candidate() {
        let registry = default();
        let type_name = std::any::type_name::<crate::isi::staking::RegisterPublicLaneCandidate>();
        assert_eq!(
            registry.wire_id(type_name),
            Some("iroha.staking.register_public_lane_candidate")
        );
        assert!(!registry.contains(type_name));
    }
    #[test]
    fn default_registry_registers_public_lane_validator() {
        let registry = default();
        let type_name = std::any::type_name::<crate::isi::staking::RegisterPublicLaneValidator>();
        assert!(registry.wire_id(type_name).is_some());
        assert!(!registry.contains(type_name));
    }
    #[test]
    fn default_registry_registers_public_lane_validator_rebind() {
        let registry = default();
        let type_name = std::any::type_name::<crate::isi::staking::RebindPublicLaneValidatorPeer>();
        assert!(registry.wire_id(type_name).is_some());
        assert!(!registry.contains(type_name));
    }
    #[test]
    fn default_registry_registers_kaigi_relay_health_report() {
        let registry = default();
        let type_name = std::any::type_name::<crate::isi::kaigi::ReportKaigiRelayHealth>();
        assert!(registry.wire_id(type_name).is_some());
        assert!(!registry.contains(type_name));
    }
    #[test]
    fn instruction_registry_inventory_is_complete_unique_and_registered() {
        let registry = default();
        let registered_type_names = registry.names().collect::<std::collections::BTreeSet<_>>();
        let mut inventoried_type_names = std::collections::BTreeSet::new();
        let mut seen_wire_ids = std::collections::BTreeMap::new();
        for entry in wire_ids::ALL {
            let type_name = (entry.type_name)();
            let wire_id = entry.wire_id;
            assert!(
                !wire_id.starts_with("iroha_data_model::"),
                "wire identifier must not encode a Rust crate path: {wire_id}"
            );
            assert!(
                inventoried_type_names.insert(type_name),
                "duplicate built-in instruction type in wire-ID inventory: {type_name}"
            );
            assert_eq!(
                registry.wire_id(type_name),
                Some(wire_id),
                "explicit wire id must be applied for {type_name}"
            );
            assert_ne!(
                type_name, wire_id,
                "wire identifiers must not collapse to concrete Rust type names"
            );
            assert!(
                !registry.contains(type_name),
                "Rust type name must not remain a decoding key for {type_name}"
            );
            assert!(
                registry.contains(wire_id),
                "{wire_id} must be a lookup key for {type_name}"
            );
            assert_eq!(
                registry
                    .entry_for_type_name(type_name)
                    .expect("registered type-name lookup")
                    .type_name,
                type_name,
                "Rust type-name lookup must retain its intended constructor"
            );
            assert_eq!(
                registry
                    .entry_for_wire_id(wire_id)
                    .expect("registered wire-id lookup")
                    .type_name,
                type_name,
                "wire-id lookup must retain the constructor assigned in the V1 inventory"
            );
            if let Some(previous) = seen_wire_ids.insert(wire_id, type_name) {
                panic!("wire id collision: {wire_id} registered for {previous} and {type_name}");
            }
        }
        assert_eq!(
            registered_type_names, inventoried_type_names,
            "every default-registry type must have one explicit wire-ID inventory entry"
        );
        assert_eq!(registry.len(), wire_ids::ALL.len());
    }
    #[test]
    fn direct_wire_id_registration_preserves_every_codec_byte_path() {
        let registry = wire_ids::register_all();
        for inventory in wire_ids::ALL {
            let type_name = (inventory.type_name)();
            let encoding = registry
                .entry_for_type_name(type_name)
                .expect("typed registrar entry");
            let decoding = registry
                .entry_for_wire_id(inventory.wire_id)
                .expect("canonical wire-id entry");
            assert_eq!(decoding.type_name, encoding.type_name, "{type_name}");
            assert!(
                std::ptr::fn_addr_eq(decoding.ctor, encoding.ctor),
                "{type_name}"
            );
            assert!(
                std::ptr::fn_addr_eq(decoding.frame, encoding.frame),
                "{type_name}"
            );
            assert!(
                std::ptr::fn_addr_eq(decoding.frame_len, encoding.frame_len),
                "{type_name}"
            );
            assert_eq!(encoding.wire_id, inventory.wire_id, "{type_name}");
        }
    }
    #[test]
    fn instruction_vtable_frame_matches_canonical_concrete_bytes() {
        let concrete = Log::new(Level::INFO, "vtable frame parity".to_owned());
        let boxed = InstructionBox::from(concrete.clone());
        let inner = &*boxed;
        let expected = norito::encode_canonical(&concrete).expect("canonical concrete frame");
        let mut actual = Vec::new();
        inner
            .dyn_write_frame(&mut actual)
            .expect("stream canonical trait-object frame");
        assert_eq!(actual, expected);
        assert_eq!(
            inner
                .dyn_frame_len()
                .expect("exact trait-object frame length"),
            expected.len()
        );
    }
    #[test]
    fn source_has_one_bounded_typed_codec_registration_inventory() {
        const EXPECTED_SOURCE_TYPED_CODEC_REGISTRARS: usize = 396;
        #[cfg(feature = "governance")]
        const EXPECTED_ENABLED_TYPED_CODEC_REGISTRARS: usize = 396;
        #[cfg(not(feature = "governance"))]
        const EXPECTED_ENABLED_TYPED_CODEC_REGISTRARS: usize = 378;
        let registry_source = include_str!("registry.rs");
        let production = registry_source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production registry source");
        let wire_source = include_str!("registry/wire_ids.rs");
        let (provider, inventory_and_tail) = wire_source
            .split_once("pub(super) const ALL: &[BuiltInWireId] = &[")
            .expect("single typed registrar and wire-ID inventory");
        let (inventory, tail) = inventory_and_tail
            .split_once("\n];")
            .expect("single inventory boundary");
        assert_eq!(
            inventory.matches("_wire_id!(").count(),
            EXPECTED_SOURCE_TYPED_CODEC_REGISTRARS,
            "typed codec registrations changed; update the canonical inventory and this bound together"
        );
        assert_eq!(
            EXPECTED_ENABLED_TYPED_CODEC_REGISTRARS,
            wire_ids::ALL.len(),
            "typed codec and wire-ID inventories must remain one-to-one"
        );
        assert_eq!(
            EXPECTED_ENABLED_TYPED_CODEC_REGISTRARS,
            inventory.matches("built_in_wire_id!(").count()
                + if cfg!(feature = "governance") {
                    inventory.matches("governance_wire_id!(").count()
                } else {
                    0
                },
            "source feature scope and enabled inventory length diverged"
        );
        for forbidden in ["register::<", "register_slice::<", "remap_wire_id"] {
            assert!(
                !provider.contains(forbidden)
                    && !production.contains(forbidden)
                    && !inventory.contains(forbidden)
                    && !tail.contains(forbidden),
                "implicit or remapped codec registration remains: {forbidden}"
            );
        }
        assert_eq!(provider.matches("register_with_id::<").count(), 1);
        assert_eq!(provider.matches("register_with_id_slice::<").count(), 2);
    }
    #[test]
    fn instruction_wire_ids_match_v1_golden_inventory_hash() {
        use sha2::{Digest, Sha256};
        #[cfg(feature = "governance")]
        const EXPECTED_WITH_GOVERNANCE_SHA256: &str =
            "14025d26bb09cfa26a1a79988bbc708899d72a4b66a065753d68795bc9aa91ab";
        const EXPECTED_WITHOUT_GOVERNANCE_SHA256: &str =
            "e6fc7d5b775f6909a95e1658fc396c2eb536a9c521cebac2af847b52ca3f4d4b";
        let assignment_digest = |entries: Vec<&wire_ids::BuiltInWireId>| {
            let mut assignments = entries
                .into_iter()
                .map(|entry| format!("{}\t{}\n", entry.type_label, entry.wire_id))
                .collect::<Vec<_>>();
            assignments.sort_unstable();
            let canonical = assignments.concat();
            hex::encode(Sha256::digest(canonical.as_bytes()))
        };
        let without_governance = assignment_digest(
            wire_ids::ALL
                .iter()
                .filter(|entry| !entry.governance_only)
                .collect(),
        );
        assert_eq!(
            without_governance, EXPECTED_WITHOUT_GOVERNANCE_SHA256,
            "non-governance V1 type-to-wire-ID assignments changed"
        );
        #[cfg(feature = "governance")]
        {
            assert_eq!(
                wire_ids::ALL
                    .iter()
                    .filter(|entry| entry.governance_only)
                    .count(),
                18,
                "governance-only V1 inventory changed without updating its explicit scope"
            );
            assert_eq!(
                assignment_digest(wire_ids::ALL.iter().collect()),
                EXPECTED_WITH_GOVERNANCE_SHA256,
                "complete V1 type-to-wire-ID assignments changed"
            );
        }
    }
    #[cfg(feature = "governance")]
    #[test]
    fn governance_instruction_wire_ids_are_exact_and_manual_council_stays_retired() {
        const PERMITTED_GOVERNANCE_WIRE_IDS: &[&str] = &[
            "iroha.instruction.v1::governance::ProposeDeployContract",
            "iroha.instruction.v1::governance::ProposeContractLifecycleGovernance",
            "iroha.instruction.v1::governance::ProposeContractEmergencyHold",
            "iroha.instruction.v1::governance::ProposeGlobalDataTriggerPermissionGovernance",
            "iroha.instruction.v1::governance::ProposeRuntimeUpgradeProposal",
            "iroha.instruction.v1::governance::ProposeSccpRouteGovernance",
            "iroha.instruction.v1::governance::ProposeSorafsProviderGovernance",
            "iroha.instruction.v1::governance::ProposeValidationFeePolicy",
            "iroha.instruction.v1::governance::ProposeValidationFeePayoutLifecycle",
            "iroha.governance.parliament.attempt.create.v1",
            "iroha.governance.parliament.transition.submit.v1",
            "iroha.instruction.v1::governance::CastZkBallot",
            "iroha.instruction.v1::governance::CastPlainBallot",
            "iroha.instruction.v1::governance::UpdatePlainConviction",
            "iroha.instruction.v1::governance::SlashGovernanceLock",
            "iroha.instruction.v1::governance::RestituteGovernanceLock",
            "iroha.instruction.v1::governance::RegisterCitizen",
            "iroha.instruction.v1::governance::UnregisterCitizen",
        ];

        let actual = wire_ids::ALL
            .iter()
            .filter(|entry| entry.governance_only)
            .map(|entry| entry.wire_id)
            .collect::<Vec<_>>();
        assert_eq!(actual, PERMITTED_GOVERNANCE_WIRE_IDS);
        let retired_manual_council_wire_id = [
            "iroha.instruction.v1::governance::",
            "Persist",
            "Council",
            "For",
            "Epoch",
        ]
        .concat();
        assert!(!PERMITTED_GOVERNANCE_WIRE_IDS.contains(&retired_manual_council_wire_id.as_str()));

        let registry = default();
        assert!(!registry.contains(&retired_manual_council_wire_id));
        assert!(
            registry
                .decode(&retired_manual_council_wire_id, &[])
                .is_none(),
            "the retired caller-selected roster wire ID must remain a tombstone"
        );
    }
    #[test]
    #[should_panic(expected = "instruction registry key collision")]
    fn instruction_registry_rejects_wire_id_collisions() {
        let _registry = InstructionRegistry::new()
            .register_with_id::<Log>("instruction.collision")
            .register_with_id::<Upgrade>("instruction.collision");
    }
    #[test]
    #[should_panic(expected = "instruction registry key collision")]
    fn instruction_registry_rejects_alternate_id_for_same_type() {
        let _registry = InstructionRegistry::new()
            .register_with_id::<Log>("instruction.log.v1")
            .register_with_id::<Log>("instruction.log.alias");
    }
    #[test]
    #[should_panic(expected = "instruction registry key collision")]
    fn instruction_registry_rejects_own_type_name_as_wire_id() {
        let _registry =
            InstructionRegistry::new().register_with_id::<Log>(std::any::type_name::<Log>());
    }
    #[test]
    #[should_panic(expected = "instruction registry key collision")]
    fn instruction_registry_rejects_wire_id_and_type_name_collisions() {
        let _registry = InstructionRegistry::new()
            .register_with_id::<Log>("instruction.log.v1")
            .register_with_id::<Upgrade>(std::any::type_name::<Log>());
    }
    #[test]
    #[should_panic(expected = "instruction registry key collision")]
    fn instruction_registry_rejects_type_name_and_existing_wire_id_collisions() {
        let _registry = InstructionRegistry::new()
            .register_with_id::<Log>(std::any::type_name::<Upgrade>())
            .register_with_id::<Upgrade>("instruction.upgrade.v1");
    }
    #[test]
    fn bootle_lantern_governance_instructions_have_unique_canonical_registrations() {
        let static_registry = wire_ids::register_all();
        let registry = default();
        let mut wire_ids = std::collections::BTreeSet::new();
        macro_rules! assert_bootle_registration {
            ($instruction:ty) => {{
                let type_name = std::any::type_name::<$instruction>();
                let wire_id = <$instruction>::WIRE_ID;
                assert!(
                    static_registry.wire_id(type_name) == Some(wire_id),
                    "{type_name} must be present in the built-in registrar list"
                );
                assert_eq!(
                    registry.wire_id(type_name),
                    Some(wire_id),
                    "{type_name} must resolve to its canonical wire id"
                );
                assert!(
                    registry.contains(wire_id),
                    "{wire_id} must be a canonical registry lookup key"
                );
                assert!(
                    wire_ids.insert(wire_id),
                    "duplicate Bootle/Lantern governance wire id: {wire_id}"
                );
            }};
        }
        assert_bootle_registration!(privacy::RegisterPrivacyBootleLanternIssuerPolicyV1);
        assert_bootle_registration!(privacy::RotatePrivacyBootleLanternIssuerPolicyV1);
        assert_bootle_registration!(privacy::RevokePrivacyBootleLanternIssuerPolicyV1);
        assert_bootle_registration!(privacy::RegisterPrivacyVegaIssuerV1);
        assert_bootle_registration!(privacy::RotatePrivacyVegaIssuerV1);
        assert_bootle_registration!(privacy::RevokePrivacyVegaIssuerV1);
    }
    #[test]
    fn x509_governance_instructions_have_unique_canonical_registrations() {
        let static_registry = wire_ids::register_all();
        let registry = default();
        let mut wire_ids = std::collections::BTreeSet::new();
        macro_rules! assert_x509_registration {
            ($instruction:ty) => {{
                let type_name = std::any::type_name::<$instruction>();
                let wire_id = <$instruction>::WIRE_ID;
                assert!(
                    static_registry.wire_id(type_name) == Some(wire_id),
                    "{type_name} must be present in the built-in registrar list"
                );
                assert_eq!(
                    registry.wire_id(type_name),
                    Some(wire_id),
                    "{type_name} must resolve to its canonical wire id"
                );
                assert!(
                    registry.contains(wire_id),
                    "{wire_id} must be a canonical registry lookup key"
                );
                assert!(
                    wire_ids.insert(wire_id),
                    "duplicate X.509 governance wire id: {wire_id}"
                );
            }};
        }
        assert_x509_registration!(privacy::RegisterPrivacyZkX509TrustAnchorV1);
        assert_x509_registration!(privacy::RotatePrivacyZkX509TrustAnchorV1);
        assert_x509_registration!(privacy::RevokePrivacyZkX509TrustAnchorV1);
        assert_x509_registration!(privacy::RegisterPrivacyZkX509CertificatePolicyV1);
        assert_x509_registration!(privacy::RotatePrivacyZkX509CertificatePolicyV1);
        assert_x509_registration!(privacy::RevokePrivacyZkX509CertificatePolicyV1);
        assert_x509_registration!(privacy::RegisterPrivacyZkX509CrlV1);
        assert_x509_registration!(privacy::RotatePrivacyZkX509CrlV1);
        assert_x509_registration!(privacy::RevokePrivacyZkX509CrlV1);
        assert_eq!(wire_ids.len(), 9);
    }
    #[test]
    fn sponsor_program_wire_id_lookup_is_clean_break() {
        assert!(is_instruction_wire_id_registered(
            "nexus::CreateFeeSponsorProgram"
        ));
        assert!(is_instruction_wire_id_registered("iroha.transfer"));
        assert!(!is_instruction_wire_id_registered(
            "nexus::UpsertFeeSponsorPolicy"
        ));
    }
    #[test]
    fn retired_private_uploaded_model_receipt_wire_id_stays_unknown() {
        const RETIRED_WIRE_ID: &str =
            "soracloud::RecordSoracloudPrivateUploadedModelExecutionReceipt";
        let registry = default();
        assert!(!registry.contains(RETIRED_WIRE_ID));
        assert!(registry.decode(RETIRED_WIRE_ID, &[0xFF; 64]).is_none());
        assert!(!is_instruction_wire_id_registered(RETIRED_WIRE_ID));
    }
    #[test]
    fn only_declarative_alias_instruction_ids_are_registered() {
        let registry = default();
        let removed_ids = [
            "iroha_data_model::isi::account_alias_lease::AcquireAccountAliasLease",
            "identity::SetAccountAliasBinding",
            "iroha.account.alias.lease.renew",
            "iroha.account.alias.binding.set",
            "iroha.account.alias.primary.set",
            "identity::SetPrimaryAccountAlias",
        ];
        for wire_id in removed_ids {
            assert!(
                !registry.contains(wire_id),
                "retired split alias instruction id must not decode: {wire_id}"
            );
            assert!(!is_instruction_wire_id_registered(wire_id));
        }
        for wire_id in [
            alias_setup::EnsureAlias::WIRE_ID,
            alias_setup::RenewAliasLease::WIRE_ID,
            alias_setup::RebindAccountAlias::WIRE_ID,
            alias_setup::CompareAndSetPrimaryAccountAlias::WIRE_ID,
            alias_setup::ConfigureAliasAutoRenew::WIRE_ID,
        ] {
            assert!(
                registry.contains(wire_id),
                "replacement must decode: {wire_id}"
            );
        }
    }
    #[test]
    fn legacy_sns_mutation_instruction_ids_are_not_registered() {
        let registry = default();
        let removed_ids = [
            "iroha_data_model::isi::sns::RegisterSnsName",
            "iroha.sns.name.register",
            "iroha_data_model::isi::sns::RenewSnsName",
            "iroha.sns.name.renew",
            "iroha_data_model::isi::sns::TransferSnsName",
            "iroha.sns.name.transfer",
            "iroha_data_model::isi::sns::UpdateSnsNameControllers",
            "iroha.sns.name.controllers.update",
            "iroha_data_model::isi::sns::FreezeSnsName",
            "iroha.sns.name.freeze",
            "iroha_data_model::isi::sns::UnfreezeSnsName",
            "iroha.sns.name.unfreeze",
        ];
        for wire_id in removed_ids {
            assert!(
                !registry.contains(wire_id),
                "retired SNS mutation instruction id must not decode: {wire_id}"
            );
            assert!(registry.decode(wire_id, &[]).is_none());
            assert!(!is_instruction_wire_id_registered(wire_id));
        }
        for wire_id in [
            alias_setup::EnsureAlias::WIRE_ID,
            alias_setup::RenewAliasLease::WIRE_ID,
            alias_setup::RebindAccountAlias::WIRE_ID,
            alias_setup::CompareAndSetPrimaryAccountAlias::WIRE_ID,
            alias_setup::ConfigureAliasAutoRenew::WIRE_ID,
        ] {
            assert!(
                registry.contains(wire_id),
                "replacement alias lifecycle instruction must decode: {wire_id}"
            );
        }
    }
    #[test]
    fn instruction_registry_excludes_direct_grouped_variants() {
        let registry = default();
        let removed_type_names = [
            std::any::type_name::<crate::isi::register::RegisterPeerWithPop>(),
            std::any::type_name::<Register<Domain>>(),
            std::any::type_name::<Register<Account>>(),
            std::any::type_name::<Register<AssetDefinition>>(),
            std::any::type_name::<Register<Nft>>(),
            std::any::type_name::<Register<Role>>(),
            std::any::type_name::<Register<Trigger>>(),
            std::any::type_name::<Unregister<Peer>>(),
            std::any::type_name::<Unregister<Domain>>(),
            std::any::type_name::<Unregister<Account>>(),
            std::any::type_name::<Unregister<AssetDefinition>>(),
            std::any::type_name::<Unregister<Nft>>(),
            std::any::type_name::<Unregister<Role>>(),
            std::any::type_name::<Unregister<Trigger>>(),
            std::any::type_name::<Mint<Quantity, Asset>>(),
            std::any::type_name::<Mint<u32, Trigger>>(),
            std::any::type_name::<Burn<Quantity, Asset>>(),
            std::any::type_name::<Burn<u32, Trigger>>(),
            std::any::type_name::<Transfer<Account, DomainId, Account>>(),
            std::any::type_name::<Transfer<Account, AssetDefinitionId, Account>>(),
            std::any::type_name::<Transfer<Asset, Quantity, Account>>(),
            std::any::type_name::<Transfer<Account, NftId, Account>>(),
            std::any::type_name::<SetKeyValue<Domain>>(),
            std::any::type_name::<SetKeyValue<Account>>(),
            std::any::type_name::<SetKeyValue<AssetDefinition>>(),
            std::any::type_name::<SetKeyValue<Nft>>(),
            std::any::type_name::<SetKeyValue<Trigger>>(),
            std::any::type_name::<RemoveKeyValue<Domain>>(),
            std::any::type_name::<RemoveKeyValue<Account>>(),
            std::any::type_name::<RemoveKeyValue<AssetDefinition>>(),
            std::any::type_name::<RemoveKeyValue<Nft>>(),
            std::any::type_name::<RemoveKeyValue<Trigger>>(),
            std::any::type_name::<Grant<Permission, Account>>(),
            std::any::type_name::<Grant<RoleId, Account>>(),
            std::any::type_name::<Grant<Permission, Role>>(),
            std::any::type_name::<Revoke<Permission, Account>>(),
            std::any::type_name::<Revoke<RoleId, Account>>(),
            std::any::type_name::<Revoke<Permission, Role>>(),
            std::any::type_name::<repo::RepoIsi>(),
            std::any::type_name::<repo::ReverseRepoIsi>(),
            std::any::type_name::<repo::RepoMarginCallIsi>(),
            std::any::type_name::<settlement::DvpIsi>(),
            std::any::type_name::<settlement::PvpIsi>(),
        ];
        for name in removed_type_names {
            assert!(
                !registry.contains(name),
                "{name} must not be in default registry"
            );
        }
        let removed_wire_ids = [
            repo::RepoIsi::WIRE_ID,
            repo::ReverseRepoIsi::WIRE_ID,
            repo::RepoMarginCallIsi::WIRE_ID,
            settlement::DvpIsi::WIRE_ID,
            settlement::PvpIsi::WIRE_ID,
        ];
        for wire_id in removed_wire_ids {
            assert!(
                !registry.contains(wire_id),
                "{wire_id} must not be in default registry"
            );
        }
    }
    #[test]
    fn instruction_registry_does_not_decode_removed_direct_wire_ids() {
        let registry = default();
        let direct_repo = repo::RepoMarginCallIsi::new(
            "registry_repo_margin".parse().expect("repo agreement id"),
        );
        let direct_dvp = settlement::DvpIsi::new(
            "registry_settlement".parse().expect("settlement id"),
            settlement_leg(account(0xB1), account(0xB2), 10),
            settlement_leg(account(0xB2), account(0xB1), 11),
            settlement::SettlementPlan::default(),
        );
        let direct_repo_payload = framed_instruction_payload(&direct_repo);
        let direct_dvp_payload = framed_instruction_payload(&direct_dvp);
        assert!(
            registry
                .decode(repo::RepoMarginCallIsi::WIRE_ID, &direct_repo_payload)
                .is_none(),
            "removed repo direct wire id must stay undecodable"
        );
        assert!(
            registry
                .decode(settlement::DvpIsi::WIRE_ID, &direct_dvp_payload)
                .is_none(),
            "removed settlement direct wire id must stay undecodable"
        );
    }
    #[test]
    fn instruction_registry_rejects_unknown_and_near_miss_wire_ids() {
        let registry = default();
        let register_box = RegisterBox::Domain(Register::domain(Domain::new(domain_id())));
        let framed = framed_instruction_payload(&register_box);
        for wire_id in [
            "",
            "iroha.register ",
            "iroha.Register",
            "iroha.register/Domain",
            "iroha.repo.initiate",
            "iroha.settlement.dvp",
            "iroha.unknown.instruction",
        ] {
            assert!(
                registry.decode(wire_id, &framed).is_none(),
                "{wire_id:?} must not decode as a default instruction"
            );
        }
    }
    #[test]
    fn instruction_registry_does_not_decode_removed_direct_type_names() {
        let registry = default();
        let direct_register = Register::domain(Domain::new(domain_id()));
        let direct_mint = Mint::asset_quantity(9_u32, asset_id());
        let direct_metadata = SetKeyValue::domain(
            domain_id(),
            "legacy".parse().expect("metadata key"),
            iroha_primitives::json::Json::new("value"),
        );
        for (type_name, framed) in [
            (
                std::any::type_name::<Register<Domain>>(),
                framed_instruction_payload(&direct_register),
            ),
            (
                std::any::type_name::<Mint<Quantity, Asset>>(),
                framed_instruction_payload(&direct_mint),
            ),
            (
                std::any::type_name::<SetKeyValue<Domain>>(),
                framed_instruction_payload(&direct_metadata),
            ),
        ] {
            assert!(
                registry.decode(type_name, &framed).is_none(),
                "{type_name} must not decode through removed direct type-name lookup"
            );
        }
    }
    #[test]
    fn public_instruction_pair_helpers_reject_removed_direct_names() {
        let direct_register = Register::domain(Domain::new(domain_id()));
        let direct_mint = Mint::asset_quantity(9_u32, asset_id());
        let direct_repo = repo::RepoMarginCallIsi::new(
            "registry_repo_pair_helper"
                .parse()
                .expect("repo agreement id"),
        );
        let direct_dvp = settlement::DvpIsi::new(
            "registry_settlement_pair_helper"
                .parse()
                .expect("settlement id"),
            settlement_leg(account(0xD1), account(0xD2), 70),
            settlement_leg(account(0xD2), account(0xD1), 71),
            settlement::SettlementPlan::default(),
        );
        for (removed_name, raw_payload, framed_payload) in [
            (
                std::any::type_name::<Register<Domain>>(),
                raw_instruction_payload(&direct_register),
                framed_instruction_payload(&direct_register),
            ),
            (
                std::any::type_name::<Mint<Quantity, Asset>>(),
                raw_instruction_payload(&direct_mint),
                framed_instruction_payload(&direct_mint),
            ),
            (
                repo::RepoMarginCallIsi::WIRE_ID,
                raw_instruction_payload(&direct_repo),
                framed_instruction_payload(&direct_repo),
            ),
            (
                settlement::DvpIsi::WIRE_ID,
                raw_instruction_payload(&direct_dvp),
                framed_instruction_payload(&direct_dvp),
            ),
        ] {
            assert!(
                crate::isi::frame_instruction_payload(removed_name, &raw_payload).is_err(),
                "{removed_name} must not be frameable through the public helper"
            );
            assert!(
                crate::isi::decode_instruction_from_pair(removed_name, &framed_payload).is_err(),
                "{removed_name} must not be decodable through the public pair helper"
            );
        }
    }
    #[test]
    fn instruction_box_from_grouped_direct_variants_uses_boxed_wire_ids() {
        assert_instruction_box_uses_wire_id(
            Register::domain(Domain::new(domain_id())).into(),
            RegisterBox::WIRE_ID,
            std::any::type_name::<RegisterBox>(),
        );
        assert_instruction_box_uses_wire_id(
            Mint::asset_quantity(12_u32, asset_id()).into(),
            MintBox::WIRE_ID,
            std::any::type_name::<MintBox>(),
        );
        assert_instruction_box_uses_wire_id(
            SetKeyValue::domain(
                domain_id(),
                "canonical".parse().expect("metadata key"),
                iroha_primitives::json::Json::new("boxed"),
            )
            .into(),
            SetKeyValueBox::WIRE_ID,
            std::any::type_name::<SetKeyValueBox>(),
        );
        assert_instruction_box_uses_wire_id(
            repo::RepoMarginCallIsi::new(
                "registry_repo_conversion"
                    .parse()
                    .expect("repo agreement id"),
            )
            .into(),
            repo::RepoInstructionBox::WIRE_ID,
            std::any::type_name::<repo::RepoInstructionBox>(),
        );
        assert_instruction_box_uses_wire_id(
            settlement::DvpIsi::new(
                "registry_settlement_conversion"
                    .parse()
                    .expect("settlement id"),
                settlement_leg(account(0xD3), account(0xD4), 80),
                settlement_leg(account(0xD4), account(0xD3), 81),
                settlement::SettlementPlan::default(),
            )
            .into(),
            settlement::SettlementInstructionBox::WIRE_ID,
            std::any::type_name::<settlement::SettlementInstructionBox>(),
        );
    }
    #[test]
    fn instruction_registry_rejects_removed_direct_names_with_boxed_payloads() {
        let register_box = RegisterBox::Domain(Register::domain(Domain::new(domain_id())));
        let mint_box = MintBox::Asset(Mint::asset_quantity(14_u32, asset_id()));
        let repo_box = repo::RepoInstructionBox::MarginCall(repo::RepoMarginCallIsi::new(
            "registry_repo_removed_name_boxed"
                .parse()
                .expect("repo agreement id"),
        ));
        let settlement_box = settlement::SettlementInstructionBox::Dvp(settlement::DvpIsi::new(
            "registry_settlement_removed_name_boxed"
                .parse()
                .expect("settlement id"),
            settlement_leg(account(0xD5), account(0xD6), 90),
            settlement_leg(account(0xD6), account(0xD5), 91),
            settlement::SettlementPlan::default(),
        ));
        for (removed_name, boxed_payload) in [
            (
                std::any::type_name::<Register<Domain>>(),
                framed_instruction_payload(&register_box),
            ),
            (
                std::any::type_name::<Mint<Quantity, Asset>>(),
                framed_instruction_payload(&mint_box),
            ),
            (
                std::any::type_name::<repo::RepoMarginCallIsi>(),
                framed_instruction_payload(&repo_box),
            ),
            (
                repo::RepoMarginCallIsi::WIRE_ID,
                framed_instruction_payload(&repo_box),
            ),
            (
                std::any::type_name::<settlement::DvpIsi>(),
                framed_instruction_payload(&settlement_box),
            ),
            (
                settlement::DvpIsi::WIRE_ID,
                framed_instruction_payload(&settlement_box),
            ),
        ] {
            assert!(
                default().decode(removed_name, &boxed_payload).is_none(),
                "{removed_name} must not alias a canonical boxed payload"
            );
            assert!(
                crate::isi::decode_instruction_from_pair(removed_name, &boxed_payload).is_err(),
                "{removed_name} must not decode through the public pair helper"
            );
        }
    }
    #[test]
    fn instruction_registry_frame_helper_rejects_direct_payloads_under_boxed_ids() {
        let direct_register = Register::domain(Domain::new(domain_id()));
        let direct_mint = Mint::asset_quantity(15_u32, asset_id());
        let direct_repo = repo::RepoMarginCallIsi::new(
            "registry_repo_frame_spoof"
                .parse()
                .expect("repo agreement id"),
        );
        let direct_dvp = settlement::DvpIsi::new(
            "registry_settlement_frame_spoof"
                .parse()
                .expect("settlement id"),
            settlement_leg(account(0xD7), account(0xD8), 100),
            settlement_leg(account(0xD8), account(0xD7), 101),
            settlement::SettlementPlan::default(),
        );
        for (boxed_wire_id, raw_payload) in [
            (
                RegisterBox::WIRE_ID,
                raw_instruction_payload(&direct_register),
            ),
            (MintBox::WIRE_ID, raw_instruction_payload(&direct_mint)),
            (
                repo::RepoInstructionBox::WIRE_ID,
                raw_instruction_payload(&direct_repo),
            ),
            (
                settlement::SettlementInstructionBox::WIRE_ID,
                raw_instruction_payload(&direct_dvp),
            ),
        ] {
            let spoofed = crate::isi::frame_instruction_payload(boxed_wire_id, &raw_payload)
                .expect("canonical boxed wire id is frameable");
            assert!(
                crate::isi::decode_instruction_from_pair(boxed_wire_id, &spoofed).is_err(),
                "{boxed_wire_id} must reject framed bytes sourced from a direct legacy payload"
            );
        }
    }
    #[test]
    fn instruction_registry_rejects_unframed_canonical_payloads() {
        let register_box = RegisterBox::Domain(Register::domain(Domain::new(domain_id())));
        let repo_box = repo::RepoInstructionBox::MarginCall(repo::RepoMarginCallIsi::new(
            "registry_repo_unframed".parse().expect("repo agreement id"),
        ));
        let settlement_box = settlement::SettlementInstructionBox::Dvp(settlement::DvpIsi::new(
            "registry_settlement_unframed"
                .parse()
                .expect("settlement id"),
            settlement_leg(account(0xC1), account(0xC2), 50),
            settlement_leg(account(0xC2), account(0xC1), 51),
            settlement::SettlementPlan::default(),
        ));
        for (wire_id, payload, source) in [
            (
                RegisterBox::WIRE_ID,
                raw_instruction_payload(&register_box),
                std::any::type_name::<RegisterBox>(),
            ),
            (
                repo::RepoInstructionBox::WIRE_ID,
                raw_instruction_payload(&repo_box),
                std::any::type_name::<repo::RepoInstructionBox>(),
            ),
            (
                settlement::SettlementInstructionBox::WIRE_ID,
                raw_instruction_payload(&settlement_box),
                std::any::type_name::<settlement::SettlementInstructionBox>(),
            ),
        ] {
            assert_default_registry_rejects_framed_payload(wire_id, &payload, source);
        }
    }
    #[test]
    fn instruction_registry_rejects_trailing_bytes_after_valid_frames() {
        let register_box = RegisterBox::Domain(Register::domain(Domain::new(domain_id())));
        let repo_box = repo::RepoInstructionBox::MarginCall(repo::RepoMarginCallIsi::new(
            "registry_repo_trailing".parse().expect("repo agreement id"),
        ));
        let settlement_box = settlement::SettlementInstructionBox::Dvp(settlement::DvpIsi::new(
            "registry_settlement_trailing"
                .parse()
                .expect("settlement id"),
            settlement_leg(account(0xC3), account(0xC4), 60),
            settlement_leg(account(0xC4), account(0xC3), 61),
            settlement::SettlementPlan::default(),
        ));
        for (wire_id, mut framed, source) in [
            (
                RegisterBox::WIRE_ID,
                framed_instruction_payload(&register_box),
                std::any::type_name::<RegisterBox>(),
            ),
            (
                repo::RepoInstructionBox::WIRE_ID,
                framed_instruction_payload(&repo_box),
                std::any::type_name::<repo::RepoInstructionBox>(),
            ),
            (
                settlement::SettlementInstructionBox::WIRE_ID,
                framed_instruction_payload(&settlement_box),
                std::any::type_name::<settlement::SettlementInstructionBox>(),
            ),
        ] {
            framed.extend_from_slice(&[0xAA, 0x55]);
            assert_default_registry_rejects_framed_payload(wire_id, &framed, source);
        }
    }
    #[test]
    fn instruction_registry_rejects_direct_payloads_spoofed_as_boxes() {
        assert_default_registry_rejects_payload(
            RegisterBox::WIRE_ID,
            Register::domain(Domain::new(domain_id())),
        );
        assert_default_registry_rejects_payload(
            MintBox::WIRE_ID,
            Mint::asset_quantity(7_u32, asset_id()),
        );
        assert_default_registry_rejects_payload(
            SetKeyValueBox::WIRE_ID,
            SetKeyValue::domain(
                domain_id(),
                "spoofed".parse().expect("metadata key"),
                iroha_primitives::json::Json::new("value"),
            ),
        );
        assert_default_registry_rejects_payload(
            repo::RepoInstructionBox::WIRE_ID,
            repo::RepoMarginCallIsi::new("registry_repo_spoof".parse().expect("repo agreement id")),
        );
        assert_default_registry_rejects_payload(
            settlement::SettlementInstructionBox::WIRE_ID,
            settlement::DvpIsi::new(
                "registry_settlement_spoof".parse().expect("settlement id"),
                settlement_leg(account(0xB3), account(0xB4), 20),
                settlement_leg(account(0xB4), account(0xB3), 21),
                settlement::SettlementPlan::default(),
            ),
        );
    }
    #[test]
    fn instruction_registry_rejects_cross_family_box_payloads() {
        let register_box = RegisterBox::Domain(Register::domain(Domain::new(domain_id())));
        let repo_box = repo::RepoInstructionBox::MarginCall(repo::RepoMarginCallIsi::new(
            "registry_repo_cross_family"
                .parse()
                .expect("repo agreement id"),
        ));
        let settlement_box = settlement::SettlementInstructionBox::Dvp(settlement::DvpIsi::new(
            "registry_settlement_cross_family"
                .parse()
                .expect("settlement id"),
            settlement_leg(account(0xB5), account(0xB6), 30),
            settlement_leg(account(0xB6), account(0xB5), 31),
            settlement::SettlementPlan::default(),
        ));
        assert_default_registry_rejects_framed_payload(
            MintBox::WIRE_ID,
            &framed_instruction_payload(&register_box),
            std::any::type_name::<RegisterBox>(),
        );
        assert_default_registry_rejects_framed_payload(
            settlement::SettlementInstructionBox::WIRE_ID,
            &framed_instruction_payload(&repo_box),
            std::any::type_name::<repo::RepoInstructionBox>(),
        );
        assert_default_registry_rejects_framed_payload(
            repo::RepoInstructionBox::WIRE_ID,
            &framed_instruction_payload(&settlement_box),
            std::any::type_name::<settlement::SettlementInstructionBox>(),
        );
    }
    #[test]
    fn instruction_registry_rejects_cross_family_payloads_under_removed_type_names() {
        let register_box = RegisterBox::Domain(Register::domain(Domain::new(domain_id())));
        let repo_box = repo::RepoInstructionBox::MarginCall(repo::RepoMarginCallIsi::new(
            "registry_repo_cross_type_name"
                .parse()
                .expect("repo agreement id"),
        ));
        let settlement_box = settlement::SettlementInstructionBox::Dvp(settlement::DvpIsi::new(
            "registry_settlement_cross_type_name"
                .parse()
                .expect("settlement id"),
            settlement_leg(account(0xD9), account(0xDA), 110),
            settlement_leg(account(0xDA), account(0xD9), 111),
            settlement::SettlementPlan::default(),
        ));
        let registry = default();
        for (wire_id, type_name, framed, source) in [
            (
                MintBox::WIRE_ID,
                std::any::type_name::<MintBox>(),
                framed_instruction_payload(&register_box),
                std::any::type_name::<RegisterBox>(),
            ),
            (
                settlement::SettlementInstructionBox::WIRE_ID,
                std::any::type_name::<settlement::SettlementInstructionBox>(),
                framed_instruction_payload(&repo_box),
                std::any::type_name::<repo::RepoInstructionBox>(),
            ),
            (
                repo::RepoInstructionBox::WIRE_ID,
                std::any::type_name::<repo::RepoInstructionBox>(),
                framed_instruction_payload(&settlement_box),
                std::any::type_name::<settlement::SettlementInstructionBox>(),
            ),
        ] {
            assert_eq!(
                registry.wire_id(type_name),
                Some(wire_id),
                "{type_name} encodes with its canonical wire identifier"
            );
            assert!(
                registry.decode(type_name, &framed).is_none(),
                "retired type-name alias must not resolve: {type_name}"
            );
            assert_default_registry_rejects_framed_payload(wire_id, &framed, source);
        }
    }
    #[test]
    fn instruction_registry_rejects_invalid_box_variant_tags() {
        let invalid_tag = u32::MAX;
        let register_box = RegisterBox::Domain(Register::domain(Domain::new(domain_id())));
        let repo_box = repo::RepoInstructionBox::MarginCall(repo::RepoMarginCallIsi::new(
            "registry_repo_bad_tag".parse().expect("repo agreement id"),
        ));
        let settlement_box = settlement::SettlementInstructionBox::Dvp(settlement::DvpIsi::new(
            "registry_settlement_bad_tag"
                .parse()
                .expect("settlement id"),
            settlement_leg(account(0xB7), account(0xB8), 40),
            settlement_leg(account(0xB8), account(0xB7), 41),
            settlement::SettlementPlan::default(),
        ));
        for (wire_id, framed) in [
            (
                RegisterBox::WIRE_ID,
                framed_instruction_payload_with_tag(&register_box, invalid_tag),
            ),
            (
                repo::RepoInstructionBox::WIRE_ID,
                framed_instruction_payload_with_tag(&repo_box, invalid_tag),
            ),
            (
                settlement::SettlementInstructionBox::WIRE_ID,
                framed_instruction_payload_with_tag(&settlement_box, invalid_tag),
            ),
        ] {
            let decoded = default()
                .decode(wire_id, &framed)
                .expect("canonical wire id remains registered");
            assert!(decoded.is_err(), "{wire_id} must reject invalid enum tag");
        }
    }
    #[test]
    fn instruction_registry_rejects_truncated_box_payloads() {
        let registry = default();
        for wire_id in [
            RegisterBox::WIRE_ID,
            MintBox::WIRE_ID,
            SetKeyValueBox::WIRE_ID,
            GrantBox::WIRE_ID,
            repo::RepoInstructionBox::WIRE_ID,
            settlement::SettlementInstructionBox::WIRE_ID,
        ] {
            let decoded = registry
                .decode(wire_id, &[0xFF])
                .expect("canonical wire id remains registered");
            assert!(decoded.is_err(), "{wire_id} must reject truncated payload");
        }
    }
    #[test]
    fn instruction_registry_decodes_boxed_stable_ids() {
        assert_default_registry_decodes(RegisterBox::Domain(Register::domain(Domain::new(
            domain_id(),
        ))));
        assert_default_registry_decodes(UnregisterBox::Domain(Unregister::domain(domain_id())));
        assert_default_registry_decodes(MintBox::Asset(Mint::asset_quantity(7_u32, asset_id())));
        assert_default_registry_decodes(BurnBox::TriggerRepetitions(Burn::trigger_repetitions(
            2,
            trigger_id(),
        )));
        assert_default_registry_decodes(TransferBox::Asset(Transfer::asset_quantity(
            asset_id(),
            3_u32,
            account(0xA2),
        )));
        assert_default_registry_decodes(SetKeyValueBox::Domain(SetKeyValue::domain(
            domain_id(),
            "color".parse().expect("metadata key"),
            iroha_primitives::json::Json::new("blue"),
        )));
        assert_default_registry_decodes(RemoveKeyValueBox::Domain(RemoveKeyValue::domain(
            domain_id(),
            "color".parse().expect("metadata key"),
        )));
        assert_default_registry_decodes(GrantBox::Role(Grant::account_role(
            role_id(),
            account(0xA3),
        )));
        assert_default_registry_decodes(RevokeBox::Role(Revoke::account_role(
            role_id(),
            account(0xA3),
        )));
        let registry = default();
        assert!(registry.contains(rwa::RwaInstructionBox::WIRE_ID));
        assert!(registry.contains(repo::RepoInstructionBox::WIRE_ID));
        assert!(registry.contains(settlement::SettlementInstructionBox::WIRE_ID));
    }
    #[test]
    fn instruction_registry_registers_and_decodes_standalone_surface() {
        let registry = default();
        let expected = [
            std::any::type_name::<content::PublishContentBundle>(),
            std::any::type_name::<content::RetireContentBundle>(),
            std::any::type_name::<soradns::SubmitDirectoryDraft>(),
            std::any::type_name::<soradns::PublishDirectory>(),
            std::any::type_name::<soradns::RevokeResolver>(),
            std::any::type_name::<soradns::UnrevokeResolver>(),
            std::any::type_name::<soradns::AddReleaseSigner>(),
            std::any::type_name::<soradns::RemoveReleaseSigner>(),
            std::any::type_name::<soradns::SetDirectoryRotationPolicy>(),
            std::any::type_name::<confidential::PublishPedersenParams>(),
            std::any::type_name::<confidential::SetPedersenParamsLifecycle>(),
            std::any::type_name::<confidential::PublishPoseidonParams>(),
            std::any::type_name::<confidential::SetPoseidonParamsLifecycle>(),
            std::any::type_name::<sorafs::SetPricingSchedule>(),
            std::any::type_name::<sorafs::UpsertProviderCredit>(),
            std::any::type_name::<crate::isi::staking::BondPublicLaneStake>(),
            std::any::type_name::<crate::isi::staking::SchedulePublicLaneUnbond>(),
            std::any::type_name::<crate::isi::staking::FinalizePublicLaneUnbond>(),
            std::any::type_name::<crate::isi::staking::SlashPublicLaneValidator>(),
            std::any::type_name::<crate::isi::staking::RecordPublicLaneRewards>(),
            std::any::type_name::<crate::isi::staking::ClaimPublicLaneRewards>(),
        ];
        for type_name in expected {
            assert!(
                registry.wire_id(type_name).is_some(),
                "{type_name} missing from default registry"
            );
            assert!(
                !registry.contains(type_name),
                "{type_name} remained a decode alias"
            );
        }
        assert_default_registry_decodes(content::PublishContentBundle {
            bundle_id: Hash::new(b"content-bundle"),
            tarball: b"tar".to_vec(),
            expires_at_height: None,
            manifest: None,
        });
        assert_default_registry_decodes(soradns::PublishDirectory {
            directory_id: [0xD1; 32],
            expected_prev: None,
        });
        assert_default_registry_decodes(confidential::PublishPedersenParams {
            params: crate::confidential::PedersenParams {
                params_id: crate::confidential::ConfidentialParamsId::new(7),
                generators_hash: [0x11; 32],
                constants_hash: [0x22; 32],
                metadata_uri_cid: None,
                params_cid: None,
                activation_height: Some(1),
                withdraw_height: None,
                status: crate::confidential::ConfidentialStatus::Active,
            },
        });
        assert_default_registry_decodes(sorafs::SetPricingSchedule::new(
            crate::sorafs::pricing::PricingScheduleRecord::launch_default(),
        ));
        assert_default_registry_decodes(sorafs::UpsertProviderCredit::new(
            None,
            crate::sorafs::pricing::ProviderCreditRecord::new(
                crate::sorafs::capacity::ProviderId::new([0xC1; 32]),
                xor_quantity_nanos(1),
                Quantity::zero(),
                Quantity::zero(),
                Quantity::zero(),
                0,
                0,
                Metadata::default(),
            ),
        ));
        assert_default_registry_decodes(crate::isi::staking::ClaimPublicLaneRewards {
            lane_id: iroha_model_base::topology::LaneId::SINGLE,
            account: account(0xA4),
            claim_plan: crate::nexus::PublicLaneRewardClaimPlanV1 {
                fee_claim: None,
                network_scope: crate::nexus::PublicLaneMonetaryScopeV1::Network(
                    crate::NetworkId::from_genesis_hash(
                        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                            b"registry reward fixture network",
                        )),
                    ),
                ),
                valid_until_height: 20,
                expected_state: Some(crate::nexus::PublicLaneRewardClaimStateV1 {
                    through_epoch: Some(8),
                }),
                records: vec![crate::nexus::PublicLaneRewardRecordRefV1 {
                    epoch: 9,
                    record_hash: iroha_crypto::Hash::new(b"registry reward fixture record"),
                }],
                sources: vec![crate::nexus::PublicLaneRewardClaimSourceV1 {
                    source_asset: AssetId::new(asset_definition_id(), account(0xA5)),
                    destination_asset: AssetId::new(asset_definition_id(), account(0xA4)),
                    expected_accrued: None,
                    payout: Quantity::from(1_u64),
                }],
            },
        });
    }
    #[test]
    fn default_registry_rejects_retired_zk_ace_instruction_wires() {
        let registry = default();
        for retired in [
            "iroha_data_model::isi::zk::RegisterZkAceIdentityCommitment",
            "iroha_data_model::isi::zk::RotateZkAceIdentityCommitment",
            "iroha_data_model::isi::zk::RevokeZkAceIdentityCommitment",
            "iroha_data_model::isi::zk::SubmitZkAceAuthorizedTransfer",
        ] {
            assert!(
                !registry.contains(retired),
                "retired ZK-ACE instruction wire unexpectedly remains registered: {retired}"
            );
            assert!(
                registry.decode(retired, &[]).is_none(),
                "retired ZK-ACE instruction wire unexpectedly remains decodable: {retired}"
            );
        }
    }
    #[test]
    fn default_registry_excludes_retired_confidential_instructions() {
        let retired_wires = [
            ["iroha_data_model::isi::zk::", "Shield"].concat(),
            ["iroha_data_model::isi::zk::", "ZkTransfer"].concat(),
            ["iroha_data_model::isi::zk::", "Unshield"].concat(),
            [
                "iroha_data_model::isi::escrow::",
                "OpenAnonymous",
                "AssetEscrow",
            ]
            .concat(),
            [
                "iroha_data_model::isi::escrow::",
                "AcceptAnonymous",
                "AssetEscrow",
            ]
            .concat(),
            [
                "iroha_data_model::isi::escrow::",
                "MarkAnonymous",
                "EscrowPaymentSent",
            ]
            .concat(),
            [
                "iroha_data_model::isi::escrow::",
                "ReleaseAnonymous",
                "AssetEscrow",
            ]
            .concat(),
            [
                "iroha_data_model::isi::escrow::",
                "CancelAnonymous",
                "AssetEscrow",
            ]
            .concat(),
            [
                "iroha_data_model::isi::escrow::",
                "OpenAnonymous",
                "EscrowDispute",
            ]
            .concat(),
            [
                "iroha_data_model::isi::escrow::",
                "ResolveAnonymous",
                "EscrowDispute",
            ]
            .concat(),
            "iroha.instruction.v1::offline::TopUpKagemushaRecursiveV4".to_owned(),
            "iroha.instruction.v1::offline::RedeemKagemushaRecursiveV4".to_owned(),
            "iroha.instruction.v1::offline::ActivateKagemushaRecursiveReleaseV4".to_owned(),
            "iroha.offline.kagemusha.recursive_release.enable.v1".to_owned(),
            "iroha.offline.kagemusha.recursive_release.cancel.v1".to_owned(),
            "iroha.offline.kagemusha.recursive_release.deactivate.v1".to_owned(),
            "iroha.offline.kagemusha.taira_canary.record.v1".to_owned(),
            "iroha.offline.kagemusha.taira_canary.authorize.v1".to_owned(),
            "iroha.instruction.v1::governance::ProposeKagemushaVerifierPolicyInstallV1".to_owned(),
            "iroha.instruction.v1::governance::ProposeKagemushaVerifierReleaseInstallV1".to_owned(),
            "iroha.instruction.v1::governance::ProposeKagemushaVerifierReleaseActivateV1"
                .to_owned(),
            "iroha.instruction.v1::governance::ProposeKagemushaVerifierReleaseRetireV1".to_owned(),
            "iroha.offline.device_attestation.register".to_owned(),
            "iroha.instruction.v1::offline::SetOfflineDeviceAttestationPolicy".to_owned(),
            "iroha.instruction.v1::sorafs::RegisterSorafsAnonymousServiceNote".to_owned(),
            "iroha.instruction.v1::sorafs::RegisterSorafsAnonymousJurorCandidacy".to_owned(),
            "iroha.instruction.v1::sorafs::RefundSorafsAnonymousServiceEscrow".to_owned(),
            "iroha.instruction.v1::sorafs::SlashSorafsAnonymousServiceEscrow".to_owned(),
        ];
        let registry = default();
        let current = RegisterBox::Domain(Register::domain(Domain::new(domain_id())));
        let raw_current = raw_instruction_payload(&current);
        let framed_current = framed_instruction_payload(&current);
        for retired in &retired_wires {
            assert!(
                !registry.contains(retired),
                "retired confidential wire must not be registered: {retired}"
            );
            assert!(
                registry.decode(retired, &[]).is_none(),
                "retired confidential wire must not be dispatchable: {retired}"
            );
            assert!(!is_instruction_wire_id_registered(retired));
            assert!(
                crate::isi::frame_instruction_payload(retired, &raw_current).is_err(),
                "public framing must reject retired wire: {retired}"
            );
            assert!(
                crate::isi::decode_instruction_from_pair(retired, &framed_current).is_err(),
                "public pair decoding must reject retired wire: {retired}"
            );
        }
    }

    #[test]
    fn structured_json_rejects_retired_confidential_dispatch() {
        for name in [
            "Shield".to_owned(),
            "ZkTransfer".to_owned(),
            "Unshield".to_owned(),
            ["OpenAnonymous", "AssetEscrow"].concat(),
            ["AcceptAnonymous", "AssetEscrow"].concat(),
            ["MarkAnonymous", "EscrowPaymentSent"].concat(),
            ["ReleaseAnonymous", "AssetEscrow"].concat(),
            ["CancelAnonymous", "AssetEscrow"].concat(),
            ["OpenAnonymous", "EscrowDispute"].concat(),
            ["ResolveAnonymous", "EscrowDispute"].concat(),
        ] {
            let retired = format!(r#"{{"name":"{name}","params":{{}}}}"#);
            norito::json::from_str::<InstructionBox>(&retired)
                .expect_err("retired confidential JSON must not dispatch");
        }
    }
    #[cfg(feature = "governance")]
    #[test]
    fn default_registry_registers_citizenship_instructions() {
        let registry = default();
        for type_name in [
            std::any::type_name::<crate::isi::governance::RegisterCitizen>(),
            std::any::type_name::<crate::isi::governance::UnregisterCitizen>(),
        ] {
            assert!(registry.wire_id(type_name).is_some());
            assert!(!registry.contains(type_name));
        }
    }
}

#[cfg(test)]
#[path = "registry/stream_token_authority_tests.rs"]
mod stream_token_authority_tests;
#[cfg(test)]
#[path = "registry/stream_token_custody_tests.rs"]
mod stream_token_custody_tests;
#[cfg(test)]
#[path = "registry/stream_token_gateway_tests.rs"]
mod stream_token_gateway_tests;

#[cfg(test)]
#[path = "registry/final_promotion_authority_tests.rs"]
mod final_promotion_authority_tests;
#[cfg(test)]
#[path = "registry/release_manifest_authority_tests.rs"]
mod release_manifest_authority_tests;
#[cfg(test)]
#[path = "registry/topology_authority_tests.rs"]
mod topology_authority_tests;

#[cfg(test)]
#[path = "registry/final_promotion_account_custody_tests.rs"]
mod final_promotion_account_custody_tests;
