use super::*;
use crate::kaigi::{
    KaigiId, KaigiParticipantCommitment, KaigiParticipantNullifier, KaigiRelayHealthStatus,
    KaigiRelayManifest, KaigiRelayRegistration, NewKaigi, scalar::KaigiAuthorizationScalarV1,
};
use iroha_crypto::Hash;
isi! {
    /// Create a new Kaigi session anchored to a domain.
    #[norito_schema(name = "iroha_data_model::isi::kaigi::CreateKaigi")]
    pub struct CreateKaigi {
        /// Template describing the call to create.
        pub call: NewKaigi,
        /// Commitment describing the host (privacy mode only).
        pub commitment: Option<KaigiParticipantCommitment>,
        /// Nullifier preventing proof replay (privacy mode only).
        pub nullifier: Option<KaigiParticipantNullifier>,
        /// Merkle root the host used when generating the proof (privacy mode only).
        pub roster_root: Option<Hash>,
        /// Proof bytes attesting ownership of the commitment (privacy mode only).
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub proof: Option<Vec<u8>>,
    }
}
isi! {
    /// Add a participant to an active Kaigi.
    #[norito_schema(name = "iroha_data_model::isi::kaigi::JoinKaigi")]
    #[derive(derive_more::Constructor)]
    pub struct JoinKaigi {
        /// Identifier of the call to join.
        pub call_id: KaigiId,
        /// Account joining the call.
        pub participant: AccountId,
    /// Commitment describing the participant (privacy mode only).
    pub commitment: Option<KaigiParticipantCommitment>,
    /// Nullifier preventing duplicate joins (privacy mode only).
    pub nullifier: Option<KaigiParticipantNullifier>,
    /// Merkle root the participant used when generating their proof (privacy mode only).
    pub roster_root: Option<Hash>,
    /// Proof bytes attesting ownership of the commitment (privacy mode only).
    #[norito (json = "crate::json_helpers::base64_vec")]
    pub proof: Option<Vec<u8>>,
    }
}
isi! {
    /// Remove a participant from an active Kaigi.
    ///
    /// Private departure proves the stored commitment opening against the current
    /// roster, original account and ledger-owned participation sequence.
    #[norito_schema(name = "iroha_data_model::isi::kaigi::LeaveKaigi")]
    pub struct LeaveKaigi {
        /// Identifier of the call to leave.
        pub call_id: KaigiId,
        /// Account leaving the call.
        pub participant: AccountId,
    /// Stored participant commitment, required for private leave.
    pub commitment: Option<KaigiParticipantCommitment>,
    /// Leave-action nullifier, required for private leave.
    pub nullifier: Option<KaigiParticipantNullifier>,
    /// Current roster root, required for private leave.
    pub roster_root: Option<Hash>,
    /// Canonical authorization proof, required for private leave.
    #[norito (json = "crate::json_helpers::base64_vec")]
    pub proof: Option<Vec<u8>>,
    }
}
isi! {
    /// Conclude an active Kaigi.
    #[norito_schema(name = "iroha_data_model::isi::kaigi::EndKaigi")]
    pub struct EndKaigi {
        /// Identifier of the call to end.
        pub call_id: KaigiId,
        /// Optional timestamp in milliseconds when the call ended.
        ///
        /// When supplied, it must be no earlier than call creation and no later than the
        /// current block; omission uses the current block time.
        pub ended_at_ms: Option<u64>,
        /// Commitment describing the host (privacy mode only).
        pub commitment: Option<KaigiParticipantCommitment>,
        /// Nullifier preventing proof replay (privacy mode only).
        pub nullifier: Option<KaigiParticipantNullifier>,
        /// Merkle root the host used when generating the proof (privacy mode only).
        pub roster_root: Option<Hash>,
        /// Proof bytes attesting ownership of the commitment (privacy mode only).
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub proof: Option<Vec<u8>>,
    }
}
isi! {
    /// Record usage metrics for a Kaigi segment.
    #[norito_schema(name = "iroha_data_model::isi::kaigi::RecordKaigiUsage")]
    pub struct RecordKaigiUsage {
    /// Identifier of the call to update.
    pub call_id: KaigiId,
    /// Duration in milliseconds for this usage segment.
    pub duration_ms: u64,
    /// Gas billed for this segment (as computed off-ledger).
    pub billed_gas: u64,
    /// Commitment to the usage tuple (privacy mode only).
    pub usage_commitment: Option<KaigiAuthorizationScalarV1>,
    /// Proof binding the commitment to the supplied usage tuple (required in privacy mode).
    ///
    /// The V1 statement does not attest an encrypted-log payload.
    #[norito (json = "crate::json_helpers::base64_vec")]
    pub proof: Option<Vec<u8>>,
}
}
isi! {
    /// Update the relay manifest advertised for a Kaigi session.
    #[norito_schema(name = "iroha_data_model::isi::kaigi::SetKaigiRelayManifest")]
    pub struct SetKaigiRelayManifest {
        /// Identifier of the call to update.
        pub call_id: KaigiId,
        /// Optional relay manifest describing the desired relay hops.
        ///
        /// A supplied manifest must expire strictly after the current block time.
        pub relay_manifest: Option<KaigiRelayManifest>,
    }
}
isi! {
    /// Register or update a Kaigi relay in the governance domain selected by
    /// its live domain-qualified primary account alias.
    #[norito_schema(name = "iroha_data_model::isi::kaigi::RegisterKaigiRelay")]
    pub struct RegisterKaigiRelay {
        /// Registration payload describing the relay capabilities.
        pub relay: KaigiRelayRegistration,
    }
}
isi! {
    /// Remove a Kaigi relay descriptor and its retained health feedback.
    ///
    /// Native execution requires authorization by the relay account (or its
    /// active canonical account-id rekey successor). Removal prevents future
    /// manifest admission; existing manifests remain self-contained and retain
    /// their pinned descriptor until the host refreshes or ends the call, or
    /// until the manifest expires.
    #[norito_schema(name = "iroha_data_model::isi::kaigi::UnregisterKaigiRelay")]
    pub struct UnregisterKaigiRelay {
        /// Relay account whose descriptor should be removed.
        pub relay_id: AccountId,
    }
}
isi! {
    /// Report the observed health for a relay participating in a Kaigi session.
    #[norito_schema(name = "iroha_data_model::isi::kaigi::ReportKaigiRelayHealth")]
    pub struct ReportKaigiRelayHealth {
        /// Identifier of the call where the relay was observed.
        pub call_id: KaigiId,
        /// Relay account whose health is being reported.
        pub relay_id: AccountId,
        /// Health status observed by the reporter.
        pub status: KaigiRelayHealthStatus,
        /// Timestamp (milliseconds since epoch) for when the observation occurred.
        ///
        /// It must not precede the call's creation time or stored relay feedback,
        /// and it must not exceed the current block time.
        pub reported_at_ms: u64,
        /// Optional free-form notes capturing failure context.
        pub notes: Option<String>,
    }
}
// Seal implementations
impl crate::seal::Instruction for CreateKaigi {}
impl crate::seal::Instruction for JoinKaigi {}
impl crate::seal::Instruction for LeaveKaigi {}
impl crate::seal::Instruction for EndKaigi {}
impl crate::seal::Instruction for RecordKaigiUsage {}
impl crate::seal::Instruction for SetKaigiRelayManifest {}
impl crate::seal::Instruction for RegisterKaigiRelay {}
impl crate::seal::Instruction for UnregisterKaigiRelay {}
impl crate::seal::Instruction for ReportKaigiRelayHealth {}
fn kaigi_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
macro_rules! impl_kaigi_decode_from_slice {
    ($ty:ty { $($field:ident : $field_ty:ty),+ $(,)? }) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = kaigi_decode_flags();
                let mut offset = 0usize;
                $(
                    let $field = super::decode_aos_canonical_field::<$field_ty>(
                        super::read_aos_field(bytes, &mut offset, flags)?,
                        flags,
                    )?;
                )+
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $($field),+ }, offset))
            }
        }
    };
}
impl_kaigi_decode_from_slice!(CreateKaigi {
    call: NewKaigi,
    commitment: Option<KaigiParticipantCommitment>,
    nullifier: Option<KaigiParticipantNullifier>,
    roster_root: Option<Hash>,
    proof: Option<Vec<u8>>,
});
impl_kaigi_decode_from_slice!(JoinKaigi {
    call_id: KaigiId,
    participant: AccountId,
    commitment: Option<KaigiParticipantCommitment>,
    nullifier: Option<KaigiParticipantNullifier>,
    roster_root: Option<Hash>,
    proof: Option<Vec<u8>>,
});
impl_kaigi_decode_from_slice!(LeaveKaigi {
    call_id: KaigiId,
    participant: AccountId,
    commitment: Option<KaigiParticipantCommitment>,
    nullifier: Option<KaigiParticipantNullifier>,
    roster_root: Option<Hash>,
    proof: Option<Vec<u8>>,
});
impl_kaigi_decode_from_slice!(EndKaigi {
    call_id: KaigiId,
    ended_at_ms: Option<u64>,
    commitment: Option<KaigiParticipantCommitment>,
    nullifier: Option<KaigiParticipantNullifier>,
    roster_root: Option<Hash>,
    proof: Option<Vec<u8>>,
});
impl_kaigi_decode_from_slice!(RecordKaigiUsage {
    call_id: KaigiId,
    duration_ms: u64,
    billed_gas: u64,
    usage_commitment: Option<KaigiAuthorizationScalarV1>,
    proof: Option<Vec<u8>>,
});
impl_kaigi_decode_from_slice!(SetKaigiRelayManifest {
    call_id: KaigiId,
    relay_manifest: Option<KaigiRelayManifest>,
});
impl_kaigi_decode_from_slice!(RegisterKaigiRelay {
    relay: KaigiRelayRegistration,
});
impl_kaigi_decode_from_slice!(UnregisterKaigiRelay {
    relay_id: AccountId,
});
impl_kaigi_decode_from_slice!(ReportKaigiRelayHealth {
    call_id: KaigiId,
    relay_id: AccountId,
    status: KaigiRelayHealthStatus,
    reported_at_ms: u64,
    notes: Option<String>,
});
#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{
        assert_registry_decodes_registered_type as assert_registry_decodes, assert_slice_roundtrip,
    };
    use crate::kaigi::{KaigiPrivacyMode, KaigiRelayHop, KaigiRoomPolicy};
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use std::str::FromStr as _;
    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked Kaigi ISI fixture keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn call_id() -> KaigiId {
        KaigiId::new(
            DomainId::try_new("wonderland", "universal").expect("domain"),
            Name::from_str("standup").expect("call name"),
        )
    }
    fn test_scalar(byte: u8) -> KaigiAuthorizationScalarV1 {
        let mut bytes = [0; 32];
        bytes[0] = byte;
        KaigiAuthorizationScalarV1::from_le_bytes(bytes).unwrap()
    }
    fn participant_commitment(byte: u8) -> KaigiParticipantCommitment {
        KaigiParticipantCommitment {
            commitment: test_scalar(byte),
        }
    }
    fn participant_nullifier(byte: u8) -> KaigiParticipantNullifier {
        KaigiParticipantNullifier {
            digest: test_scalar(byte),
        }
    }
    fn relay_manifest() -> KaigiRelayManifest {
        KaigiRelayManifest {
            hops: vec![KaigiRelayHop {
                relay_id: account(3),
                hpke_public_key: vec![0xA1, 0xA2, 0xA3],
                weight: 2,
            }],
            expiry_ms: 1_700_100_000,
        }
    }
    fn relay_registration() -> KaigiRelayRegistration {
        KaigiRelayRegistration {
            relay_id: account(4),
            hpke_public_key: vec![0xB1, 0xB2, 0xB3],
            bandwidth_class: 7,
        }
    }
    fn new_kaigi() -> NewKaigi {
        let mut call = NewKaigi::with_defaults(call_id(), account(1));
        call.title = Some("Daily standup".to_owned());
        call.description = Some("Engineering sync".to_owned());
        call.max_participants = Some(16);
        call.gas_rate_per_minute = 5;
        call.scheduled_start_ms = Some(1_700_010_000);
        call.billing_account = Some(account(2));
        call.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
        call.room_policy = KaigiRoomPolicy::Authenticated;
        call.relay_manifest = Some(relay_manifest());
        call
    }

    fn assert_canonical_wire_envelope<T>(
        registry: &crate::isi::InstructionRegistry,
        expected_wire_id: &'static str,
        value: T,
    ) where
        T: crate::isi::Instruction + Into<crate::isi::InstructionBox>,
    {
        let type_name = std::any::type_name::<T>();
        assert_eq!(registry.wire_id(type_name), Some(expected_wire_id));
        assert!(registry.contains(expected_wire_id));
        assert!(!registry.contains(type_name));

        let boxed: crate::isi::InstructionBox = value.into();
        assert_eq!(
            crate::isi::instruction_wire_id(&boxed),
            Some(expected_wire_id)
        );

        let (wire_id, framed) = crate::isi::framed_instruction_payload(&boxed)
            .expect("registered Kaigi instruction frame");
        assert_eq!(wire_id, expected_wire_id);
        let decoded = crate::isi::decode_instruction_from_pair(wire_id, &framed)
            .expect("decode canonical Kaigi instruction pair");
        assert_eq!(crate::isi::Instruction::id(&*decoded), type_name);
        assert_eq!(
            crate::isi::Instruction::dyn_encode(&*decoded),
            crate::isi::Instruction::dyn_encode(&*boxed)
        );
        assert!(crate::isi::decode_instruction_from_pair(type_name, &framed).is_err());

        let encoded = norito::to_bytes(&boxed).expect("encode Kaigi InstructionBox");
        let decoded: crate::isi::InstructionBox =
            norito::decode_from_bytes(&encoded).expect("decode Kaigi InstructionBox");
        assert_eq!(crate::isi::Instruction::id(&*decoded), type_name);
        assert_eq!(
            crate::isi::Instruction::dyn_encode(&*decoded),
            crate::isi::Instruction::dyn_encode(&*boxed)
        );
    }

    #[test]
    fn kaigi_decode_from_slice_roundtrips() {
        let call_id = call_id();
        let commitment = participant_commitment(0x11);
        let nullifier = participant_nullifier(0x22);
        let roster_root = Hash::new("kaigi-roster-root");
        assert_slice_roundtrip(CreateKaigi {
            call: new_kaigi(),
            commitment: Some(commitment),
            nullifier: Some(nullifier),
            roster_root: Some(roster_root),
            proof: Some(vec![0x01, 0x02, 0x03]),
        });
        assert_slice_roundtrip(JoinKaigi {
            call_id: call_id.clone(),
            participant: account(5),
            commitment: Some(commitment),
            nullifier: Some(nullifier),
            roster_root: Some(roster_root),
            proof: Some(vec![0x04, 0x05]),
        });
        assert_slice_roundtrip(LeaveKaigi {
            call_id: call_id.clone(),
            participant: account(5),
            commitment: Some(commitment),
            nullifier: Some(nullifier),
            roster_root: Some(roster_root),
            proof: Some(vec![0x06, 0x07]),
        });
        assert_slice_roundtrip(EndKaigi {
            call_id: call_id.clone(),
            ended_at_ms: Some(1_700_020_000),
            commitment: Some(commitment),
            nullifier: Some(nullifier),
            roster_root: Some(roster_root),
            proof: Some(vec![0x08, 0x09]),
        });
        assert_slice_roundtrip(RecordKaigiUsage {
            call_id: call_id.clone(),
            duration_ms: 60_000,
            billed_gas: 15,
            usage_commitment: Some(test_scalar(7)),
            proof: Some(vec![0x10, 0x11]),
        });
        assert_slice_roundtrip(SetKaigiRelayManifest {
            call_id: call_id.clone(),
            relay_manifest: Some(relay_manifest()),
        });
        assert_slice_roundtrip(RegisterKaigiRelay {
            relay: relay_registration(),
        });
        assert_slice_roundtrip(UnregisterKaigiRelay {
            relay_id: account(4),
        });
        assert_slice_roundtrip(ReportKaigiRelayHealth {
            call_id,
            relay_id: account(4),
            status: KaigiRelayHealthStatus::Degraded,
            reported_at_ms: 1_700_030_000,
            notes: Some("packet loss".to_owned()),
        });
    }
    #[test]
    fn kaigi_default_registry_decodes_canonical_wire_ids() {
        let registry = crate::isi::registry::default();
        let call_id = call_id();
        let value = CreateKaigi {
            call: new_kaigi(),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        };
        assert_registry_decodes(&registry, value.clone());
        assert_canonical_wire_envelope(
            &registry,
            "iroha.instruction.v1::kaigi::CreateKaigi",
            value,
        );

        let value = JoinKaigi {
            call_id: call_id.clone(),
            participant: account(5),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        };
        assert_registry_decodes(&registry, value.clone());
        assert_canonical_wire_envelope(&registry, "iroha.instruction.v1::kaigi::JoinKaigi", value);

        let value = LeaveKaigi {
            call_id: call_id.clone(),
            participant: account(5),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        };
        assert_registry_decodes(&registry, value.clone());
        assert_canonical_wire_envelope(&registry, "iroha.instruction.v1::kaigi::LeaveKaigi", value);

        let value = EndKaigi {
            call_id: call_id.clone(),
            ended_at_ms: None,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        };
        assert_registry_decodes(&registry, value.clone());
        assert_canonical_wire_envelope(&registry, "iroha.instruction.v1::kaigi::EndKaigi", value);

        let value = RecordKaigiUsage {
            call_id: call_id.clone(),
            duration_ms: 60_000,
            billed_gas: 15,
            usage_commitment: None,
            proof: None,
        };
        assert_registry_decodes(&registry, value.clone());
        assert_canonical_wire_envelope(
            &registry,
            "iroha.instruction.v1::kaigi::RecordKaigiUsage",
            value,
        );

        let value = SetKaigiRelayManifest {
            call_id: call_id.clone(),
            relay_manifest: Some(relay_manifest()),
        };
        assert_registry_decodes(&registry, value.clone());
        assert_canonical_wire_envelope(
            &registry,
            "iroha.instruction.v1::kaigi::SetKaigiRelayManifest",
            value,
        );

        let value = RegisterKaigiRelay {
            relay: relay_registration(),
        };
        assert_registry_decodes(&registry, value.clone());
        assert_canonical_wire_envelope(
            &registry,
            "iroha.instruction.v1::kaigi::RegisterKaigiRelay",
            value,
        );

        let value = UnregisterKaigiRelay {
            relay_id: account(4),
        };
        assert_registry_decodes(&registry, value.clone());
        assert_canonical_wire_envelope(
            &registry,
            "iroha.instruction.v1::kaigi::UnregisterKaigiRelay",
            value,
        );

        let value = ReportKaigiRelayHealth {
            call_id,
            relay_id: account(4),
            status: KaigiRelayHealthStatus::Healthy,
            reported_at_ms: 1_700_030_000,
            notes: None,
        };
        assert_registry_decodes(&registry, value.clone());
        assert_canonical_wire_envelope(
            &registry,
            "iroha.instruction.v1::kaigi::ReportKaigiRelayHealth",
            value,
        );
    }
}
