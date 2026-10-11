//! Canonical JSON object key codecs for persisted data-model identities.
use iroha_crypto::Hash;
use norito::json;
use norito::json::JsonKeyCodec;
macro_rules! impl_id_key_codec {
    ($($ty:path),+ $(,)?) => {
        $(
            impl JsonKeyCodec for $ty {
                fn encode_json_key(&self, out: &mut String) {
                    json::write_json_string(&self.to_string(), out);
                }
                fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
                    encoded
                        .parse::<$ty>()
                        .map_err(|err| json::Error::Message(err.to_string()))
                }
            }
        )+
    };
}
macro_rules! impl_nested_json_key_codec {
    ($($ty:path),+ $(,)?) => {
        $(
            impl JsonKeyCodec for $ty {
                fn encode_json_key(&self, out: &mut String) {
                    let mut encoded = String::new();
                    norito::json::JsonSerialize::json_serialize(self, &mut encoded);
                    json::write_json_string(&encoded, out);
                }
                fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
                    let mut parser = json::Parser::new(encoded);
                    norito::json::JsonDeserialize::json_deserialize(&mut parser)
                }
            }
        )+
    };
}
impl_id_key_codec!(
    crate::asset::AssetDefinitionId,
    crate::asset::AssetId,
    crate::nft::NftId,
    crate::role::RoleId,
    crate::trigger::TriggerId,
    crate::oracle::FeedId,
    crate::proof::ProofId,
    crate::isi::settlement::SettlementId,
);
// Parliament certificate identities are available without governance instructions;
// their canonical storage keys must have the same availability.
impl_id_key_codec!(
    crate::governance::types::GovernanceAttemptId,
    crate::governance::types::BallotAttemptId,
    crate::governance::types::TleKeySessionId,
);
// Musubi uses structural, versioned keys whose complete typed JSON form is
// embedded into the surrounding storage object's string key. This avoids
// delimiter ambiguity for nested package/account identities while keeping
// snapshot ordering identical to the underlying Rust `Ord` implementation.
impl_nested_json_key_codec!(
    crate::musubi::MusubiNamespaceV1,
    crate::musubi::MusubiPackageIdV1,
    crate::musubi::MusubiPackageSelectorV1,
    crate::musubi::MusubiPackageMemberKeyV1,
    crate::musubi::MusubiMaintainerDirectoryKeyV1,
    crate::musubi::MusubiInviteIdV1,
    crate::musubi::MusubiReleaseIdV1,
    crate::musubi::ArchiveId,
    crate::musubi::MusubiArchiveLocationKeyV1,
    crate::musubi::MusubiProviderLocationKeyV1,
    crate::musubi::MusubiProviderBundleAttestationKeyV1,
    crate::musubi::MusubiAliasNameV1,
    crate::musubi::MusubiAliasHistoryKeyV1,
);
// AXT budget families use their complete typed issuer-signed identity as the
// consensus storage key. Require the one canonical Norito JSON spelling so
// two snapshot keys cannot decode to the same budget family.
impl JsonKeyCodec for crate::nexus::AxtHandleBudgetKey {
    fn encode_json_key(&self, out: &mut String) {
        let mut encoded = String::new();
        norito::json::JsonSerialize::json_serialize(self, &mut encoded);
        json::write_json_string(&encoded, out);
    }

    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        let mut parser = json::Parser::new(encoded);
        let decoded = norito::json::JsonDeserialize::json_deserialize(&mut parser)?;
        let mut canonical = String::new();
        norito::json::JsonSerialize::json_serialize(&decoded, &mut canonical);
        if canonical != encoded {
            return Err(json::Error::Message(
                "AXT handle budget key must use canonical JSON".into(),
            ));
        }
        Ok(decoded)
    }
}
// Replay-ledger keys are consensus snapshot identities as well. Apply the
// same exact-spelling rule as budget keys so aliases cannot split replay state.
impl JsonKeyCodec for crate::nexus::AxtHandleReplayKey {
    fn encode_json_key(&self, out: &mut String) {
        let mut encoded = String::new();
        norito::json::JsonSerialize::json_serialize(self, &mut encoded);
        json::write_json_string(&encoded, out);
    }

    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        let mut parser = json::Parser::new(encoded);
        let decoded: Self = norito::json::JsonDeserialize::json_deserialize(&mut parser)?;
        let mut canonical = String::new();
        norito::json::JsonSerialize::json_serialize(&decoded, &mut canonical);
        if canonical != encoded {
            return Err(json::Error::Message(
                "AXT handle replay key must use canonical JSON".into(),
            ));
        }
        decoded.validate().map_err(|error| {
            json::Error::Message(format!("invalid AXT handle replay key: {error}"))
        })?;
        Ok(decoded)
    }
}
// Fresh issuer spend nonces are permanent consensus identities. The complete
// issuer context is part of the key and must have one exact snapshot spelling.
impl JsonKeyCodec for crate::nexus::AxtAnchoredSpendReplayKeyV1 {
    fn encode_json_key(&self, out: &mut String) {
        let mut encoded = String::new();
        norito::json::JsonSerialize::json_serialize(self, &mut encoded);
        json::write_json_string(&encoded, out);
    }

    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        let mut parser = json::Parser::new(encoded);
        let decoded: Self = norito::json::JsonDeserialize::json_deserialize(&mut parser)?;
        let mut canonical = String::new();
        norito::json::JsonSerialize::json_serialize(&decoded, &mut canonical);
        if canonical != encoded {
            return Err(json::Error::Message(
                "AXT spend nonce key must use canonical JSON".into(),
            ));
        }
        decoded.validate().map_err(|error| {
            json::Error::Message(format!("invalid AXT spend nonce key: {error}"))
        })?;
        Ok(decoded)
    }
}
// A physical source-transfer coordinate is a permanent consensus identity.
// Reject alternate JSON spellings and malformed block/transaction selectors.
impl JsonKeyCodec for crate::nexus::AxtSourceTransferReplayKeyV1 {
    fn encode_json_key(&self, out: &mut String) {
        let mut encoded = String::new();
        norito::json::JsonSerialize::json_serialize(self, &mut encoded);
        json::write_json_string(&encoded, out);
    }

    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        let mut parser = json::Parser::new(encoded);
        let decoded: Self = norito::json::JsonDeserialize::json_deserialize(&mut parser)?;
        let mut canonical = String::new();
        norito::json::JsonSerialize::json_serialize(&decoded, &mut canonical);
        if canonical != encoded {
            return Err(json::Error::Message(
                "AXT source transfer replay key must use canonical JSON".into(),
            ));
        }
        decoded.validate().map_err(|error| {
            json::Error::Message(format!("invalid AXT source transfer replay key: {error}"))
        })?;
        Ok(decoded)
    }
}
impl JsonKeyCodec for crate::account::AccountId {
    fn encode_json_key(&self, out: &mut String) {
        json::write_json_string(&self.to_string(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        <Self as json::JsonObjectKeyOwned>::from_json_key_text(encoded).map_err(|error| {
            if cfg!(all(test, sumeragi_model_mutation = "DM25"))
                && matches!(
                    error,
                    json::Error::ScopedDecodeResource(_) | json::Error::DecodeResource(_)
                )
            {
                return json::Error::Message(error.to_string());
            }
            error
        })
    }
}
impl JsonKeyCodec for crate::proof::VerifyingKeyId {
    fn encode_json_key(&self, out: &mut String) {
        let mut buf = String::new();
        norito::json::JsonSerialize::json_serialize(self, &mut buf);
        json::write_json_string(&buf, out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        let mut parser = json::Parser::new(encoded);
        norito::json::JsonDeserialize::json_deserialize(&mut parser)
    }
}
impl JsonKeyCodec for crate::da::types::StorageTicketId {
    fn encode_json_key(&self, out: &mut String) {
        self.as_bytes().encode_json_key(out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        <[u8; 32] as JsonKeyCodec>::decode_json_key(encoded).map(Self::new)
    }
}
impl JsonKeyCodec for crate::runtime::RuntimeUpgradeId {
    fn encode_json_key(&self, out: &mut String) {
        <[u8; 32] as JsonKeyCodec>::encode_json_key(&self.0, out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        <[u8; 32] as JsonKeyCodec>::decode_json_key(encoded).map(Self)
    }
}
impl JsonKeyCodec for crate::escrow::EscrowId {
    fn encode_json_key(&self, out: &mut String) {
        self.as_hash().encode_json_key(out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        <Hash as JsonKeyCodec>::decode_json_key(encoded).map(Self::new)
    }
}
impl JsonKeyCodec for crate::account::rekey::AccountAlias {
    fn encode_json_key(&self, out: &mut String) {
        let mut buf = String::new();
        norito::json::JsonSerialize::json_serialize(self, &mut buf);
        json::write_json_string(&buf, out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        let mut parser = json::Parser::new(encoded);
        norito::json::JsonDeserialize::json_deserialize(&mut parser)
    }
}
impl JsonKeyCodec for crate::smart_contract::ContractAlias {
    fn encode_json_key(&self, out: &mut String) {
        norito::json::write_json_string(self.as_ref(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        encoded
            .parse()
            .map_err(|err: iroha_model_base::error::ParseError| {
                json::Error::Message(err.reason().into())
            })
    }
}
impl JsonKeyCodec for crate::smart_contract::ContractAddress {
    fn encode_json_key(&self, out: &mut String) {
        json::write_json_string(self.as_ref(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        encoded
            .parse()
            .map_err(|err: crate::smart_contract::ContractAddressError| {
                json::Error::Message(err.to_string())
            })
    }
}
impl JsonKeyCodec for crate::confidential::ConfidentialParamsId {
    fn encode_json_key(&self, out: &mut String) {
        json::write_json_string(&self.to_string(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        encoded
            .parse::<u32>()
            .map(crate::confidential::ConfidentialParamsId::from)
            .map_err(|err| json::Error::Message(err.to_string()))
    }
}
impl JsonKeyCodec for crate::sorafs::capacity::ProviderId {
    fn encode_json_key(&self, out: &mut String) {
        <[u8; 32] as JsonKeyCodec>::encode_json_key(&self.0, out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        <[u8; 32] as JsonKeyCodec>::decode_json_key(encoded).map(Self)
    }
}
impl JsonKeyCodec for crate::sorafs::pin_registry::ReplicationOrderId {
    fn encode_json_key(&self, out: &mut String) {
        <[u8; 32] as JsonKeyCodec>::encode_json_key(self.as_bytes(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        <[u8; 32] as JsonKeyCodec>::decode_json_key(encoded).map(Self::new)
    }
}
impl JsonKeyCodec for crate::sorafs::pin_registry::ManifestAliasId {
    fn encode_json_key(&self, out: &mut String) {
        json::write_json_string(&self.as_label(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        let (namespace, name) = encoded
            .split_once('/')
            .ok_or_else(|| json::Error::Message("invalid manifest alias key".into()))?;
        Ok(Self::new(namespace.to_owned(), name.to_owned()))
    }
}
impl JsonKeyCodec for crate::oracle::OracleDisputeId {
    fn encode_json_key(&self, out: &mut String) {
        <u64 as JsonKeyCodec>::encode_json_key(&self.0, out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        <u64 as JsonKeyCodec>::decode_json_key(encoded).map(Self)
    }
}
impl JsonKeyCodec for crate::oracle::OracleProviderKey {
    fn encode_json_key(&self, out: &mut String) {
        let mut buf = String::new();
        norito::json::JsonSerialize::json_serialize(self, &mut buf);
        json::write_json_string(&buf, out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        let mut parser = json::Parser::new(encoded);
        norito::json::JsonDeserialize::json_deserialize(&mut parser)
    }
}
impl JsonKeyCodec for crate::oracle::DefiOracleAttestationKey {
    fn encode_json_key(&self, out: &mut String) {
        let mut buf = String::new();
        norito::json::JsonSerialize::json_serialize(self, &mut buf);
        json::write_json_string(&buf, out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        let mut parser = json::Parser::new(encoded);
        norito::json::JsonDeserialize::json_deserialize(&mut parser)
    }
}
impl JsonKeyCodec for crate::oracle::OracleChangeId {
    fn encode_json_key(&self, out: &mut String) {
        self.0.encode_json_key(out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        <Hash as JsonKeyCodec>::decode_json_key(encoded).map(Self)
    }
}
impl JsonKeyCodec for crate::nexus::UniversalAccountId {
    fn encode_json_key(&self, out: &mut String) {
        <Hash as JsonKeyCodec>::encode_json_key(self.as_hash(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        <Hash as JsonKeyCodec>::decode_json_key(encoded)
            .map(crate::nexus::UniversalAccountId::from_hash)
    }
}
impl JsonKeyCodec for crate::nexus::FeeSponsorProgramId {
    fn encode_json_key(&self, out: &mut String) {
        json::write_json_string(&self.to_string(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        encoded
            .parse::<crate::nexus::FeeSponsorProgramId>()
            .map_err(|err| json::Error::Message(err.to_string()))
    }
}
macro_rules! impl_fee_sponsor_struct_key_codec {
    ($($ty:path),+ $(,)?) => {
        $(
            impl JsonKeyCodec for $ty {
                fn encode_json_key(&self, out: &mut String) {
                    let mut encoded = String::new();
                    norito::json::JsonSerialize::json_serialize(self, &mut encoded);
                    json::write_json_string(&encoded, out);
                }
                fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
                    let mut parser = json::Parser::new(encoded);
                    norito::json::JsonDeserialize::json_deserialize(&mut parser)
                }
            }
        )+
    };
}
impl_fee_sponsor_struct_key_codec!(
    crate::nexus::FeeSponsorProgramRevisionKey,
    crate::nexus::FeeSponsorEnrollmentKey,
    crate::nexus::FeeSponsorVaultKey,
    crate::nexus::FeeSponsorBudgetCounterKey,
);
impl JsonKeyCodec for crate::account::OpaqueAccountId {
    fn encode_json_key(&self, out: &mut String) {
        <Hash as JsonKeyCodec>::encode_json_key(self.as_hash(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        <Hash as JsonKeyCodec>::decode_json_key(encoded).map(crate::account::OpaqueAccountId::from)
    }
}
impl JsonKeyCodec for crate::identifier::IdentifierPolicyId {
    fn encode_json_key(&self, out: &mut String) {
        json::write_json_string(&self.to_string(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        encoded
            .parse::<crate::identifier::IdentifierPolicyId>()
            .map_err(|err| json::Error::Message(err.to_string()))
    }
}
impl JsonKeyCodec for crate::ram_lfe::RamLfeProgramId {
    fn encode_json_key(&self, out: &mut String) {
        json::write_json_string(&self.to_string(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        encoded
            .parse::<crate::ram_lfe::RamLfeProgramId>()
            .map_err(|err| json::Error::Message(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn da_pin_keys_roundtrip_with_retained_undo() {
        use super::*;
        use crate::da::types::StorageTicketId;
        use iroha_model_base::topology::LaneId;
        use mv::storage::StorageReadOnly;
        let ticket = StorageTicketId::new([0xa7; 32]);
        let storage = mv::storage::Storage::<StorageTicketId, u64>::new();
        {
            let mut block = storage.block();
            block.insert(ticket, 7);
            block.commit();
        }
        let text = json::to_json(&storage).unwrap();
        let restored: mv::storage::Storage<StorageTicketId, u64> = json::from_str(&text).unwrap();
        assert_eq!(restored.view().get(&ticket), Some(&7));
        assert!(restored.block_and_revert().is_empty());
        let key = (LaneId::new(u32::MAX), u64::MAX, 0_u64);
        let mut encoded = String::new();
        key.encode_json_key(&mut encoded);
        let inner: String = json::from_str(&encoded).unwrap();
        assert_eq!(<(LaneId, u64, u64)>::decode_json_key(&inner).unwrap(), key);
        assert!(StorageTicketId::decode_json_key("00").is_err());
        assert!(StorageTicketId::decode_json_key(&"zz".repeat(32)).is_err());
    }
    use crate::account::AccountId;
    use crate::{
        governance::types::{BallotAttemptId, GovernanceAttemptId, TleKeySessionId},
        musubi::{
            ArchiveId, MusubiInviteIdV1, MusubiMaintainerDirectoryKeyV1, MusubiPackageIdV1,
            MusubiPackageScopeV1, MusubiProviderBundleAttestationKeyV1,
        },
        sorafs::{capacity::ProviderId, pin_registry::ReplicationOrderId},
    };
    use iroha_crypto::KeyPair;
    use iroha_model_base::topology::DataSpaceId;
    use norito::json::JsonKeyCodec;
    use norito::json::Parser;
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked JSON key codec fixture keypair")
    }
    #[test]
    fn governance_hash_ids_are_canonical_json_storage_keys() {
        fn check<T>(key: &T)
        where
            T: JsonKeyCodec + core::fmt::Debug + PartialEq,
        {
            let mut encoded = String::new();
            key.encode_json_key(&mut encoded);
            let mut parser = Parser::new(&encoded);
            let raw = parser.parse_string().expect("parse governance storage key");
            assert_eq!(&T::decode_json_key(&raw).expect("decode storage key"), key);
            assert_eq!(raw.len(), 64, "canonical keys contain exactly 32 hex bytes");
            for invalid in [
                raw.to_uppercase(),
                format!("0x{raw}"),
                raw[..62].to_owned(),
                format!("{raw}00"),
                "zz".repeat(32),
            ] {
                assert!(T::decode_json_key(&invalid).is_err());
            }
        }

        check(&GovernanceAttemptId::new([0xab; 32]));
        check(&BallotAttemptId::new([0xbc; 32]));
        check(&TleKeySessionId::new([0xcd; 32]));
    }
    #[test]
    fn account_storage_keys_preserve_original_refusal_fields_scope_and_retry() {
        use norito::core::{
            DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError,
            classify_decode_attempt,
        };
        use norito::json;
        let expected = AccountId::new(
            KeyPair::from_seed(vec![42; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let literal = expected.canonical_i105().unwrap();
        let storage = mv::storage::Storage::<AccountId, u64>::new();
        {
            let mut block = storage.block();
            block.insert(expected.clone(), 7);
            block.commit();
        }
        let wire = json::to_json(&storage).unwrap();
        let source_pointer = wire.as_ptr();
        let decode = |mode| -> Result<(), json::Error> {
            if mode == 0 {
                assert_eq!(AccountId::decode_json_key(&literal)?, expected);
            } else {
                let restored: mv::storage::Storage<AccountId, u64> = json::from_json(&wire)?;
                assert_eq!(restored.view().get(&expected), Some(&7));
            }
            Ok(())
        };
        let limits = |bytes| {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let demands = [0, 1].map(|mode| {
            let (decoded, usage) =
                norito::core::with_decode_limits_measured(limits(usize::MAX), || decode(mode));
            decoded.expect("actual reader accepts the original canonical input");
            let demand = usage.total_allocated_bytes();
            assert!(demand > 0);
            demand
        });
        let context_limit = demands
            .iter()
            .try_fold(0_usize, |sum, demand| sum.checked_add(*demand))
            .unwrap()
            .checked_mul(2)
            .unwrap();
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let original = DecodeBudgetContext::try_new_owned(limits(context_limit), &pool).unwrap();
        let baseline = pool.reserved_bytes();
        // This original pool owns decoder counters. Ordinary Storage/DTO graphs are
        // not claimed to have physical original-pool admission by this control.
        for (mode, demand) in demands.into_iter().enumerate() {
            let before = original.consumed_allocated_bytes();
            let mut observed = None;
            let refusal = original.with(|| norito::with_decode_limits_scope(
                limits(demand - 1), || classify_decode_attempt(|| {
                    let error = decode(mode).expect_err("one-byte-short original reader must refuse");
                    let norito::json::Error::ScopedDecodeResource(origin) = &error else {
                        panic!("AccountId storage key must retain its original scoped refusal: {error:?}");
                    };
                    observed = Some(origin.clone());
                    Err::<(), _>(error.into_core_error())
                }))).unwrap_err();
            assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
            let refusal = refusal.into_error();
            assert_eq!(
                refusal.decode_resource_error(),
                Some(DecodeResourceError::TotalAllocationExceeded {
                    attempted: u64::try_from(demand).unwrap(),
                    limit: u64::try_from(demand - 1).unwrap(),
                })
            );
            let norito::Error::ScopedDecodeResource(returned) = refusal else {
                panic!("reader must return its exact original observer");
            };
            assert_eq!(returned, observed.unwrap());
            drop(returned);
            assert_eq!(pool.reserved_bytes(), baseline);
            let after_refusal = original.consumed_allocated_bytes();
            // Outer counters debit the attempted final charge before the narrower
            // inner ceiling refuses. Retry reuses that same cumulative owner.
            assert_eq!(after_refusal - before, u64::try_from(demand).unwrap());
            original
                .with(|| decode(mode))
                .expect("same input and original context retry");
            assert_eq!(
                original.consumed_allocated_bytes() - after_refusal,
                u64::try_from(demand).unwrap()
            );
            assert_eq!(pool.reserved_bytes(), baseline);
            let (refusal, usage) =
                norito::core::with_decode_limits_measured(limits(demand - 1), || decode(mode));
            let error = refusal
                .expect_err("same input unscoped refusal")
                .into_core_error();
            assert_eq!(
                error.decode_resource_error(),
                Some(DecodeResourceError::TotalAllocationExceeded {
                    attempted: u64::try_from(demand).unwrap(),
                    limit: u64::try_from(demand - 1).unwrap(),
                })
            );
            assert!(!matches!(error, norito::Error::ScopedDecodeResource(_)));
            assert!(usage.total_allocated_bytes() < demand);
        }
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
        let error = AccountId::decode_json_key("alice@banka.dataspace").unwrap_err();
        assert!(error.into_core_error().decode_resource_error().is_none());
        assert_eq!(wire.as_ptr(), source_pointer);
        assert_eq!(storage.view().get(&expected), Some(&7));
    }

    #[test]
    fn account_id_json_key_codec_roundtrip() {
        let keypair = checked_random_keypair();
        let account = AccountId::new(keypair.public_key().clone());
        let mut encoded = String::new();
        account.encode_json_key(&mut encoded);
        let mut parser = Parser::new(&encoded);
        let raw_key = parser.parse_string().expect("parse encoded json key");
        let decoded = AccountId::decode_json_key(&raw_key).expect("decode json key");
        assert_eq!(decoded, account);
    }
    #[test]
    fn musubi_maintainer_directory_key_json_codec_roundtrip() {
        let keypair = checked_random_keypair();
        let key = MusubiMaintainerDirectoryKeyV1::pending(
            MusubiPackageIdV1::new(
                DataSpaceId::new(7),
                MusubiPackageScopeV1::DataspaceRoot,
                "codec".parse().expect("package name"),
            ),
            AccountId::new(keypair.public_key().clone()),
            MusubiInviteIdV1::new([0x42; 32]),
        );
        let mut encoded = String::new();
        key.encode_json_key(&mut encoded);
        let mut parser = Parser::new(&encoded);
        let raw_key = parser.parse_string().expect("parse encoded JSON key");
        let decoded = MusubiMaintainerDirectoryKeyV1::decode_json_key(&raw_key)
            .expect("decode maintainer directory key");
        assert_eq!(decoded, key);
    }
    #[test]
    fn musubi_provider_bundle_attestation_key_json_codec_roundtrip() {
        let key = MusubiProviderBundleAttestationKeyV1 {
            archive_id: ArchiveId::new([0x41; 32]),
            replication_order: ReplicationOrderId::new([0x42; 32]),
            provider_id: ProviderId::new([0x43; 32]),
        };
        let mut encoded = String::new();
        key.encode_json_key(&mut encoded);
        let mut parser = Parser::new(&encoded);
        let raw_key = parser.parse_string().expect("parse encoded JSON key");
        let decoded = MusubiProviderBundleAttestationKeyV1::decode_json_key(&raw_key)
            .expect("decode provider bundle attestation key");
        assert_eq!(decoded, key);
        let with_unknown_field = raw_key
            .strip_suffix('}')
            .expect("structural Musubi key is a JSON object")
            .to_owned()
            + ",\"unexpected\":true}";
        assert!(
            MusubiProviderBundleAttestationKeyV1::decode_json_key(&with_unknown_field).is_err(),
            "provider attestation key must reject unknown fields"
        );
    }
    #[test]
    fn account_id_json_key_codec_rejects_domain_suffix_literal() {
        let err = crate::account::AccountId::decode_json_key("alice@banka.dataspace")
            .expect_err("domain suffix literal must be rejected");
        assert!(
            matches!(&err, norito::json::Error::Message(message) if message == "invalid I105 account identifier"),
            "unexpected error: {err}"
        );
        assert!(!err.is_decode_resource_limit());
    }
}
