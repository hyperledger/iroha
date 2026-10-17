//! Owner-issued consent for one exact native AMX debit on one immutable bank root.

use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::json::Json;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::AmxError;
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, NetworkId,
    asset::{AssetBalanceScope, AssetId},
    block::consensus::SumeragiRootScope,
    permission::Permission,
};

/// The exact consent projected into the direct `CanPrepareAmx` permission.
///
/// `transaction_id` is the canonical [`super::AmxTransactionV1::id`] of every participant,
/// leg, deadline and nonce. The registered parent and child roots give those participant
/// identifiers their immutable meaning. A decoded value grants no authority: native Prepare
/// requires this permission in the relay account's current committed direct permissions.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxDebitApprovalV1")]
pub struct AmxDebitApprovalV1 {
    /// Parent Global genesis identity under which the complete transaction is coordinated.
    pub global_network: NetworkId,
    /// Exact participant genesis identity which owns the balance.
    pub participant_network: NetworkId,
    /// Native consensus instance derived from that participant's signed genesis and chain.
    #[norito(
        with = "crate::json_helpers::fixed_bytes_hex",
        bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
    )]
    pub participant_instance: [u8; 32],
    /// Full parent-assigned participant identifier.
    pub dataspace: DataSpaceId,
    /// Domain-separated digest of the complete canonical AMX transaction.
    #[norito(
        with = "crate::json_helpers::fixed_bytes_hex",
        bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
    )]
    pub transaction_id: [u8; 32],
    /// Exact balance bucket whose owner may issue or revoke this consent.
    pub debited_asset: AssetId,
}

impl AmxDebitApprovalV1 {
    /// Validate the complete shape without establishing owner consent.
    ///
    /// # Errors
    /// Rejects a universal participant, shared parent/child identity, empty fingerprint,
    /// or a balance bucket outside the selected participant.
    pub fn validate(&self) -> Result<(), AmxError> {
        if self.global_network == self.participant_network
            || self.participant_instance == [0; 32]
            || self.transaction_id == [0; 32]
            || self.dataspace == DataSpaceId::UNIVERSAL
            || self.debited_asset.scope() != &AssetBalanceScope::Dataspace(self.dataspace)
        {
            return Err(AmxError::Transaction("invalid exact native debit approval"));
        }
        Ok(())
    }

    /// Bind consent to independently authenticated participant root coordinates.
    ///
    /// # Errors
    /// Rejects malformed consent or any substituted parent, child, dataspace or instance.
    pub fn validate_root(
        &self,
        network: NetworkId,
        scope: SumeragiRootScope,
        instance: [u8; 32],
    ) -> Result<(), AmxError> {
        self.validate()?;
        if network != self.participant_network
            || instance != self.participant_instance
            || scope
                != (SumeragiRootScope::Dataspace {
                    parent_network_id: self.global_network,
                    dataspace_id: self.dataspace,
                })
        {
            return Err(AmxError::Transaction(
                "native debit approval belongs to another root",
            ));
        }
        Ok(())
    }

    /// Project the canonical direct permission without depending on the executor crate.
    ///
    /// This is only a request/value constructor. Granting it requires the debit owner's
    /// existing signed/controller-authorized instruction; holding it does not permit delegation.
    ///
    /// # Errors
    /// Rejects malformed consent or preserves the original local JSON allocation refusal.
    pub fn permission(&self) -> Result<Permission, AmxError> {
        #[derive(DeriveJsonSerialize)]
        struct Payload<'a> {
            approval: &'a AmxDebitApprovalV1,
        }
        self.validate()?;
        norito::core::classify_decode_attempt(|| {
            let payload = Json::try_new(Payload { approval: self })?;
            Ok(Permission::new("CanPrepareAmx".into(), payload))
        })
        .map_err(super::encoding)
    }

    /// Exact live component scratch needed by one [`Self::matches_permission`] call.
    ///
    /// Physical producers reserve these bytes before comparison and retain the reservation
    /// until it returns. Checked writers additionally charge their active codec context.
    /// The context's own control backing must be admitted separately.
    ///
    /// # Errors
    /// Rejects malformed expected consent or impossible canonical account geometry.
    pub fn permission_match_scratch_bytes(&self) -> Result<usize, AmxError> {
        self.validate()?;
        norito::core::classify_decode_attempt(|| {
            self.debited_asset
                .account()
                .checked_json_key_scratch_bytes()
                .map_err(norito::json::BoundedJsonError::into_core_error)
        })
        .map_err(super::encoding)
    }

    /// Compare one original direct permission without allocating a replacement token.
    ///
    /// The canonical JSON keys are written in their lexical order into a borrowed byte
    /// comparator. Checked component writers stream even multisignature account text;
    /// neither a controller graph, JSON value nor serialized permission is constructed.
    /// The sole live allocation is the exact checked I105 scratch reported by
    /// [`Self::permission_match_scratch_bytes`], charged to the active codec scope.
    /// Extra fields and changed terms fail this exact comparison.
    ///
    /// # Errors
    /// Rejects malformed expected consent and preserves a checked component writer's
    /// original local resource refusal.
    pub fn matches_permission(&self, permission: &Permission) -> Result<bool, AmxError> {
        use norito::json::{FastJsonWrite, JsonSerialize, JsonWriteSink};

        self.validate()?;
        if permission.name() != "CanPrepareAmx" {
            return Ok(false);
        }
        let mut output = PermissionComparator {
            remaining: permission.payload().as_ref().as_bytes(),
            equal: true,
        };
        norito::core::classify_decode_attempt(|| {
            let mut write = || -> Result<(), norito::json::BoundedJsonError> {
                output.push_str("{\"approval\":{\"dataspace\":")?;
                self.dataspace.json_serialize_to(&mut output)?;
                output.push_str(",\"debited_asset\":")?;
                self.debited_asset.write_json_to(&mut output)?;
                output.push_str(",\"global_network\":")?;
                self.global_network.write_json_to(&mut output)?;
                output.push_str(",\"participant_instance\":")?;
                crate::json_helpers::fixed_bytes_hex::serialize_bounded(
                    &self.participant_instance,
                    &mut output,
                )?;
                output.push_str(",\"participant_network\":")?;
                self.participant_network.write_json_to(&mut output)?;
                output.push_str(",\"transaction_id\":")?;
                crate::json_helpers::fixed_bytes_hex::serialize_bounded(
                    &self.transaction_id,
                    &mut output,
                )?;
                output.push_str("}}")
            };
            write().map_err(norito::json::BoundedJsonError::into_core_error)
        })
        .map_err(super::encoding)?;
        Ok(output.equal && output.remaining.is_empty())
    }
}

struct PermissionComparator<'a> {
    remaining: &'a [u8],
    equal: bool,
}

impl norito::json::JsonWriteSink for PermissionComparator<'_> {
    fn push(&mut self, value: char) -> Result<(), norito::json::BoundedJsonError> {
        let mut bytes = [0; 4];
        self.push_str(value.encode_utf8(&mut bytes))
    }

    fn push_str(&mut self, value: &str) -> Result<(), norito::json::BoundedJsonError> {
        if let Some(rest) = self.remaining.strip_prefix(value.as_bytes()) {
            self.remaining = rest;
        } else {
            self.equal = false;
            self.remaining = &[];
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account::AccountId, asset::AssetDefinitionId};
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};

    fn approval() -> AmxDebitApprovalV1 {
        let account = AccountId::new(
            KeyPair::from_seed(vec![81; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        AmxDebitApprovalV1 {
            global_network: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"approval parent"),
            )),
            participant_network: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"approval bank"),
            )),
            participant_instance: [31; 32],
            dataspace: DataSpaceId::new(7),
            transaction_id: [41; 32],
            debited_asset: AssetId::with_scope(
                AssetDefinitionId::derive_from_components(
                    iroha_model_base::domain::DomainId::try_new("bank", "universal").unwrap(),
                    "cash".parse().unwrap(),
                ),
                account,
                AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
            ),
        }
    }

    #[test]
    fn exact_native_debit_approval_roundtrips_and_binds_every_root_coordinate() {
        #[derive(DeriveJsonDeserialize)]
        struct Payload {
            approval: AmxDebitApprovalV1,
        }

        let value = approval();
        let frame = norito::encode_canonical(&value).unwrap();
        assert_eq!(
            norito::decode_canonical::<AmxDebitApprovalV1>(&frame).unwrap(),
            value
        );
        let json = norito::json::to_json(&value).unwrap();
        assert_eq!(
            norito::json::from_str::<AmxDebitApprovalV1>(&json).unwrap(),
            value
        );
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: value.global_network,
            dataspace_id: value.dataspace,
        };
        value
            .validate_root(value.participant_network, scope, value.participant_instance)
            .unwrap();
        assert!(
            value
                .validate_root(value.global_network, scope, value.participant_instance)
                .is_err()
        );
        assert!(
            value
                .validate_root(
                    value.participant_network,
                    SumeragiRootScope::Global,
                    value.participant_instance
                )
                .is_err()
        );
        assert!(
            value
                .validate_root(value.participant_network, scope, [32; 32])
                .is_err()
        );
        let permission = value.permission().unwrap();
        assert_eq!(permission.name(), "CanPrepareAmx");
        assert!(value.matches_permission(&permission).unwrap());
        assert_eq!(
            permission
                .payload()
                .try_into_any::<Payload>()
                .unwrap()
                .approval,
            value
        );
        let mut changed = value.clone();
        changed.transaction_id[0] ^= 1;
        assert_ne!(changed.permission().unwrap(), permission);
        assert!(!changed.matches_permission(&permission).unwrap());
        changed = value;
        changed.debited_asset = AssetId::new(
            changed.debited_asset.definition().clone(),
            changed.debited_asset.account().clone(),
        );
        assert!(changed.permission().is_err());
    }

    #[test]
    fn exact_native_debit_permission_comparison_refuses_extra_fields_and_other_names() {
        let value = approval();
        let permission = value.permission().unwrap();
        let wrong_name = Permission::new("CanTransferAsset".into(), permission.payload().clone());
        assert!(!value.matches_permission(&wrong_name).unwrap());
        let mut json: norito::json::Value = permission.payload().try_into_any().unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("extra".into(), norito::json::Value::Bool(true));
        let extra = Permission::new("CanPrepareAmx".into(), Json::try_new(json).unwrap());
        assert!(!value.matches_permission(&extra).unwrap());
        let mut malformed = value;
        malformed.transaction_id = [0; 32];
        assert!(malformed.matches_permission(&permission).is_err());
    }

    #[test]
    fn exact_native_debit_permission_comparison_measures_single_and_multisig_scratch() {
        use crate::account::{MultisigMember, MultisigPolicy};
        let single = approval();
        let mut multisig = single.clone();
        let members = (1..=64u8)
            .map(|seed| {
                MultisigMember::new(
                    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                    1,
                )
                .unwrap()
            })
            .collect();
        multisig.debited_asset.account =
            AccountId::new_multisig(MultisigPolicy::new(1, members).unwrap());
        for expected in [single, multisig] {
            let permission = expected.permission().unwrap();
            let scratch = expected.permission_match_scratch_bytes().unwrap();
            let limits =
                |bytes| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 64);
            let (result, usage) =
                norito::core::with_decode_limits_measured(limits(scratch), || {
                    expected.matches_permission(&permission)
                });
            assert!(result.unwrap());
            assert_eq!(usage.total_allocated_bytes(), scratch);
            let refused = norito::core::with_decode_limits_scope(limits(scratch - 1), || {
                expected.matches_permission(&permission)
            });
            assert!(
                matches!(refused, Err(AmxError::Resource(_))),
                "original matcher scratch refusal must retain its resource classification"
            );
        }
    }
}
