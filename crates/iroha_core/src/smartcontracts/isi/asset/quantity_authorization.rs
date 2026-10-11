// Borrowed projections of the existing quantity-authorization frames.
//
// Root schema declarations are the exact existing owned tuple/Vec identities;
// payloads use the existing tuple/sequence codecs. These private write-only
// projections remove clone/output scratch without defining another wire layout.

use super::*;
use norito::core::{Encoder, SerializePayload};
use std::io::{self, Write};

// Forward only the original payload and its length hints. This adapter adds no
// schema, frame, field, allocation, or alternate encoding; Option/tuple/sequence
// codecs still own their existing layout flags, prefixes, and counted emission.
struct PayloadRef<'a, T>(&'a T);
impl<T: SerializePayload> SerializePayload for PayloadRef<'_, T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        SerializePayload::serialize(self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        SerializePayload::encoded_len_hint(self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        SerializePayload::encoded_len_exact(self.0)
    }
}

/// A borrowed debit declaration with the existing owned root-frame identity.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::quantity_authorization::DebitFrame",
    frame = "(alloc::string::String, core::option::Option<iroha_data_model::account::model::AccountId>)"
)]
pub(super) struct DebitFrame<'a>(pub(super) &'a str, pub(super) Option<&'a AccountId>);
impl SerializePayload for DebitFrame<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        (self.0, self.1.map(PayloadRef)).serialize(writer)
    }
}

/// Existing transaction or typed-purpose declaration without copying the binding.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::quantity_authorization::TranscriptFrame",
    frame = "(alloc::string::String, alloc::string::String, alloc::vec::Vec<u8>)"
)]
pub(super) struct TranscriptFrame<'a>(pub(super) &'a str, pub(super) &'a str, pub(super) &'a [u8]);
impl SerializePayload for TranscriptFrame<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        (self.0, self.1, self.2).serialize(writer)
    }
}

/// Fixed original source details streamed as the same canonical byte sequence.
pub(super) enum SourceDetail {
    Empty,
    Retail(RetailMonetaryPurposeV1),
    Privacy(PrivacyPublicReserveOwnerV1),
}
fn write_frame_bytes<T: norito::NoritoSerialize>(
    value: &T,
    writer: &mut Encoder<'_>,
) -> Result<(), norito::Error> {
    let length = u64::try_from(norito::canonical_frame_len(value)?)
        .map_err(|_| norito::Error::LengthMismatch)?;
    norito::core::write_seq_len(writer, length)?;
    norito::core::write_canonical_to_writer(value, writer)
}
impl SerializePayload for SourceDetail {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        match self {
            Self::Empty => {
                let bytes: &[u8] = &[];
                bytes.serialize(writer)
            }
            Self::Retail(value) => write_frame_bytes(value, writer),
            Self::Privacy(value) => write_frame_bytes(value, writer),
        }
    }
}

/// Existing source-policy name and its original canonical detail bytes.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::quantity_authorization::SourceFrame",
    frame = "(alloc::string::String, alloc::vec::Vec<u8>)"
)]
pub(super) struct SourceFrame<'a>(pub(super) &'a str, pub(super) SourceDetail);
impl SerializePayload for SourceFrame<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        (self.0, PayloadRef(&self.1)).serialize(writer)
    }
}

/// Existing control and destination-admission declaration.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::quantity_authorization::ControlFrame",
    frame = "(alloc::string::String, alloc::string::String)"
)]
pub(super) struct ControlFrame<'a>(pub(super) &'a str, pub(super) &'a str);
impl SerializePayload for ControlFrame<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        (self.0, self.1).serialize(writer)
    }
}

/// Original resolved transfer legs projected without collecting or cloning a Vec.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::quantity_authorization::BindingFrame",
    frame = "alloc::vec::Vec<(iroha_data_model::asset::id::model::AssetId, iroha_data_model::asset::id::model::AssetId, iroha_primitives::numeric::Quantity)>"
)]
pub(super) enum BindingFrame<'a> {
    Transfers(&'a [(AssetId, AssetId, TransferDeltaTranscript)]),
    #[cfg(test)]
    Owned(&'a [(AssetId, AssetId, Quantity)]),
}
impl SerializePayload for BindingFrame<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        match self {
            Self::Transfers(legs) => norito::core::write_element_sequence::<
                (
                    PayloadRef<'_, AssetId>,
                    PayloadRef<'_, AssetId>,
                    PayloadRef<'_, Quantity>,
                ),
                _,
            >(
                writer,
                legs.iter().map(|(source, destination, delta)| {
                    (
                        PayloadRef(source),
                        PayloadRef(destination),
                        PayloadRef(&delta.amount),
                    )
                }),
            ),
            #[cfg(test)]
            Self::Owned(legs) => norito::core::write_element_sequence::<
                (
                    PayloadRef<'_, AssetId>,
                    PayloadRef<'_, AssetId>,
                    PayloadRef<'_, Quantity>,
                ),
                _,
            >(
                writer,
                legs.iter().map(|(source, destination, amount)| {
                    (
                        PayloadRef(source),
                        PayloadRef(destination),
                        PayloadRef(amount),
                    )
                }),
            ),
        }
    }
}

/// Borrow original supply binding bytes or stream one original retail-policy frame.
/// Both variants encode the existing `Vec<u8>` field without an owned byte buffer.
pub(super) enum SupplyBinding<'a> {
    Bytes(&'a [u8]),
    RetailPolicy(&'a RetailDailyLimitPolicyV1),
}
impl SerializePayload for SupplyBinding<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        match self {
            Self::Bytes(bytes) => bytes.serialize(writer),
            Self::RetailPolicy(policy) => write_frame_bytes(*policy, writer),
        }
    }
}

/// Two already-authorized FX legs encoded in their original `Vec` tuple layout.
struct FxBindings<'a>([(&'a AssetId, &'a AssetId, &'a Quantity); 2]);
impl SerializePayload for FxBindings<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<
            (
                PayloadRef<'_, AssetId>,
                PayloadRef<'_, AssetId>,
                PayloadRef<'_, Quantity>,
            ),
            _,
        >(
            writer,
            self.0.iter().map(|(source, destination, amount)| {
                (
                    PayloadRef(*source),
                    PayloadRef(*destination),
                    PayloadRef(*amount),
                )
            }),
        )
    }
}

/// Existing native FX authorization frame borrowing every original value.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::quantity_authorization::FxFrame",
    frame = "(alloc::string::String, iroha_data_model::account::model::AccountId, iroha_data_model::isi::settlement::FxCorridorPolicy, alloc::vec::Vec<(iroha_data_model::asset::id::model::AssetId, iroha_data_model::asset::id::model::AssetId, iroha_primitives::numeric::Quantity)>)"
)]
pub(super) struct FxFrame<'a> {
    pub(super) authority: &'a AccountId,
    pub(super) policy: &'a iroha_data_model::isi::settlement::FxCorridorPolicy,
    pub(super) legs: [(&'a AssetId, &'a AssetId, &'a Quantity); 2],
}
impl SerializePayload for FxFrame<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        (
            "iroha:fastpq:native-fx-authorization:v1",
            PayloadRef(self.authority),
            PayloadRef(self.policy),
            FxBindings(self.legs),
        )
            .serialize(writer)
    }
}

/// Existing supply-authorization tuple without string, binding, ID or quantity copies.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::quantity_authorization::SupplyFrame",
    frame = "(alloc::string::String, bool, alloc::string::String, alloc::vec::Vec<u8>, iroha_data_model::account::model::AccountId, iroha_data_model::asset::id::model::AssetId, iroha_primitives::numeric::Quantity)"
)]
pub(super) struct SupplyFrame<'a> {
    pub(super) mint: bool,
    pub(super) purpose: &'a str,
    pub(super) binding: SupplyBinding<'a>,
    pub(super) authority: &'a AccountId,
    pub(super) id: &'a AssetId,
    pub(super) amount: &'a Quantity,
}
impl SerializePayload for SupplyFrame<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        (
            "iroha:fastpq:supply-authorization:v1",
            self.mint,
            self.purpose,
            PayloadRef(&self.binding),
            PayloadRef(self.authority),
            PayloadRef(self.id),
            PayloadRef(self.amount),
        )
            .serialize(writer)
    }
}

/// Retirement-purpose context streams exact borrowed original arguments.
/// Only checked frame representability limits this mandatory digest; proof-policy
/// quotas are applied separately by the optional proof materializer.
/// Framing uses the existing canonical schemas directly and allocates no temporary
/// tuple/Vec/controller/domain copies. The digest is an observation, never a capability.
pub(super) fn retirement_context(
    purpose: &str,
    authority: &AccountId,
    definition: &AssetDefinitionId,
    incarnation: &iroha_data_model::nexus::AxtAssetIncarnationV1,
    domain: Option<&iroha_model_base::domain::DomainId>,
    balance: Option<(&AssetId, &Quantity)>,
) -> Option<Hash> {
    retirement_context_stream(
        purpose,
        authority,
        definition,
        incarnation,
        domain,
        balance,
        u64::MAX,
    )
}

// Shared streaming kernel; the explicit finite capacity supports only the
// independent test byte/quota oracle. Production uses u64 frame representability.
fn retirement_context_stream(
    purpose: &str,
    authority: &AccountId,
    definition: &AssetDefinitionId,
    incarnation: &iroha_data_model::nexus::AxtAssetIncarnationV1,
    domain: Option<&iroha_model_base::domain::DomainId>,
    balance: Option<(&AssetId, &Quantity)>,
    limit: u64,
) -> Option<Hash> {
    let mut remaining = limit;
    Hash::new_from_writer(|writer| {
        writer.write_all(b"iroha:fastpq:original-retirement:v1\0")?;
        // Include the fixed header in the checked cumulative frame length.
        remaining = remaining
            .checked_sub(b"iroha:fastpq:original-retirement:v1\0".len() as u64)
            .ok_or(io::ErrorKind::InvalidData)?;
        write_delimited_frame(&purpose, &mut remaining, writer)?;
        write_delimited_frame(authority, &mut remaining, writer)?;
        write_delimited_frame(definition, &mut remaining, writer)?;
        write_delimited_frame(incarnation, &mut remaining, writer)?;
        write_delimited_frame(&domain.is_some(), &mut remaining, writer)?;
        if let Some(domain) = domain {
            write_delimited_frame(domain, &mut remaining, writer)?;
        }
        write_delimited_frame(&balance.is_some(), &mut remaining, writer)?;
        if let Some((id, amount)) = balance {
            write_delimited_frame(id, &mut remaining, writer)?;
            write_delimited_frame(amount, &mut remaining, writer)?;
        }
        Ok(())
    })
    .ok()
}

// Framing includes the root type's alignment. Reject a target at compile time if
// a borrowed projection would introduce different padding from the original DTO.
const _: () = {
    assert!(
        std::mem::align_of::<DebitFrame<'static>>()
            == std::mem::align_of::<(String, Option<AccountId>)>()
    );
    assert!(
        std::mem::align_of::<TranscriptFrame<'static>>()
            == std::mem::align_of::<(String, String, Vec<u8>)>()
    );
    assert!(
        std::mem::align_of::<SourceFrame<'static>>() == std::mem::align_of::<(String, Vec<u8>)>()
    );
    assert!(
        std::mem::align_of::<ControlFrame<'static>>() == std::mem::align_of::<(String, String)>()
    );
    assert!(
        std::mem::align_of::<BindingFrame<'static>>()
            == std::mem::align_of::<Vec<(AssetId, AssetId, Quantity)>>()
    );
    assert!(
        std::mem::align_of::<FxFrame<'static>>()
            == std::mem::align_of::<(
                String,
                AccountId,
                iroha_data_model::isi::settlement::FxCorridorPolicy,
                Vec<(AssetId, AssetId, Quantity)>
            )>()
    );
    assert!(
        std::mem::align_of::<SupplyFrame<'static>>()
            == std::mem::align_of::<(String, bool, String, Vec<u8>, AccountId, AssetId, Quantity)>(
            )
    );
};

/// Measure and account a frame before streaming bytes into the original hasher.
/// A failed write discards the incomplete hash; no output-sized allocation exists.
pub(super) fn write_delimited_frame<T: norito::NoritoSerialize>(
    value: &T,
    remaining: &mut u64,
    writer: &mut dyn Write,
) -> io::Result<()> {
    let length = reserve_frame(value, remaining)?;
    writer.write_all(&length.to_le_bytes())?;
    norito::core::write_canonical_to_writer(value, writer)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}
fn reserve_frame<T: norito::NoritoSerialize>(value: &T, remaining: &mut u64) -> io::Result<u64> {
    let length = norito::canonical_frame_len(value)
        .ok()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(io::ErrorKind::InvalidData)?;
    let cost = length.checked_add(8).ok_or(io::ErrorKind::InvalidData)?;
    *remaining = remaining
        .checked_sub(cost)
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok(length)
}

/// Supply hashes its original frame without any proof-profile quota.
pub(super) fn supply_context(value: &SupplyFrame<'_>) -> Option<Hash> {
    frame_context_stream(value, u64::MAX)
}

/// Native FX hashes the exact original tuple frame, without owned projections.
pub(super) fn fx_context(value: &FxFrame<'_>) -> Option<Hash> {
    frame_context_stream(value, u64::MAX)
}

// Supply and FX originally hash a single frame without its accounted delimiter.
fn frame_context_stream<T: norito::NoritoSerialize>(value: &T, limit: u64) -> Option<Hash> {
    let mut remaining = limit;
    reserve_frame(value, &mut remaining).ok()?;
    Hash::new_from_writer(|writer| {
        norito::core::write_canonical_to_writer(value, writer)
            .map_err(|_| io::ErrorKind::InvalidData.into())
    })
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        account::controller::{MultisigMember, MultisigPolicy},
        privacy::*,
    };
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID, BOB_KEYPAIR};

    fn inputs() -> (AssetId, AssetId, Quantity) {
        let domain =
            iroha_model_base::domain::DomainId::try_new("quantity-wire", "universal").unwrap();
        let definition =
            AssetDefinitionId::derive_from_components(domain, "decimal".parse().unwrap());
        let controller = AccountId::new_multisig(
            MultisigPolicy::new(
                2,
                vec![
                    MultisigMember::new(ALICE_KEYPAIR.public_key().clone(), 1).unwrap(),
                    MultisigMember::new(BOB_KEYPAIR.public_key().clone(), 1).unwrap(),
                ],
            )
            .unwrap(),
        );
        (
            AssetId::with_scope(
                definition.clone(),
                controller,
                AssetBalanceScope::Dataspace(DataSpaceId::new(17)),
            ),
            AssetId::of(definition, BOB_ID.clone()),
            "18446744073709551616.0000000000000000000000000001"
                .parse()
                .unwrap(),
        )
    }

    fn assert_frame<V: norito::NoritoSerialize, O: norito::NoritoSerialize>(view: &V, owned: &O) {
        assert_eq!(
            <V as norito::NoritoSchema>::frame_name(),
            <O as norito::NoritoSchema>::frame_name()
        );
        assert_eq!(std::mem::align_of::<V>(), std::mem::align_of::<O>());
        assert_eq!(
            norito::encode_canonical(view).unwrap(),
            norito::encode_canonical(owned).unwrap()
        );
    }

    fn assert_forwarded_lengths<T: SerializePayload>(value: &T) {
        let borrowed = PayloadRef(value);
        assert_eq!(borrowed.encoded_len_hint(), value.encoded_len_hint());
        assert_eq!(borrowed.encoded_len_exact(), value.encoded_len_exact());
    }

    fn reserve_owners() -> [PrivacyPublicReserveOwnerV1; 2] {
        let namespace = |protocol| {
            PrivacyNamespaceV1::new(
                protocol,
                PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                    pool_id: PrivacyPoolIdV1::new([7; 32]),
                }),
            )
        };
        [
            PrivacyPublicReserveOwnerV1::Orchard {
                namespace: namespace(PrivacyProtocolIdV1::OrchardHalo2ActionsV1),
                bootstrap_digest: PrivacyOrchardPoolBootstrapDigestV1::new([9; 32]),
            },
            PrivacyPublicReserveOwnerV1::PrivateIvm {
                namespace: namespace(PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1),
                bootstrap_digest: PrivacyProofManagedPoolBootstrapDigestV1::new([11; 32]),
            },
        ]
    }

    #[test]
    fn every_borrowed_authorization_frame_preserves_owned_schema_alignment_and_native_bytes() {
        let (source, destination, amount) = inputs();
        let authority = source.account();
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_forwarded_lengths(authority);
        assert_forwarded_lengths(&source);
        assert_forwarded_lengths(&amount);
        assert_forwarded_lengths(&SourceDetail::Empty);
        for owner in [None, Some(authority)] {
            assert_frame(
                &DebitFrame("user", owner),
                &("user".to_owned(), owner.cloned()),
            );
        }
        for length in [0, 1, 127, 128, 16_383] {
            let binding = vec![0xa5; length];
            assert_frame(
                &TranscriptFrame("typed-purpose", "scope λ", &binding),
                &(
                    "typed-purpose".to_owned(),
                    "scope λ".to_owned(),
                    binding.clone(),
                ),
            );
            let supply = SupplyFrame {
                mint: true,
                purpose: "retail-reserve-mint",
                binding: SupplyBinding::Bytes(&binding),
                authority,
                id: &source,
                amount: &amount,
            };
            assert_frame(
                &supply,
                &(
                    "iroha:fastpq:supply-authorization:v1".to_owned(),
                    true,
                    "retail-reserve-mint".to_owned(),
                    binding.clone(),
                    authority.clone(),
                    source.clone(),
                    amount.clone(),
                ),
            );
        }
        assert_frame(
            &SourceFrame("User", SourceDetail::Empty),
            &("User".to_owned(), Vec::<u8>::new()),
        );
        for purpose in [
            RetailMonetaryPurposeV1::MintToReserve,
            RetailMonetaryPurposeV1::CreditRetail,
            RetailMonetaryPurposeV1::DefundRetail,
            RetailMonetaryPurposeV1::BurnReserve,
        ] {
            assert_frame(
                &SourceFrame("RetailMonetary", SourceDetail::Retail(purpose)),
                &(
                    "RetailMonetary".to_owned(),
                    norito::encode_canonical(&purpose).unwrap(),
                ),
            );
        }
        for owner in reserve_owners() {
            assert_frame(
                &SourceFrame("PrivacyPoolBridge", SourceDetail::Privacy(owner)),
                &(
                    "PrivacyPoolBridge".to_owned(),
                    norito::encode_canonical(&owner).unwrap(),
                ),
            );
        }
        assert_frame(
            &ControlFrame("Enforce", "existing-account"),
            &("Enforce".to_owned(), "existing-account".to_owned()),
        );
        let owned = vec![
            (source.clone(), destination.clone(), amount.clone()),
            (destination.clone(), source.clone(), Quantity::zero()),
        ];
        assert_frame(&BindingFrame::Owned(&owned), &owned);
        let legs = owned
            .iter()
            .map(|(from, to, amount)| {
                (
                    from.clone(),
                    to.clone(),
                    TransferDeltaTranscript {
                        from_account: from.account().clone(),
                        to_account: to.account().clone(),
                        asset_definition: from.definition().clone(),
                        amount: amount.clone(),
                        from_balance_before: amount.clone(),
                        from_balance_after: Quantity::zero(),
                        to_balance_before: Quantity::zero(),
                        to_balance_after: amount.clone(),
                        from_smt_witness: TransferSmtWitness::default(),
                        to_smt_witness: TransferSmtWitness::default(),
                    },
                )
            })
            .collect::<Vec<_>>();
        assert_frame(&BindingFrame::Transfers(&legs), &owned);
        assert_frame(
            &BindingFrame::Transfers(&[]),
            &Vec::<(AssetId, AssetId, Quantity)>::new(),
        );
    }

    #[test]
    fn streamed_supply_hash_retains_exact_frame_hash_and_quota_boundary() {
        let (source, _, amount) = inputs();
        for mint in [true, false] {
            let binding = vec![0x2b; 128];
            let value = SupplyFrame {
                mint,
                purpose: "ordinary",
                binding: SupplyBinding::Bytes(&binding),
                authority: &ALICE_ID,
                id: &source,
                amount: &amount,
            };
            let owned = (
                "iroha:fastpq:supply-authorization:v1".to_owned(),
                mint,
                "ordinary".to_owned(),
                binding.clone(),
                ALICE_ID.clone(),
                source.clone(),
                amount.clone(),
            );
            let frame = norito::encode_canonical(&owned).unwrap();
            let bound = u64::try_from(frame.len()).unwrap() + 8;
            assert_eq!(frame_context_stream(&value, bound), Some(Hash::new(&frame)));
            assert_eq!(supply_context(&value), Some(Hash::new(&frame)));
            assert_eq!(frame_context_stream(&value, bound - 1), None);
            assert_eq!(frame_context_stream(&value, 0), None);
        }
    }

    #[test]
    fn streamed_movement_hash_matches_original_owned_oracle_across_purposes_and_limits() {
        let (source, destination, amount) = inputs();
        let bindings = vec![(source.clone(), destination, amount)];
        use NumericAssetTransferSourcePolicy as P;
        let [orchard, private_ivm] = reserve_owners();
        let policies = [
            P::User,
            P::GameSessionFunding,
            P::FxEscrowDeposit,
            P::NativeEscrowCustody,
            P::SorafsReserveCustody,
            P::KagemushaReserveCustody,
            P::FxEscrowRelease,
            P::FeeSponsorCustody,
            P::OracleReward,
            P::OraclePenalty,
            P::OracleDisputeResolution,
            P::SocialReward,
            P::SocialEscrow,
            P::StakingUnbond,
            P::StakingSlash,
            P::ModerationChallengeRefund,
            P::ModerationChallengeSlash,
            P::GovernanceSlash,
            P::GovernanceRestitution,
            P::GovernanceUnlock,
            P::CitizenshipRelease,
            P::SccpEscrowLock,
            P::SccpEscrowRelease,
            P::RetailMonetary(RetailMonetaryPurposeV1::CreditRetail),
            P::PrivacyPoolBridge(orchard),
            P::PrivacyPoolBridge(private_ivm),
        ];
        for (index, source_policy) in policies.into_iter().enumerate() {
            let debit = match index % 3 {
                0 => NumericMovementDebitAuthorization::ExactUser(source.account().clone()),
                1 => NumericMovementDebitAuthorization::InitialGenesisBootstrap(
                    source.account().clone(),
                ),
                _ => NumericMovementDebitAuthorization::Protocol,
            };
            let transcript = if index % 2 == 0 {
                NumericMovementTranscriptRequirement::TransactionRequired("asset transfer")
            } else {
                NumericMovementTranscriptRequirement::TransactionOrTypedPurpose {
                    tag: "retained",
                    binding: vec![0x31; 128],
                }
            };
            let authorization = NumericAssetMovementAuthorization {
                debit,
                transcript_authority: source.account().clone(),
                transcript,
                source_policy,
                control_policy: NumericAssetTransferControlPolicy::Enforce,
                destination_admission: if index % 2 == 0 {
                    NumericAssetDestinationAdmissionPolicy::ExistingAccount
                } else {
                    NumericAssetDestinationAdmissionPolicy::ImplicitReceive
                },
            };
            for limit in [0, 63, 64, 511, 1024, 16_384, u64::MAX] {
                assert_eq!(
                    authorization.quantity_authorization_context(&bindings, limit),
                    authorization.quantity_authorization_context_owned_reference(&bindings, limit),
                    "policy {index}, limit {limit}"
                );
            }
            let mut lower = 0;
            let mut upper = 16_384;
            assert!(
                authorization
                    .quantity_authorization_context_owned_reference(&bindings, upper)
                    .is_some()
            );
            while lower + 1 < upper {
                let middle = lower + (upper - lower) / 2;
                if authorization
                    .quantity_authorization_context_owned_reference(&bindings, middle)
                    .is_some()
                {
                    upper = middle
                } else {
                    lower = middle
                }
            }
            assert!(
                authorization
                    .quantity_authorization_context(&bindings, upper)
                    .is_some()
            );
            assert_eq!(
                authorization.quantity_authorization_context(&bindings, upper - 1),
                None
            );
        }
    }

    #[test]
    fn borrowed_fx_context_matches_owned_frame_and_retains_authority_policy_and_leg_binding() {
        use iroha_data_model::{isi::settlement::FxCorridorPolicy, oracle::FeedId};
        let (source, destination, amount) = inputs();
        let domain =
            iroha_model_base::domain::DomainId::try_new("fx-context", "universal").unwrap();
        let policy = FxCorridorPolicy {
            policy_id: "context-corridor".parse().unwrap(),
            revision: 1,
            owner: source.account().clone(),
            source_dataspace: DataSpaceId::new(17),
            source_asset_definition_id: source.definition().clone(),
            destination_dataspace: DataSpaceId::new(18),
            destination_asset_definition_id: AssetDefinitionId::derive_from_components(
                domain.clone(),
                "other".parse().unwrap(),
            ),
            allowed_destination_alias_domains: [domain].into_iter().collect(),
            oracle_feed_id: FeedId("context-feed".parse().unwrap()),
            max_oracle_age_ms: 1000,
            max_source_amount_per_settlement: Quantity::from(10_u32),
            max_destination_amount_per_settlement: Quantity::from(10_u32),
            velocity_window_ms: 1000,
            max_settlements_per_window: 10,
            max_source_amount_per_window: Quantity::from(100_u32),
            max_destination_amount_per_window: Quantity::from(100_u32),
            enabled: true,
        };
        assert_eq!(policy.invariant_error(), None);
        let legs = [
            (&source, &destination, &amount),
            (&destination, &source, &amount),
        ];
        let view = FxFrame {
            authority: source.account(),
            policy: &policy,
            legs,
        };
        let owned = (
            "iroha:fastpq:native-fx-authorization:v1".to_owned(),
            source.account().clone(),
            policy.clone(),
            vec![
                (source.clone(), destination.clone(), amount.clone()),
                (destination.clone(), source.clone(), amount.clone()),
            ],
        );
        assert_frame(&view, &owned);
        let bytes = norito::encode_canonical(&owned).unwrap();
        let expected = Hash::new(&bytes);
        let frame_bound = u64::try_from(bytes.len()).unwrap() + 8;
        assert_eq!(fx_context(&view), Some(expected));
        assert_eq!(frame_context_stream(&view, frame_bound), Some(expected));
        for small in [0, frame_bound - 1] {
            assert_eq!(frame_context_stream(&view, small), None);
            assert_eq!(fx_context(&view), Some(expected));
        }
        let mut changed_policy = policy.clone();
        changed_policy.revision += 1;
        assert_ne!(
            fx_context(&FxFrame {
                policy: &changed_policy,
                ..view
            }),
            Some(expected)
        );
        assert_ne!(
            fx_context(&FxFrame {
                authority: &BOB_ID,
                ..view
            }),
            Some(expected)
        );
        assert_ne!(
            fx_context(&FxFrame {
                legs: [legs[1], legs[0]],
                ..view
            }),
            Some(expected)
        );
    }

    #[test]
    fn borrowed_retail_policy_binding_streams_the_exact_inner_frame_for_mint_and_burn() {
        let (source, _, amount) = inputs();
        let policy = RetailDailyLimitPolicyV1 {
            asset_definition_id: source.definition().clone(),
            physical_dataspace: DataSpaceId::new(17),
            revision: 1,
            daily_cap: Quantity::from(100_u32),
            identity_issuer: source.account().clone(),
            identity_issuer_public_key: ALICE_KEYPAIR.public_key().clone(),
            monetary_issuer_account: source.account().clone(),
            reserve_account: source.account().clone(),
            institutional_exceptions: Default::default(),
        };
        for mint in [false, true] {
            let purpose = if mint {
                "retail-reserve-mint"
            } else {
                "retail-reserve-burn"
            };
            let view = SupplyFrame {
                mint,
                purpose,
                binding: SupplyBinding::RetailPolicy(&policy),
                authority: source.account(),
                id: &source,
                amount: &amount,
            };
            let inner = norito::encode_canonical(&policy).unwrap();
            let owned = (
                "iroha:fastpq:supply-authorization:v1".to_owned(),
                mint,
                purpose.to_owned(),
                inner.clone(),
                source.account().clone(),
                source.clone(),
                amount.clone(),
            );
            assert_frame(&view, &owned);
            let bytes = norito::encode_canonical(&owned).unwrap();
            let expected = Hash::new(&bytes);
            let frame_bound = u64::try_from(bytes.len()).unwrap() + 8;
            assert_eq!(supply_context(&view), Some(expected));
            assert_eq!(frame_context_stream(&view, frame_bound), Some(expected));
            for small in [0, frame_bound - 1] {
                assert_eq!(frame_context_stream(&view, small), None);
                assert_eq!(supply_context(&view), Some(expected));
            }
            assert_eq!(
                supply_context(&SupplyFrame {
                    binding: SupplyBinding::Bytes(&inner),
                    ..view
                }),
                Some(expected)
            );
            let mut changed = policy.clone();
            changed.revision += 1;
            assert_ne!(
                supply_context(&SupplyFrame {
                    binding: SupplyBinding::RetailPolicy(&changed),
                    ..view
                }),
                Some(expected)
            );
        }
    }

    #[test]
    fn mandatory_movement_context_uses_stream_representability_independently_of_small_proof_quotas()
    {
        let (source, destination, amount) = inputs();
        let bindings = [(source.clone(), destination, amount)];
        let authorization = NumericAssetMovementAuthorization::retained(
            source.account(),
            RetainedNumericAssetMovementPurpose::GovernanceSlash(vec![0x31; 16_384]),
        );
        let projected = BindingFrame::Owned(&bindings);
        let expected = authorization
            .quantity_authorization_context_owned_reference(&bindings, u64::MAX)
            .unwrap();
        assert_eq!(
            authorization.quantity_authorization_context_inputs(&projected),
            Some(expected)
        );
        for small in [0, 63, 64, 511, 1024] {
            assert_eq!(
                authorization.quantity_authorization_context_stream(&projected, small),
                None
            );
            assert_eq!(
                authorization.quantity_authorization_context_inputs(&projected),
                Some(expected)
            );
        }
        let different = NumericAssetMovementAuthorization::retained(
            source.account(),
            RetainedNumericAssetMovementPurpose::GovernanceRestitution(vec![0x31; 16_384]),
        );
        assert_ne!(
            different.quantity_authorization_context_inputs(&projected),
            Some(expected)
        );
    }

    #[test]
    fn delimited_frame_refuses_before_output_and_propagates_writer_failure() {
        #[derive(Default)]
        struct RejectWriter {
            attempted: usize,
        }
        impl Write for RejectWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.attempted += bytes.len();
                Err(io::ErrorKind::WriteZero.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let payload = [1u8; 512];
        let value = TranscriptFrame("typed-purpose", "bound", &payload);
        let length = u64::try_from(norito::canonical_frame_len(&value).unwrap()).unwrap();
        let mut writer = RejectWriter::default();
        assert!(write_delimited_frame(&value, &mut (length + 7), &mut writer).is_err());
        assert_eq!(writer.attempted, 0);
        assert!(write_delimited_frame(&value, &mut (length + 8), &mut writer).is_err());
        assert_eq!(writer.attempted, 8);
    }
}

#[cfg(test)]
mod retirement_context_tests {
    use super::*;
    use iroha_data_model::nexus::AxtAssetIncarnationV1;
    use iroha_model_base::domain::DomainId;
    use iroha_test_samples::{ALICE_ID, BOB_ID};

    #[test]
    fn original_retirement_frames_bind_scope_authority_incarnation_and_exact_preimage_limit() {
        let domain = DomainId::try_new("retire-context", "universal").unwrap();
        let definition =
            AssetDefinitionId::derive_from_components(domain.clone(), "units".parse().unwrap());
        let incarnation =
            AxtAssetIncarnationV1::try_from_bytes(Hash::new(b"original registration").into())
                .unwrap();
        let other =
            AxtAssetIncarnationV1::try_from_bytes(Hash::new(b"later registration").into()).unwrap();
        let asset = AssetId::of(definition.clone(), ALICE_ID.clone());
        let amount = Quantity::from(7_u32);
        let context = |purpose, authority, incarnation, domain, balance, limit| {
            retirement_context_stream(
                purpose,
                authority,
                &definition,
                incarnation,
                domain,
                balance,
                limit,
            )
        };
        let expected = context(
            "domain-unregister",
            &ALICE_ID,
            &incarnation,
            Some(&domain),
            Some((&asset, &amount)),
            u64::MAX,
        )
        .unwrap();
        assert_eq!(
            retirement_context(
                "domain-unregister",
                &ALICE_ID,
                &definition,
                &incarnation,
                Some(&domain),
                Some((&asset, &amount))
            ),
            Some(expected),
        );
        for changed in [
            context(
                "definition-unregister",
                &ALICE_ID,
                &incarnation,
                None,
                Some((&asset, &amount)),
                u64::MAX,
            ),
            context(
                "domain-unregister",
                &BOB_ID,
                &incarnation,
                Some(&domain),
                Some((&asset, &amount)),
                u64::MAX,
            ),
            context(
                "domain-unregister",
                &ALICE_ID,
                &other,
                Some(&domain),
                Some((&asset, &amount)),
                u64::MAX,
            ),
            context(
                "domain-unregister",
                &ALICE_ID,
                &incarnation,
                Some(&domain),
                None,
                u64::MAX,
            ),
        ] {
            assert_ne!(changed, Some(expected));
        }
        let mut low = 0;
        let mut high = 16_384;
        assert_eq!(
            context(
                "domain-unregister",
                &ALICE_ID,
                &incarnation,
                Some(&domain),
                Some((&asset, &amount)),
                high
            ),
            Some(expected)
        );
        while low + 1 < high {
            let middle = low + (high - low) / 2;
            if context(
                "domain-unregister",
                &ALICE_ID,
                &incarnation,
                Some(&domain),
                Some((&asset, &amount)),
                middle,
            )
            .is_some()
            {
                high = middle;
            } else {
                low = middle;
            }
        }
        assert_eq!(
            context(
                "domain-unregister",
                &ALICE_ID,
                &incarnation,
                Some(&domain),
                Some((&asset, &amount)),
                high
            ),
            Some(expected)
        );
        assert_eq!(
            context(
                "domain-unregister",
                &ALICE_ID,
                &incarnation,
                Some(&domain),
                Some((&asset, &amount)),
                high - 1
            ),
            None
        );
    }
}
