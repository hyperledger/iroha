//! Captured complete frames for every concrete type emitted by `queries!`.

use std::{collections::BTreeMap, fmt::Debug};

use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::{AccountAlias, AccountAliasDomain, address::ChainDiscriminantGuard},
    da::types::StorageTicketId,
    escrow::{AssetEscrowStatus, EscrowId},
    nexus::{FeeSponsorProgramId, UniversalAccountId},
    oracle::{
        DefiOracleAttestationKey, FeedId, KeyedHash, OracleChangeId, OracleDisputeId,
        OracleProviderKey,
    },
    prelude::{AccountId, AssetDefinitionId, AssetId, NftId},
    proof::{ProofId, ProofStatus},
    query,
    sorafs::{
        capacity::ProviderId,
        moderation_ledger::{
            ModerationFinalizedCursorV1, ModerationFinalizedEventCursorV1, RepairFinalizedCursorV1,
            RepairFinalizedEventCursorV1,
        },
        orderbook::{
            OrderbookFinalizedCursorV1, OrderbookFinalizedEventCursorV1, OrderbookOrderStatusV1,
            OrderbookSettlementChannelStatusV1,
        },
        pin_registry::{ManifestDigest, PinManifestFinalizedCursorV1, PinStatusKindV1},
        proof_ledger::{
            ProofOutcomeFinalizedCursorV1, ProofOutcomeFinalizedEventCursorV1, ProofOutcomeKindV1,
        },
        reputation::{
            ReputationJournalFinalizedCursorV1, ReputationJournalFinalizedEventCursorV1,
            ReputationJournalSourceIdV1,
        },
        reserve::{ReserveFinalizedCursorV1, ReserveFinalizedEventCursorV1},
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use norito::{
    NoritoDeserialize, NoritoSerialize,
    json::{self, JsonDeserialize, JsonSerialize, Value},
};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut encoded = String::new();
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("String formatting");
    }
    encoded
}

fn frame<T>(value: &T) -> String
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de> + Debug + PartialEq,
{
    let bytes = norito::to_bytes(value).expect("encode generated query frame");
    let decoded: T = norito::decode_from_bytes(&bytes).expect("decode generated query frame");
    assert_eq!(&decoded, value);
    let header = norito::core::Header::read(bytes.as_slice()).expect("read frame header");
    assert_eq!(header.schema, norito::schema::identity::frame_hash::<T>());
    let mut wrong_schema = bytes.clone();
    wrong_schema[6] ^= 1;
    assert!(matches!(
        norito::decode_from_bytes::<T>(&wrong_schema),
        Err(norito::Error::SchemaMismatch)
    ));
    hex(&bytes)
}

fn record<T>(values: impl IntoIterator<Item = T>) -> Value
where
    T: NoritoSerialize
        + for<'de> NoritoDeserialize<'de>
        + norito::NoritoSchema
        + JsonSerialize
        + JsonDeserialize
        + Clone
        + Debug
        + PartialEq,
{
    let identity_hash = norito::schema::identity::frame_hash::<T>();
    assert_eq!(T::frame_name(), T::nominal_name());
    let cases = values
        .into_iter()
        .map(|value| {
            let json = json::to_value(&value).expect("generated query JSON");
            let decoded: T = json::from_value(json.clone()).expect("decode generated query JSON");
            assert_eq!(decoded, value);
            json::object([
                ("json", json),
                ("frame", Value::String(frame(&value))),
                ("vector_frame", Value::String(frame(&vec![value.clone()]))),
                ("option_frame", Value::String(frame(&Some(value.clone())))),
                (
                    "map_frame",
                    Value::String(frame(&BTreeMap::from([(7_u8, value)]))),
                ),
            ])
            .expect("query case")
        })
        .collect();
    json::object([
        ("nominal", Value::String(T::nominal_name())),
        ("serialize_hash", Value::String(hex(&identity_hash))),
        ("deserialize_hash", Value::String(hex(&identity_hash))),
        ("cases", Value::Array(cases)),
    ])
    .expect("query type")
}

fn account() -> AccountId {
    // Synthetic fixture key; no signing or live-network workflow uses this key.
    let key = KeyPair::try_from_seed(vec![0x35; 32], Algorithm::Ed25519).expect("fixture key");
    AccountId::new(key.public_key().clone())
}

fn domain() -> DomainId {
    DomainId::try_new("market", "universal").expect("fixture domain")
}

fn asset_definition() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(domain(), "coin".parse().expect("fixture asset name"))
}

// Sample real query payloads, including absent and present pagination anchors,
// both alias scopes and every query-filter enum variant. Names and hashes are
// captured from the current compiled types before adding identity declarations.
fn generated_queries() -> Vec<Value> {
    let _address_context = ChainDiscriminantGuard::enter(0x02f1);
    let mut rows = Vec::new();
    rows.push(record((0..2).map(|sample| {
        query::account::FindAccountByAlias::new(AccountAlias::new(
            "merchant".parse().expect("alias label"),
            (sample != 0).then(|| AccountAliasDomain::new("market".parse().expect("alias domain"))),
            DataSpaceId::new(11),
        ))
    })));
    rows.push(record([query::account::FindAccountById::new(account())]));
    rows.push(record([query::account::FindAccountIds]));
    rows.push(record((0..2).map(|sample| {
        query::account::FindAccountRecoveryPolicyByAlias::new(AccountAlias::new(
            "merchant".parse().expect("alias label"),
            (sample != 0).then(|| AccountAliasDomain::new("market".parse().expect("alias domain"))),
            DataSpaceId::new(11),
        ))
    })));
    rows.push(record((0..2).map(|sample| {
        query::account::FindAccountRecoveryRequestByAlias::new(AccountAlias::new(
            "merchant".parse().expect("alias label"),
            (sample != 0).then(|| AccountAliasDomain::new("market".parse().expect("alias domain"))),
            DataSpaceId::new(11),
        ))
    })));
    rows.push(record([query::account::FindAccounts]));
    rows.push(record([query::account::FindAccountsWithAsset::new(
        asset_definition(),
    )]));
    rows.push(record((0..2).map(|sample| {
        query::account::FindAliasesByAccountId::new(
            account(),
            (sample != 0).then(|| "universal".to_owned()),
            (sample != 0).then(|| "market".to_owned()),
        )
    })));
    rows.push(record([query::asset::FindAssetById::new(AssetId::new(
        asset_definition(),
        account(),
    ))]));
    rows.push(record([query::asset::FindAssetDefinitionById::new(
        asset_definition(),
    )]));
    rows.push(record([query::asset::FindAssets]));
    rows.push(record([
        query::asset::FindAssetsByAccountId::new(account()),
    ]));
    rows.push(record([query::asset::FindAssetDefinitions]));
    rows.push(record([query::block::FindBlockHeaders]));
    rows.push(record([query::block::FindBlocks]));
    rows.push(record([query::bond::FindBondById::new(asset_definition())]));
    rows.push(record([query::bond::FindBonds]));
    rows.push(record([query::da::FindDaPinIntentByAlias::new(
        "merchant@market.universal".to_owned(),
    )]));
    rows.push(record([
        query::da::FindDaPinIntentByLaneEpochSequence::new(LaneId::new(3), 42, 42),
    ]));
    rows.push(record([query::da::FindDaPinIntentByManifest::new(
        ManifestDigest::new([0x29; 32]),
    )]));
    rows.push(record([query::da::FindDaPinIntentByTicket::new(
        StorageTicketId::new([0x28; 32]),
    )]));
    rows.push(record([query::domain::FindDomainById::new(domain())]));
    rows.push(record([query::domain::FindDomains]));
    rows.push(record([query::domain::FindDomainsByAccountId::new(
        account(),
    )]));
    rows.push(record([query::endorsement::FindDomainCommittee::new(
        "committee".to_owned(),
    )]));
    rows.push(record([
        query::endorsement::FindDomainEndorsementPolicy::new(domain()),
    ]));
    rows.push(record([query::endorsement::FindDomainEndorsements::new(
        domain(),
    )]));
    rows.push(record([query::escrow::FindAssetEscrowById::new(
        EscrowId::new(Hash::new(b"query escrow")),
    )]));
    rows.push(record([query::escrow::FindAssetEscrows]));
    rows.push(record([query::escrow::FindAssetEscrowsByBuyer::new(
        account(),
    )]));
    rows.push(record([query::escrow::FindAssetEscrowsBySeller::new(
        account(),
    )]));
    rows.push(record((0..10).map(|sample| {
        query::escrow::FindAssetEscrowsByStatus::new(
            [
                AssetEscrowStatus::Open,
                AssetEscrowStatus::Accepted,
                AssetEscrowStatus::PaymentSent,
                AssetEscrowStatus::Disputed,
                AssetEscrowStatus::Released,
                AssetEscrowStatus::Cancelled,
                AssetEscrowStatus::Resolved,
                AssetEscrowStatus::Locked,
                AssetEscrowStatus::DrawnDown,
                AssetEscrowStatus::Expired,
            ][(sample) % 10],
        )
    })));
    rows.push(record([query::executor::FindExecutorDataModel]));
    rows.push(record([query::executor::FindParameters]));
    rows.push(record([query::nexus::FindFeeSponsorProgramById::new(
        FeeSponsorProgramId::new(account(), "sponsor".parse().expect("program name")),
    )]));
    rows.push(record([query::nexus::FindFeeSponsorProgramIds]));
    rows.push(record([query::nexus::FindFeeSponsorPrograms]));
    rows.push(record([
        query::nexus::FindFeeSponsorProgramsBySponsor::new(account()),
    ]));
    rows.push(record([query::nft::FindNftById::new(NftId::new(
        domain(),
        "collectible".parse().expect("NFT name"),
    ))]));
    rows.push(record([query::nft::FindNfts]));
    rows.push(record([query::nft::FindNftsByAccountId::new(account())]));
    rows.push(record([
        query::oracle::FindDefiOracleAttestationsByKey::new(DefiOracleAttestationKey {
            domain: 1,
            subject_id: 42,
        }),
    ]));
    rows.push(record([
        query::oracle::FindLatestDefiOracleAttestation::new(DefiOracleAttestationKey {
            domain: 1,
            subject_id: 42,
        }),
    ]));
    rows.push(record([query::oracle::FindOracleChangeById::new(
        OracleChangeId(Hash::new(b"query change")),
    )]));
    rows.push(record([query::oracle::FindOracleChanges]));
    rows.push(record([query::oracle::FindOracleDisputeById::new(
        OracleDisputeId(17),
    )]));
    rows.push(record([query::oracle::FindOracleDisputes]));
    rows.push(record([query::oracle::FindOracleDisputesByFeedId::new(
        "price_xor_usd".parse::<FeedId>().expect("feed name"),
    )]));
    rows.push(record([query::oracle::FindOracleFeedById::new(
        "price_xor_usd".parse::<FeedId>().expect("feed name"),
    )]));
    rows.push(record([query::oracle::FindOracleFeeds]));
    rows.push(record([query::oracle::FindOracleHistoryByFeedId::new(
        "price_xor_usd".parse::<FeedId>().expect("feed name"),
    )]));
    rows.push(record([
        query::oracle::FindOracleProviderStatsByFeedId::new(
            "price_xor_usd".parse::<FeedId>().expect("feed name"),
        ),
    ]));
    rows.push(record([query::oracle::FindOracleProviderStatsByKey::new(
        OracleProviderKey::new("price_xor_usd".parse().expect("feed name"), account()),
    )]));
    rows.push(record([query::oracle::FindTwitterBindingByHash::new(
        KeyedHash::new("fixture-pepper", b"synthetic pepper", b"fixture handle"),
    )]));
    rows.push(record([query::oracle::FindTwitterBindingsByUaid::new(
        UniversalAccountId::from_hash(Hash::new(b"query uaid")),
    )]));
    rows.push(record([query::peer::FindPeers]));
    rows.push(record([
        query::permission::FindPermissionsByAccountId::new(account()),
    ]));
    rows.push(record([query::proof::FindProofRecordById::new(ProofId {
        backend: "halo2/ipa".to_owned(),
        proof_hash: [0x27; 32],
    })]));
    rows.push(record([query::proof::FindProofRecords]));
    rows.push(record([query::proof::FindProofRecordsByBackend::new(
        "halo2/ipa".to_owned(),
    )]));
    rows.push(record((0..3).map(|sample| {
        query::proof::FindProofRecordsByStatus::new(
            [
                ProofStatus::Submitted,
                ProofStatus::Verified,
                ProofStatus::Rejected,
            ][(sample) % 3],
        )
    })));
    rows.push(record([query::repo::FindRepoAgreements]));
    rows.push(record([query::role::FindRoleIds]));
    rows.push(record([query::role::FindRoles]));
    rows.push(record([query::role::FindRolesByAccountId::new(account())]));
    rows.push(record([query::runtime::FindAbiVersion]));
    rows.push(record([query::rwa::FindRwas]));
    rows.push(record([query::settlement::FindFxCorridorPolicyById::new(
        "corridor".parse().expect("policy name"),
    )]));
    rows.push(record([query::settlement::FindFxCorridorPolicyRegistry]));
    rows.push(record([query::settlement::FindSettlementReceiptById::new(
        iroha_data_model::isi::SettlementId::new(
            account(),
            "business_receipt".parse().expect("settlement reference"),
        ),
    )]));
    rows.push(record([
        query::smart_contract::FindContractManifestByArtifactId::new(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::new(u64::MAX),
                Hash::new(b"query contract"),
            ),
        ),
    ]));
    rows.push(record([query::sns::FindDataspaceNameOwnerById::new(
        DataSpaceId::new(11),
    )]));
    rows.push(record([
        query::sorafs::FindSorafsCitizenBondBySerialCommitment::new([0x42; 32]),
    ]));
    rows.push(record([query::sorafs::FindSorafsCitizenBondSnapshot]));
    rows.push(record([query::sorafs::FindSorafsModerationAppeal::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
    )]));
    rows.push(record([query::sorafs::FindSorafsModerationCase::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
    )]));
    rows.push(record([query::sorafs::FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-1".to_owned(),
    )]));
    rows.push(record([query::sorafs::FindSorafsModerationCommit::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        account(),
    )]));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsModerationEvents::new(
            ModerationFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            },
            (sample != 0).then_some(ModerationFinalizedEventCursorV1 {
                sequence: 7,
                block_height: 41,
                block_hash: [0x44; 32],
                event_index: 2,
            }),
            16,
        )
    })));
    rows.push(record([
        query::sorafs::FindSorafsModerationJurorEligibility::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            account(),
        ),
    ]));
    rows.push(record([query::sorafs::FindSorafsModerationNoShow::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        account(),
    )]));
    rows.push(record([query::sorafs::FindSorafsModerationOutcome::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
    )]));
    rows.push(record([query::sorafs::FindSorafsModerationPolicy]));
    rows.push(record([query::sorafs::FindSorafsModerationReveal::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        account(),
    )]));
    rows.push(record([query::sorafs::FindSorafsModerationSnapshot::new(
        16, 16,
    )]));
    rows.push(record([query::sorafs::FindSorafsModerationStatus]));
    rows.push(record([
        query::sorafs::FindSorafsOrderbookCancellationByOrderId::new([0x42; 32]),
    ]));
    rows.push(record([
        query::sorafs::FindSorafsOrderbookChannelById::new([0x42; 32]),
    ]));
    rows.push(record((0..4).map(|sample| {
        query::sorafs::FindSorafsOrderbookChannels::new(
            (sample != 0).then_some(OrderbookFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then(|| {
                [
                    OrderbookSettlementChannelStatusV1::Open,
                    OrderbookSettlementChannelStatusV1::Closed,
                    OrderbookSettlementChannelStatusV1::Expired,
                ][(sample - 1) % 3]
            }),
            (sample != 0).then_some([0x42; 32]),
            16,
        )
    })));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsOrderbookEvents::new(
            (sample != 0).then_some(OrderbookFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then_some(OrderbookFinalizedEventCursorV1 {
                sequence: 7,
                block_height: 41,
                block_hash: [0x44; 32],
                event_index: 2,
            }),
            16,
        )
    })));
    rows.push(record([query::sorafs::FindSorafsOrderbookOrderById::new(
        [0x42; 32],
    )]));
    rows.push(record((0..7).map(|sample| {
        query::sorafs::FindSorafsOrderbookOrders::new(
            (sample != 0).then_some(OrderbookFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then(|| {
                [
                    OrderbookOrderStatusV1::Open,
                    OrderbookOrderStatusV1::PartiallyFilled,
                    OrderbookOrderStatusV1::Filled,
                    OrderbookOrderStatusV1::Cancelled,
                    OrderbookOrderStatusV1::Expired,
                    OrderbookOrderStatusV1::ProviderRevoked,
                ][(sample - 1) % 6]
            }),
            (sample != 0).then_some([0x42; 32]),
            16,
        )
    })));
    rows.push(record([query::sorafs::FindSorafsOrderbookPolicy]));
    rows.push(record([
        query::sorafs::FindSorafsOrderbookReceiptById::new([0x42; 32]),
    ]));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsOrderbookReceipts::new(
            (sample != 0).then_some(OrderbookFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then_some([0x42; 32]),
            (sample != 0).then_some([0x42; 32]),
            16,
        )
    })));
    rows.push(record([query::sorafs::FindSorafsOrderbookStatus]));
    rows.push(record([query::sorafs::FindSorafsOrderbookTradeById::new(
        [0x42; 32],
    )]));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsOrderbookTrades::new(
            (sample != 0).then_some(OrderbookFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then_some([0x42; 32]),
            16,
        )
    })));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsPinManifest::new(
            ManifestDigest::new([0x29; 32]),
            (sample != 0).then_some(PinManifestFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
        )
    })));
    rows.push(record((0..4).map(|sample| {
        query::sorafs::FindSorafsPinManifests::new(
            (sample != 0).then_some(PinManifestFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then(|| {
                [
                    PinStatusKindV1::Pending,
                    PinStatusKindV1::Approved,
                    PinStatusKindV1::Retired,
                ][(sample - 1) % 3]
            }),
            (sample != 0).then(|| ManifestDigest::new([0x29; 32])),
            16,
            65_536,
        )
    })));
    rows.push(record([
        query::sorafs::FindSorafsPopAuditDigestBySequence::new(42),
    ]));
    rows.push(record([
        query::sorafs::FindSorafsPopCommitmentRootByVersion::new(42),
    ]));
    rows.push(record([
        query::sorafs::FindSorafsPopCredentialCommitmentByDigest::new([0x42; 32]),
    ]));
    rows.push(record([query::sorafs::FindSorafsPopIssuerPolicy]));
    rows.push(record([query::sorafs::FindSorafsPopRegistryStatus]));
    rows.push(record([
        query::sorafs::FindSorafsPopRevocationByNonceCommitment::new([0x42; 32]),
    ]));
    rows.push(record([
        query::sorafs::FindSorafsPopRevocationPublicationByVersion::new(42),
    ]));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsProofOutcome::new(
            [ProofOutcomeKindV1::Pdp, ProofOutcomeKindV1::Potr][(sample) % 2],
            [0x42; 32],
            (sample != 0).then_some(ProofOutcomeFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
        )
    })));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsProofOutcomeEvents::new(
            (sample != 0).then_some(ProofOutcomeFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then_some(ProofOutcomeFinalizedEventCursorV1 {
                sequence: 7,
                block_height: 41,
                block_hash: [0x44; 32],
                event_index: 2,
            }),
            16,
        )
    })));
    rows.push(record([query::sorafs::FindSorafsProviderOwner::new(
        ProviderId([0x2a; 32]),
    )]));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsRepairEvents::new(
            (sample != 0).then_some(RepairFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then_some(RepairFinalizedEventCursorV1 {
                sequence: 7,
                block_height: 41,
                block_hash: [0x44; 32],
                event_index: 2,
            }),
            16,
        )
    })));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsRepairStatus::new((sample != 0).then_some(
            RepairFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            },
        ))
    })));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsRepairTask::new(
            "repair-ticket-1".to_owned(),
            (sample != 0).then_some(RepairFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
        )
    })));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsRepairTasks::new(
            (sample != 0).then_some(RepairFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then_some([0x42; 32]),
            16,
        )
    })));
    rows.push(record([
        query::sorafs::FindSorafsReputationJournalAuthorityPolicy,
    ]));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsReputationJournalEventBySourceId::new(
            ReputationJournalSourceIdV1([0x2b; 32]),
            (sample != 0).then_some(ReputationJournalFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
                finalized_at_unix_ms: 1_700_000_000_000,
            }),
        )
    })));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsReputationJournalEvents::new(
            (sample != 0).then_some(ReputationJournalFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
                finalized_at_unix_ms: 1_700_000_000_000,
            }),
            (sample != 0).then_some(ReputationJournalFinalizedEventCursorV1 {
                sequence: 7,
                block_height: 41,
                block_hash: [0x44; 32],
                event_index: 2,
            }),
            16,
        )
    })));
    rows.push(record([query::sorafs::FindSorafsReserveAppealById::new(
        [0x42; 32],
    )]));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsReserveAppeals::new(
            (sample != 0).then_some(ReserveFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then_some([0x42; 32]),
            16,
        )
    })));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsReserveEvents::new(
            (sample != 0).then_some(ReserveFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then_some(ReserveFinalizedEventCursorV1 {
                sequence: 7,
                block_height: 41,
                block_hash: [0x44; 32],
                event_index: 2,
            }),
            16,
        )
    })));
    rows.push(record([query::sorafs::FindSorafsReserveMovementById::new(
        [0x42; 32],
    )]));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsReserveMovements::new(
            (sample != 0).then_some(ReserveFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then_some([0x42; 32]),
            16,
        )
    })));
    rows.push(record([query::sorafs::FindSorafsReservePolicy]));
    rows.push(record([query::sorafs::FindSorafsReserveProviderById::new(
        ProviderId([0x2a; 32]),
    )]));
    rows.push(record((0..2).map(|sample| {
        query::sorafs::FindSorafsReserveProviders::new(
            (sample != 0).then_some(ReserveFinalizedCursorV1 {
                height: 42,
                block_hash: [0x43; 32],
            }),
            (sample != 0).then_some(ProviderId([0x2a; 32])),
            16,
        )
    })));
    rows.push(record([query::transaction::FindTransactions]));
    rows.push(record([query::trigger::FindActiveTriggerIds]));
    rows.push(record([query::trigger::FindTriggerById::new(
        "daily".parse().expect("trigger id"),
    )]));
    rows.push(record([query::trigger::FindTriggers]));
    rows
}

#[test]
fn generated_queries_preserve_captured_frames() {
    let rows = generated_queries();
    assert_eq!(rows.len(), 129);
    assert_eq!(
        rows.iter()
            .map(|row| row.get("cases").unwrap().as_array().unwrap().len())
            .sum::<usize>(),
        173,
    );
    let captured: Value = json::from_str(include_str!(
        "fixtures/query_generated_identity_frames.json"
    ))
    .expect("immutable generated query capture");
    super::fixture_json::assert_json_matches(
        &captured,
        &Value::Array(rows),
        "generated query identities",
    );
}

#[test]
#[ignore = "explicit maintenance capture of the complete generated query catalog"]
fn print_generated_query_identity_frames() {
    println!(
        "GENERATED_QUERY_IDENTITY_FRAMES={}",
        json::to_json(&Value::Array(generated_queries())).unwrap()
    );
}

#[test]
#[ignore = "explicit maintenance capture of the first-release scoped manifest query"]
fn print_scoped_manifest_query_identity_frame() {
    let row = record([
        query::smart_contract::FindContractManifestByArtifactId::new(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                DataSpaceId::new(u64::MAX),
                Hash::new(b"query contract"),
            ),
        ),
    ]);
    println!(
        "SCOPED_MANIFEST_QUERY_FRAME={}",
        json::to_json(&row).unwrap()
    );
}

#[test]
#[ignore = "explicit maintenance capture of the owner-qualified settlement receipt query"]
fn print_settlement_receipt_query_identity_frame() {
    let _address_context = ChainDiscriminantGuard::enter(0x02f1);
    let row = record([query::settlement::FindSettlementReceiptById::new(
        iroha_data_model::isi::SettlementId::new(
            account(),
            "business_receipt".parse().expect("settlement reference"),
        ),
    )]);
    println!(
        "SETTLEMENT_RECEIPT_QUERY_FRAME={}",
        json::to_json(&row).unwrap()
    );
}
