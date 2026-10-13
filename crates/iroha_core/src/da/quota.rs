//! Deterministic consensus accounting for authenticated DA ingest.
use super::DaPinIntentValidationError;
use iroha_config::parameters::actual::Da as DaPolicy;
use iroha_crypto::blake3_256;
use iroha_data_model::{account::AccountId, da::pin_intent::DaPinIntentBundle};
use iroha_model_base::state_path::StatePath;
use mv::storage::StorageReadOnly;
use norito::{Decode, Encode, decode_from_bytes, to_bytes};
use std::{collections::BTreeMap, str::FromStr};
const QUOTA_USAGE_KEY_PREFIX_V1: &str = "da_ingest_quota_v1/authority/";
const QUOTA_USAGE_VERSION_V1: u8 = 1;
const MAX_QUOTA_USAGE_BYTES: usize = 128;
/// Transactional smart-contract-state writes prepared for one accepted block.
pub(crate) type DaIngestQuotaWrites = BTreeMap<StatePath, Vec<u8>>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::da::quota::DaIngestQuotaUsageV1")]
struct DaIngestQuotaUsageV1 {
    version: u8,
    window: u64,
    count: u64,
    bytes: u64,
}
impl DaIngestQuotaUsageV1 {
    const fn empty(window: u64) -> Self {
        Self {
            version: QUOTA_USAGE_VERSION_V1,
            window,
            count: 0,
            bytes: 0,
        }
    }
}
fn quota_key(owner: &AccountId) -> Result<StatePath, DaPinIntentValidationError> {
    let owner_bytes =
        to_bytes(owner).map_err(|error| DaPinIntentValidationError::QuotaStateCorrupt {
            owner: owner.clone(),
            reason: format!("failed to encode owner identity: {error}"),
        })?;
    let digest = blake3_256(&owner_bytes);
    StatePath::from_str(&format!(
        "{QUOTA_USAGE_KEY_PREFIX_V1}{}",
        hex::encode(digest)
    ))
    .map_err(|error| DaPinIntentValidationError::QuotaStateCorrupt {
        owner: owner.clone(),
        reason: format!("failed to construct quota state key: {error}"),
    })
}
fn decode_usage(
    owner: &AccountId,
    bytes: &[u8],
) -> Result<DaIngestQuotaUsageV1, DaPinIntentValidationError> {
    if bytes.len() > MAX_QUOTA_USAGE_BYTES {
        return Err(DaPinIntentValidationError::QuotaStateCorrupt {
            owner: owner.clone(),
            reason: format!("usage record exceeds {MAX_QUOTA_USAGE_BYTES} bytes"),
        });
    }
    let usage = decode_from_bytes::<DaIngestQuotaUsageV1>(bytes).map_err(|error| {
        DaPinIntentValidationError::QuotaStateCorrupt {
            owner: owner.clone(),
            reason: format!("usage record does not decode: {error}"),
        }
    })?;
    if usage.version != QUOTA_USAGE_VERSION_V1 {
        return Err(DaPinIntentValidationError::QuotaStateCorrupt {
            owner: owner.clone(),
            reason: format!("unsupported usage version {}", usage.version),
        });
    }
    let canonical =
        to_bytes(&usage).map_err(|error| DaPinIntentValidationError::QuotaStateCorrupt {
            owner: owner.clone(),
            reason: format!("usage record cannot be re-encoded: {error}"),
        })?;
    if canonical != bytes {
        return Err(DaPinIntentValidationError::QuotaStateCorrupt {
            owner: owner.clone(),
            reason: "usage record is not exact canonical Norito".to_owned(),
        });
    }
    Ok(usage)
}
fn charge(
    owner: &AccountId,
    usage: &mut DaIngestQuotaUsageV1,
    payload_bytes: u64,
    policy: &DaPolicy,
) -> Result<(), DaPinIntentValidationError> {
    usage.count =
        usage
            .count
            .checked_add(1)
            .ok_or_else(|| DaPinIntentValidationError::QuotaOverflow {
                owner: owner.clone(),
            })?;
    usage.bytes = usage.bytes.checked_add(payload_bytes).ok_or_else(|| {
        DaPinIntentValidationError::QuotaOverflow {
            owner: owner.clone(),
        }
    })?;
    let max_count = policy.ingest_quota_max_count_per_account.get();
    let max_bytes = policy.ingest_quota_max_bytes_per_account.get();
    if usage.count > max_count || usage.bytes > max_bytes {
        return Err(DaPinIntentValidationError::QuotaExceeded {
            owner: owner.clone(),
            window: usage.window,
            count: usage.count,
            max_count,
            bytes: usage.bytes,
            max_bytes,
        });
    }
    Ok(())
}
fn prepare_with_lookup(
    bundle: &DaPinIntentBundle,
    block_height: u64,
    policy: &DaPolicy,
    mut read: impl FnMut(&StatePath) -> Option<Vec<u8>>,
) -> Result<DaIngestQuotaWrites, DaPinIntentValidationError> {
    let Some(first_intent) = bundle.intents.first() else {
        return Ok(BTreeMap::new());
    };
    let first_authorization = &first_intent.authorization;
    let window = block_height.checked_sub(1).ok_or_else(|| {
        DaPinIntentValidationError::QuotaStateCorrupt {
            owner: first_authorization.owner.clone(),
            reason: "block height must be non-zero".to_owned(),
        }
    })? / policy.ingest_quota_window_blocks.get();
    let mut usages = BTreeMap::<AccountId, (StatePath, DaIngestQuotaUsageV1)>::new();
    for intent in &bundle.intents {
        let authorization = &intent.authorization;
        let owner = &authorization.owner;
        if !usages.contains_key(owner) {
            let key = quota_key(owner)?;
            let usage = match read(&key) {
                Some(bytes) => {
                    let stored = decode_usage(owner, &bytes)?;
                    if stored.window > window {
                        return Err(DaPinIntentValidationError::QuotaStateCorrupt {
                            owner: owner.clone(),
                            reason: format!(
                                "stored window {} is ahead of block window {window}",
                                stored.window
                            ),
                        });
                    }
                    if stored.window == window {
                        stored
                    } else {
                        DaIngestQuotaUsageV1::empty(window)
                    }
                }
                None => DaIngestQuotaUsageV1::empty(window),
            };
            usages.insert(owner.clone(), (key, usage));
        }
        let (_, usage) = usages
            .get_mut(owner)
            .expect("owner usage was inserted immediately above");
        charge(owner, usage, authorization.payload_bytes, policy)?;
    }
    usages
        .into_iter()
        .map(|(owner, (key, usage))| {
            let encoded = to_bytes(&usage).map_err(|error| {
                DaPinIntentValidationError::QuotaStateCorrupt {
                    owner,
                    reason: format!("failed to encode quota usage: {error}"),
                }
            })?;
            Ok((key, encoded))
        })
        .collect()
}
/// Prepare deterministic per-account count and byte charges for one block.
///
/// The returned writes must be committed through the same `WorldBlock` as the
/// pin-intent indexes. Merely checking this function without applying its
/// result would allow later blocks to reuse the same quota window.
pub(crate) fn prepare_ingest_quota_writes(
    state: &impl StorageReadOnly<StatePath, Vec<u8>>,
    bundle: &DaPinIntentBundle,
    block_height: u64,
    policy: &DaPolicy,
) -> Result<DaIngestQuotaWrites, DaPinIntentValidationError> {
    prepare_with_lookup(bundle, block_height, policy, |key| state.get(key).cloned())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
    use iroha_data_model::{
        NetworkId,
        block::BlockHeader,
        da::{
            ingest::{DaIngestAuthorizationV1, DaIngestSignatureV1},
            pin_intent::DaPinIntent,
            types::{BlobDigest, StorageTicketId},
        },
        sorafs::pin_registry::ManifestDigest,
    };
    use iroha_model_base::topology::LaneId;
    use std::num::NonZeroU64;
    fn authorized_intent(owner_seed: u8, sequence: u64, payload_bytes: u64) -> DaPinIntent {
        let key_pair = KeyPair::try_from_seed(vec![owner_seed; 32], Algorithm::Ed25519)
            .expect("valid deterministic key");
        let owner = AccountId::new(key_pair.public_key().clone());
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xA5; 32])),
        );
        let mut authorization = DaIngestAuthorizationV1 {
            network_id,
            owner,
            lane_id: LaneId::SINGLE,
            epoch: 1,
            sequence,
            payload_hash: BlobDigest::new([0x11; 32]),
            payload_bytes,
            request_content_hash: Hash::prehashed([0x22; 32]),
            signatures: Vec::new(),
        };
        let signature = Signature::try_new(key_pair.private_key(), &authorization.signing_digest())
            .expect("sign authorization");
        authorization.signatures.push(DaIngestSignatureV1 {
            signer: key_pair.public_key().clone(),
            signature,
        });
        crate::da::signed_test_pin_intent(
            authorization,
            &key_pair,
            StorageTicketId::new([u8::try_from(sequence).expect("fixture value fits u8"); 32]),
            ManifestDigest::new([u8::try_from(sequence).expect("fixture value fits u8"); 32]),
            None,
        )
    }
    #[test]
    fn quota_frame_owner_rejects_substitution_and_preserves_decoder_policy() {
        let owner = authorized_intent(12, 1, 1).authorization.owner;
        let usage = DaIngestQuotaUsageV1 {
            version: QUOTA_USAGE_VERSION_V1,
            window: 7,
            count: 3,
            bytes: 1024,
        };
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &usage,
            "iroha_core::da::quota::DaIngestQuotaUsageV1",
        );
        let bytes = norito::encode_canonical(&usage).expect("quota frame");
        assert_eq!(
            decode_usage(&owner, &bytes).expect("actual quota decoder"),
            usage
        );
        let wrong_owner = norito::encode_canonical(&owner).expect("account frame");
        assert!(matches!(
            decode_usage(&owner, &wrong_owner),
            Err(DaPinIntentValidationError::QuotaStateCorrupt { .. })
        ));
        let mut unsupported = usage;
        unsupported.version += 1;
        let unsupported =
            norito::encode_canonical(&unsupported).expect("current owner, wrong version");
        assert!(matches!(decode_usage(&owner, &unsupported),
            Err(DaPinIntentValidationError::QuotaStateCorrupt { reason, .. })
                if reason.contains("unsupported usage version")));
    }
    #[test]
    fn quota_counts_all_intents_for_one_owner_transactionally() {
        let policy = DaPolicy {
            ingest_quota_max_count_per_account: NonZeroU64::new(2).expect("nonzero"),
            ingest_quota_max_bytes_per_account: NonZeroU64::new(10).expect("nonzero"),
            ..Default::default()
        };
        let bundle =
            DaPinIntentBundle::new(vec![authorized_intent(7, 1, 4), authorized_intent(7, 2, 6)]);
        let writes = prepare_with_lookup(&bundle, 1, &policy, |_| None)
            .expect("exact count and byte ceilings are admitted");
        assert_eq!(writes.len(), 1);
        let mut exceeded = bundle.clone();
        exceeded.intents.push(authorized_intent(7, 3, 1));
        let error = prepare_with_lookup(&exceeded, 1, &policy, |_| None)
            .expect_err("the whole block must share one transactional accumulator");
        assert!(matches!(
            error,
            DaPinIntentValidationError::QuotaExceeded { .. }
        ));
    }
    #[test]
    fn quota_window_rollover_resets_prior_usage() {
        let policy = DaPolicy {
            ingest_quota_window_blocks: NonZeroU64::new(2).expect("nonzero"),
            ingest_quota_max_count_per_account: NonZeroU64::new(1).expect("nonzero"),
            ..Default::default()
        };
        let first = DaPinIntentBundle::new(vec![authorized_intent(9, 1, 1)]);
        let writes = prepare_with_lookup(&first, 1, &policy, |_| None).expect("first window");
        let second = DaPinIntentBundle::new(vec![authorized_intent(9, 2, 1)]);
        let error = prepare_with_lookup(&second, 2, &policy, |key| writes.get(key).cloned())
            .expect_err("height two is still in the first window");
        assert!(matches!(
            error,
            DaPinIntentValidationError::QuotaExceeded { .. }
        ));
        prepare_with_lookup(&second, 3, &policy, |key| writes.get(key).cloned())
            .expect("height three starts a fresh deterministic window");
    }
    #[test]
    fn quota_rejects_checked_counter_overflow() {
        let policy = DaPolicy::default();
        let bundle = DaPinIntentBundle::new(vec![authorized_intent(10, 1, 1)]);
        let stored = to_bytes(&DaIngestQuotaUsageV1 {
            version: QUOTA_USAGE_VERSION_V1,
            window: 0,
            count: u64::MAX,
            bytes: 0,
        })
        .expect("encode overflow fixture");
        let error = prepare_with_lookup(&bundle, 1, &policy, |_| Some(stored.clone()))
            .expect_err("quota arithmetic must never wrap");
        assert!(matches!(
            error,
            DaPinIntentValidationError::QuotaOverflow { .. }
        ));
    }
    #[test]
    fn quota_rejects_noncanonical_or_future_state() {
        let policy = DaPolicy::default();
        let bundle = DaPinIntentBundle::new(vec![authorized_intent(11, 1, 1)]);
        let malformed = vec![0xFF; MAX_QUOTA_USAGE_BYTES + 1];
        let error = prepare_with_lookup(&bundle, 1, &policy, |_| Some(malformed.clone()))
            .expect_err("oversized state must fail closed");
        assert!(matches!(
            error,
            DaPinIntentValidationError::QuotaStateCorrupt { .. }
        ));
        let future = to_bytes(&DaIngestQuotaUsageV1 {
            version: QUOTA_USAGE_VERSION_V1,
            window: 1,
            count: 0,
            bytes: 0,
        })
        .expect("encode future-window fixture");
        let error = prepare_with_lookup(&bundle, 1, &policy, |_| Some(future.clone()))
            .expect_err("a future persisted window must fail closed");
        assert!(matches!(
            error,
            DaPinIntentValidationError::QuotaStateCorrupt { .. }
        ));
    }
}
