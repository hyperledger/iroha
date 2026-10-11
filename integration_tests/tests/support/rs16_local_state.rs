//! Bounded observations of one actual observer's local account and fee rows.
//!
//! Signed client queries route to authoritative validators. This diagnostic uses the existing
//! node-local projection export and binds its height/hash to independently checked finality. The
//! rows are local process observations, not authenticated complete-State restoration proofs.

use std::time::Instant;

use eyre::{Result, ensure, eyre};
use iroha_core::{
    query::{
        projection_checkpoint::{
            QUERY_PROJECTION_SCHEMA_VERSION, QueryProjectionResourceKind,
            query_projection_default_partition_for_account,
        },
        projection_rowset::{QUERY_PROJECTION_ROWSET_VERSION, QueryProjectionShardRowSet},
        projection_shard::{
            QUERY_PROJECTION_SHARD_ARCHIVE_VERSION, QUERY_PROJECTION_SHARD_ROWSET_CODEC,
            QueryProjectionShardArchive,
        },
    },
    sumeragi::certified_chain::CertifiedBlock,
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    account::AccountId,
    asset::{AssetBalanceScope, AssetId},
    block::BlockHeader,
    da::types::BlobDigest,
};
use iroha_primitives::numeric::Quantity;
use iroha_test_network::NetworkPeer;
use tokio::runtime::Runtime;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DECODE_LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    MAX_RESPONSE_BYTES,
    MAX_RESPONSE_BYTES,
    2 * MAX_RESPONSE_BYTES,
    8 * MAX_RESPONSE_BYTES,
    32,
);

/// Fetch one bounded local shard within the caller's unchanged operation deadline.
fn read_local_rows(
    peer: &NetworkPeer,
    rt: &Runtime,
    resource: QueryProjectionResourceKind,
    account: &AccountId,
    certified: &CertifiedBlock,
    deadline: Instant,
) -> Result<QueryProjectionShardRowSet> {
    ensure!(
        Instant::now() < deadline,
        "original local observation deadline elapsed"
    );
    let partition = query_projection_default_partition_for_account(&account.to_string());
    let path = format!(
        "/v1/node/query/projection/shards/{}/{partition}",
        resource.as_stable_str(),
    );
    let url = format!("{}{path}", peer.torii_url().trim_end_matches('/'));
    // Shard export is an operator route. Use this exact peer's retained operator
    // authority and network binding; the normal authentication middleware remains
    // active even while this observer's inbound consensus transport is held.
    let context = peer.client();
    let headers = iroha_torii::operator_signed_request_headers(
        context.client().operator_key_pair().ok_or_else(|| {
            eyre!("local shard observation requires this peer's operator authority")
        })?,
        context.client().network_id(),
        &iroha_torii::Method::GET,
        &path.parse()?,
        &[],
    )?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    let bytes = rt.block_on(async {
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let mut response = client
                .get(url)
                .headers(headers)
                .send()
                .await?
                .error_for_status()?;
            ensure!(
                response.status() == reqwest::StatusCode::OK,
                "local shard export redirected"
            );
            ensure!(
                response
                    .content_length()
                    .is_none_or(|length| length <= MAX_RESPONSE_BYTES as u64),
                "local shard response exceeds diagnostic byte bound"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    chunk.len() <= MAX_RESPONSE_BYTES - bytes.len(),
                    "local shard response exceeds diagnostic byte bound"
                );
                bytes.extend_from_slice(&chunk);
            }
            Ok::<_, eyre::Report>(bytes)
        })
        .await?
    })?;
    let rows = decode_local_rows(
        &bytes,
        resource,
        partition,
        certified.committed().height(),
        certified.committed().block_hash(),
    )?;
    ensure!(
        Instant::now() < deadline,
        "local observation exceeded its original deadline"
    );
    Ok(rows)
}

/// Reject stale, substituted, corrupt, or ambiguous local diagnostic rows.
fn decode_local_rows(
    bytes: &[u8],
    resource: QueryProjectionResourceKind,
    partition: u32,
    height: u64,
    hash: HashOf<BlockHeader>,
) -> Result<QueryProjectionShardRowSet> {
    ensure!(
        bytes.len() <= MAX_RESPONSE_BYTES,
        "local shard byte bound exceeded"
    );
    let archive: QueryProjectionShardArchive =
        norito::decode_from_bytes_with_limits(bytes, DECODE_LIMITS)?;
    ensure!(
        archive.version == QUERY_PROJECTION_SHARD_ARCHIVE_VERSION
            && archive.schema_version == QUERY_PROJECTION_SCHEMA_VERSION
            && archive.resource == resource
            && archive.partition_id == partition
            && archive.asset_definition_id.is_none()
            && archive.indexed_height == height
            && archive.indexed_block_hash == Some(hash)
            && archive.payload_codec.0 == QUERY_PROJECTION_SHARD_ROWSET_CODEC
            && archive.payload_hash == BlobDigest::from_hash(blake3::hash(&archive.payload)),
        "local projection does not match the requested shard and certified height/hash"
    );
    let rows: QueryProjectionShardRowSet =
        norito::decode_from_bytes_with_limits(&archive.payload, DECODE_LIMITS)?;
    ensure!(
        rows.resource() == resource
            && rows.partition_id() == partition
            && rows.asset_definition_id().is_none()
            && rows.row_count() == archive.row_count,
        "local rowset does not match its archive"
    );
    let valid = match &rows {
        QueryProjectionShardRowSet::Accounts(rows) => {
            rows.version == QUERY_PROJECTION_ROWSET_VERSION
                && rows.rows.iter().all(|row| {
                    query_projection_default_partition_for_account(&row.account_id) == partition
                })
                && rows
                    .rows
                    .windows(2)
                    .all(|pair| pair[0].account_id < pair[1].account_id)
        }
        QueryProjectionShardRowSet::AccountAssets(rows) => {
            rows.version == QUERY_PROJECTION_ROWSET_VERSION
                && rows.rows.iter().all(|row| {
                    query_projection_default_partition_for_account(&row.account_id) == partition
                })
                && rows.rows.windows(2).all(|pair| {
                    (&pair[0].account_id, &pair[0].asset, &pair[0].scope)
                        < (&pair[1].account_id, &pair[1].asset, &pair[1].scope)
                })
        }
        _ => false,
    };
    ensure!(
        valid,
        "local rowset has invalid versions, partitions, or duplicate/unordered rows"
    );
    Ok(rows)
}

/// Check the account in this peer's actual local committed view.
pub(super) fn account_present(
    peer: &NetworkPeer,
    rt: &Runtime,
    account: &AccountId,
    certified: &CertifiedBlock,
    deadline: Instant,
) -> Result<bool> {
    let QueryProjectionShardRowSet::Accounts(rows) = read_local_rows(
        peer,
        rt,
        QueryProjectionResourceKind::Accounts,
        account,
        certified,
        deadline,
    )?
    else {
        unreachable!("validated accounts resource")
    };
    Ok(rows
        .rows
        .iter()
        .any(|row| row.account_id == account.to_string()))
}

/// Read both exact fee buckets from this peer, without authoritative-peer proxying.
pub(super) fn balances(
    peer: &NetworkPeer,
    rt: &Runtime,
    ids: &[AssetId; 2],
    certified: &CertifiedBlock,
    deadline: Instant,
) -> Result<[Quantity; 2]> {
    let mut values = Vec::with_capacity(2);
    for id in ids {
        let rows = read_local_rows(
            peer,
            rt,
            QueryProjectionResourceKind::AccountAssets,
            id.account(),
            certified,
            deadline,
        )?;
        values.push(balance_in(&rows, id)?);
    }
    values
        .try_into()
        .map_err(|_| eyre!("two exact local balances required"))
}

/// Select one exact account/definition/scope tuple; another scope is never a fallback.
fn balance_in(rows: &QueryProjectionShardRowSet, id: &AssetId) -> Result<Quantity> {
    let QueryProjectionShardRowSet::AccountAssets(rows) = rows else {
        return Err(eyre!("account assets resource required"));
    };
    let scope = match id.scope() {
        AssetBalanceScope::Global => "global".to_owned(),
        AssetBalanceScope::Dataspace(dataspace) => format!("dataspace:{}", dataspace.as_u64()),
    };
    let account = id.account().to_string();
    let asset = id.definition().to_string();
    let mut matches = rows
        .rows
        .iter()
        .filter(|row| row.account_id == account && row.asset == asset && row.scope == scope);
    let value = matches
        .next()
        .ok_or_else(|| eyre!("exact local fee bucket missing"))?;
    ensure!(matches.next().is_none(), "duplicate local fee bucket");
    Ok(value.quantity.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::query::{
        index_status::QueryIndexStatus,
        projection_rowset::{
            QueryProjectionAccountAssetRow, QueryProjectionAccountAssetsShardRowSet,
            QueryProjectionAccountRow, QueryProjectionAccountsShardRowSet,
        },
    };
    use iroha_crypto::Hash;
    use iroha_test_samples::ALICE_ID;

    fn account_archive() -> QueryProjectionShardArchive {
        let account_id = ALICE_ID.to_string();
        let partition = query_projection_default_partition_for_account(&account_id);
        let rows = QueryProjectionShardRowSet::Accounts(QueryProjectionAccountsShardRowSet::new(
            partition,
            vec![QueryProjectionAccountRow {
                account_id,
                primary_alias: None,
                primary_alias_name: None,
                primary_alias_dataspace: None,
                primary_alias_domain: None,
                has_primary_alias: false,
            }],
        ));
        QueryProjectionShardArchive::from_index_status(
            QueryIndexStatus {
                indexed_height: 2,
                indexed_block_hash: Some(HashOf::from_untyped_unchecked(Hash::new(
                    b"local committed block",
                ))),
            },
            1,
            QueryProjectionResourceKind::Accounts,
            partition,
            None,
            rows.row_count(),
            rows.encode_payload().unwrap(),
        )
    }

    fn check(archive: &QueryProjectionShardArchive) -> Result<QueryProjectionShardRowSet> {
        let original = account_archive();
        decode_local_rows(
            &norito::to_bytes(archive)?,
            original.resource,
            original.partition_id,
            original.indexed_height,
            original.indexed_block_hash.unwrap(),
        )
    }

    #[test]
    fn local_projection_accepts_exact_snapshot_and_refuses_substituted_metadata() {
        let original = account_archive();
        assert_eq!(check(&original).unwrap().row_count(), 1);
        for mutate in [
            |a: &mut QueryProjectionShardArchive| a.version += 1,
            |a: &mut QueryProjectionShardArchive| a.schema_version += 1,
            |a: &mut QueryProjectionShardArchive| {
                a.resource = QueryProjectionResourceKind::AccountAssets
            },
            |a: &mut QueryProjectionShardArchive| a.partition_id += 1,
            |a: &mut QueryProjectionShardArchive| {
                a.asset_definition_id = Some("unrequested".into())
            },
            |a: &mut QueryProjectionShardArchive| a.indexed_height += 1,
            |a: &mut QueryProjectionShardArchive| a.indexed_block_hash = None,
            |a: &mut QueryProjectionShardArchive| a.payload_codec.0.clear(),
            |a: &mut QueryProjectionShardArchive| {
                a.payload_hash = BlobDigest::from_hash(blake3::hash(b"substituted"))
            },
            |a: &mut QueryProjectionShardArchive| a.row_count += 1,
        ] {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert!(
                check(&changed).is_err(),
                "accepted substituted diagnostic: {changed:?}"
            );
        }
    }

    #[test]
    fn local_projection_refuses_rehashed_duplicate_wrong_partition_and_version_rows() {
        for case in 0..4 {
            let mut archive = account_archive();
            let QueryProjectionShardRowSet::Accounts(mut rows) =
                norito::decode_from_bytes(&archive.payload).unwrap()
            else {
                unreachable!()
            };
            match case {
                0 => rows.rows.push(rows.rows[0].clone()),
                1 => rows.partition_id += 1,
                2 => rows.version += 1,
                3 => {
                    let original = rows.partition_id;
                    rows.rows[0].account_id.push('x');
                    while query_projection_default_partition_for_account(&rows.rows[0].account_id)
                        == original
                    {
                        rows.rows[0].account_id.push('x');
                    }
                }
                _ => unreachable!(),
            }
            let rows = QueryProjectionShardRowSet::Accounts(rows);
            archive.row_count = rows.row_count();
            archive.payload = rows.encode_payload().unwrap();
            archive.payload_hash = BlobDigest::from_hash(blake3::hash(&archive.payload));
            assert!(
                check(&archive).is_err(),
                "accepted invalid local rows case {case}"
            );
        }
    }

    #[test]
    fn local_projection_refuses_oversized_and_trailing_responses() {
        let archive = account_archive();
        for bytes in [vec![0; MAX_RESPONSE_BYTES + 1], {
            let mut bytes = norito::to_bytes(&archive).unwrap();
            bytes.push(0);
            bytes
        }] {
            assert!(
                decode_local_rows(
                    &bytes,
                    archive.resource,
                    archive.partition_id,
                    archive.indexed_height,
                    archive.indexed_block_hash.unwrap(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn local_fee_observation_requires_exact_account_asset_and_scope() {
        let id = AssetId::new(
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .unwrap(),
            ALICE_ID.clone(),
        );
        let row = QueryProjectionAccountAssetRow {
            account_id: id.account().to_string(),
            asset: id.definition().to_string(),
            asset_name: String::new(),
            asset_alias: None,
            scope: "global".into(),
            quantity: Quantity::from(19_u32),
            primary_alias: None,
            primary_alias_name: None,
            primary_alias_dataspace: None,
            primary_alias_domain: None,
            has_primary_alias: false,
        };
        let rows = |rows| {
            QueryProjectionShardRowSet::AccountAssets(QueryProjectionAccountAssetsShardRowSet::new(
                query_projection_default_partition_for_account(&id.account().to_string()),
                rows,
            ))
        };
        assert_eq!(
            balance_in(&rows(vec![row.clone()]), &id).unwrap(),
            row.quantity
        );
        for changed in [
            QueryProjectionAccountAssetRow {
                account_id: "other".into(),
                ..row.clone()
            },
            QueryProjectionAccountAssetRow {
                asset: "other".into(),
                ..row.clone()
            },
            QueryProjectionAccountAssetRow {
                scope: "dataspace:0".into(),
                ..row.clone()
            },
        ] {
            assert!(balance_in(&rows(vec![changed]), &id).is_err());
        }
        assert!(balance_in(&rows(vec![row.clone(), row]), &id).is_err());
        assert!(balance_in(&rows(Vec::new()), &id).is_err());
    }
}
