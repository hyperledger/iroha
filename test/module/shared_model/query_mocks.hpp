/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_MOCKS_HPP
#define IROHA_QUERY_MOCKS_HPP

#include <gmock/gmock.h>

#include "interfaces/queries/asset_pagination_meta.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "interfaces/queries/get_account.hpp"
#include "interfaces/queries/get_account_asset_transactions.hpp"
#include "interfaces/queries/get_account_assets.hpp"
#include "interfaces/queries/get_account_detail.hpp"
#include "interfaces/queries/get_account_transactions.hpp"
#include "interfaces/queries/get_asset_info.hpp"
#include "interfaces/queries/get_block.hpp"
#include "interfaces/queries/get_engine_receipts.hpp"
#include "interfaces/queries/get_peers.hpp"
#include "interfaces/queries/get_role_permissions.hpp"
#include "interfaces/queries/get_roles.hpp"
#include "interfaces/queries/get_signatories.hpp"
#include "interfaces/queries/get_transactions.hpp"
#include "interfaces/queries/query.hpp"
#include "interfaces/queries/query_payload_meta.hpp"
#include "interfaces/queries/query_variant.hpp"
#include "interfaces/queries/tx_pagination_meta.hpp"

namespace shared_model {
  namespace interface {
    struct MockQuery : public Query {
      MOCK_CONST_METHOD0(get, const Query::QueryVariantType &());
      MOCK_CONST_METHOD0(creatorAccountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(queryCounter, types::CounterType());
      MOCK_CONST_METHOD0(signatures, types::SignatureRangeType());
      MOCK_METHOD2(addSignature,
                   bool(types::SignedHexStringView,
                        types::PublicKeyHexStringView));
      MOCK_CONST_METHOD0(createdTime, types::TimestampType());
      MOCK_CONST_METHOD0(payload, const types::BlobType &());
      MOCK_CONST_METHOD0(blob, const types::BlobType &());
      MOCK_CONST_METHOD0(hash, const types::HashType &());
      MOCK_CONST_METHOD0(clone, Query *());
    };

    struct SpecificMockQueryBase {};

    template <typename T>
    struct SpecificMockQuery : public T, public SpecificMockQueryBase {
      using SpecificQuery = T;
    };

    struct MockAssetPaginationMeta
        : public SpecificMockQuery<AssetPaginationMeta> {
      MOCK_CONST_METHOD0(pageSize, types::TransactionsNumberType());
      MOCK_CONST_METHOD0(firstAssetId, std::optional<types::AssetIdType>());
      MOCK_CONST_METHOD0(clone, AssetPaginationMeta *());
    };

    struct MockGetAccountAssets : public SpecificMockQuery<GetAccountAssets> {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(
          paginationMeta,
          std::optional<
              std::reference_wrapper<const interface::AssetPaginationMeta>>());
      MOCK_CONST_METHOD0(clone, GetAccountAssets *());
    };

    struct MockGetAccountAssetTransactions
        : public SpecificMockQuery<GetAccountAssetTransactions> {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(assetId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(paginationMeta, const TxPaginationMeta &());
      MOCK_CONST_METHOD0(clone, GetAccountAssetTransactions *());
    };

    struct MockAccountDetailPaginationMeta
        : public AccountDetailPaginationMeta {
      MOCK_CONST_METHOD0(pageSize, size_t());
      MOCK_CONST_METHOD0(
          firstRecordId,
          std::optional<std::reference_wrapper<const AccountDetailRecordId>>());
      MOCK_CONST_METHOD0(clone, AccountDetailPaginationMeta *());
    };

    struct MockGetAccountDetail : public GetAccountDetail {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(key, std::optional<types::AccountDetailKeyType>());
      MOCK_CONST_METHOD0(writer, std::optional<types::AccountIdType>());
      MOCK_CONST_METHOD0(clone, GetAccountDetail *());
      MOCK_CONST_METHOD0(
          paginationMeta,
          std::optional<
              std::reference_wrapper<const AccountDetailPaginationMeta>>());
    };

    struct MockGetAccount : public SpecificMockQuery<GetAccount> {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(clone, GetAccount *());
    };

    struct MockGetAccountTransactions
        : public SpecificMockQuery<GetAccountTransactions> {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(paginationMeta, const TxPaginationMeta &());
      MOCK_CONST_METHOD0(clone, GetAccountTransactions *());
    };

    struct MockGetAssetInfo : public SpecificMockQuery<GetAssetInfo> {
      MOCK_CONST_METHOD0(assetId, const types::AssetIdType &());
      MOCK_CONST_METHOD0(clone, GetAssetInfo *());
    };

    struct MockGetBlock : public SpecificMockQuery<GetBlock> {
      MOCK_CONST_METHOD0(height, types::HeightType());
      MOCK_CONST_METHOD0(clone, GetBlock *());
    };

    struct MockGetRolePermissions
        : public SpecificMockQuery<GetRolePermissions> {
      MOCK_CONST_METHOD0(roleId, const types::RoleIdType &());
      MOCK_CONST_METHOD0(clone, GetRolePermissions *());
    };

    struct MockGetSignatories : public SpecificMockQuery<GetSignatories> {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(clone, GetSignatories *());
    };

    struct MockGetTransactions : public SpecificMockQuery<GetTransactions> {
      MOCK_CONST_METHOD0(transactionHashes, const TransactionHashesType &());
      MOCK_CONST_METHOD0(clone, GetTransactions *());
    };

    struct MockGetPeers : public SpecificMockQuery<GetPeers> {
      MOCK_CONST_METHOD0(clone, GetPeers *());
    };

    struct MockTxPaginationMeta : public TxPaginationMeta {
      MOCK_CONST_METHOD0(pageSize, types::TransactionsNumberType());
      MOCK_CONST_METHOD0(firstTxHash, std::optional<types::HashType>());
      MOCK_CONST_METHOD0(firstTxTime, std::optional<types::TimestampType>());
      MOCK_CONST_METHOD0(lastTxTime, std::optional<types::TimestampType>());
      MOCK_CONST_METHOD0(firstTxHeight, std::optional<types::HeightType>());
      MOCK_CONST_METHOD0(lastTxHeight, std::optional<types::HeightType>());
      MOCK_CONST_METHOD0(clone, TxPaginationMeta *());
      MOCK_CONST_METHOD0(ordering, Ordering const &());
    };

    struct MockGetEngineReceipts : public SpecificMockQuery<GetEngineReceipts> {
      MOCK_CONST_METHOD0(txHash, const std::string &());
      MOCK_CONST_METHOD0(clone, GetEngineReceipts *());
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_QUERY_MOCKS_HPP
