/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_SPECIFIC_QUERY_EXECUTOR_HPP
#define IROHA_ROCKSDB_SPECIFIC_QUERY_EXECUTOR_HPP

#include "ametsuchi/specific_query_executor.hpp"

#include <fmt/format.h>
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "common/result.hpp"
#include "interfaces/iroha_internal/query_response_factory.hpp"
#include "interfaces/permissions.hpp"

namespace rocksdb {
  class Transaction;
}

namespace shared_model::interface {
  class GetAccount;
  class GetBlock;
  class GetSignatories;
  class GetAccountTransactions;
  class GetAccountAssetTransactions;
  class GetTransactions;
  class GetAccountAssets;
  class GetAccountDetail;
  class GetRoles;
  class GetRolePermissions;
  class GetAssetInfo;
  class GetPendingTransactions;
  class GetPeers;
  class GetEngineReceipts;
  class PermissionToString;
}  // namespace shared_model::interface

namespace iroha {
  class PendingTransactionStorage;
}  // namespace iroha

namespace iroha::ametsuchi {
  class BlockStorage;

  class RocksDbSpecificQueryExecutor : public SpecificQueryExecutor {
   public:
    RocksDbSpecificQueryExecutor(
        std::shared_ptr<RocksDBPort> db_port,
        BlockStorage &block_store,
        std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter);

    QueryExecutorResult execute(
        const shared_model::interface::Query &qry) override;

    bool hasAccountRolePermission(
        shared_model::interface::permissions::Role permission,
        const std::string &account_id) const override;

    QueryExecutorResult operator()(
        const shared_model::interface::GetAccount &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetBlock &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetSignatories &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetAccountTransactions &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetTransactions &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetAccountAssetTransactions &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetAccountAssets &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetAccountDetail &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetRoles &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetRolePermissions &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetAssetInfo &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetPendingTransactions &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetPeers &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    QueryExecutorResult operator()(
        const shared_model::interface::GetEngineReceipts &query,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        shared_model::interface::RolePermissionSet const &creator_permissions);

   private:
    boost::optional<shared_model::interface::RolePermissionSet>
    getAccountPermissions(std::string_view domain,
                          std::string_view account) const;

   private:
    std::shared_ptr<RocksDBPort> db_port_;
    mutable std::shared_ptr<RocksDBContext> db_context_;
    BlockStorage &block_store_;
    std::shared_ptr<PendingTransactionStorage> pending_txs_storage_;
    std::shared_ptr<shared_model::interface::QueryResponseFactory>
        query_response_factory_;
    std::shared_ptr<shared_model::interface::PermissionToString>
        perm_converter_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_ROCKSDB_SPECIFIC_QUERY_EXECUTOR_HPP
