/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_specific_query_executor.hpp"

#include <fmt/core.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <rocksdb/utilities/transaction.h>
#include <boost/algorithm/string.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "ametsuchi/impl/executor_common.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "backend/plain/peer.hpp"
#include "common/bind.hpp"
#include "interfaces/common_objects/amount.hpp"
#include "interfaces/queries/asset_pagination_meta.hpp"
#include "interfaces/queries/get_account.hpp"
#include "interfaces/queries/get_account_asset_transactions.hpp"
#include "interfaces/queries/get_account_assets.hpp"
#include "interfaces/queries/get_account_detail.hpp"
#include "interfaces/queries/get_account_transactions.hpp"
#include "interfaces/queries/get_asset_info.hpp"
#include "interfaces/queries/get_block.hpp"
#include "interfaces/queries/get_engine_receipts.hpp"
#include "interfaces/queries/get_peers.hpp"
#include "interfaces/queries/get_pending_transactions.hpp"
#include "interfaces/queries/get_role_permissions.hpp"
#include "interfaces/queries/get_roles.hpp"
#include "interfaces/queries/get_signatories.hpp"
#include "interfaces/queries/get_transactions.hpp"
#include "interfaces/queries/query.hpp"
#include "interfaces/queries/tx_pagination_meta.hpp"

using namespace iroha;
using namespace iroha::ametsuchi;

using ErrorQueryType =
    shared_model::interface::QueryResponseFactory::ErrorQueryType;

using shared_model::interface::permissions::Role;

using shared_model::interface::RolePermissionSet;

#define IROHA_ERROR_IF_CONDITION(condition, type, error_msg, code) \
  if (condition) {                                                 \
    return query_response_factory_->createErrorQueryResponse(      \
        type, error_msg, code, query_hash);                        \
  }
#define IROHA_ERROR_NOT_IMPLEMENTED() \
  IROHA_ERROR_IF_CONDITION(           \
      true, ErrorQueryType::kNotSupported, query.toString(), 0)
#define IROHA_ERROR_IF_NOT_OK()                                           \
  IROHA_ERROR_IF_CONDITION(                                               \
      not status.ok(),                                                    \
      ErrorQueryType::kStatefulFailed,                                    \
      fmt::format("{}, status: {}", query.toString(), status.ToString()), \
      1)
#define IROHA_ERROR_IF_NOT_FOUND(type, code)                              \
  IROHA_ERROR_IF_CONDITION(                                               \
      status.IsNotFound(),                                                \
      type,                                                               \
      fmt::format("{}, status: {}", query.toString(), status.ToString()), \
      code)                                                               \
  IROHA_ERROR_IF_NOT_OK()
#define IROHA_ERROR_IF_NOT_SET(elem)                            \
  IROHA_ERROR_IF_CONDITION(not creator_permissions.isSet(elem), \
                           ErrorQueryType::kStatefulFailed,     \
                           query.toString(),                    \
                           2)
#define IROHA_ERROR_IF_ANY_NOT_SET(all, domain, my)                       \
  IROHA_ERROR_IF_CONDITION(not((creator_permissions.isSet(all))           \
                               or (domain_id == creator_domain_id         \
                                   and creator_permissions.isSet(domain)) \
                               or (query.accountId() == creator_id        \
                                   and creator_permissions.isSet(my))),   \
                           ErrorQueryType::kStatefulFailed,               \
                           query.toString(),                              \
                           2)

RocksDbSpecificQueryExecutor::RocksDbSpecificQueryExecutor(
    std::shared_ptr<RocksDBPort> db_port,
    BlockStorage &block_store,
    std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
    std::shared_ptr<shared_model::interface::QueryResponseFactory>
        response_factory,
    std::shared_ptr<shared_model::interface::PermissionToString> perm_converter)
    : db_port_(std::move(db_port)),
      block_store_(block_store),
      pending_txs_storage_(std::move(pending_txs_storage)),
      query_response_factory_{std::move(response_factory)},
      perm_converter_(std::move(perm_converter)) {
  db_port_->prepareTransaction(*db_context_);
}

QueryExecutorResult RocksDbSpecificQueryExecutor::execute(
    const shared_model::interface::Query &qry) {
  return boost::apply_visitor(
      [this, &qry](const auto &query) {
        auto &query_hash = qry.hash();
        try {
          RocksDbCommon common(db_context_);

          auto names = splitId(qry.creatorAccountId());
          auto &account_name = names.at(0);
          auto &domain_id = names.at(1);

          // get account permissions
          RolePermissionSet const creator_permissions =
              accountPermissions(common, domain_id, account_name);
          ;

          return (*this)(
              query, qry.creatorAccountId(), query_hash, creator_permissions);
        } catch (IrohaDbError &e) {
          return query_response_factory_->createErrorQueryResponse(
              ErrorQueryType::kStatefulFailed,
              fmt::format("Query: {}, message: {}", query.toString(), e.what()),
              e.code(),
              query_hash);
        }
      },
      qry.get());
}

bool RocksDbSpecificQueryExecutor::hasAccountRolePermission(
    shared_model::interface::permissions::Role permission,
    const std::string &account_id) const {
  RocksDbCommon common(db_context_);

  auto names = splitId(account_id);
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);

  RolePermissionSet const account_permissions =
      accountPermissions(common, domain_id, account_name);
  return account_permissions.isSet(permission);
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetAccount &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetBlock &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetSignatories &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetAccountTransactions &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetTransactions &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetAccountAssetTransactions &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetAccountAssets &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetAccountDetail &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetRoles &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetRolePermissions &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetAssetInfo &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetPendingTransactions &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetPeers &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

QueryExecutorResult RocksDbSpecificQueryExecutor::operator()(
    const shared_model::interface::GetEngineReceipts &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}
