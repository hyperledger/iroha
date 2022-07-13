/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_specific_query_executor.hpp"

#include <fmt/core.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <rocksdb/utilities/transaction.h>
#include "ametsuchi/block_storage.hpp"
#include "ametsuchi/impl/executor_common.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "backend/plain/account_detail_record_id.hpp"
#include "backend/plain/engine_receipt.hpp"
#include "backend/plain/peer.hpp"
#include "common/bind.hpp"
#include "common/common.hpp"
#include "common/to_lower.hpp"
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
#include "interfaces/transaction.hpp"
#include "pending_txs_storage/pending_txs_storage.hpp"

using namespace iroha;
using namespace iroha::ametsuchi;

namespace {
  struct PaginationBounds {
    using HeightType = shared_model::interface::types::HeightType;
    using TimestampType = shared_model::interface::types::TimestampType;

    HeightType heightFrom;
    HeightType heightTo;

    TimestampType tsFrom;
    TimestampType tsTo;
  };
}  // namespace

using ErrorQueryType =
    shared_model::interface::QueryResponseFactory::ErrorQueryType;

using shared_model::interface::permissions::Role;

using shared_model::interface::RolePermissionSet;

RocksDbSpecificQueryExecutor::RocksDbSpecificQueryExecutor(
    std::shared_ptr<RocksDBContext> db_context,
    BlockStorage &block_store,
    std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
    std::shared_ptr<shared_model::interface::QueryResponseFactory>
        response_factory,
    std::shared_ptr<shared_model::interface::PermissionToString> perm_converter)
    : db_context_(std::move(db_context)),
      block_store_(block_store),
      pending_txs_storage_(std::move(pending_txs_storage)),
      query_response_factory_{std::move(response_factory)},
      perm_converter_(std::move(perm_converter)) {
  assert(db_context_);
}

std::shared_ptr<RocksDBContext> RocksDbSpecificQueryExecutor::getTxContext() {
  return db_context_;
}

QueryExecutorResult RocksDbSpecificQueryExecutor::execute(
    const shared_model::interface::Query &qry) {
  return boost::apply_visitor(
      [this, &qry](const auto &query) {
        auto &query_hash = qry.hash();
        try {
          RocksDbCommon common(db_context_);
          auto const &[account_name, domain_id] =
              staticSplitId<2ull>(qry.creatorAccountId());

          // get account permissions
          if (auto perm_result =
                  accountPermissions(common, account_name, domain_id);
              expected::hasError(perm_result))
            return query_response_factory_->createErrorQueryResponse(
                ErrorQueryType::kStatefulFailed,
                fmt::format("Query: {}, message: {}",
                            query.toString(),
                            perm_result.assumeError().description),
                perm_result.assumeError().code,
                query_hash);
          else if (auto result = (*this)(common,
                                         query,
                                         qry.creatorAccountId(),
                                         query_hash,
                                         perm_result.assumeValue());
                   expected::hasError(result))
            return query_response_factory_->createErrorQueryResponse(
                ErrorQueryType::kStatefulFailed,
                fmt::format("Query: {}, message: {}",
                            query.toString(),
                            result.assumeError().description),
                result.assumeError().code,
                query_hash);
          else
            return std::move(result.assumeValue());
        } catch (std::exception &e) {
          return query_response_factory_->createErrorQueryResponse(
              ErrorQueryType::kStatefulFailed,
              fmt::format("Query: {}, message: {}", query.toString(), e.what()),
              1001,
              query_hash);
        }
      },
      qry.get());
}

bool RocksDbSpecificQueryExecutor::hasAccountRolePermission(
    shared_model::interface::permissions::Role permission,
    const std::string &account_id) const {
  RocksDbCommon common(db_context_);

  auto const &[account_name, domain_id] = staticSplitId<2ull>(account_id);
  if (auto account_permissions =
          accountPermissions(common, account_name, domain_id);
      expected::hasValue(account_permissions))
    return account_permissions.assumeValue().isSet(permission);

  return false;
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetAccount &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto const &[creator_account_name, creator_domain_id] =
      staticSplitId<2ull>(creator_id);
  auto const &[account_name, domain_id] =
      staticSplitId<2ull>(query.accountId());

  RDB_ERROR_CHECK(checkPermissions(domain_id,
                                   creator_domain_id,
                                   query.accountId(),
                                   creator_id,
                                   creator_permissions,
                                   Role::kGetAllAccounts,
                                   Role::kGetDomainAccounts,
                                   Role::kGetMyAccount));

  uint64_t quorum;
  if (auto result = forQuorum<kDbOperation::kGet, kDbEntry::kMustExist>(
          common, account_name, domain_id);
      expected::hasError(result))
    return query_response_factory_->createErrorQueryResponse(
        ErrorQueryType::kNoAccount,
        fmt::format("Query: {}, message: {}",
                    query.toString(),
                    result.assumeError().description),
        result.assumeError().code,
        query_hash);
  else
    quorum = *result.assumeValue();

  uint64_t total;
  RDB_TRY_GET_VALUE(
      details, aggregateAccountDetails(common, account_name, domain_id, total));

  std::vector<std::string> roles;
  auto status =
      ametsuchi::enumerateKeys(common,
                               [&](auto role) {
                                 roles.emplace_back(role.ToStringView());
                                 return true;
                               },
                               RocksDBPort::ColumnFamilyType::kWsv,
                               fmtstrings::kPathAccountRoles,
                               domain_id,
                               account_name);
  RDB_ERROR_CHECK(canExist(status, [&]() {
    return fmt::format("Enumerate roles for account {}", query.accountId());
  }));

  return query_response_factory_->createAccountResponse(
      query.accountId(),
      shared_model::interface::types::DomainIdType(domain_id),
      quorum,
      details,
      roles,
      query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetBlock &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RDB_ERROR_CHECK(checkPermissions(creator_permissions, {Role::kGetBlocks}));

  auto const ledger_height = block_store_.size();
  if (query.height() > ledger_height)
    return makeError<QueryExecutorResult>(
        ErrorCodes::kQueryHeightOverflow,
        "requested height ({}) is greater than the ledger's one ({})",
        std::to_string(query.height()),
        std::to_string(ledger_height));

  auto block_deserialization_msg = [height = query.height()] {
    return "could not retrieve block with given height: "
        + std::to_string(height);
  };
  auto block = block_store_.fetch(query.height());
  if (!block)
    return makeError<QueryExecutorResult>(ErrorCodes::kFetchBlockFailed,
                                          "Block deserialization error: {}",
                                          block_deserialization_msg());

  return query_response_factory_->createBlockResponse(std::move(*block),
                                                      query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetSignatories &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto const &[creator_account_name, creator_domain_id] =
      staticSplitId<2ull>(creator_id);
  auto const &[account_name, domain_id] =
      staticSplitId<2ull>(query.accountId());

  RDB_ERROR_CHECK(checkPermissions(domain_id,
                                   creator_domain_id,
                                   query.accountId(),
                                   creator_id,
                                   creator_permissions,
                                   Role::kGetAllSignatories,
                                   Role::kGetDomainSignatories,
                                   Role::kGetMySignatories));

  std::vector<std::string> signatories;
  auto const status =
      enumerateKeys(common,
                    [&](auto const &signatory) {
                      signatories.emplace_back(signatory.ToStringView());
                      return true;
                    },
                    RocksDBPort::ColumnFamilyType::kWsv,
                    fmtstrings::kPathSignatories,
                    domain_id,
                    account_name);
  RDB_ERROR_CHECK(canExist(status, [&]() {
    return fmt::format("Enumerate signatories for account {}",
                       query.accountId());
  }));

  if (signatories.empty())
    return query_response_factory_->createErrorQueryResponse(
        ErrorQueryType::kNoSignatories,
        fmt::format("{}, status: not found", query.toString()),
        0,
        query_hash);

  return query_response_factory_->createSignatoriesResponse(signatories,
                                                            query_hash);
}

struct TxPosition {
  uint64_t ts;
  uint64_t height;
  uint64_t index;
};

inline void decodePosition(std::string_view ts,
                           std::string_view height,
                           std::string_view index,
                           TxPosition &out) {
  std::from_chars(ts.data(), ts.data() + ts.size(), out.ts);
  std::from_chars(height.data(), height.data() + height.size(), out.height);
  std::from_chars(index.data(), index.data() + index.size(), out.index);
}

template <typename Pred, typename OutputIterator>
iroha::expected::Result<void, std::string>
RocksDbSpecificQueryExecutor::getTransactionsFromBlock(uint64_t block_id,
                                                       uint64_t tx_index,
                                                       Pred &&pred,
                                                       OutputIterator dest_it) {
  auto opt_block = block_store_.fetch(block_id);
  if (not opt_block) {
    return iroha::expected::makeError(
        fmt::format("Failed to retrieve block with id {}", block_id));
  }
  auto &block = opt_block.value();

  const auto block_size = block->transactions().size();
  auto const tx_id = tx_index;
  if (tx_id >= block_size)
    return iroha::expected::makeError(
        fmt::format("Failed to retrieve transaction with id {} "
                    "from block height {}.",
                    tx_id,
                    block_id));

  auto &tx = block->transactions()[tx_id];
  if (pred(tx)) {
    *dest_it++ = tx.moveTo();
  }

  return {};
}

template <bool readTxsWithAssets, typename Qry>
RocksDbSpecificQueryExecutor::ExecutionResult
RocksDbSpecificQueryExecutor::readTxs(
    RocksDbCommon &common,
    std::shared_ptr<shared_model::interface::QueryResponseFactory>
        &query_response_factory,
    const Qry &query,
    const shared_model::interface::types::HashType &query_hash) {
  auto &ordering = query.paginationMeta().ordering();
  shared_model::interface::Ordering::OrderingEntry const *ordering_ptr =
      nullptr;
  size_t count = 0ull;
  ordering.get(ordering_ptr, count);
  assert(count > 0ull);

  RDB_TRY_GET_VALUE(opt_txs_total,
                    forTxsTotalCount<kDbOperation::kGet, kDbEntry::kCanExist>(
                        common, query.accountId()));

  std::vector<std::unique_ptr<shared_model::interface::Transaction>>
      response_txs;
  uint64_t remains = query.paginationMeta().pageSize() + 1ull;
  std::optional<shared_model::crypto::Hash> next_page;

  static_assert(
      std::is_same_v<
          typename decltype(query.paginationMeta().firstTxTime())::value_type,
          typename decltype(query.paginationMeta().lastTxTime())::value_type>,
      "Type of firstTxTime and lastTxTime must be the same!");
  static_assert(
      std::is_same_v<decltype(PaginationBounds::tsFrom),
                     typename decltype(
                         query.paginationMeta().lastTxTime())::value_type>,
      "Type of firstTxTime and lastTxTime must be the same!");

  static_assert(
      std::is_same_v<
          typename decltype(query.paginationMeta().firstTxHeight())::value_type,
          typename decltype(query.paginationMeta().lastTxHeight())::value_type>,
      "Height types must be the same!");
  static_assert(
      std::is_same_v<decltype(PaginationBounds::heightFrom),
                     typename decltype(
                         query.paginationMeta().lastTxHeight())::value_type>,
      "Height types must be the same!");

  PaginationBounds const bounds{
      query.paginationMeta().firstTxHeight().value_or(
          shared_model::interface::types::HeightType(1ull)),
      query.paginationMeta().lastTxHeight().value_or(
          std::numeric_limits<typename decltype(
              query.paginationMeta().lastTxHeight())::value_type>::max()),
      query.paginationMeta().firstTxTime().value_or(
          std::numeric_limits<typename decltype(
              query.paginationMeta().firstTxTime())::value_type>::min()),
      query.paginationMeta().lastTxTime().value_or(
          std::numeric_limits<typename decltype(
              query.paginationMeta().lastTxTime())::value_type>::max())};

  auto parser = [&](auto p, auto d) {
    auto const &[asset, tx_hash] = staticSplitId<2ull>(d.ToStringView(), "%");
    if (readTxsWithAssets)
      if (asset.empty())
        return true;

    auto const position =
        staticSplitId<5ull>(p.ToStringView(), fmtstrings::kDelimiter);

    TxPosition tx_position = {0ull, 0ull, 0ull};
    if (ordering_ptr->field
        == shared_model::interface::Ordering::Field::kCreatedTime)
      decodePosition(
          position.at(0), position.at(2), position.at(4), tx_position);
    else
      decodePosition(
          position.at(4), position.at(0), position.at(2), tx_position);

    static_assert(
        std::is_unsigned_v<decltype(
                tx_position
                    .height)> && std::is_unsigned_v<decltype(bounds.heightFrom)>,
        "Height must be unsigned");
    if ((tx_position.height - bounds.heightFrom)
        > (bounds.heightTo - bounds.heightFrom))
      return true;

    static_assert(
        std::is_unsigned_v<decltype(
                tx_position.ts)> && std::is_unsigned_v<decltype(bounds.tsFrom)>,
        "TS must be unsigned");
    if ((tx_position.ts - bounds.tsFrom) > (bounds.tsTo - bounds.tsFrom))
      return true;

    // get transactions corresponding to indexes
    if (remains-- > 1ull) {
      auto txs_result =
          getTransactionsFromBlock(tx_position.height,
                                   tx_position.index,
                                   [](auto &) { return true; },
                                   std::back_inserter(response_txs));
      if (auto e = iroha::expected::resultToOptionalError(txs_result))
        return true;

      return true;
    } else {
      next_page = shared_model::crypto::Hash(tx_hash);
      return false;
    }
  };

  rocksdb::Status status = rocksdb::Status::OK();
  if (query.paginationMeta().firstTxHash()) {
    if (auto result =
            forTransactionStatus<kDbOperation::kGet, kDbEntry::kMustExist>(
                common, *query.paginationMeta().firstTxHash());
        expected::hasValue(result)) {
      assert(ordering_ptr->field
                 == shared_model::interface::Ordering::Field::kCreatedTime
             || ordering_ptr->field
                 == shared_model::interface::Ordering::Field::kPosition);

      auto const &[tx_status, tx_height, tx_index, tx_ts] =
          staticSplitId<4ull>(*result.template assumeValue(), "#");

      if (ordering_ptr->field
          == shared_model::interface::Ordering::Field::kCreatedTime) {
        auto it = common.template seek(RocksDBPort::ColumnFamilyType::kWsv,
                                       fmtstrings::kTransactionByTs,
                                       query.accountId(),
                                       tx_ts,
                                       tx_height,
                                       tx_index);
        status = enumerateKeysAndValues(common,
                                        parser,
                                        it,
                                        fmtstrings::kPathTransactionByTs,
                                        query.accountId());
      } else {
        auto it = common.template seek(RocksDBPort::ColumnFamilyType::kWsv,
                                       fmtstrings::kTransactionByPosition,
                                       query.accountId(),
                                       tx_height,
                                       tx_index,
                                       tx_ts);
        status = enumerateKeysAndValues(common,
                                        parser,
                                        it,
                                        fmtstrings::kPathTransactionByPosition,
                                        query.accountId());
      }
    }
  } else {
    if (ordering_ptr->field
        == shared_model::interface::Ordering::Field::kCreatedTime) {
      auto it = common.template seek(RocksDBPort::ColumnFamilyType::kWsv,
                                     fmtstrings::kTransactionByTsLowerBound,
                                     query.accountId(),
                                     bounds.tsFrom);
      status = enumerateKeysAndValues(common,
                                      parser,
                                      it,
                                      fmtstrings::kPathTransactionByTs,
                                      query.accountId());
    } else {
      auto it = common.template seek(RocksDBPort::ColumnFamilyType::kWsv,
                                     fmtstrings::kTransactionByHeight,
                                     query.accountId(),
                                     bounds.heightFrom);
      status = enumerateKeysAndValues(common,
                                      parser,
                                      it,
                                      fmtstrings::kPathTransactionByPosition,
                                      query.accountId());
    }
  }

  RDB_ERROR_CHECK(canExist(status, [&]() {
    return fmt::format("Enumerate transactions for account {}",
                       query.accountId());
  }));

  return query_response_factory->createTransactionsPageResponse(
      std::move(response_txs),
      next_page,
      opt_txs_total ? *opt_txs_total : 0ull,
      query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetAccountTransactions &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto const &[creator_account_name, creator_domain_id] =
      staticSplitId<2ull>(creator_id);
  auto const &[account_name, domain_id] =
      staticSplitId<2ull>(query.accountId());

  RDB_ERROR_CHECK(checkPermissions(domain_id,
                                   creator_domain_id,
                                   query.accountId(),
                                   creator_id,
                                   creator_permissions,
                                   Role::kGetAllAccTxs,
                                   Role::kGetDomainAccTxs,
                                   Role::kGetMyAccTxs));

  return readTxs<false>(common, query_response_factory_, query, query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetTransactions &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto const &[creator_account_name, creator_domain_id] =
      staticSplitId<2ull>(creator_id);
  RDB_ERROR_CHECK(checkPermissions(creator_domain_id,
                                   creator_domain_id,
                                   creator_permissions,
                                   Role::kGetAllTxs,
                                   Role::kGetMyTxs));

  std::string h_hex;
  std::vector<std::unique_ptr<shared_model::interface::Transaction>>
      response_txs;

  bool const canRequestAll = creator_permissions.isSet(Role::kGetAllTxs);
  for (auto const &hash : query.transactionHashes()) {
    h_hex.clear();
    toLowerAppend(hash.hex(), h_hex);

    std::optional<std::string_view> opt;
    if (auto r = forTransactionStatus<kDbOperation::kGet, kDbEntry::kMustExist>(
            common, hash);
        expected::hasError(r))
      return query_response_factory_->createErrorQueryResponse(
          ErrorQueryType::kStatefulFailed,
          fmt::format("Query: {}, message: {}",
                      query.toString(),
                      r.assumeError().description),
          ErrorCodes::kNoTransaction,
          query_hash);
    else
      opt = std::move(r.assumeValue());

    auto const &[tx_status, tx_height, tx_index, tx_ts] =
        staticSplitId<4ull>(*opt, "#");

    TxPosition tx_position = {0ull, 0ull, 0ull};
    decodePosition(tx_ts, tx_height, tx_index, tx_position);

    if (auto r =
            forTransactionByPosition<kDbOperation::kGet, kDbEntry::kMustExist>(
                common,
                creator_id,
                tx_position.ts,
                tx_position.height,
                tx_position.index);
        !canRequestAll
        && (expected::hasError(r)
            || staticSplitId<2ull>(*r.assumeValue(), "%").at(1) != h_hex))
      continue;

    auto txs_result =
        getTransactionsFromBlock(tx_position.height,
                                 tx_position.index,
                                 [](auto &) { return true; },
                                 std::back_inserter(response_txs));
    if (auto e = iroha::expected::resultToOptionalError(txs_result))
      return makeError<QueryExecutorResult>(
          ErrorCodes::kRetrieveTransactionsFailed,
          "Retrieve txs failed: {}",
          e.value());
  }

  return query_response_factory_->createTransactionsResponse(
      std::move(response_txs), query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetAccountAssetTransactions &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto const &[creator_account_name, creator_domain_id] =
      staticSplitId<2ull>(creator_id);
  auto const &[account_name, domain_id] =
      staticSplitId<2ull>(query.accountId());

  RDB_ERROR_CHECK(checkPermissions(domain_id,
                                   creator_domain_id,
                                   query.accountId(),
                                   creator_id,
                                   creator_permissions,
                                   Role::kGetAllAccAstTxs,
                                   Role::kGetDomainAccAstTxs,
                                   Role::kGetMyAccAstTxs));

  return readTxs<true>(common, query_response_factory_, query, query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetAccountAssets &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto const &[creator_account_name, creator_domain_id] =
      staticSplitId<2ull>(creator_id);
  auto const &[account_name, domain_id] =
      staticSplitId<2ull>(query.accountId());

  RDB_ERROR_CHECK(checkPermissions(domain_id,
                                   creator_domain_id,
                                   query.accountId(),
                                   creator_id,
                                   creator_permissions,
                                   Role::kGetAllAccAst,
                                   Role::kGetDomainAccAst,
                                   Role::kGetMyAccAst));

  RDB_TRY_GET_VALUE(
      opt_acc_asset_size,
      forAccountAssetSize<kDbOperation::kGet, kDbEntry::kCanExist>(
          common, account_name, domain_id));

  uint64_t account_asset_size = opt_acc_asset_size ? *opt_acc_asset_size : 0ull;

  const auto pagination_meta{query.paginationMeta()};
  const auto req_first_asset_id =
      pagination_meta | [](auto const &pagination_meta) {
        return pagination_meta.get().firstAssetId();
      };
  const auto req_page_size = pagination_meta | [](const auto &pagination_meta) {
    return std::optional<size_t>(pagination_meta.get().pageSize());
  };

  std::vector<std::tuple<shared_model::interface::types::AccountIdType,
                         shared_model::interface::types::AssetIdType,
                         shared_model::interface::Amount>>
      assets;
  std::optional<shared_model::interface::types::AssetIdType> next_asset_id;

  bool first_found = !req_first_asset_id;
  uint64_t remains = req_page_size ? *req_page_size + 1ull
                                   : std::numeric_limits<uint64_t>::max();
  auto status = enumerateKeysAndValues(
      common,
      [&](auto asset, auto value) {
        if (!first_found) {
          if (asset.ToStringView() != *req_first_asset_id)
            return true;
          first_found = true;
        }

        if (remains-- > 1ull) {
          assets.emplace_back(
              query.accountId(),
              asset.ToStringView(),
              shared_model::interface::Amount(value.ToStringView()));
          return true;
        } else {
          next_asset_id = asset.ToStringView();
          return false;
        }
      },
      RocksDBPort::ColumnFamilyType::kWsv,
      fmtstrings::kPathAccountAssets,
      domain_id,
      account_name);
  RDB_ERROR_CHECK(canExist(status, [&] {
    return fmt::format("Account {} assets", query.accountId());
  }));

  if (assets.empty() and req_first_asset_id)
    return makeError<QueryExecutorResult>(
        ErrorCodes::kAssetNotFound, "Asset {} not found", *req_first_asset_id);

  return query_response_factory_->createAccountAssetResponse(
      assets, account_asset_size, next_asset_id, query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetAccountDetail &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto const &[creator_account_name, creator_domain_id] =
      staticSplitId<2ull>(creator_id);
  auto const &[account_name, domain_id] =
      staticSplitId<2ull>(query.accountId());

  if (auto r = forAccount<kDbOperation::kCheck, kDbEntry::kMustExist>(
          common, account_name, domain_id);
      expected::hasError(r))
    return query_response_factory_->createErrorQueryResponse(
        ErrorQueryType::kNoAccountDetail,
        fmt::format("Query: {}, message: {}",
                    query.toString(),
                    r.assumeError().description),
        r.assumeError().code,
        query_hash);

  RDB_ERROR_CHECK(checkPermissions(domain_id,
                                   creator_domain_id,
                                   query.accountId(),
                                   creator_id,
                                   creator_permissions,
                                   Role::kGetAllAccDetail,
                                   Role::kGetDomainAccDetail,
                                   Role::kGetMyAccDetail));

  auto writer = query.writer();
  auto key = query.key();
  auto pagination = query.paginationMeta();

  std::optional<PaginationContext> p;
  if (pagination) {
    std::optional<PaginationContext::FirstEntry> fe;
    if (pagination->get().firstRecordId())
      fe = PaginationContext::FirstEntry{
          pagination->get().firstRecordId()->get().writer(),
          pagination->get().firstRecordId()->get().key()};

    p = PaginationContext{std::move(fe), pagination->get().pageSize()};
  }

  std::string next_writer, next_key;
  uint64_t total;
  RDB_TRY_GET_VALUE(json,
                    aggregateAccountDetails(
                        common,
                        account_name,
                        domain_id,
                        total,
                        writer ? std::string_view{*writer} : std::string_view{},
                        key ? std::string_view{*key} : std::string_view{},
                        std::move(p),
                        &next_writer,
                        &next_key));

  std::optional<shared_model::plain::AccountDetailRecordId> next;
  if (!next_writer.empty() || !next_key.empty())
    next = shared_model::plain::AccountDetailRecordId(std::move(next_writer),
                                                      std::move(next_key));

  RDB_TRY_GET_VALUE(
      opt_acc_details_count,
      forAccountDetailsCount<kDbOperation::kGet, kDbEntry::kCanExist>(
          common, account_name, domain_id));
  return query_response_factory_->createAccountDetailResponse(
      json, total, next, query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetRoles &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RDB_ERROR_CHECK(checkPermissions(creator_permissions, {Role::kGetRoles}));

  std::vector<std::string> roles;
  auto status = enumerateKeys(common,
                              [&](auto const &role) {
                                if (!role.empty())
                                  roles.emplace_back(role.ToStringView());
                                else {
                                  assert(!"Role can not be empty string!");
                                }
                                return true;
                              },
                              RocksDBPort::ColumnFamilyType::kWsv,
                              fmtstrings::kPathRoles);
  RDB_ERROR_CHECK(canExist(status, [&] { return "Enumerate roles"; }));

  return query_response_factory_->createRolesResponse(std::move(roles),
                                                      query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetRolePermissions &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RDB_ERROR_CHECK(checkPermissions(creator_permissions, {Role::kGetRoles}));
  auto &role_id = query.roleId();

  RDB_TRY_GET_VALUE(
      opt_permissions,
      forRole<kDbOperation::kGet, kDbEntry::kMustExist>(common, role_id));

  return query_response_factory_->createRolePermissionsResponse(
      *opt_permissions, query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetAssetInfo &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RDB_ERROR_CHECK(checkPermissions(creator_permissions, {Role::kReadAssets}));
  auto const &[asset_name, domain_id] = staticSplitId<2ull>(query.assetId());

  if (auto result = forAsset<kDbOperation::kGet, kDbEntry::kMustExist>(
          common, asset_name, domain_id);
      expected::hasError(result))
    return query_response_factory_->createErrorQueryResponse(
        ErrorQueryType::kNoAsset,
        fmt::format("Query: {}, message: {}",
                    query.toString(),
                    result.assumeError().description),
        result.assumeError().code,
        query_hash);
  else
    return query_response_factory_->createAssetResponse(
        query.assetId(),
        std::string{domain_id},
        static_cast<shared_model::interface::types::PrecisionType>(
            *result.assumeValue()),
        query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetPendingTransactions &q,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  std::vector<std::unique_ptr<shared_model::interface::Transaction>>
      response_txs;
  if (q.paginationMeta()) {
    return pending_txs_storage_
        ->getPendingTransactions(creator_id,
                                 q.paginationMeta()->get().pageSize(),
                                 q.paginationMeta()->get().firstTxHash(),
                                 q.paginationMeta()->get().firstTxTime(),
                                 q.paginationMeta()->get().lastTxTime())
        .match(
            [this, &response_txs, &query_hash](auto &&response) {
              auto &interface_txs = response.value.transactions;
              response_txs.reserve(interface_txs.size());
              // TODO igor-egorov 2019-06-06 IR-555 avoid use of clone()
              std::transform(interface_txs.begin(),
                             interface_txs.end(),
                             std::back_inserter(response_txs),
                             [](auto &tx) { return clone(*tx); });
              return query_response_factory_
                  ->createPendingTransactionsPageResponse(
                      std::move(response_txs),
                      response.value.all_transactions_size,
                      std::move(response.value.next_batch_info),
                      query_hash);
            },
            [this, &q, &query_hash](auto &&error) {
              switch (error.error) {
                case iroha::PendingTransactionStorage::ErrorCode::kNotFound:
                  return query_response_factory_->createErrorQueryResponse(
                      shared_model::interface::QueryResponseFactory::
                          ErrorQueryType::kStatefulFailed,
                      std::string("The batch with specified first "
                                  "transaction hash not found, the hash: ")
                          + q.paginationMeta()->get().firstTxHash()->toString(),
                      4,  // missing first tx hash error
                      query_hash);
                default:
                  BOOST_ASSERT_MSG(false,
                                   "Unknown and unhandled type of error "
                                   "happend in pending txs storage");
                  return query_response_factory_->createErrorQueryResponse(
                      shared_model::interface::QueryResponseFactory::
                          ErrorQueryType::kStatefulFailed,
                      std::string("Unknown type of error happened: ")
                          + std::to_string(error.error),
                      1,  // unknown internal error
                      query_hash);
              }
            });
  } else {  // TODO 2019-06-06 igor-egorov IR-516 remove deprecated
    // interface
    auto interface_txs =
        pending_txs_storage_->getPendingTransactions(creator_id);
    response_txs.reserve(interface_txs.size());

    std::transform(interface_txs.begin(),
                   interface_txs.end(),
                   std::back_inserter(response_txs),
                   [](auto &tx) { return clone(*tx); });
    return query_response_factory_->createTransactionsResponse(
        std::move(response_txs), query_hash);
  }
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetPeers &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RDB_ERROR_CHECK(checkPermissions(creator_permissions, {Role::kGetPeers}));
  std::vector<std::shared_ptr<shared_model::plain::Peer>> peers;

  auto enum_peers = [&](auto const &path, bool syncing_peer) {
    return enumerateKeysAndValues(
        common,
        [&](auto pubkey, auto address) {
          peers.emplace_back(std::make_shared<shared_model::plain::Peer>(
              address.ToStringView(),
              std::string{pubkey.ToStringView()},
              std::nullopt,
              syncing_peer));
          return true;
        },
        RocksDBPort::ColumnFamilyType::kWsv,
        path);
  };

  auto status = enum_peers(fmtstrings::kPathPeers, false);
  RDB_ERROR_CHECK(
      canExist(status, [&]() { return fmt::format("Enumerate peers"); }));

  status = enum_peers(fmtstrings::kPathSPeers, true);
  RDB_ERROR_CHECK(
      canExist(status, [&]() { return fmt::format("Enumerate peers"); }));

  for (auto &peer : peers) {
    RDB_TRY_GET_VALUE(opt_tls,
                      forPeerTLS<kDbOperation::kGet, kDbEntry::kCanExist>(
                          common, peer->pubkey(), peer->isSyncingPeer()));

    if (opt_tls)
      utils::reinterpret_pointer_cast<shared_model::plain::Peer>(peer)
          ->setTlsCertificate(
              shared_model::interface::types::TLSCertificateType{*opt_tls});
  }

  return query_response_factory_->createPeersResponse(
      std::vector<std::shared_ptr<shared_model::interface::Peer>>(peers.begin(),
                                                                  peers.end()),
      query_hash);
}

RocksDbSpecificQueryExecutor::ExecutionResult RocksDbSpecificQueryExecutor::
operator()(
    RocksDbCommon &common,
    const shared_model::interface::GetEngineReceipts &query,
    const shared_model::interface::types::AccountIdType &creator_id,
    const shared_model::interface::types::HashType &query_hash,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto const &[_, creator_domain_id] = staticSplitId<2ull>(creator_id);

  RDB_ERROR_CHECK(checkPermissions(creator_domain_id,
                                   creator_domain_id,
                                   creator_id,
                                   creator_id,
                                   creator_permissions,
                                   Role::kGetAllEngineReceipts,
                                   Role::kGetDomainEngineReceipts,
                                   Role::kGetMyEngineReceipts));

  std::vector<std::unique_ptr<shared_model::interface::EngineReceipt>> records;

  std::optional<std::string> error;
  auto status = enumerateKeysAndValues(
      common,
      [&](auto, auto cid) {
        uint64_t call_id;
        std::from_chars(cid.data(), cid.data() + cid.size(), call_id);

        std::optional<shared_model::interface::types::EvmDataHexString> callee;
        std::optional<shared_model::interface::types::EvmDataHexString>
            cantract_address;
        std::optional<shared_model::interface::types::EvmDataHexString>
            engine_response;

        if (auto result =
                forCallEngineCallResponse<kDbOperation::kGet,
                                          kDbEntry::kCanExist>(common, call_id);
            expected::hasError(result)) {
          error = fmt::format("CallEngineResponse code: {}, failed: {}",
                              result.template assumeError().code,
                              result.template assumeError().description);
          return false;
        } else if (result.assumeValue()) {
          auto const &[callee_, response_] =
              staticSplitId<2ull>(*result.assumeValue(), "|");
          callee = callee_;
          engine_response = response_;
        }

        if (auto result =
                forCallEngineDeploy<kDbOperation::kGet, kDbEntry::kCanExist>(
                    common, call_id);
            expected::hasError(result)) {
          error = fmt::format("CallEngineDeploy code: {}, failed: {}",
                              result.template assumeError().code,
                              result.template assumeError().description);
          return false;
        } else if (result.assumeValue()) {
          cantract_address = *result.assumeValue();
        }

        auto record = std::make_unique<shared_model::plain::EngineReceipt>(
            0ull,  //*cmd_index
            "",    // caller
            callee,
            cantract_address,
            engine_response);

        auto logs_status = enumerateKeysAndValues(
            common,
            [&](auto, auto l) {
              auto const &[log_ix_str, address, data] =
                  staticSplitId<3ull>(l.ToStringView(), "#");
              uint64_t log_id = std::stoull(
                  std::string(log_ix_str.data(), log_ix_str.size()));

              auto log = std::make_unique<shared_model::plain::EngineLog>(
                  shared_model::interface::types::EvmAddressHexString(
                      address.data(), address.size()),
                  shared_model::interface::types::EvmDataHexString(
                      data.data(), data.size()));

              auto topics_status = enumerateKeysAndValues(
                  common,
                  [&](auto, auto t) {
                    auto tstr = t.ToStringView();
                    log->addTopic(
                        shared_model::interface::types::EvmTopicsHexString(
                            tstr.data(), tstr.size()));
                    return true;
                  },
                  RocksDBPort::ColumnFamilyType::kWsv,
                  fmtstrings::kPathEngineTopics,
                  log_id);
              if (!topics_status.ok()) {
                error = fmt::format("enumerate CallEngineTopics failed.");
                return false;
              }

              record->getMutableLogs().emplace_back(std::move(log));
              return true;
            },
            RocksDBPort::ColumnFamilyType::kWsv,
            fmtstrings::kPathEngineLogs,
            call_id);
        if (!logs_status.ok()) {
          error = fmt::format("enumerate CallEngineLogs failed.");
          return false;
        }

        records.emplace_back(std::move(record));
        return true;
      },
      RocksDBPort::ColumnFamilyType::kWsv,
      fmtstrings::kPathEngineCallIds,
      query.txHash());
  RDB_ERROR_CHECK(canExist(status, [&] {
    return fmt::format("PathEngineCallsIds enumeration failed: {}",
                       query.txHash());
  }));

  if (error)
    return makeError<QueryExecutorResult>(
        ErrorCodes::kGetReceipts, "GetEngineReceipts failed: {}", *error);

  return query_response_factory_->createEngineReceiptsResponse(records,
                                                               query_hash);
}
