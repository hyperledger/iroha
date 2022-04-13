/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_specific_query_executor.hpp"

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/transform.hpp>
#include <boost/range/irange.hpp>
#include <tuple>
#include <unordered_map>

#include "ametsuchi/block_storage.hpp"
#include "ametsuchi/impl/executor_common.hpp"
#include "ametsuchi/impl/soci_std_optional.hpp"
#include "ametsuchi/impl/soci_utils.hpp"
#include "backend/plain/account_detail_record_id.hpp"
#include "backend/plain/engine_receipt.hpp"
#include "backend/plain/peer.hpp"
#include "common/bind.hpp"
#include "common/byteutils.hpp"
#include "common/range_tools.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/common_objects/amount.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/permission_to_string.hpp"
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
#include "logger/logger.hpp"
#include "pending_txs_storage/pending_txs_storage.hpp"

using namespace shared_model::interface::permissions;

namespace {

  using namespace iroha;

  std::string getAccountRolePermissionCheckSql(
      shared_model::interface::permissions::Role permission,
      const std::string &account_alias = ":role_account_id") {
    const auto perm_str =
        shared_model::interface::RolePermissionSet({permission}).toBitstring();
    const auto bits = shared_model::interface::RolePermissionSet::size();
    // TODO 14.09.18 andrei: IR-1708 Load SQL from separate files
    return fmt::format(R"(
          SELECT
            (
              COALESCE(bit_or(rp.permission), '0'::bit({0}))
              & ('{1}'::bit({0}) | '{2}'::bit({0}))
            ) != '0'::bit({0})
            AS perm
          FROM role_has_permissions AS rp
          JOIN account_has_roles AS ar on ar.role_id = rp.role_id
          WHERE ar.account_id = {3})",
                       bits,
                       perm_str,
                       iroha::ametsuchi::kRootRolePermStr,
                       account_alias);
  }

  /**
   * Generate an SQL subquery called `has_perms' which checks if creator has
   * corresponding permissions for target account taken from column `t' of table
   * `target' (should be provided separately).
   * It verifies individual, domain, and global permissions, and returns true in
   * `perm' column if any of listed permissions is present, and false otherwise
   */
  auto hasQueryPermissionInternal(
      shared_model::interface::types::AccountIdType const &creator,
      Role indiv_permission_id,
      Role all_permission_id,
      Role domain_permission_id) {
    const auto bits = shared_model::interface::RolePermissionSet::size();
    const auto perm_str =
        shared_model::interface::RolePermissionSet({indiv_permission_id})
            .toBitstring();
    const auto all_perm_str =
        shared_model::interface::RolePermissionSet({all_permission_id})
            .toBitstring();
    const auto domain_perm_str =
        shared_model::interface::RolePermissionSet({domain_permission_id})
            .toBitstring();

    const std::string creator_quoted{fmt::format("'{}'", creator)};

    return fmt::format(
        R"(
        target_domain AS (select split_part(target.t, '@', 2) as td from target),
        has_root_perm AS ({0}),
        has_indiv_perm AS (
          SELECT (COALESCE(bit_or(rp.permission), '0'::bit({1}))
          & '{3}') = '{3}' FROM role_has_permissions AS rp
              JOIN account_has_roles AS ar on ar.role_id = rp.role_id
              WHERE ar.account_id = '{2}'
        ),
        has_all_perm AS (
          SELECT (COALESCE(bit_or(rp.permission), '0'::bit({1}))
          & '{4}') = '{4}' FROM role_has_permissions AS rp
              JOIN account_has_roles AS ar on ar.role_id = rp.role_id
              WHERE ar.account_id = '{2}'
        ),
        has_domain_perm AS (
          SELECT (COALESCE(bit_or(rp.permission), '0'::bit({1}))
          & '{5}') = '{5}' FROM role_has_permissions AS rp
              JOIN account_has_roles AS ar on ar.role_id = rp.role_id
              WHERE ar.account_id = '{2}'
        ),
        has_perms as (
          SELECT (SELECT * from has_root_perm)
              OR ('{2}' = (select t from target) AND (SELECT * FROM has_indiv_perm))
              OR (SELECT * FROM has_all_perm)
              OR ('{6}' = (select td from target_domain) AND (SELECT * FROM has_domain_perm)) AS perm
        )
    )",
        getAccountRolePermissionCheckSql(Role::kRoot, creator_quoted),
        bits,
        creator,
        perm_str,
        all_perm_str,
        domain_perm_str,
        iroha::ametsuchi::getDomainFromName(creator));
  }

  /**
   * Generate an SQL subquery called `has_perms' which checks if creator has
   * corresponding permissions for given target account.
   * It verifies individual, domain, and global permissions, and returns true in
   * `perm' column if any of listed permissions is present, and false otherwise
   */
  auto hasQueryPermissionTarget(
      shared_model::interface::types::AccountIdType const &creator,
      shared_model::interface::types::AccountIdType const &target_account,
      Role indiv_permission_id,
      Role all_permission_id,
      Role domain_permission_id) {
    return fmt::format("target AS (select '{}'::text as t), {}",
                       target_account,
                       hasQueryPermissionInternal(creator,
                                                  indiv_permission_id,
                                                  all_permission_id,
                                                  domain_permission_id));
  }

  /// Query result is a tuple of optionals, since there could be no entry
  template <typename... Value>
  using QueryType = boost::tuple<std::optional<Value>...>;

  /**
   * Create an error response in case user does not have permissions to perform
   * a query
   * @tparam Roles - type of roles
   * @param roles, which user lacks
   * @return lambda returning the error response itself
   */
  template <typename... Roles>
  auto notEnoughPermissionsResponse(
      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter,
      Roles... roles) {
    return [perm_converter, roles...] {
      std::string error = "user must have at least one of the permissions: ";
      for (auto role : {roles...}) {
        error += perm_converter->toString(role) + ", ";
      }
      return error;
    };
  }

  static const std::string kEmptyDetailsResponse{"{}"};

  template <typename T>
  auto resultWithoutNulls(T range) {
    return iroha::dereferenceOptionals(
        range | boost::adaptors::transformed([](auto &&t) {
          return iroha::ametsuchi::rebind(t);
        }));
  }

  using OrderingField = shared_model::interface::Ordering::Field;
  using OrderingDirection = shared_model::interface::Ordering::Direction;
  using OrderingEntry = shared_model::interface::Ordering::OrderingEntry;

  std::unordered_map<OrderingField, std::string> const kOrderingFieldMapping = {
      {OrderingField::kCreatedTime, "ts"},
      {OrderingField::kPosition, "height"},
  };

  std::unordered_map<OrderingDirection, std::string> const
      kOrderingDirectionMapping = {
          {OrderingDirection::kAscending, "ASC"},
          {OrderingDirection::kDescending, "DESC"},
  };

  /**
   * Makes a DB string representation of the response ordering.
   * It APPENDS string data to destination, but not replaces it.
   * @tparam StringType - string type destination
   * @tparam OrderingType - source type ordering data
   * @param src - source ordering data
   * @param dst - destination of the formatted data
   * @return true on success, false otherwise
   */
  template <typename StringType>
  bool formatOrderBy(shared_model::interface::Ordering const &src,
                     StringType &dst) {
    OrderingEntry const *ptr = nullptr;
    size_t count = 0;
    src.get(ptr, count);

    dst.append(" ORDER BY ");
    for (size_t ix = 0; ix < count; ++ix) {
      auto const &ordering_entry = ptr[ix];
      auto it_field = kOrderingFieldMapping.find(ordering_entry.field);
      if (kOrderingFieldMapping.end() == it_field) {
        BOOST_ASSERT_MSG(false, "Ordering field mapping missed!");
        return false;
      }

      auto it_direction =
          kOrderingDirectionMapping.find(ordering_entry.direction);
      if (kOrderingDirectionMapping.end() == it_direction) {
        BOOST_ASSERT_MSG(false, "Ordering direction mapping missed!");
        return false;
      }

      dst.append(it_field->second);
      dst.append(1, ' ');
      dst.append(it_direction->second);
      dst.append(1, ',');
    }

    dst.append("index ASC");
    return true;
  }
}  // namespace

namespace iroha {
  namespace ametsuchi {

    PostgresSpecificQueryExecutor::PostgresSpecificQueryExecutor(
        soci::session &sql,
        BlockStorage &block_store,
        std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        logger::LoggerPtr log)
        : sql_(sql),
          block_store_(block_store),
          pending_txs_storage_(std::move(pending_txs_storage)),
          query_response_factory_{std::move(response_factory)},
          perm_converter_(std::move(perm_converter)),
          log_(std::move(log)) {
      for (size_t value = 0; value < (size_t)OrderingField::kMaxValueCount;
           ++value) {
        BOOST_ASSERT_MSG(kOrderingFieldMapping.find((OrderingField)value)
                             != kOrderingFieldMapping.end(),
                         "Unnamed ordering field found!");
      }
      for (size_t value = 0; value < (size_t)OrderingDirection::kMaxValueCount;
           ++value) {
        BOOST_ASSERT_MSG(
            kOrderingDirectionMapping.find((OrderingDirection)value)
                != kOrderingDirectionMapping.end(),
            "Unnamed ordering direction found!");
      }
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::execute(
        const shared_model::interface::Query &qry) {
      return boost::apply_visitor(
          [this, &qry](const auto &query) {
            return (*this)(query, qry.creatorAccountId(), qry.hash());
          },
          qry.get());
    }

    template <typename RangeGen, typename Pred, typename OutputIterator>
    iroha::expected::Result<void, std::string>
    PostgresSpecificQueryExecutor::getTransactionsFromBlock(
        uint64_t block_id,
        RangeGen &&range_gen,
        Pred &&pred,
        OutputIterator dest_it) {
      auto opt_block = block_store_.fetch(block_id);
      if (not opt_block) {
        return iroha::expected::makeError(
            fmt::format("Failed to retrieve block with id {}", block_id));
      }
      auto &block = opt_block.value();

      const auto block_size = block->transactions().size();
      for (auto tx_id : range_gen(block_size)) {
        if (tx_id >= block_size) {
          return iroha::expected::makeError(
              fmt::format("Failed to retrieve transaction with id {} "
                          "from block height {}.",
                          tx_id,
                          block_id));
        }
        auto &tx = block->transactions()[tx_id];
        if (pred(tx)) {
          *dest_it++ = tx.moveTo();
        }
      }

      return {};
    }

    template <typename QueryTuple,
              typename PermissionTuple,
              typename QueryExecutor,
              typename ResponseCreator,
              typename PermissionsErrResponse>
    QueryExecutorResult PostgresSpecificQueryExecutor::executeQuery(
        QueryExecutor &&query_executor,
        const shared_model::interface::types::HashType &query_hash,
        ResponseCreator &&response_creator,
        PermissionsErrResponse &&perms_err_response) {
      using T = concat<QueryTuple, PermissionTuple>;
      try {
        soci::rowset<T> st = std::forward<QueryExecutor>(query_executor)();
        auto range = boost::make_iterator_range(st.begin(), st.end());

        return iroha::ametsuchi::apply(
            viewPermissions<PermissionTuple>(range.front()),
            [this, range, &response_creator, &perms_err_response, &query_hash](
                auto... perms) {
              bool temp[] = {not perms...};
              if (std::all_of(std::begin(temp), std::end(temp), [](auto b) {
                    return b;
                  })) {
                // TODO [IR-1816] Akvinikym 03.12.18: replace magic number 2
                // with a named constant
                return this->logAndReturnErrorResponse(
                    QueryErrorType::kStatefulFailed,
                    std::forward<PermissionsErrResponse>(perms_err_response)(),
                    2,
                    query_hash);
              }
              auto query_range =
                  range | boost::adaptors::transformed([](auto &t) {
                    return viewQuery<QueryTuple>(t);
                  });
              return std::forward<ResponseCreator>(response_creator)(
                  query_range, perms...);
            });
      } catch (const std::exception &e) {
        return this->logAndReturnErrorResponse(
            QueryErrorType::kStatefulFailed, e.what(), 1, query_hash);
      }
    }

    bool PostgresSpecificQueryExecutor::hasAccountRolePermission(
        shared_model::interface::permissions::Role permission,
        const std::string &account_id) const {
      using T = boost::tuple<int>;
      try {
        soci::rowset<T> st =
            (sql_.prepare << fmt::format(
                 R"({})", getAccountRolePermissionCheckSql(permission)),
             soci::use(account_id, "role_account_id"));
        return st.begin()->get<0>();
      } catch (const std::exception &e) {
        log_->error("Failed to validate query: {}", e.what());
        return false;
      }
    }

    std::unique_ptr<shared_model::interface::QueryResponse>
    PostgresSpecificQueryExecutor::logAndReturnErrorResponse(
        QueryErrorType error_type,
        QueryErrorMessageType error_body,
        QueryErrorCodeType error_code,
        const shared_model::interface::types::HashType &query_hash) const {
      std::string error;
      switch (error_type) {
        case QueryErrorType::kNoAccount:
          error = "could find account with such id: " + error_body;
          break;
        case QueryErrorType::kNoSignatories:
          error = "no signatories found in account with such id: " + error_body;
          break;
        case QueryErrorType::kNoAccountDetail:
          error = "no details in account with such id: " + error_body;
          break;
        case QueryErrorType::kNoRoles:
          error =
              "no role with such name in account with such id: " + error_body;
          break;
        case QueryErrorType::kNoAsset:
          error =
              "no asset with such name in account with such id: " + error_body;
          break;
          // other errors are either handled by generic response or do not
          // appear yet
        default:
          error = "failed to execute query: " + error_body;
          break;
      }

      log_->error("{}", error);
      return query_response_factory_->createErrorQueryResponse(
          error_type, error, error_code, query_hash);
    }

    template <typename Query,
              typename QueryChecker,
              typename QueryApplier,
              typename... Permissions>
    QueryExecutorResult PostgresSpecificQueryExecutor::executeTransactionsQuery(
        const Query &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash,
        QueryChecker &&qry_checker,
        char const *related_txs,
        QueryApplier applier,
        Permissions... perms) {
      using QueryTuple = QueryType<shared_model::interface::types::HeightType,
                                   uint64_t,
                                   uint64_t>;
      using PermissionTuple = boost::tuple<int>;
      const auto &pagination_info = q.paginationMeta();
      auto first_hash = pagination_info.firstTxHash();
      // retrieve one extra transaction to populate next_hash
      auto query_size = pagination_info.pageSize() + 1u;

      char const *base = R"(WITH
               {0},
               my_txs AS (
                 SELECT DISTINCT ROW_NUMBER() OVER({1}) AS row, hash, ts, height, index
                 FROM tx_positions
                 WHERE
                 {2} -- related_txs
                 {5} -- time interval begin
                 {6} -- time interval end
                 {7} -- height begin
                 {8} -- height end
                 {1} -- ordering
                 ),
               total_size AS (SELECT COUNT(*) FROM my_txs) {3}
               SELECT my_txs.height, my_txs.index, count, perm FROM my_txs
               {4}
               RIGHT OUTER JOIN has_perms ON TRUE
               JOIN total_size ON TRUE
               LIMIT :page_size)";

      auto const &ordering = q.paginationMeta().ordering();
      ordering_str_.clear();

      if (!formatOrderBy(ordering, ordering_str_)) {
        return this->logAndReturnErrorResponse(QueryErrorType::kStatefulFailed,
                                               "Ordering query failed.",
                                               1,
                                               query_hash);
      }
      auto query = fmt::format(
          base,
          hasQueryPermissionTarget(creator_id, q.accountId(), perms...),
          (ordering_str_.empty() ? "" : ordering_str_.c_str()),
          related_txs,
          (first_hash
               ? R"(, base_row AS(SELECT row FROM my_txs WHERE hash = lower(:hash) LIMIT 1))"
               : ""),
          (first_hash ? R"(JOIN base_row ON my_txs.row >= base_row.row)" : ""),
          "AND (:first_tx_time::text IS NULL OR :first_tx_time<=ts)",
          "AND (:last_tx_time::text IS NULL OR :last_tx_time>=ts )",
          "AND (:first_tx_height::text IS NULL OR :first_tx_height<=height)",
          "AND (:last_tx_height::text IS NULL OR :last_tx_height>=height )");

      return executeQuery<QueryTuple, PermissionTuple>(
          applier(query),
          query_hash,
          [&](auto range, auto &) {
            auto range_without_nulls = resultWithoutNulls(std::move(range));
            uint64_t total_size = 0;
            if (not boost::empty(range_without_nulls)) {
              total_size = boost::get<2>(*range_without_nulls.begin());
            }
            std::map<uint64_t, std::vector<uint64_t>> index;
            // unpack results to get map from block height to index of tx in
            // a block
            for (auto t : range_without_nulls) {
              iroha::ametsuchi::apply(
                  t, [&index](auto &height, auto &idx, auto &) {
                    index[height].push_back(idx);
                  });
            }

            std::vector<std::unique_ptr<shared_model::interface::Transaction>>
                response_txs;
            // get transactions corresponding to indexes
            for (auto &block : index) {
              auto txs_result = this->getTransactionsFromBlock(
                  block.first,
                  [&block](auto) { return block.second; },
                  [](auto &) { return true; },
                  std::back_inserter(response_txs));
              if (auto e = iroha::expected::resultToOptionalError(txs_result)) {
                return this->logAndReturnErrorResponse(
                    QueryErrorType::kStatefulFailed, e.value(), 1, query_hash);
              }
            }

            if (response_txs.empty()) {
              if (first_hash) {
                // if 0 transactions are returned, and there is a specified
                // paging hash, we assume it's invalid, since query with valid
                // hash is guaranteed to return at least one transaction
                auto error = fmt::format("invalid pagination hash: {}",
                                         first_hash->hex());
                return this->logAndReturnErrorResponse(
                    QueryErrorType::kStatefulFailed, error, 4, query_hash);
              }
              // if paging hash is not specified, we should check, why 0
              // transactions are returned - it can be because there are
              // actually no transactions for this query or some of the
              // parameters were wrong
              if (auto query_incorrect =
                      std::forward<QueryChecker>(qry_checker)(q)) {
                return this->logAndReturnErrorResponse(
                    QueryErrorType::kStatefulFailed,
                    query_incorrect.error_message,
                    query_incorrect.error_code,
                    query_hash);
              }
            }

            // if the number of returned transactions is equal to the
            // page size + 1, it means that the last transaction is the
            // first one in the next page and we need to return it as
            // the next hash
            if (response_txs.size() == query_size) {
              auto next_hash = response_txs.back()->hash();
              response_txs.pop_back();
              return query_response_factory_->createTransactionsPageResponse(
                  std::move(response_txs), next_hash, total_size, query_hash);
            }

            return query_response_factory_->createTransactionsPageResponse(
                std::move(response_txs), std::nullopt, total_size, query_hash);
          },
          notEnoughPermissionsResponse(perm_converter_, perms...));
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetAccount &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      using QueryTuple =
          QueryType<shared_model::interface::types::AccountIdType,
                    shared_model::interface::types::DomainIdType,
                    shared_model::interface::types::QuorumType,
                    shared_model::interface::types::DetailType,
                    std::string>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd =
          fmt::format(R"(WITH {},
      t AS (
          SELECT a.account_id, a.domain_id, a.quorum, a.data, ARRAY_AGG(ar.role_id) AS roles
          FROM account AS a, account_has_roles AS ar
          WHERE a.account_id = :target_account_id
          AND ar.account_id = a.account_id
          GROUP BY a.account_id
      )
      SELECT account_id, domain_id, quorum, data, roles, perm
      FROM t RIGHT OUTER JOIN has_perms AS p ON TRUE
      )",
                      hasQueryPermissionTarget(creator_id,
                                               q.accountId(),
                                               Role::kGetMyAccount,
                                               Role::kGetAllAccounts,
                                               Role::kGetDomainAccounts));

      auto query_apply = [this, &query_hash](auto &account_id,
                                             auto &domain_id,
                                             auto &quorum,
                                             auto &data,
                                             auto &roles_str) {
        std::vector<shared_model::interface::types::RoleIdType> roles;
        auto roles_str_no_brackets = roles_str.substr(1, roles_str.size() - 2);
        boost::split(
            roles, roles_str_no_brackets, [](char c) { return c == ','; });
        return query_response_factory_->createAccountResponse(
            account_id, domain_id, quorum, data, std::move(roles), query_hash);
      };

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(q.accountId(), "target_account_id"));
          },
          query_hash,
          [this, &q, &query_apply, &query_hash](auto range, auto &) {
            auto range_without_nulls = resultWithoutNulls(std::move(range));
            if (range_without_nulls.empty()) {
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kNoAccount, q.accountId(), 0, query_hash);
            }

            return iroha::ametsuchi::apply(range_without_nulls.front(),
                                           query_apply);
          },
          notEnoughPermissionsResponse(perm_converter_,
                                       Role::kGetMyAccount,
                                       Role::kGetAllAccounts,
                                       Role::kGetDomainAccounts));
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetBlock &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      if (not hasAccountRolePermission(Role::kGetBlocks, creator_id)) {
        // no permission
        return query_response_factory_->createErrorQueryResponse(
            shared_model::interface::QueryResponseFactory::ErrorQueryType::
                kStatefulFailed,
            notEnoughPermissionsResponse(perm_converter_, Role::kGetBlocks)(),
            2,
            query_hash);
      }

      auto ledger_height = block_store_.size();
      if (q.height() > ledger_height) {
        // invalid height
        return logAndReturnErrorResponse(
            QueryErrorType::kStatefulFailed,
            "requested height (" + std::to_string(q.height())
                + ") is greater than the ledger's one ("
                + std::to_string(ledger_height) + ")",
            3,
            query_hash);
      }

      auto block_deserialization_msg = [height = q.height()] {
        return "could not retrieve block with given height: "
            + std::to_string(height);
      };
      auto block = block_store_.fetch(q.height());
      if (not block) {
        // for some reason, block with such height was not retrieved
        return logAndReturnErrorResponse(QueryErrorType::kStatefulFailed,
                                         block_deserialization_msg(),
                                         1,
                                         query_hash);
      }
      return query_response_factory_->createBlockResponse(std::move(*block),
                                                          query_hash);
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetSignatories &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      using QueryTuple = QueryType<std::string>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd =
          fmt::format(R"(WITH {},
      t AS (
          SELECT public_key FROM account_has_signatory
          WHERE account_id = :account_id
      )
      SELECT public_key, perm FROM t
      RIGHT OUTER JOIN has_perms ON TRUE
      )",
                      hasQueryPermissionTarget(creator_id,
                                               q.accountId(),
                                               Role::kGetMySignatories,
                                               Role::kGetAllSignatories,
                                               Role::kGetDomainSignatories));

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] { return (sql_.prepare << cmd, soci::use(q.accountId())); },
          query_hash,
          [this, &q, &query_hash](auto range, auto &) {
            auto range_without_nulls = resultWithoutNulls(std::move(range));
            if (range_without_nulls.empty()) {
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kNoSignatories, q.accountId(), 0, query_hash);
            }

            auto pubkeys = boost::copy_range<std::vector<std::string>>(
                range_without_nulls | boost::adaptors::transformed([](auto t) {
                  return boost::get<0>(t);
                }));

            return query_response_factory_->createSignatoriesResponse(
                pubkeys, query_hash);
          },

          notEnoughPermissionsResponse(perm_converter_,
                                       Role::kGetMySignatories,
                                       Role::kGetAllSignatories,
                                       Role::kGetDomainSignatories));
    }
    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetAccountTransactions &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      char const *related_txs = R"(
          creator_id = :account_id
          AND asset_id IS NULL
      )";

      const auto &pagination_info = q.paginationMeta();
      auto first_hash = pagination_info.firstTxHash();
      // retrieve one extra transaction to populate next_hash
      auto query_size = pagination_info.pageSize() + 1u;

      auto first_tx_time = pagination_info.firstTxTime();
      auto last_tx_time = pagination_info.lastTxTime();
      auto first_tx_height = pagination_info.firstTxHeight();
      auto last_tx_height = pagination_info.lastTxHeight();
      soci::indicator ind = soci::i_null;
      auto apply_query = [&](const auto &query) {
        return [&] {
          if (first_hash) {
            return (sql_.prepare << query,
                    soci::use(q.accountId(), "account_id"),
                    soci::use(first_hash->hex(), "hash"),
                    soci::use(query_size, "page_size"),
                    soci::use(first_tx_time, ind, "first_tx_time"),
                    soci::use(last_tx_time, ind, "last_tx_time"),
                    soci::use(first_tx_height, ind, "first_tx_height"),
                    soci::use(last_tx_height, ind, "last_tx_height"));
          } else {
            return (sql_.prepare << query,
                    soci::use(q.accountId(), "account_id"),
                    soci::use(query_size, "page_size"),
                    soci::use(first_tx_time, ind, "first_tx_time"),
                    soci::use(last_tx_time, ind, "last_tx_time"),
                    soci::use(first_tx_height, ind, "first_tx_height"),
                    soci::use(last_tx_height, ind, "last_tx_height"));
          }
        };
      };

      auto check_query = [this](const auto &q) {
        if (this->existsInDb<int>(
                "account", "account_id", "quorum", q.accountId())) {
          return QueryFallbackCheckResult{};
        }
        return QueryFallbackCheckResult{
            5, "no account with such id found: " + q.accountId()};
      };

      return executeTransactionsQuery(q,
                                      creator_id,
                                      query_hash,
                                      std::move(check_query),
                                      related_txs,
                                      apply_query,
                                      Role::kGetMyAccTxs,
                                      Role::kGetAllAccTxs,
                                      Role::kGetDomainAccTxs);
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetTransactions &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      std::string hash_str = boost::algorithm::join(
          q.transactionHashes()
              | boost::adaptors::transformed(
                    [](const auto &h) { return "lower('" + h.hex() + "')"; }),
          ", ");

      using QueryTuple =
          QueryType<shared_model::interface::types::HeightType, std::string>;
      using PermissionTuple = boost::tuple<int, int>;

      auto cmd = fmt::format(
          R"(WITH has_my_perm AS ({}),
      has_all_perm AS ({}),
      t AS (
          SELECT DISTINCT height, hash FROM tx_positions WHERE hash IN ({})
      )
      SELECT height, hash, has_my_perm.perm, has_all_perm.perm FROM t
      RIGHT OUTER JOIN has_my_perm ON TRUE
      RIGHT OUTER JOIN has_all_perm ON TRUE
      )",
          getAccountRolePermissionCheckSql(Role::kGetMyTxs, ":account_id"),
          getAccountRolePermissionCheckSql(Role::kGetAllTxs, ":account_id"),
          hash_str);

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd, soci::use(creator_id, "account_id"));
          },
          query_hash,
          [&](auto range, auto &my_perm, auto &all_perm) {
            std::map<uint64_t, std::unordered_set<std::string>> index;
            uint64_t counter = 0ull;

            for (auto const &i : range) {
              iroha::ametsuchi::apply(i, [&](auto &height, auto &hash) {
                if (!height || !hash)
                  return;

                if (index[*height].insert(*hash).second)
                  ++counter;
              });
            }

            if (counter != q.transactionHashes().size()) {
              // TODO [IR-1816] Akvinikym 03.12.18: replace magic number 4
              // with a named constant
              // at least one of the hashes in the query was invalid -
              // nonexistent or permissions were missed
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kStatefulFailed,
                  "At least one of the supplied hashes is incorrect",
                  4,
                  query_hash);
            }

            std::vector<std::unique_ptr<shared_model::interface::Transaction>>
                response_txs;
            for (auto &blk : index) {
              auto &block_idx = blk.first;
              auto &txs_hashes = blk.second;
              auto txs_result = this->getTransactionsFromBlock(
                  block_idx,
                  [](auto size) {
                    return boost::irange(static_cast<decltype(size)>(0), size);
                  },
                  [&](auto &tx) {
                    return txs_hashes.count(tx.hash().hex()) > 0
                        and (all_perm
                             or (my_perm
                                 and tx.creatorAccountId() == creator_id));
                  },
                  std::back_inserter(response_txs));
              if (auto e = iroha::expected::resultToOptionalError(txs_result)) {
                return this->logAndReturnErrorResponse(
                    QueryErrorType::kStatefulFailed, e.value(), 1, query_hash);
              }
            }

            return query_response_factory_->createTransactionsResponse(
                std::move(response_txs), query_hash);
          },
          notEnoughPermissionsResponse(
              perm_converter_, Role::kGetMyTxs, Role::kGetAllTxs));
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetAccountAssetTransactions &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      char const *related_txs = R"(
          creator_id = :account_id
          AND asset_id = :asset_id
      )";

      const auto &pagination_info = q.paginationMeta();
      auto first_hash = pagination_info.firstTxHash();
      // retrieve one extra transaction to populate next_hash
      auto query_size = pagination_info.pageSize() + 1u;
      auto first_tx_time = pagination_info.firstTxTime();
      auto last_tx_time = pagination_info.lastTxTime();
      auto first_tx_height = pagination_info.firstTxHeight();
      auto last_tx_height = pagination_info.lastTxHeight();
      soci::indicator ind = soci::i_null;
      auto apply_query = [&](const auto &query) {
        return [&] {
          if (first_hash) {
            return (sql_.prepare << query,
                    soci::use(q.accountId(), "account_id"),
                    soci::use(q.assetId(), "asset_id"),
                    soci::use(first_hash->hex(), "hash"),
                    soci::use(query_size, "page_size"),
                    soci::use(first_tx_time, ind, "first_tx_time"),
                    soci::use(last_tx_time, ind, "last_tx_time"),
                    soci::use(first_tx_height, ind, "first_tx_height"),
                    soci::use(last_tx_height, ind, "last_tx_height"));
          } else {
            return (sql_.prepare << query,
                    soci::use(q.accountId(), "account_id"),
                    soci::use(q.assetId(), "asset_id"),
                    soci::use(query_size, "page_size"),
                    soci::use(first_tx_time, ind, "first_tx_time"),
                    soci::use(last_tx_time, ind, "last_tx_time"),
                    soci::use(first_tx_height, ind, "first_tx_height"),
                    soci::use(last_tx_height, ind, "last_tx_height"));
          }
        };
      };

      auto check_query = [this](const auto &q) {
        if (not this->existsInDb<int>(
                "account", "account_id", "quorum", q.accountId())) {
          return QueryFallbackCheckResult{
              5, "no account with such id found: " + q.accountId()};
        }
        if (not this->existsInDb<int>(
                "asset", "asset_id", "precision", q.assetId())) {
          return QueryFallbackCheckResult{
              6, "no asset with such id found: " + q.assetId()};
        }

        return QueryFallbackCheckResult{};
      };

      return executeTransactionsQuery(q,
                                      creator_id,
                                      query_hash,
                                      std::move(check_query),
                                      related_txs,
                                      apply_query,
                                      Role::kGetMyAccAstTxs,
                                      Role::kGetAllAccAstTxs,
                                      Role::kGetDomainAccAstTxs);
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetAccountAssets &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      using QueryTuple =
          QueryType<shared_model::interface::types::AccountIdType,
                    shared_model::interface::types::AssetIdType,
                    std::string,
                    size_t>;
      using PermissionTuple = boost::tuple<int>;

      // get the assets
      auto cmd = fmt::format(R"(
      with {},
      all_data as (
          select row_number() over () rn, *
          from (
              select *
              from account_has_asset
              where account_id = :account_id
              order by asset_id
          ) t
      ),
      total_number as (
          select rn total_number
          from all_data
          order by rn desc
          limit 1
      ),
      page_start as (
          select rn
          from all_data
          where coalesce(asset_id = :first_asset_id, true)
          limit 1
      ),
      page_data as (
          select * from all_data, page_start, total_number
          where
              all_data.rn >= page_start.rn and
              coalesce( -- TODO remove after pagination is mandatory IR-516
                  all_data.rn < page_start.rn + :page_size,
                  true
              )
      )
      select account_id, asset_id, amount, total_number, perm
          from
              page_data
              right join has_perms on true
      )",
                             hasQueryPermissionTarget(creator_id,
                                                      q.accountId(),
                                                      Role::kGetMyAccAst,
                                                      Role::kGetAllAccAst,
                                                      Role::kGetDomainAccAst));

      // These must stay alive while soci query is being done.
      const auto pagination_meta{q.paginationMeta()};
      const auto req_first_asset_id =
          pagination_meta | [](const auto &pagination_meta) {
            return std::optional<std::string>(
                pagination_meta.get().firstAssetId());
          };
      const auto req_page_size =  // TODO 2019.05.31 mboldyrev make it
                                  // non-optional after IR-516
          pagination_meta | [](const auto &pagination_meta) {
            return std::optional<size_t>(pagination_meta.get().pageSize() + 1);
          };

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(q.accountId(), "account_id"),
                    soci::use(req_first_asset_id, "first_asset_id"),
                    soci::use(req_page_size, "page_size"));
          },
          query_hash,
          [&](auto range, auto &) {
            auto range_without_nulls = resultWithoutNulls(std::move(range));
            std::vector<
                std::tuple<shared_model::interface::types::AccountIdType,
                           shared_model::interface::types::AssetIdType,
                           shared_model::interface::Amount>>
                assets;
            size_t total_number = 0;
            for (const auto &row : range_without_nulls) {
              iroha::ametsuchi::apply(
                  row,
                  [&assets, &total_number](auto &account_id,
                                           auto &asset_id,
                                           auto &amount,
                                           auto &total_number_col) {
                    total_number = total_number_col;
                    assets.push_back(std::make_tuple(
                        std::move(account_id),
                        std::move(asset_id),
                        shared_model::interface::Amount(amount)));
                  });
            }
            if (assets.empty() and req_first_asset_id) {
              // nonexistent first_asset_id provided in query request
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kStatefulFailed,
                  q.accountId(),
                  4,
                  query_hash);
            }
            assert(total_number >= assets.size());
            const bool is_last_page = not q.paginationMeta()
                or (assets.size() <= q.paginationMeta()->get().pageSize());
            std::optional<shared_model::interface::types::AssetIdType>
                next_asset_id;
            if (not is_last_page) {
              next_asset_id = std::get<1>(assets.back());
              assets.pop_back();
              assert(assets.size() == q.paginationMeta()->get().pageSize());
            }
            return query_response_factory_->createAccountAssetResponse(
                assets, total_number, next_asset_id, query_hash);
          },
          notEnoughPermissionsResponse(perm_converter_,
                                       Role::kGetMyAccAst,
                                       Role::kGetAllAccAst,
                                       Role::kGetDomainAccAst));
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetAccountDetail &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      using QueryTuple =
          QueryType<shared_model::interface::types::DetailType,
                    uint32_t,
                    shared_model::interface::types::AccountIdType,
                    shared_model::interface::types::AccountDetailKeyType,
                    uint32_t>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd =
          fmt::format(R"(
      with {},
      detail AS (
          with filtered_plain_data as (
              select row_number() over () rn, *
              from (
                  select
                      data_by_writer.key writer,
                      plain_data.key as key,
                      plain_data.value as value
                  from
                      jsonb_each((
                          select data
                          from account
                          where account_id = :account_id
                      )) data_by_writer,
                  jsonb_each(data_by_writer.value) plain_data
                  where
                      coalesce(data_by_writer.key = :writer, true) and
                      coalesce(plain_data.key = :key, true)
                  order by data_by_writer.key asc, plain_data.key asc
              ) t
          ),
          page_limits as (
              select start.rn as start, start.rn + :page_size as end
                  from (
                      select rn
                      from filtered_plain_data
                      where
                          coalesce(writer = :first_record_writer, true) and
                          coalesce(key = :first_record_key, true)
                      limit 1
                  ) start
          ),
          total_number as (select count(1) total_number from filtered_plain_data),
          next_record as (
              select writer, key
              from
                  filtered_plain_data,
                  page_limits
              where rn = page_limits.end
          ),
          page as (
              select json_object_agg(writer, data_by_writer) json
              from (
                  select writer, json_object_agg(key, value) data_by_writer
                  from
                      filtered_plain_data,
                      page_limits
                  where
                      rn >= page_limits.start and
                      coalesce(rn < page_limits.end, true)
                  group by writer
              ) t
          ),
          target_account_exists as (
            select count(1) val
            from account
            where account_id = :account_id
          )
          select
              page.json json,
              total_number,
              next_record.writer next_writer,
              next_record.key next_key,
              target_account_exists.val target_account_exists
          from
              page
              left join total_number on true
              left join next_record on true
              right join target_account_exists on true
      )
      select detail.*, perm from detail
      right join has_perms on true
      )",
                      hasQueryPermissionTarget(creator_id,
                                               q.accountId(),
                                               Role::kGetMyAccDetail,
                                               Role::kGetAllAccDetail,
                                               Role::kGetDomainAccDetail));

      const auto writer = q.writer();
      const auto key = q.key();
      boost::optional<std::string> first_record_writer;
      boost::optional<std::string> first_record_key;
      boost::optional<size_t> page_size;
      // TODO 2019.05.29 mboldyrev IR-516 remove when pagination is made
      // mandatory
      q.paginationMeta() | [&](const auto &pagination_meta) {
        page_size = pagination_meta.get().pageSize();
        pagination_meta.get().firstRecordId() |
            [&](const auto &first_record_id) {
              first_record_writer = first_record_id.get().writer();
              first_record_key = first_record_id.get().key();
            };
      };

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(q.accountId(), "account_id"),
                    soci::use(writer, "writer"),
                    soci::use(key, "key"),
                    soci::use(first_record_writer, "first_record_writer"),
                    soci::use(first_record_key, "first_record_key"),
                    soci::use(page_size, "page_size"));
          },
          query_hash,
          [&, this](auto range, auto &) {
            if (range.empty()) {
              assert(not range.empty());
              log_->error("Empty response range in {}.", q);
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kNoAccountDetail,
                  q.accountId(),
                  0,
                  query_hash);
            }

            return iroha::ametsuchi::apply(
                range.front(),
                [&, this](auto &json,
                          auto &total_number,
                          auto &next_writer,
                          auto &next_key,
                          auto &target_account_exists) {
                  if (target_account_exists.value_or(0) == 0) {
                    // TODO 2019.06.11 mboldyrev IR-558 redesign missing data
                    // handling
                    return this->logAndReturnErrorResponse(
                        QueryErrorType::kNoAccountDetail,
                        q.accountId(),
                        0,
                        query_hash);
                  }
                  assert(target_account_exists.value() == 1);
                  if (json) {
                    BOOST_ASSERT_MSG(total_number, "Mandatory value missing!");
                    if (not total_number) {
                      this->log_->error(
                          "Mandatory total_number value is missing in "
                          "getAccountDetail query result {}.",
                          q);
                    }
                    std::optional<shared_model::plain::AccountDetailRecordId>
                        next_record_id{[this, &next_writer, &next_key]()
                                           -> decltype(next_record_id) {
                          if (next_key or next_writer) {
                            if (not next_writer) {
                              log_->error(
                                  "next_writer not set for next_record_id!");
                              assert(next_writer);
                              return std::nullopt;
                            }
                            if (not next_key) {
                              log_->error(
                                  "next_key not set for next_record_id!");
                              assert(next_key);
                              return std::nullopt;
                            }
                            return shared_model::plain::AccountDetailRecordId{
                                next_writer.value(), next_key.value()};
                          }
                          return std::nullopt;
                        }()};
                    return query_response_factory_->createAccountDetailResponse(
                        json.value(),
                        total_number.value_or(0),
                        next_record_id |
                            [](const auto &next_record_id) {
                              return std::optional<std::reference_wrapper<
                                  const shared_model::interface::
                                      AccountDetailRecordId>>(next_record_id);
                            },
                        query_hash);
                  }
                  if (total_number.value_or(0) > 0) {
                    // the only reason for it is nonexistent first record
                    assert(first_record_writer or first_record_key);
                    return this->logAndReturnErrorResponse(
                        QueryErrorType::kStatefulFailed,
                        q.accountId(),
                        4,
                        query_hash);
                  } else {
                    // no account details matching query
                    // TODO 2019.06.11 mboldyrev IR-558 redesign missing data
                    // handling
                    return query_response_factory_->createAccountDetailResponse(
                        kEmptyDetailsResponse, 0, std::nullopt, query_hash);
                  }
                });
          },
          notEnoughPermissionsResponse(perm_converter_,
                                       Role::kGetMyAccDetail,
                                       Role::kGetAllAccDetail,
                                       Role::kGetDomainAccDetail));
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetRoles &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      using QueryTuple = QueryType<shared_model::interface::types::RoleIdType>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd = fmt::format(
          R"(WITH has_perms AS ({})
      SELECT role_id, perm FROM role
      RIGHT OUTER JOIN has_perms ON TRUE
      )",
          getAccountRolePermissionCheckSql(Role::kGetRoles));

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(creator_id, "role_account_id"));
          },
          query_hash,
          [&](auto range, auto &) {
            auto range_without_nulls = resultWithoutNulls(std::move(range));
            auto roles = boost::copy_range<
                std::vector<shared_model::interface::types::RoleIdType>>(
                range_without_nulls | boost::adaptors::transformed([](auto t) {
                  return iroha::ametsuchi::apply(
                      t, [](auto &role_id) { return role_id; });
                }));

            return query_response_factory_->createRolesResponse(roles,
                                                                query_hash);
          },
          notEnoughPermissionsResponse(perm_converter_, Role::kGetRoles));
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetRolePermissions &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      using QueryTuple = QueryType<std::string>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd = fmt::format(
          R"(WITH has_perms AS ({}),
      perms AS (SELECT permission FROM role_has_permissions
                WHERE role_id = :role_name)
      SELECT permission, perm FROM perms
      RIGHT OUTER JOIN has_perms ON TRUE
      )",
          getAccountRolePermissionCheckSql(Role::kGetRoles));

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(creator_id, "role_account_id"),
                    soci::use(q.roleId(), "role_name"));
          },
          query_hash,
          [this, &q, &creator_id, &query_hash](auto range, auto &) {
            auto range_without_nulls = resultWithoutNulls(std::move(range));
            if (range_without_nulls.empty()) {
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kNoRoles,
                  "{" + q.roleId() + ", " + creator_id + "}",
                  0,
                  query_hash);
            }

            return iroha::ametsuchi::apply(
                range_without_nulls.front(),
                [this, &query_hash](auto &permission) {
                  return query_response_factory_->createRolePermissionsResponse(
                      shared_model::interface::RolePermissionSet(permission),
                      query_hash);
                });
          },
          notEnoughPermissionsResponse(perm_converter_, Role::kGetRoles));
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetAssetInfo &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      using QueryTuple =
          QueryType<shared_model::interface::types::DomainIdType, uint32_t>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd = fmt::format(
          R"(WITH has_perms AS ({}),
      perms AS (SELECT domain_id, precision FROM asset
                WHERE asset_id = :asset_id)
      SELECT domain_id, precision, perm FROM perms
      RIGHT OUTER JOIN has_perms ON TRUE
      )",
          getAccountRolePermissionCheckSql(Role::kReadAssets));

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(creator_id, "role_account_id"),
                    soci::use(q.assetId(), "asset_id"));
          },
          query_hash,
          [this, &q, &creator_id, &query_hash](auto range, auto &) {
            auto range_without_nulls = resultWithoutNulls(std::move(range));
            if (range_without_nulls.empty()) {
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kNoAsset,
                  "{" + q.assetId() + ", " + creator_id + "}",
                  0,
                  query_hash);
            }

            return iroha::ametsuchi::apply(
                range_without_nulls.front(),
                [this, &q, &query_hash](auto &domain_id, auto &precision) {
                  return query_response_factory_->createAssetResponse(
                      q.assetId(), domain_id, precision, query_hash);
                });
          },
          notEnoughPermissionsResponse(perm_converter_, Role::kReadAssets));
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetPendingTransactions &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
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
                              + q.paginationMeta()
                                    ->get()
                                    .firstTxHash()
                                    ->toString(),
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

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetPeers &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      using QueryTuple = QueryType<std::string,
                                   shared_model::interface::types::AddressType,
                                   std::string>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd = fmt::format(
          R"(WITH has_perms AS ({})
      SELECT public_key, address, tls_certificate, perm FROM peer
      RIGHT OUTER JOIN has_perms ON TRUE
      UNION
      SELECT public_key, address, tls_certificate, perm FROM sync_peer
      RIGHT OUTER JOIN has_perms ON TRUE
      )",
          getAccountRolePermissionCheckSql(Role::kGetPeers));

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(creator_id, "role_account_id"));
          },
          query_hash,
          [&](auto range, auto &) {
            shared_model::interface::types::PeerList peers;
            for (const auto &row : range) {
              iroha::ametsuchi::apply(
                  row,
                  [&peers](
                      auto &peer_key, auto &address, auto &tls_certificate) {
                    if (peer_key and address) {
                      peers.push_back(
                          std::make_shared<shared_model::plain::Peer>(
                              *address,
                              *std::move(peer_key),
                              tls_certificate,
                              false));
                    }
                  });
            }
            return query_response_factory_->createPeersResponse(peers,
                                                                query_hash);
          },
          notEnoughPermissionsResponse(perm_converter_, Role::kGetPeers));
    }

    QueryExecutorResult PostgresSpecificQueryExecutor::operator()(
        const shared_model::interface::GetEngineReceipts &q,
        const shared_model::interface::types::AccountIdType &creator_id,
        const shared_model::interface::types::HashType &query_hash) {
      auto cmd = fmt::format(
          R"(
            with
              target as (
                select distinct creator_id as t
                from tx_positions
                where hash=lower(:tx_hash)
              ),
              {}
            select
              engine_calls.cmd_index,
              target.t caller,
              engine_calls.callee,
              engine_calls.created_address,
              engine_calls.engine_response,
              burrow_tx_logs.log_idx,
              burrow_tx_logs.address,
              burrow_tx_logs.data,
              burrow_tx_logs_topics.topic,
              has_perms.perm
            from
              target
              left join engine_calls on engine_calls.tx_hash = lower(:tx_hash)
              left join burrow_tx_logs on engine_calls.call_id = burrow_tx_logs.call_id
              left join burrow_tx_logs_topics on burrow_tx_logs.log_idx = burrow_tx_logs_topics.log_idx
              right outer join has_perms on true
            order by engine_calls.cmd_index asc
            )",
          hasQueryPermissionInternal(creator_id,
                                     Role::kGetMyEngineReceipts,
                                     Role::kGetAllEngineReceipts,
                                     Role::kGetDomainEngineReceipts));

      using QueryTuple =
          QueryType<shared_model::interface::types::CommandIndexType,
                    shared_model::interface::types::AccountIdType,
                    shared_model::interface::types::EvmDataHexString,
                    shared_model::interface::types::EvmAddressHexString,
                    shared_model::interface::types::EvmDataHexString,
                    uint32_t,
                    shared_model::interface::types::EvmAddressHexString,
                    shared_model::interface::types::EvmDataHexString,
                    shared_model::interface::types::EvmTopicsHexString>;

      using PermissionTuple = boost::tuple<int>;

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd, soci::use(q.txHash(), "tx_hash"));
          },
          query_hash,
          [&](auto range, auto &) {
            using RecordsCollection = std::vector<
                std::unique_ptr<shared_model::interface::EngineReceipt>>;
            using RecordPtr =
                std::unique_ptr<shared_model::plain::EngineReceipt>;
            using EngineLogPtr =
                std::unique_ptr<shared_model::plain::EngineLog>;

            RecordsCollection records;
            RecordPtr record;
            EngineLogPtr log;
            std::optional<uint32_t> prev_log_ix;
            std::optional<shared_model::interface::types::CommandIndexType>
                prev_cmd_ix;

            auto store_record = [](RecordsCollection &records,
                                   RecordPtr &&rec) {
              if (!!rec) {
                records.emplace_back(std::move(rec));
              }
            };

            auto store_log = [](RecordPtr &rec, EngineLogPtr &&el) {
              if (!!rec && !!el) {
                rec->getMutableLogs().emplace_back(std::move(el));
              }
            };

            for (const auto &row : range) {
              iroha::ametsuchi::apply(
                  row,
                  [&store_record,
                   &store_log,
                   &record,
                   &log,
                   &records,
                   &prev_log_ix,
                   &prev_cmd_ix](auto &cmd_index,
                                 auto &caller,
                                 auto &payload_callee,
                                 auto &payload_cantract_address,
                                 auto &engine_response,
                                 auto &logs_ix,
                                 auto &log_address,
                                 auto &log_data,
                                 auto &log_topic) {
                    if (!cmd_index || !caller)
                      return;

                    using namespace shared_model::interface::types;

                    auto const new_cmd = (prev_cmd_ix != cmd_index);
                    auto const new_log = (prev_log_ix != logs_ix);
                    assert(!new_cmd || new_log || !prev_log_ix);

                    if (new_log) {
                      store_log(record, std::move(log));

                      if (!!logs_ix) {
                        assert(!!log_address && !!log_data);
                        log = std::make_unique<shared_model::plain::EngineLog>(
                            *log_address, *log_data);
                      }
                      prev_log_ix = logs_ix;
                    }

                    if (!!log_topic) {
                      assert(!!log);
                      log->addTopic(*log_topic);
                    }

                    if (new_cmd) {
                      store_record(records, std::move(record));

                      record =
                          std::make_unique<shared_model::plain::EngineReceipt>(
                              *cmd_index,
                              *caller,
                              payload_callee,
                              payload_cantract_address,
                              engine_response);
                      prev_cmd_ix = cmd_index;
                    }
                  });
            }
            store_log(record, std::move(log));
            store_record(records, std::move(record));

            return query_response_factory_->createEngineReceiptsResponse(
                records, query_hash);
          },
          notEnoughPermissionsResponse(perm_converter_,
                                       Role::kGetMyEngineReceipts,
                                       Role::kGetAllEngineReceipts,
                                       Role::kGetDomainEngineReceipts));
    }

    template <typename ReturnValueType>
    bool PostgresSpecificQueryExecutor::existsInDb(
        const std::string &table_name,
        const std::string &key_name,
        const std::string &value_name,
        const std::string &value) const {
      auto cmd = fmt::format(R"(SELECT {}
                                   FROM {}
                                   WHERE {} = '{}'
                                   LIMIT 1)",
                             value_name,
                             table_name,
                             key_name,
                             value);
      soci::rowset<ReturnValueType> result = this->sql_.prepare << cmd;
      return result.begin() != result.end();
    }

  }  // namespace ametsuchi
}  // namespace iroha
