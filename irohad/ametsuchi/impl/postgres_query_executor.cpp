/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_query_executor.hpp"

#include <boost-tuple.h>
#include <soci/boost-tuple.h>
#include <soci/postgresql/soci-postgresql.h>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/algorithm/transform.hpp>
#include <boost/range/irange.hpp>

#include "ametsuchi/impl/soci_utils.hpp"
#include "common/byteutils.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "interfaces/queries/get_account.hpp"
#include "interfaces/queries/get_account_asset_transactions.hpp"
#include "interfaces/queries/get_account_assets.hpp"
#include "interfaces/queries/get_account_detail.hpp"
#include "interfaces/queries/get_account_transactions.hpp"
#include "interfaces/queries/get_asset_info.hpp"
#include "interfaces/queries/get_block.hpp"
#include "interfaces/queries/get_pending_transactions.hpp"
#include "interfaces/queries/get_role_permissions.hpp"
#include "interfaces/queries/get_roles.hpp"
#include "interfaces/queries/get_signatories.hpp"
#include "interfaces/queries/get_transactions.hpp"
#include "interfaces/queries/query.hpp"
#include "interfaces/queries/tx_pagination_meta.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

using namespace shared_model::interface::permissions;

namespace {

  using namespace iroha;

  shared_model::interface::types::DomainIdType getDomainFromName(
      const shared_model::interface::types::AccountIdType &account_id) {
    // TODO 03.10.18 andrei: IR-1728 Move getDomainFromName to shared_model
    std::vector<std::string> res;
    boost::split(res, account_id, boost::is_any_of("@"));
    return res.at(1);
  }

  std::string getAccountRolePermissionCheckSql(
      shared_model::interface::permissions::Role permission,
      const std::string &account_alias = "role_account_id") {
    const auto perm_str =
        shared_model::interface::RolePermissionSet({permission}).toBitstring();
    const auto bits = shared_model::interface::RolePermissionSet::size();
    // TODO 14.09.18 andrei: IR-1708 Load SQL from separate files
    std::string query = (boost::format(R"(
          SELECT (COALESCE(bit_or(rp.permission), '0'::bit(%1%))
          & '%2%') = '%2%' AS perm FROM role_has_permissions AS rp
              JOIN account_has_roles AS ar on ar.role_id = rp.role_id
              WHERE ar.account_id = :%3%)")
                         % bits % perm_str % account_alias)
                            .str();
    return query;
  }

  /**
   * Generate an SQL subquery which checks if creator has corresponding
   * permissions for target account
   * It verifies individual, domain, and global permissions, and returns true if
   * any of listed permissions is present
   */
  auto hasQueryPermission(
      const shared_model::interface::types::AccountIdType &creator,
      const shared_model::interface::types::AccountIdType &target_account,
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

    boost::format cmd(R"(
    WITH
        has_indiv_perm AS (
          SELECT (COALESCE(bit_or(rp.permission), '0'::bit(%1%))
          & '%3%') = '%3%' FROM role_has_permissions AS rp
              JOIN account_has_roles AS ar on ar.role_id = rp.role_id
              WHERE ar.account_id = '%2%'
        ),
        has_all_perm AS (
          SELECT (COALESCE(bit_or(rp.permission), '0'::bit(%1%))
          & '%4%') = '%4%' FROM role_has_permissions AS rp
              JOIN account_has_roles AS ar on ar.role_id = rp.role_id
              WHERE ar.account_id = '%2%'
        ),
        has_domain_perm AS (
          SELECT (COALESCE(bit_or(rp.permission), '0'::bit(%1%))
          & '%5%') = '%5%' FROM role_has_permissions AS rp
              JOIN account_has_roles AS ar on ar.role_id = rp.role_id
              WHERE ar.account_id = '%2%'
        )
    SELECT ('%2%' = '%6%' AND (SELECT * FROM has_indiv_perm))
        OR (SELECT * FROM has_all_perm)
        OR ('%7%' = '%8%' AND (SELECT * FROM has_domain_perm)) AS perm
    )");

    return (cmd % bits % creator % perm_str % all_perm_str % domain_perm_str
            % target_account % getDomainFromName(creator)
            % getDomainFromName(target_account))
        .str();
  }

  /// Query result is a tuple of optionals, since there could be no entry
  template <typename... Value>
  using QueryType = boost::tuple<boost::optional<Value>...>;

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

}  // namespace

namespace iroha {
  namespace ametsuchi {

    template <typename RangeGen, typename Pred>
    std::vector<std::unique_ptr<shared_model::interface::Transaction>>
    PostgresQueryExecutorVisitor::getTransactionsFromBlock(uint64_t block_id,
                                                           RangeGen &&range_gen,
                                                           Pred &&pred) {
      std::vector<std::unique_ptr<shared_model::interface::Transaction>> result;
      auto serialized_block = block_store_.get(block_id);
      if (not serialized_block) {
        log_->error("Failed to retrieve block with id {}", block_id);
        return result;
      }
      auto deserialized_block =
          converter_->deserialize(bytesToString(*serialized_block));
      // boost::get of pointer returns pointer to requested type, or nullptr
      if (auto e =
              boost::get<expected::Error<std::string>>(&deserialized_block)) {
        log_->error("{}", e->error);
        return result;
      }

      auto &block =
          boost::get<
              expected::Value<std::unique_ptr<shared_model::interface::Block>>>(
              deserialized_block)
              .value;

      boost::transform(range_gen(boost::size(block->transactions()))
                           | boost::adaptors::transformed(
                                 [&block](auto i) -> decltype(auto) {
                                   return block->transactions()[i];
                                 })
                           | boost::adaptors::filtered(pred),
                       std::back_inserter(result),
                       [&](const auto &tx) { return clone(tx); });

      return result;
    }

    template <typename QueryTuple,
              typename PermissionTuple,
              typename QueryExecutor,
              typename ResponseCreator,
              typename PermissionsErrResponse>
    QueryExecutorResult PostgresQueryExecutorVisitor::executeQuery(
        QueryExecutor &&query_executor,
        ResponseCreator &&response_creator,
        PermissionsErrResponse &&perms_err_response) {
      using T = concat<QueryTuple, PermissionTuple>;
      try {
        soci::rowset<T> st = std::forward<QueryExecutor>(query_executor)();
        auto range = boost::make_iterator_range(st.begin(), st.end());

        return apply(
            viewPermissions<PermissionTuple>(range.front()),
            [this, range, &response_creator, &perms_err_response](
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
                    2);
              }
              auto query_range = range
                  | boost::adaptors::transformed([](auto &t) {
                                   return rebind(viewQuery<QueryTuple>(t));
                                 })
                  | boost::adaptors::filtered([](const auto &t) {
                                   return static_cast<bool>(t);
                                 })
                  | boost::adaptors::transformed([](auto t) { return *t; });
              return std::forward<ResponseCreator>(response_creator)(
                  query_range, perms...);
            });
      } catch (const std::exception &e) {
        return this->logAndReturnErrorResponse(
            QueryErrorType::kStatefulFailed, e.what(), 1);
      }
    }

    template <class Q>
    bool PostgresQueryExecutor::validateSignatures(const Q &query) {
      auto keys_range =
          query.signatures() | boost::adaptors::transformed([](const auto &s) {
            return s.publicKey().hex();
          });

      if (boost::size(keys_range) != 1) {
        return false;
      }
      std::string keys = *std::begin(keys_range);
      // not using bool since it is not supported by SOCI
      boost::optional<uint8_t> signatories_valid;

      auto qry = R"(
        SELECT count(public_key) = 1
        FROM account_has_signatory
        WHERE account_id = :account_id AND public_key = :pk
        )";

      try {
        *sql_ << qry, soci::into(signatories_valid),
            soci::use(query.creatorAccountId(), "account_id"),
            soci::use(keys, "pk");
      } catch (const std::exception &e) {
        log_->error("{}", e.what());
        return false;
      }

      return signatories_valid and *signatories_valid;
    }

    PostgresQueryExecutor::PostgresQueryExecutor(
        std::unique_ptr<soci::session> sql,
        KeyValueStorage &block_store,
        std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
        std::shared_ptr<shared_model::interface::BlockJsonConverter> converter,
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        logger::LoggerManagerTreePtr log_manager)
        : sql_(std::move(sql)),
          block_store_(block_store),
          pending_txs_storage_(std::move(pending_txs_storage)),
          visitor_(*sql_,
                   block_store_,
                   pending_txs_storage_,
                   std::move(converter),
                   response_factory,
                   perm_converter,
                   log_manager->getChild("Visitor")->getLogger()),
          query_response_factory_{std::move(response_factory)},
          log_(log_manager->getLogger()) {}

    QueryExecutorResult PostgresQueryExecutor::validateAndExecute(
        const shared_model::interface::Query &query,
        const bool validate_signatories = true) {
      visitor_.setCreatorId(query.creatorAccountId());
      visitor_.setQueryHash(query.hash());
      if (validate_signatories and not validateSignatures(query)) {
        // TODO [IR-1816] Akvinikym 03.12.18: replace magic number 3
        // with a named constant
        return query_response_factory_->createErrorQueryResponse(
            shared_model::interface::QueryResponseFactory::ErrorQueryType::
                kStatefulFailed,
            "query signatories did not pass validation",
            3,
            query.hash());
      }
      return boost::apply_visitor(visitor_, query.get());
    }

    bool PostgresQueryExecutor::validate(
        const shared_model::interface::BlocksQuery &query,
        const bool validate_signatories = true) {
      if (validate_signatories and not validateSignatures(query)) {
        log_->error("query signatories did not pass validation");
        return false;
      }
      if (not visitor_.hasAccountRolePermission(Role::kGetBlocks,
                                                query.creatorAccountId())) {
        log_->error("query creator does not have enough permissions");
        return false;
      }

      return true;
    }

    bool PostgresQueryExecutorVisitor::hasAccountRolePermission(
        shared_model::interface::permissions::Role permission,
        const std::string &account_id) const {
      using T = boost::tuple<int>;
      boost::format cmd(R"(%s)");
      try {
        soci::rowset<T> st =
            (sql_.prepare
                 << (cmd % getAccountRolePermissionCheckSql(permission)).str(),
             soci::use(account_id, "role_account_id"));
        return st.begin()->get<0>();
      } catch (const std::exception &e) {
        log_->error("Failed to validate query: {}", e.what());
        return false;
      }
    }

    PostgresQueryExecutorVisitor::PostgresQueryExecutorVisitor(
        soci::session &sql,
        KeyValueStorage &block_store,
        std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
        std::shared_ptr<shared_model::interface::BlockJsonConverter> converter,
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        logger::LoggerPtr log)
        : sql_(sql),
          block_store_(block_store),
          pending_txs_storage_(std::move(pending_txs_storage)),
          converter_(std::move(converter)),
          query_response_factory_{std::move(response_factory)},
          perm_converter_(std::move(perm_converter)),
          log_(std::move(log)) {}

    void PostgresQueryExecutorVisitor::setCreatorId(
        const shared_model::interface::types::AccountIdType &creator_id) {
      creator_id_ = creator_id;
    }

    void PostgresQueryExecutorVisitor::setQueryHash(
        const shared_model::interface::types::HashType &query_hash) {
      query_hash_ = query_hash;
    }

    std::unique_ptr<shared_model::interface::QueryResponse>
    PostgresQueryExecutorVisitor::logAndReturnErrorResponse(
        QueryErrorType error_type,
        QueryErrorMessageType error_body,
        QueryErrorCodeType error_code) const {
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
          error_type, error, error_code, query_hash_);
    }

    template <typename Query,
              typename QueryChecker,
              typename QueryApplier,
              typename... Permissions>
    QueryExecutorResult PostgresQueryExecutorVisitor::executeTransactionsQuery(
        const Query &q,
        QueryChecker &&qry_checker,
        const std::string &related_txs,
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

      auto base = boost::format(R"(WITH has_perms AS (%s),
      my_txs AS (%s),
      first_hash AS (%s),
      total_size AS (
        SELECT COUNT(*) FROM my_txs
      ),
      t AS (
        SELECT my_txs.height, my_txs.index
        FROM my_txs JOIN
        first_hash ON my_txs.height > first_hash.height
        OR (my_txs.height = first_hash.height AND
            my_txs.index >= first_hash.index)
        LIMIT :page_size
      )
      SELECT height, index, count, perm FROM t
      RIGHT OUTER JOIN has_perms ON TRUE
      JOIN total_size ON TRUE
      )");

      // select tx with specified hash
      auto first_by_hash = R"(SELECT height, index FROM position_by_hash
      WHERE hash = :hash LIMIT 1)";

      // select first ever tx
      auto first_tx = R"(SELECT height, index FROM position_by_hash
      ORDER BY height, index ASC LIMIT 1)";

      auto cmd = base % hasQueryPermission(creator_id_, q.accountId(), perms...)
          % related_txs;
      if (first_hash) {
        cmd = base % first_by_hash;
      } else {
        cmd = base % first_tx;
      }

      auto query = cmd.str();

      return executeQuery<QueryTuple, PermissionTuple>(
          applier(query),
          [&](auto range, auto &) {
            uint64_t total_size = 0;
            if (not boost::empty(range)) {
              total_size = boost::get<2>(*range.begin());
            }
            std::map<uint64_t, std::vector<uint64_t>> index;
            // unpack results to get map from block height to index of tx in
            // a block
            boost::for_each(range, [&index](auto t) {
              apply(t, [&index](auto &height, auto &idx, auto &) {
                index[height].push_back(idx);
              });
            });

            std::vector<std::unique_ptr<shared_model::interface::Transaction>>
                response_txs;
            // get transactions corresponding to indexes
            for (auto &block : index) {
              auto txs = this->getTransactionsFromBlock(
                  block.first,
                  [&block](auto) { return block.second; },
                  [](auto &) { return true; });
              std::move(
                  txs.begin(), txs.end(), std::back_inserter(response_txs));
            }

            if (response_txs.empty()) {
              if (first_hash) {
                // if 0 transactions are returned, and there is a specified
                // paging hash, we assume it's invalid, since query with valid
                // hash is guaranteed to return at least one transaction
                auto error = (boost::format("invalid pagination hash: %s")
                              % first_hash->hex())
                                 .str();
                return this->logAndReturnErrorResponse(
                    QueryErrorType::kStatefulFailed, error, 4);
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
                    query_incorrect.error_code);
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
                  std::move(response_txs), next_hash, total_size, query_hash_);
            }

            return query_response_factory_->createTransactionsPageResponse(
                std::move(response_txs), total_size, query_hash_);
          },
          notEnoughPermissionsResponse(perm_converter_, perms...));
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetAccount &q) {
      using QueryTuple =
          QueryType<shared_model::interface::types::AccountIdType,
                    shared_model::interface::types::DomainIdType,
                    shared_model::interface::types::QuorumType,
                    shared_model::interface::types::DetailType,
                    std::string>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd = (boost::format(R"(WITH has_perms AS (%s),
      t AS (
          SELECT a.account_id, a.domain_id, a.quorum, a.data, ARRAY_AGG(ar.role_id) AS roles
          FROM account AS a, account_has_roles AS ar
          WHERE a.account_id = :target_account_id
          AND ar.account_id = a.account_id
          GROUP BY a.account_id
      )
      SELECT account_id, domain_id, quorum, data, roles, perm
      FROM t RIGHT OUTER JOIN has_perms AS p ON TRUE
      )")
                  % hasQueryPermission(creator_id_,
                                       q.accountId(),
                                       Role::kGetMyAccount,
                                       Role::kGetAllAccounts,
                                       Role::kGetDomainAccounts))
                     .str();

      auto query_apply = [this](auto &account_id,
                                auto &domain_id,
                                auto &quorum,
                                auto &data,
                                auto &roles_str) {
        std::vector<shared_model::interface::types::RoleIdType> roles;
        auto roles_str_no_brackets = roles_str.substr(1, roles_str.size() - 2);
        boost::split(
            roles, roles_str_no_brackets, [](char c) { return c == ','; });
        return query_response_factory_->createAccountResponse(
            account_id, domain_id, quorum, data, std::move(roles), query_hash_);
      };

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(q.accountId(), "target_account_id"));
          },
          [this, &q, &query_apply](auto range, auto &) {
            if (range.empty()) {
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kNoAccount, q.accountId(), 0);
            }

            return apply(range.front(), query_apply);
          },
          notEnoughPermissionsResponse(perm_converter_,
                                       Role::kGetMyAccount,
                                       Role::kGetAllAccounts,
                                       Role::kGetDomainAccounts));
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetBlock &q) {
      if (not hasAccountRolePermission(Role::kGetBlocks, creator_id_)) {
        // no permission
        return query_response_factory_->createErrorQueryResponse(
            shared_model::interface::QueryResponseFactory::ErrorQueryType::
                kStatefulFailed,
            notEnoughPermissionsResponse(perm_converter_, Role::kGetBlocks)(),
            2,
            query_hash_);
      }

      auto ledger_height = block_store_.last_id();
      if (q.height() > ledger_height) {
        // invalid height
        return logAndReturnErrorResponse(
            QueryErrorType::kStatefulFailed,
            "requested height (" + std::to_string(q.height())
                + ") is greater than the ledger's one ("
                + std::to_string(ledger_height) + ")",
            3);
      }

      auto block_deserialization_msg = [height = q.height()] {
        return "could not retrieve block with given height: "
            + std::to_string(height);
      };
      auto serialized_block = block_store_.get(q.height());
      if (not serialized_block) {
        // for some reason, block with such height was not retrieved
        return logAndReturnErrorResponse(
            QueryErrorType::kStatefulFailed, block_deserialization_msg(), 1);
      }

      return converter_->deserialize(bytesToString(*serialized_block))
          .match(
              [this](auto &&block) {
                return this->query_response_factory_->createBlockResponse(
                    std::move(block.value), query_hash_);
              },
              [this, err_msg = block_deserialization_msg()](const auto &err) {
                auto extended_error =
                    err_msg + ", because it was not deserialized: " + err.error;
                return this->logAndReturnErrorResponse(
                    QueryErrorType::kStatefulFailed,
                    std::move(extended_error),
                    1);
              });
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetSignatories &q) {
      using QueryTuple = QueryType<std::string>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd = (boost::format(R"(WITH has_perms AS (%s),
      t AS (
          SELECT public_key FROM account_has_signatory
          WHERE account_id = :account_id
      )
      SELECT public_key, perm FROM t
      RIGHT OUTER JOIN has_perms ON TRUE
      )")
                  % hasQueryPermission(creator_id_,
                                       q.accountId(),
                                       Role::kGetMySignatories,
                                       Role::kGetAllSignatories,
                                       Role::kGetDomainSignatories))
                     .str();

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] { return (sql_.prepare << cmd, soci::use(q.accountId())); },
          [this, &q](auto range, auto &) {
            if (range.empty()) {
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kNoSignatories, q.accountId(), 0);
            }

            auto pubkeys = boost::copy_range<
                std::vector<shared_model::interface::types::PubkeyType>>(
                range | boost::adaptors::transformed([](auto t) {
                  return apply(t, [&](auto &public_key) {
                    return shared_model::interface::types::PubkeyType{
                        shared_model::crypto::Blob::fromHexString(public_key)};
                  });
                }));

            return query_response_factory_->createSignatoriesResponse(
                pubkeys, query_hash_);
          },
          notEnoughPermissionsResponse(perm_converter_,
                                       Role::kGetMySignatories,
                                       Role::kGetAllSignatories,
                                       Role::kGetDomainSignatories));
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetAccountTransactions &q) {
      std::string related_txs = R"(SELECT DISTINCT height, index
      FROM index_by_creator_height
      WHERE creator_id = :account_id
      ORDER BY height, index ASC)";

      const auto &pagination_info = q.paginationMeta();
      auto first_hash = pagination_info.firstTxHash();
      // retrieve one extra transaction to populate next_hash
      auto query_size = pagination_info.pageSize() + 1u;

      auto apply_query = [&](const auto &query) {
        return [&] {
          if (first_hash) {
            return (sql_.prepare << query,
                    soci::use(q.accountId()),
                    soci::use(first_hash->hex()),
                    soci::use(query_size));
          } else {
            return (sql_.prepare << query,
                    soci::use(q.accountId()),
                    soci::use(query_size));
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
                                      std::move(check_query),
                                      related_txs,
                                      apply_query,
                                      Role::kGetMyAccTxs,
                                      Role::kGetAllAccTxs,
                                      Role::kGetDomainAccTxs);
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetTransactions &q) {
      auto escape = [](auto &hash) { return "'" + hash.hex() + "'"; };
      std::string hash_str = std::accumulate(
          std::next(q.transactionHashes().begin()),
          q.transactionHashes().end(),
          escape(q.transactionHashes().front()),
          [&escape](auto &acc, auto &val) { return acc + "," + escape(val); });

      using QueryTuple =
          QueryType<shared_model::interface::types::HeightType, std::string>;
      using PermissionTuple = boost::tuple<int, int>;

      auto cmd =
          (boost::format(R"(WITH has_my_perm AS (%s),
      has_all_perm AS (%s),
      t AS (
          SELECT height, hash FROM position_by_hash WHERE hash IN (%s)
      )
      SELECT height, hash, has_my_perm.perm, has_all_perm.perm FROM t
      RIGHT OUTER JOIN has_my_perm ON TRUE
      RIGHT OUTER JOIN has_all_perm ON TRUE
      )") % getAccountRolePermissionCheckSql(Role::kGetMyTxs, "account_id")
           % getAccountRolePermissionCheckSql(Role::kGetAllTxs, "account_id")
           % hash_str)
              .str();

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd, soci::use(creator_id_, "account_id"));
          },
          [&](auto range, auto &my_perm, auto &all_perm) {
            if (boost::size(range) != q.transactionHashes().size()) {
              // TODO [IR-1816] Akvinikym 03.12.18: replace magic number 4
              // with a named constant
              // at least one of the hashes in the query was invalid -
              // nonexistent or permissions were missed
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kStatefulFailed,
                  "At least one of the supplied hashes is incorrect",
                  4);
            }
            std::map<uint64_t, std::unordered_set<std::string>> index;
            boost::for_each(range, [&index](auto t) {
              apply(t, [&index](auto &height, auto &hash) {
                index[height].insert(hash);
              });
            });

            std::vector<std::unique_ptr<shared_model::interface::Transaction>>
                response_txs;
            for (auto &block : index) {
              auto txs = this->getTransactionsFromBlock(
                  block.first,
                  [](auto size) {
                    return boost::irange(static_cast<decltype(size)>(0), size);
                  },
                  [&](auto &tx) {
                    return block.second.count(tx.hash().hex()) > 0
                        and (all_perm
                             or (my_perm
                                 and tx.creatorAccountId() == creator_id_));
                  });
              std::move(
                  txs.begin(), txs.end(), std::back_inserter(response_txs));
            }

            return query_response_factory_->createTransactionsResponse(
                std::move(response_txs), query_hash_);
          },
          notEnoughPermissionsResponse(
              perm_converter_, Role::kGetMyTxs, Role::kGetAllTxs));
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetAccountAssetTransactions &q) {
      std::string related_txs = R"(SELECT DISTINCT height, index
          FROM position_by_account_asset
          WHERE account_id = :account_id
          AND asset_id = :asset_id
          ORDER BY height, index ASC)";

      const auto &pagination_info = q.paginationMeta();
      auto first_hash = pagination_info.firstTxHash();
      // retrieve one extra transaction to populate next_hash
      auto query_size = pagination_info.pageSize() + 1u;

      auto apply_query = [&](const auto &query) {
        return [&] {
          if (first_hash) {
            return (sql_.prepare << query,
                    soci::use(q.accountId()),
                    soci::use(q.assetId()),
                    soci::use(first_hash->hex()),
                    soci::use(query_size));
          } else {
            return (sql_.prepare << query,
                    soci::use(q.accountId()),
                    soci::use(q.assetId()),
                    soci::use(query_size));
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
                                      std::move(check_query),
                                      related_txs,
                                      apply_query,
                                      Role::kGetMyAccAstTxs,
                                      Role::kGetAllAccAstTxs,
                                      Role::kGetDomainAccAstTxs);
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetAccountAssets &q) {
      using QueryTuple =
          QueryType<shared_model::interface::types::AccountIdType,
                    shared_model::interface::types::AssetIdType,
                    std::string>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd = (boost::format(R"(WITH has_perms AS (%s),
      t AS (
          SELECT * FROM account_has_asset
          WHERE account_id = :account_id
      )
      SELECT account_id, asset_id, amount, perm FROM t
      RIGHT OUTER JOIN has_perms ON TRUE
      )")
                  % hasQueryPermission(creator_id_,
                                       q.accountId(),
                                       Role::kGetMyAccAst,
                                       Role::kGetAllAccAst,
                                       Role::kGetDomainAccAst))
                     .str();

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] { return (sql_.prepare << cmd, soci::use(q.accountId())); },
          [&](auto range, auto &) {
            std::vector<
                std::tuple<shared_model::interface::types::AccountIdType,
                           shared_model::interface::types::AssetIdType,
                           shared_model::interface::Amount>>
                assets;
            boost::for_each(range, [&assets](auto t) {
              apply(t,
                    [&assets](auto &account_id, auto &asset_id, auto &amount) {
                      assets.push_back(std::make_tuple(
                          std::move(account_id),
                          std::move(asset_id),
                          shared_model::interface::Amount(amount)));
                    });
            });
            // TODO mboldyrev 2019.05.17 IR-473 implement pagination
            return query_response_factory_->createAccountAssetResponse(
                assets, assets.size(), boost::none, query_hash_);
          },
          notEnoughPermissionsResponse(perm_converter_,
                                       Role::kGetMyAccAst,
                                       Role::kGetAllAccAst,
                                       Role::kGetDomainAccAst));
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetAccountDetail &q) {
      using QueryTuple = QueryType<shared_model::interface::types::DetailType>;
      using PermissionTuple = boost::tuple<int>;

      std::string query_detail;
      if (q.key() and q.writer()) {
        auto filled_json = (boost::format("{\"%s\", \"%s\"}") % q.writer().get()
                            % q.key().get());
        query_detail = (boost::format(R"(SELECT json_build_object('%s'::text,
            json_build_object('%s'::text, (SELECT data #>> '%s'
            FROM account WHERE account_id = :account_id))) AS json)")
                        % q.writer().get() % q.key().get() % filled_json)
                           .str();
      } else if (q.key() and not q.writer()) {
        query_detail =
            (boost::format(
                 R"(SELECT json_object_agg(key, value) AS json FROM (SELECT
            json_build_object(kv.key, json_build_object('%1%'::text,
            kv.value -> '%1%')) FROM jsonb_each((SELECT data FROM account
            WHERE account_id = :account_id)) kv WHERE kv.value ? '%1%') AS
            jsons, json_each(json_build_object))")
             % q.key().get())
                .str();
      } else if (not q.key() and q.writer()) {
        query_detail = (boost::format(R"(SELECT json_build_object('%1%'::text,
          (SELECT data -> '%1%' FROM account WHERE account_id =
           :account_id)) AS json)")
                        % q.writer().get())
                           .str();
      } else {
        query_detail = (boost::format(R"(SELECT data#>>'{}' AS json FROM account
            WHERE account_id = :account_id)"))
                           .str();
      }
      auto cmd = (boost::format(R"(WITH has_perms AS (%s),
      detail AS (%s)
      SELECT json, perm FROM detail
      RIGHT OUTER JOIN has_perms ON TRUE
      )")
                  % hasQueryPermission(creator_id_,
                                       q.accountId(),
                                       Role::kGetMyAccDetail,
                                       Role::kGetAllAccDetail,
                                       Role::kGetDomainAccDetail)
                  % query_detail)
                     .str();

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(q.accountId(), "account_id"));
          },
          [this, &q](auto range, auto &) {
            if (range.empty()) {
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kNoAccountDetail, q.accountId(), 0);
            }

            return apply(range.front(), [this](auto &json) {
              return query_response_factory_->createAccountDetailResponse(
                  json, query_hash_);
            });
          },
          notEnoughPermissionsResponse(perm_converter_,
                                       Role::kGetMyAccDetail,
                                       Role::kGetAllAccDetail,
                                       Role::kGetDomainAccDetail));
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetRoles &q) {
      using QueryTuple = QueryType<shared_model::interface::types::RoleIdType>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd = (boost::format(
                      R"(WITH has_perms AS (%s)
      SELECT role_id, perm FROM role
      RIGHT OUTER JOIN has_perms ON TRUE
      )") % getAccountRolePermissionCheckSql(Role::kGetRoles))
                     .str();

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(creator_id_, "role_account_id"));
          },
          [&](auto range, auto &) {
            auto roles = boost::copy_range<
                std::vector<shared_model::interface::types::RoleIdType>>(
                range | boost::adaptors::transformed([](auto t) {
                  return apply(t, [](auto &role_id) { return role_id; });
                }));

            return query_response_factory_->createRolesResponse(roles,
                                                                query_hash_);
          },
          notEnoughPermissionsResponse(perm_converter_, Role::kGetRoles));
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetRolePermissions &q) {
      using QueryTuple = QueryType<std::string>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd = (boost::format(
                      R"(WITH has_perms AS (%s),
      perms AS (SELECT permission FROM role_has_permissions
                WHERE role_id = :role_name)
      SELECT permission, perm FROM perms
      RIGHT OUTER JOIN has_perms ON TRUE
      )") % getAccountRolePermissionCheckSql(Role::kGetRoles))
                     .str();

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(creator_id_, "role_account_id"),
                    soci::use(q.roleId(), "role_name"));
          },
          [this, &q](auto range, auto &) {
            if (range.empty()) {
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kNoRoles,
                  "{" + q.roleId() + ", " + creator_id_ + "}",
                  0);
            }

            return apply(range.front(), [this](auto &permission) {
              return query_response_factory_->createRolePermissionsResponse(
                  shared_model::interface::RolePermissionSet(permission),
                  query_hash_);
            });
          },
          notEnoughPermissionsResponse(perm_converter_, Role::kGetRoles));
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetAssetInfo &q) {
      using QueryTuple =
          QueryType<shared_model::interface::types::DomainIdType, uint32_t>;
      using PermissionTuple = boost::tuple<int>;

      auto cmd = (boost::format(
                      R"(WITH has_perms AS (%s),
      perms AS (SELECT domain_id, precision FROM asset
                WHERE asset_id = :asset_id)
      SELECT domain_id, precision, perm FROM perms
      RIGHT OUTER JOIN has_perms ON TRUE
      )") % getAccountRolePermissionCheckSql(Role::kReadAssets))
                     .str();

      return executeQuery<QueryTuple, PermissionTuple>(
          [&] {
            return (sql_.prepare << cmd,
                    soci::use(creator_id_, "role_account_id"),
                    soci::use(q.assetId(), "asset_id"));
          },
          [this, &q](auto range, auto &) {
            if (range.empty()) {
              return this->logAndReturnErrorResponse(
                  QueryErrorType::kNoAsset,
                  "{" + q.assetId() + ", " + creator_id_ + "}",
                  0);
            }

            return apply(range.front(),
                         [this, &q](auto &domain_id, auto &precision) {
                           return query_response_factory_->createAssetResponse(
                               q.assetId(), domain_id, precision, query_hash_);
                         });
          },
          notEnoughPermissionsResponse(perm_converter_, Role::kReadAssets));
    }

    QueryExecutorResult PostgresQueryExecutorVisitor::operator()(
        const shared_model::interface::GetPendingTransactions &q) {
      std::vector<std::unique_ptr<shared_model::interface::Transaction>>
          response_txs;
      auto interface_txs =
          pending_txs_storage_->getPendingTransactions(creator_id_);
      response_txs.reserve(interface_txs.size());

      std::transform(interface_txs.begin(),
                     interface_txs.end(),
                     std::back_inserter(response_txs),
                     [](auto &tx) { return clone(*tx); });
      return query_response_factory_->createTransactionsResponse(
          std::move(response_txs), query_hash_);
    }

    template <typename ReturnValueType>
    bool PostgresQueryExecutorVisitor::existsInDb(
        const std::string &table_name,
        const std::string &key_name,
        const std::string &value_name,
        const std::string &value) const {
      auto cmd = (boost::format(R"(SELECT %s
                                   FROM %s
                                   WHERE %s = '%s'
                                   LIMIT 1)")
                  % value_name % table_name % key_name % value)
                     .str();
      soci::rowset<ReturnValueType> result = this->sql_.prepare << cmd;
      return result.begin() != result.end();
    }

  }  // namespace ametsuchi
}  // namespace iroha
