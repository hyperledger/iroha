/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_SPECIFIC_QUERY_EXECUTOR_HPP
#define IROHA_POSTGRES_SPECIFIC_QUERY_EXECUTOR_HPP

#include "ametsuchi/specific_query_executor.hpp"

#include <soci/soci.h>
#include "common/result.hpp"
#include "interfaces/iroha_internal/query_response_factory.hpp"
#include "logger/logger_fwd.hpp"

namespace shared_model {
  namespace interface {
    class PermissionToString;
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
  }  // namespace interface
}  // namespace shared_model

namespace iroha {

  class PendingTransactionStorage;

  namespace ametsuchi {

    class BlockStorage;

    using QueryErrorType =
        shared_model::interface::QueryResponseFactory::ErrorQueryType;

    using ErrorQueryResponse = shared_model::interface::ErrorQueryResponse;
    using QueryErrorMessageType = ErrorQueryResponse::ErrorMessageType;
    using QueryErrorCodeType = ErrorQueryResponse::ErrorCodeType;

    class PostgresSpecificQueryExecutor : public SpecificQueryExecutor {
     public:
      PostgresSpecificQueryExecutor(
          soci::session &sql,
          BlockStorage &block_store,
          std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
          std::shared_ptr<shared_model::interface::QueryResponseFactory>
              response_factory,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter,
          logger::LoggerPtr log);

      QueryExecutorResult execute(
          const shared_model::interface::Query &qry) override;

      bool hasAccountRolePermission(
          shared_model::interface::permissions::Role permission,
          const std::string &account_id) const override;

      QueryExecutorResult operator()(
          const shared_model::interface::GetAccount &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetBlock &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetSignatories &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetAccountTransactions &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetTransactions &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetAccountAssetTransactions &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetAccountAssets &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetAccountDetail &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetRoles &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetRolePermissions &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetAssetInfo &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetPendingTransactions &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetPeers &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

      QueryExecutorResult operator()(
          const shared_model::interface::GetEngineReceipts &q,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash);

     private:
      /**
       * Get transactions from block using range from range_gen and filtered by
       * predicate pred and store them in dest_it
       */
      template <typename RangeGen, typename Pred, typename OutputIterator>
      iroha::expected::Result<void, std::string> getTransactionsFromBlock(
          uint64_t block_id,
          RangeGen &&range_gen,
          Pred &&pred,
          OutputIterator dest_it);

      /**
       * Execute query and return its response
       * @tparam QueryTuple - types of values, returned by the query
       * @tparam PermissionTuple - permissions, needed for the query
       * @tparam QueryExecutor - type of function, which executes the query
       * @tparam ResponseCreator - type of function, which creates response of
       * the query, successful or error one
       * @tparam PermissionsErrResponse - type of function, which creates error
       * response in case something wrong with permissions
       * @param query_executor - function, executing query
       * @param query_hash - hash of query
       * @param response_creator - function, creating query response
       * @param perms_err_response - function, creating error response
       * @return query response created as a result of query execution
       */
      template <typename QueryTuple,
                typename PermissionTuple,
                typename QueryExecutor,
                typename ResponseCreator,
                typename PermissionsErrResponse>
      QueryExecutorResult executeQuery(
          QueryExecutor &&query_executor,
          const shared_model::interface::types::HashType &query_hash,
          ResponseCreator &&response_creator,
          PermissionsErrResponse &&perms_err_response);

      /**
       * Create a query error response and log it
       * @param error_type - type of query error
       * @param error_body - stringified error of the query
       * @param error_code of the query
       * @param query_hash - hash of query
       * @return ptr to created error response
       */
      std::unique_ptr<shared_model::interface::QueryResponse>
      logAndReturnErrorResponse(
          iroha::ametsuchi::QueryErrorType error_type,
          QueryErrorMessageType error_body,
          QueryErrorCodeType error_code,
          const shared_model::interface::types::HashType &query_hash) const;

      /**
       * Execute query which returns list of transactions
       * uses pagination
       * @param query - query object
       * @param creator_id - query creator account id
       * @param query_hash - hash of query
       * @param qry_checker - fallback checker of the query, needed if paging
       * hash is not specified and 0 transaction are returned as a query result
       * @param related_txs - SQL query which returns transaction relevant
       * to this query
       * @param applier - function which accepts SQL
       * and returns another function which executes that query
       * @param perms - permissions, necessary to execute the query
       * @return Result of a query execution
       */
      template <typename Query,
                typename QueryChecker,
                typename QueryApplier,
                typename... Permissions>
      QueryExecutorResult executeTransactionsQuery(
          const Query &query,
          const shared_model::interface::types::AccountIdType &creator_id,
          const shared_model::interface::types::HashType &query_hash,
          QueryChecker &&qry_checker,
          char const *related_txs,
          QueryApplier applier,
          Permissions... perms);

      /**
       * Check if entry with such key exists in the database
       * @tparam ReturnValueType - type of the value to be returned in the
       * underlying query
       * @param table_name - name of the table to be checked
       * @param key_name - name of the table attribute, against which the search
       * is performed
       * @param value_name - name of the value, which is to be returned
       * from the search (attribute with such name is to exist)
       * @param value - actual value of the key attribute
       * @return true, if entry with such value of the key attribute exists,
       * false otherwise
       *
       * @throws if check query finishes with an exception
       */
      template <typename ReturnValueType>
      bool existsInDb(const std::string &table_name,
                      const std::string &key_name,
                      const std::string &value_name,
                      const std::string &value) const;

      struct QueryFallbackCheckResult {
        QueryFallbackCheckResult() = default;
        QueryFallbackCheckResult(
            shared_model::interface::ErrorQueryResponse::ErrorCodeType
                error_code,
            shared_model::interface::ErrorQueryResponse::ErrorMessageType
                &&error_message)
            : contains_error{true},
              error_code{error_code},
              error_message{std::move(error_message)} {}

        explicit operator bool() const {
          return contains_error;
        }
        bool contains_error = false;
        shared_model::interface::ErrorQueryResponse::ErrorCodeType error_code =
            0;
        shared_model::interface::ErrorQueryResponse::ErrorMessageType
            error_message = "";
      };

      soci::session &sql_;
      BlockStorage &block_store_;
      std::shared_ptr<PendingTransactionStorage> pending_txs_storage_;
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          query_response_factory_;
      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter_;
      logger::LoggerPtr log_;
      std::string ordering_str_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_SPECIFIC_QUERY_EXECUTOR_HPP
