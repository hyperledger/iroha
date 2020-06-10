/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_FRAMEWORK_EXECUTOR_ITF_HPP
#define IROHA_TEST_FRAMEWORK_EXECUTOR_ITF_HPP

#include <memory>

#include <boost/optional.hpp>
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "ametsuchi/query_executor.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "common/result.hpp"
#include "framework/common_constants.hpp"
#include "framework/executor_itf/executor_itf_helper.hpp"
#include "framework/executor_itf/executor_itf_param.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/queries/query.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "module/shared_model/command_mocks.hpp"
#include "module/shared_model/query_mocks.hpp"

namespace shared_model {
  namespace interface {
    class MockCommandFactory;
    class MockQueryFactory;
    class Transaction;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {
    class SpecificQueryExecutor;
  }

  namespace integration_framework {

    class ExecutorItf {
     public:
      /**
       * Create and initialize an ExecutorItf.
       * Creates admin account, role and domain with all permissions.
       * @param target The backend that will be used (@see ExecutorItfTarget).
       * @return Created ExecutorItf or string error description.
       */
      static iroha::expected::Result<std::unique_ptr<ExecutorItf>, std::string>
      create(ExecutorItfTarget target);

      ~ExecutorItf();

      // ------------------- execute commands & transactions -------------------

      /**
       * Execute a command as account.
       * @param cmd The command to execute.
       * @param account_id The issuer account id.
       * @param do_validation Initializes the same parameter of command
       * executor.
       * @return Result of command execution.
       */
      iroha::ametsuchi::CommandResult executeCommandAsAccount(
          const shared_model::interface::Command &cmd,
          const std::string &account_id,
          bool do_validation) const;

      /**
       * Execute a command as account.
       * @tparam SpecificCommand The type of executed specific command.
       * @param cmd The command to execute.
       * @param account_id The issuer account id.
       * @param do_validation Whether to perform permissions check.
       * @return Result of command execution.
       */
      template <typename SpecificCommand,
                typename = std::enable_if_t<detail::isSpecificCommand<
                    typename SpecificCommand::ModelType>>>
      iroha::ametsuchi::CommandResult executeCommandAsAccount(
          const SpecificCommand &specific_cmd,
          const std::string &account_id,
          bool do_validation) const {
        shared_model::interface::Command::CommandVariantType variant{
            specific_cmd};
        shared_model::interface::MockCommand cmd;
        EXPECT_CALL(cmd, get()).WillRepeatedly(::testing::ReturnRef(variant));
        return executeCommandAsAccount(cmd, account_id, do_validation);
      }

      /**
       * Execute a command as admin without validation.
       * @tparam SpecificCommand The type of executed specific command.
       * @param cmd The command to execute.
       * @return Result of command execution.
       */
      template <typename T>
      auto executeMaintenanceCommand(const T &cmd) const
          -> decltype(executeCommandAsAccount(cmd, std::string{}, false)) {
        return executeCommandAsAccount(cmd, common_constants::kAdminId, false);
      }

      /**
       * Execute a transaction.
       * @param cmd The transaction to execute.
       * @param do_validation Whether to perform permissions check.
       * @return Error in case of failure.
       */
      iroha::expected::Result<void, iroha::ametsuchi::TxExecutionError>
      executeTransaction(
          const shared_model::interface::Transaction &transaction,
          bool do_validation = true) const;

      // ------------------------- execute queries -----------------------------

      /**
       * Execute a query.
       * @param query The query to execute.
       * @return Result of query execution.
       */
      iroha::ametsuchi::QueryExecutorResult executeQuery(
          const shared_model::interface::Query &query) const;

      /**
       * Execute a query as account.
       * @tparam SpecificQuery The interface type of executed specific query.
       * @param query The query to execute.
       * @param account_id The issuer account id.
       * @param query_counter The value to set to query counter field. If
       * boost::none provided, the built-in query counter value will be used.
       * @return Result of query execution.
       */
      template <typename SpecificQuery,
                typename = std::enable_if_t<detail::isSpecificQuery<
                    detail::InterfaceQuery<SpecificQuery>>>>
      iroha::ametsuchi::QueryExecutorResult executeQuery(
          const SpecificQuery &specific_query,
          const std::string &account_id,
          boost::optional<shared_model::interface::types::CounterType>
              query_counter = boost::none) {
        shared_model::interface::Query::QueryVariantType variant{
            detail::getInterfaceQueryRef(specific_query)};
        shared_model::interface::MockQuery query;
        EXPECT_CALL(query, get()).WillRepeatedly(::testing::ReturnRef(variant));
        EXPECT_CALL(query, creatorAccountId())
            .WillRepeatedly(::testing::ReturnRef(account_id));
        if (query_counter) {
          EXPECT_CALL(query, queryCounter())
              .WillRepeatedly(::testing::Return(query_counter.value()));
        } else {
          EXPECT_CALL(query, queryCounter())
              .WillRepeatedly(::testing::Return(++query_counter_));
        }
        EXPECT_CALL(query, hash())
            .WillRepeatedly(::testing::ReturnRefOfCopy(
                shared_model::interface::types::HashType{query.toString()}));
        return executeQuery(query);
      }

      /**
       * Execute a query as admin.
       * @tparam T The type of executed specific query.
       * @param query The query to execute.
       * @return Result of query execution.
       */
      template <typename T>
      auto executeQuery(const T &query) -> decltype(
          executeQuery(query,
                       std::string{},
                       shared_model::interface::types::CounterType{})) {
        return executeQuery(
            query, common_constants::kAdminId, ++query_counter_);
      }

      /**
       * A struct that holds the general query response and provides the result
       * of extraction of a specific response from it.
       */
      template <typename SpecificQueryResponse>
      struct SpecificQueryResult {
        SpecificQueryResult(
            iroha::ametsuchi::QueryExecutorResult &&query_response)
            : wrapped_response(std::move(query_response)),
              specific_response(
                  detail::convertToSpecificQueryResponse<SpecificQueryResponse>(
                      wrapped_response)) {}

        iroha::ametsuchi::QueryExecutorResult wrapped_response;
        iroha::expected::Result<const SpecificQueryResponse &,
                                iroha::ametsuchi::QueryExecutorResult &>
            specific_response;
      };

      /**
       * Execute a query as account and try to convert the result to appropriate
       * type.
       * @param query The query to execute.
       * @param account_id The issuer account id.
       * @param query_counter The value to set to query counter field. If
       * boost::none provided, the built-in query counter value will be used.
       * @return Result of query execution.
       */
      template <typename T,
                typename SpecificQuery = detail::InterfaceQuery<T>,
                typename ExpectedReturnType =
                    detail::GetSpecificQueryResponse<SpecificQuery>,
                typename... Types>
      SpecificQueryResult<ExpectedReturnType> executeQueryAndConvertResult(
          const T &specific_query, Types &&... args) {
        return SpecificQueryResult<ExpectedReturnType>(
            executeQuery(specific_query, std::forward<Types>(args)...));
      }

      // -------------- mock command and query factories getters ---------------

      /// Get mock command factory.
      const std::unique_ptr<shared_model::interface::MockCommandFactory>
          &getMockCommandFactory() const;

      /// Get mock query factory.
      const std::unique_ptr<shared_model::interface::MockQueryFactory>
          &getMockQueryFactory() const;

      // ------------------ helper functions to prepare state ------------------

      /**
       * Create a role with given permissions.
       * @param role_id The created role id.
       * @param role_permissions The permissions for this role.
       * @return The aggregate result of corresponding commands.
       */
      iroha::ametsuchi::CommandResult createRoleWithPerms(
          const std::string &role_id,
          const shared_model::interface::RolePermissionSet &role_permissions)
          const;

      /**
       * Create an account.
       * The account is added to a default group and default role that are
       * created for it in case they do not exist.
       * All grantable permissions of this account are provided for admin.
       * @param account_name The created account name (without domain).
       * @param domain The domain to add the account to. Will be created if not
       * exists.
       * @param pubkey The public key of created account.
       * @param role_perms The permissions for this role.
       * @return The aggregate result of corresponding commands.
       */
      iroha::ametsuchi::CommandResult createUserWithPerms(
          const std::string &account_name,
          const std::string &domain,
          shared_model::interface::types::PublicKeyHexStringView pubkey,
          const shared_model::interface::RolePermissionSet &role_perms) const;

      /**
       * Create a domain.
       * The default role (with no permissions) for this domain is created if it
       * does not exist.
       * @param name The created domain name.
       * @return The aggregate result of corresponding commands.
       */
      iroha::ametsuchi::CommandResult createDomain(
          const std::string &name) const;

     private:
      ExecutorItf(
          std::shared_ptr<iroha::ametsuchi::CommandExecutor> cmd_executor,
          std::shared_ptr<iroha::ametsuchi::SpecificQueryExecutor>
              query_executor,
          logger::LoggerManagerTreePtr log_manager);

      /// Prepare WSV (as part of initialization).
      iroha::expected::Result<void, std::string> prepareState() const;

      /// Create admin account with all permissions.
      iroha::ametsuchi::CommandResult createAdmin() const;

      /**
       * Create an account.
       * The account is added to a default group and default role that are
       * created for it in case they do not exist.
       * @param account_name The created account name (without domain).
       * @param domain The domain to add the account to. Will be created if not
       * exists.
       * @param pubkey The public key of created account.
       * @param role_perms The permissions for this role.
       * @return The aggregate result of corresponding commands.
       */
      iroha::ametsuchi::CommandResult createUserWithPermsInternal(
          const std::string &account_name,
          const std::string &domain,
          shared_model::interface::types::PublicKeyHexStringView pubkey,
          const shared_model::interface::RolePermissionSet &role_perms) const;

      /// Grant all grantable permissions of the given account to admin.
      iroha::ametsuchi::CommandResult grantAllToAdmin(
          const std::string &account_name) const;

      logger::LoggerManagerTreePtr log_manager_;
      logger::LoggerPtr log_;

      const std::unique_ptr<shared_model::interface::MockCommandFactory>
          mock_command_factory_;
      const std::unique_ptr<shared_model::interface::MockQueryFactory>
          mock_query_factory_;

      std::shared_ptr<iroha::ametsuchi::CommandExecutor> cmd_executor_;
      std::shared_ptr<iroha::ametsuchi::TransactionExecutor> tx_executor_;
      std::shared_ptr<iroha::ametsuchi::SpecificQueryExecutor> query_executor_;

      mutable shared_model::interface::types::CounterType orphan_cmd_counter_;
      shared_model::interface::types::CounterType query_counter_;
    };

  }  // namespace integration_framework
}  // namespace iroha

#endif  // IROHA_TEST_FRAMEWORK_EXECUTOR_ITF_HPP
