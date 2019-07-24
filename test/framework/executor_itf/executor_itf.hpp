/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_FRAMEWORK_EXECUTOR_ITF_HPP
#define IROHA_TEST_FRAMEWORK_EXECUTOR_ITF_HPP

#include <memory>

#include <boost/mpl/contains.hpp>
#include <boost/optional.hpp>
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "ametsuchi/query_executor.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "common/result.hpp"
#include "framework/common_constants.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "module/shared_model/command_mocks.hpp"
#include "module/shared_model/query_mocks.hpp"

namespace shared_model {
  namespace crypto {
    class PublicKey;
  }
  namespace interface {
    class Command;
    class MockCommandFactory;
    class MockQueryFactory;
    class Transaction;
  }
}  // namespace shared_model

namespace iroha {
  namespace integration_framework {

    class ExecutorItf {
     public:
      /**
       * Create and initialize an ExecutorItf.
       * - connect to database 
       * - prepare database schema
       * - initialize command & query executors
       * - create admin account, role and domain with all permissions
       *
       * @param pg_opts (optional) The options for database connection. When not
       * provided, use the default.
       * @return Created ExecutorItf or string error description.
       */
      static iroha::expected::Result<std::unique_ptr<ExecutorItf>, std::string>
      create(boost::optional<iroha::ametsuchi::PostgresOptions> pg_opts =
                 boost::none);

      ~ExecutorItf();

      // ------------------- execute commands & transactions -------------------

      /**
       * Execute a command as account.
       * @param cmd The command to execute.
       * @param account_id The issuer account id.
       * @return Result of command execution.
       */
      iroha::ametsuchi::CommandResult executeCommandAsAccount(
          const shared_model::interface::Command &cmd,
          const std::string &account_id) const;

      /**
       * Execute a command as account.
       * @tparam SpecificCommand The type of executed specific command.
       * @param cmd The command to execute.
       * @param account_id The issuer account id.
       * @return Result of command execution.
       */
      template <typename SpecificCommand,
                typename = std::enable_if_t<boost::mpl::contains<
                    shared_model::interface::Command::CommandVariantType::types,
                    typename SpecificCommand::ModelType>::type::value>>
      iroha::ametsuchi::CommandResult executeCommandAsAccount(
          const SpecificCommand &specific_cmd,
          const std::string &account_id) const {
        shared_model::interface::Command::CommandVariantType variant{
            specific_cmd};
        shared_model::interface::MockCommand cmd;
        EXPECT_CALL(cmd, get()).WillRepeatedly(::testing::ReturnRef(variant));
        return executeCommandAsAccount(cmd, account_id);
      }

      /**
       * Execute a command as admin.
       * @tparam SpecificCommand The type of executed specific command.
       * @param cmd The command to execute.
       * @return Result of command execution.
       */
      template <typename T>
      auto executeCommand(const T &cmd) const
          -> decltype(executeCommandAsAccount(cmd, std::string{})) {
        return executeCommandAsAccount(cmd, common_constants::kAdminId);
      }

      /**
       * Execute a transaction.
       * @param cmd The transaction to execute.
       * @param do_validation Whether to enable permissions validation.
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
                typename = std::enable_if_t<boost::mpl::contains<
                    shared_model::interface::Query::QueryVariantType::types,
                    SpecificQuery>::type::value>>
      iroha::ametsuchi::QueryExecutorResult executeQuery(
          const SpecificQuery &specific_query,
          const std::string &account_id,
          boost::optional<shared_model::interface::types::CounterType>
              query_counter) {
        shared_model::interface::Query::QueryVariantType variant{
            specific_query};
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
       * Execute a query as account.
       * @tparam T The type of executed specific query that has the member type
       * ModelType of the corresponding interface specific query.
       * @param query The query to execute.
       * @param account_id The issuer account id.
       * @param query_counter The value to set to query counter field. If
       * boost::none provided, the built-in query counter value will be used.
       * @return Result of query execution.
       */
      template <typename T, typename SpecificQuery = typename T::ModelType>
      iroha::ametsuchi::QueryExecutorResult executeQuery(
          const T &specific_query,
          const std::string &account_id,
          boost::optional<shared_model::interface::types::CounterType>
              query_counter) {
        return executeQuery<SpecificQuery>(
            specific_query, account_id, query_counter);
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
          const shared_model::crypto::PublicKey &pubkey,
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
      ExecutorItf(logger::LoggerManagerTreePtr log_manager,
                  iroha::ametsuchi::PostgresOptions pg_opts);

      /**
       * Connect to database, prepare schema and initialize the depending
       * objects.
       * @return The aggregate result of required actions.
       */
      iroha::expected::Result<void, std::string> connect();

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
          const shared_model::crypto::PublicKey &pubkey,
          const shared_model::interface::RolePermissionSet &role_perms) const;

      /// Grant all grantable permissions of the given account to admin.
      iroha::ametsuchi::CommandResult grantAllToAdmin(
          const std::string &account_name) const;

      logger::LoggerManagerTreePtr log_manager_;
      logger::LoggerPtr log_;

      iroha::ametsuchi::PostgresOptions pg_opts_;

      std::unique_ptr<shared_model::interface::MockCommandFactory>
          mock_command_factory_;
      std::unique_ptr<shared_model::interface::MockQueryFactory>
          mock_query_factory_;

      std::shared_ptr<iroha::ametsuchi::CommandExecutor> cmd_executor_;
      std::shared_ptr<iroha::ametsuchi::TransactionExecutor> tx_executor_;
      std::shared_ptr<iroha::ametsuchi::QueryExecutor> query_executor_;

      shared_model::interface::types::CounterType query_counter_;
    };

  }  // namespace integration_framework
}  // namespace iroha

#endif  // IROHA_TEST_FRAMEWORK_EXECUTOR_ITF_HPP
