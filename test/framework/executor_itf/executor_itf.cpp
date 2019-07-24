/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/executor_itf/executor_itf.hpp"

#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_query_executor.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "framework/config_helper.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/permissions.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace iroha::integration_framework;
using namespace iroha::ametsuchi;
using namespace common_constants;
using namespace iroha::expected;

namespace {
  logger::LoggerManagerTreePtr getDefaultLogManager() {
    return getTestLoggerManager()->getChild("ExecutorITF");
  }

  std::string getDefaultRole(const std::string &name) {
    return name + "_default_role";
  }
}  // namespace

ExecutorItf::ExecutorItf(logger::LoggerManagerTreePtr log_manager,
                         iroha::ametsuchi::PostgresOptions pg_opts)
    : log_manager_(std::move(log_manager)),
      log_(log_manager_->getLogger()),
      pg_opts_(std::move(pg_opts)),
      mock_command_factory_(
          std::make_unique<shared_model::interface::MockCommandFactory>()),
      mock_query_factory_(
          std::make_unique<shared_model::interface::MockQueryFactory>()),
      query_counter_(0) {}

ExecutorItf::~ExecutorItf() {
  // storage cleanup
}

using CreateResult = Result<std::unique_ptr<ExecutorItf>, std::string>;

CreateResult ExecutorItf::create(
    boost::optional<iroha::ametsuchi::PostgresOptions> pg_opts) {
  auto log_manager = getDefaultLogManager();
  std::unique_ptr<ExecutorItf> executor_itf(
      new ExecutorItf(log_manager, pg_opts.value_or_eval([&log_manager] {
        return iroha::ametsuchi::PostgresOptions{
            ::integration_framework::getPostgresCredsOrDefault(),
            ::integration_framework::kDefaultWorkingDatabaseName,
            log_manager->getChild("PostgresOptions")->getLogger()};
      })));
  return executor_itf->connect() | [&executor_itf] {
    return executor_itf->createAdmin().match(
        [&executor_itf](const auto &) -> CreateResult {
          return std::move(executor_itf);
        },
        [](const auto &error) -> CreateResult {
          return error.error.toString();
        });
  };
}

CommandResult ExecutorItf::executeCommandAsAccount(
    const shared_model::interface::Command &cmd,
    const std::string &account_id) const {
  cmd_executor_->setCreatorAccountId(account_id);
  return cmd_executor_->execute(cmd);
}

Result<void, TxExecutionError> ExecutorItf::executeTransaction(
    const shared_model::interface::Transaction &transaction,
    bool do_validation) const {
  return tx_executor_->execute(transaction, do_validation);
}

iroha::ametsuchi::QueryExecutorResult ExecutorItf::executeQuery(
    const shared_model::interface::Query &query) const {
  return query_executor_->validateAndExecute(query, false);
}

const std::unique_ptr<shared_model::interface::MockCommandFactory>
    &ExecutorItf::getMockCommandFactory() const {
  return mock_command_factory_;
}

const std::unique_ptr<shared_model::interface::MockQueryFactory>
    &ExecutorItf::getMockQueryFactory() const {
  return mock_query_factory_;
}

CommandResult ExecutorItf::createRoleWithPerms(
    const std::string &role_id,
    const shared_model::interface::RolePermissionSet &role_permissions) const {
  return executeCommand(
      *getMockCommandFactory()->constructCreateRole(role_id, role_permissions));
}

CommandResult ExecutorItf::createUserWithPerms(
    const std::string &account_name,
    const std::string &domain,
    const shared_model::crypto::PublicKey &pubkey,
    const shared_model::interface::RolePermissionSet &role_perms) const {
  return createUserWithPermsInternal(account_name, domain, pubkey, role_perms) |
      [&, this] { return this->grantAllToAdmin(account_name + "@" + domain); };
}

CommandResult ExecutorItf::createDomain(const std::string &name) const {
  const std::string default_role = getDefaultRole(name);
  createRoleWithPerms(default_role, {});
  return executeCommand(
      *getMockCommandFactory()->constructCreateDomain(name, default_role));
}

Result<void, std::string> ExecutorItf::connect() {
  // initialize DB session, command & query executors
  return {};
}

CommandResult ExecutorItf::grantAllToAdmin(
    const std::string &account_id) const {
  static const std::string admin_role_name = getDefaultRole(kAdminName);
  shared_model::interface::GrantablePermissionSet all_grantable_perms;
  CommandResult grant_perm_result =
      executeCommand(*getMockCommandFactory()->constructAppendRole(
          account_id, admin_role_name));
  all_grantable_perms.setAll();
  all_grantable_perms.iterate(
      [this, &account_id, &grant_perm_result](const auto &perm) {
        grant_perm_result |= [this, perm, &account_id] {
          return this->executeCommandAsAccount(
              *this->getMockCommandFactory()->constructGrantPermission(kAdminId,
                                                                       perm),
              account_id);
        };
      });
  return grant_perm_result | [&, this] {
    return this->executeCommand(
        *this->getMockCommandFactory()->constructDetachRole(account_id,
                                                            admin_role_name));
  };
}

CommandResult ExecutorItf::createUserWithPermsInternal(
    const std::string &account_name,
    const std::string &domain,
    const shared_model::crypto::PublicKey &pubkey,
    const shared_model::interface::RolePermissionSet &role_perms) const {
  createDomain(domain);

  const std::string account_id = account_name + "@" + domain;
  const std::string account_role_name = getDefaultRole(account_name);

  return executeCommand(*getMockCommandFactory()->constructCreateAccount(
             account_name, domain, pubkey))
      | [&, this] { return createRoleWithPerms(account_role_name, role_perms); }
  | [&, this] {
      return this->executeCommand(
          *this->getMockCommandFactory()->constructAppendRole(
              account_id, account_role_name));
    };
}

CommandResult ExecutorItf::createAdmin() const {
  shared_model::interface::RolePermissionSet all_role_perms;
  all_role_perms.setAll();
  return createUserWithPermsInternal(
      kAdminName, kDomain, kAdminKeypair.publicKey(), all_role_perms);
}
