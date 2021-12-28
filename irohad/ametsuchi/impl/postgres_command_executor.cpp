/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_command_executor.hpp"

#include <exception>
#include <forward_list>
#include <memory>

#include <fmt/core.h>
#include <soci/postgresql/soci-postgresql.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/format.hpp>
#include "ametsuchi/impl/executor_common.hpp"
#include "ametsuchi/impl/postgres_block_storage.hpp"
#include "ametsuchi/impl/postgres_burrow_storage.hpp"
#include "ametsuchi/impl/postgres_specific_query_executor.hpp"
#include "ametsuchi/impl/soci_std_optional.hpp"
#include "ametsuchi/impl/soci_string_view.hpp"
#include "ametsuchi/impl/soci_utils.hpp"
#include "ametsuchi/setting_query.hpp"
#include "ametsuchi/vm_caller.hpp"
#include "interfaces/commands/add_asset_quantity.hpp"
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/commands/add_signatory.hpp"
#include "interfaces/commands/append_role.hpp"
#include "interfaces/commands/call_engine.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/commands/compare_and_set_account_detail.hpp"
#include "interfaces/commands/create_account.hpp"
#include "interfaces/commands/create_asset.hpp"
#include "interfaces/commands/create_domain.hpp"
#include "interfaces/commands/create_role.hpp"
#include "interfaces/commands/detach_role.hpp"
#include "interfaces/commands/grant_permission.hpp"
#include "interfaces/commands/remove_peer.hpp"
#include "interfaces/commands/remove_signatory.hpp"
#include "interfaces/commands/revoke_permission.hpp"
#include "interfaces/commands/set_account_detail.hpp"
#include "interfaces/commands/set_quorum.hpp"
#include "interfaces/commands/set_setting_value.hpp"
#include "interfaces/commands/subtract_asset_quantity.hpp"
#include "interfaces/commands/transfer_asset.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/permission_to_string.hpp"
#include "interfaces/permissions.hpp"
#include "utils/string_builder.hpp"

using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;

namespace {
  constexpr size_t kRolePermissionSetSize =
      shared_model::interface::RolePermissionSet::size();
  constexpr size_t kGrantablePermissionSetSize =
      shared_model::interface::GrantablePermissionSet::size();

  // soci does not allow boolean variable exchange, so use PostgreSQL conversion
  // from string
  const std::string kPgTrue{"true"};
  const std::string kPgFalse{"false"};

  std::string makeJsonString(std::string value) {
    return std::string{"\""} + value + "\"";
  }

  iroha::expected::Error<iroha::ametsuchi::CommandError> makeCommandError(
      std::string command_name,
      const iroha::ametsuchi::CommandError::ErrorCodeType code,
      std::string &&query_args) noexcept {
    return iroha::expected::makeError(iroha::ametsuchi::CommandError{
        std::move(command_name), code, std::move(query_args)});
  }

  /// mapping between pairs of SQL error substrings and related fake error
  /// codes, which are indices in this collection
  const std::vector<std::tuple<std::string, std::string>> kSqlToFakeErrorCode =
      {std::make_tuple("Key (account_id)=", "is not present in table"),
       std::make_tuple("Key (permittee_account_id)", "is not present in table"),
       std::make_tuple("Key (role_id)=", "is not present in table"),
       std::make_tuple("Key (domain_id)=", "is not present in table"),
       std::make_tuple("Key (asset_id)=", "already exists"),
       std::make_tuple("Key (domain_id)=", "already exists"),
       std::make_tuple("Key (role_id)=", "already exists"),
       std::make_tuple("Key (account_id, public_key)=", "already exists"),
       std::make_tuple("Key (account_id)=", "already exists"),
       std::make_tuple("Key (default_role)=", "is not present in table")};

  /// mapping between command name, fake error code and related real error code
  const std::map<std::string, std::map<int, int>> kCmdNameToErrorCode{
      std::make_pair(
          "AddSignatory",
          std::map<int, int>{std::make_pair(0, 3), std::make_pair(7, 4)}),
      std::make_pair(
          "AppendRole",
          std::map<int, int>{std::make_pair(0, 3), std::make_pair(2, 4)}),
      std::make_pair(
          "DetachRole",
          std::map<int, int>{std::make_pair(0, 3), std::make_pair(2, 5)}),
      std::make_pair("RemoveSignatory",
                     std::map<int, int>{std::make_pair(0, 3)}),
      std::make_pair("SetAccountDetail",
                     std::map<int, int>{std::make_pair(0, 3)}),
      std::make_pair("SetQuorum", std::map<int, int>{std::make_pair(0, 3)}),
      std::make_pair("GrantPermission",
                     std::map<int, int>{std::make_pair(1, 3)}),
      std::make_pair("RevokePermission",
                     std::map<int, int>{std::make_pair(1, 3)}),
      std::make_pair(
          "CreateAccount",
          std::map<int, int>{std::make_pair(3, 3), std::make_pair(8, 4)}),
      std::make_pair(
          "CreateAsset",
          std::map<int, int>{std::make_pair(3, 3), std::make_pair(4, 4)}),
      std::make_pair(
          "CreateDomain",
          std::map<int, int>{std::make_pair(5, 3), std::make_pair(9, 4)}),
      std::make_pair("CreateRole", std::map<int, int>{std::make_pair(6, 3)}),
      std::make_pair("AddSignatory", std::map<int, int>{std::make_pair(7, 4)})};

  /**
   * Get a real error code based on the fake one and a command name
   * @param fake_error_code - inner error code to be translated into the user's
   * one
   * @param command_name of the failed command
   * @return real error code
   */
  boost::optional<iroha::ametsuchi::CommandError::ErrorCodeType>
  getRealErrorCode(size_t fake_error_code, const std::string &command_name) {
    auto fake_to_real_code = kCmdNameToErrorCode.find(command_name);
    if (fake_to_real_code == kCmdNameToErrorCode.end()) {
      return {};
    }

    auto real_code = fake_to_real_code->second.find(fake_error_code);
    if (real_code == fake_to_real_code->second.end()) {
      return {};
    }

    return real_code->second;
  }

  // TODO [IR-1830] Akvinikym 31.10.18: make benchmarks to compare exception
  // parsing vs nested queries
  /**
   * Get an error code from the text SQL error
   * @param command_name - name of the failed command
   * @param error - string error, which SQL gave out
   * @param query_args - a string representation of query arguments
   * @return command_error structure
   */
  iroha::ametsuchi::CommandResult getCommandError(
      std::string command_name,
      const std::string &error,
      std::string &&query_args) noexcept {
    std::string key, to_be_presented;
    bool errors_matched;

    // go through mapping of SQL errors and get index of the current error - it
    // is "fake" error code
    for (size_t fakeErrorCode = 0; fakeErrorCode < kSqlToFakeErrorCode.size();
         ++fakeErrorCode) {
      std::tie(key, to_be_presented) = kSqlToFakeErrorCode[fakeErrorCode];
      errors_matched = error.find(key) != std::string::npos
          and error.find(to_be_presented) != std::string::npos;
      if (errors_matched) {
        if (auto real_error_code =
                getRealErrorCode(fakeErrorCode, command_name)) {
          return makeCommandError(
              std::move(command_name), *real_error_code, std::move(query_args));
        }
        break;
      }
    }
    // parsing is not successful, return the general error
    return makeCommandError(std::move(command_name), 1, std::move(query_args));
  }

  template <typename T>
  std::string permissionSetToBitString(
      const shared_model::interface::PermissionSet<T> &set) {
    return (boost::format("'%s'") % set.toBitstring()).str();
  }

  std::string checkAccountRolePermission(
      const std::string &permission_bitstring,
      const shared_model::interface::types::AccountIdType &account_id) {
    std::string query = (boost::format(R"(
          SELECT
              COALESCE(bit_or(rp.permission), '0'::bit(%1%))
              & (%2%::bit(%1%) | '%3%'::bit(%1%))
              != '0'::bit(%1%) has_rp
          FROM role_has_permissions AS rp
              JOIN account_has_roles AS ar on ar.role_id = rp.role_id
              WHERE ar.account_id = %4%)")
                         % kRolePermissionSetSize % permission_bitstring
                         % iroha::ametsuchi::kRootRolePermStr % account_id)
                            .str();
    return query;
  }

  std::string checkAccountRolePermission(
      const std::string &permission_bitstring,
      const std::string &additional_permission_bitstring,
      const shared_model::interface::types::AccountIdType &account_id) {
    std::string query = (boost::format(R"(
          SELECT
              COALESCE(bit_or(rp.permission), '0'::bit(%1%))
              & (%2%::bit(%1%) | %5%::bit(%1%) | '%3%'::bit(%1%))
              != '0'::bit(%1%) has_rp
          FROM role_has_permissions AS rp
              JOIN account_has_roles AS ar on ar.role_id = rp.role_id
              WHERE ar.account_id = %4%)")
                         % kRolePermissionSetSize % permission_bitstring
                         % iroha::ametsuchi::kRootRolePermStr % account_id
                         % additional_permission_bitstring)
                            .str();
    return query;
  }

  std::string checkAccountRolePermission(
      Role additional_permission,
      Role permission,
      const shared_model::interface::types::AccountIdType &account_id) {
    return checkAccountRolePermission(
        permissionSetToBitString(shared_model::interface::RolePermissionSet(
            {additional_permission})),
        permissionSetToBitString(
            shared_model::interface::RolePermissionSet({permission})),
        account_id);
  }

  std::string checkAccountRolePermission(
      Role permission,
      const shared_model::interface::types::AccountIdType &account_id) {
    return checkAccountRolePermission(
        permissionSetToBitString(
            shared_model::interface::RolePermissionSet({permission})),
        account_id);
  }

  std::string checkAccountGrantablePermission(
      Grantable permission,
      const shared_model::interface::types::AccountIdType &creator_id,
      const shared_model::interface::types::AccountIdType &account_id) {
    const auto perm_str =
        shared_model::interface::GrantablePermissionSet({permission})
            .toBitstring();
    std::string query = (boost::format(R"(
          SELECT
              COALESCE(bit_or(permission), '0'::bit(%1%)) & '%2%' = '%2%'
              or (%3%)
          FROM account_has_grantable_permissions
          WHERE account_id = %4% AND
          permittee_account_id = %5%
          )") % kGrantablePermissionSetSize
                         % perm_str
                         % checkAccountRolePermission(Role::kRoot, creator_id)
                         % account_id % creator_id)
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
      Role domain_permission_id,
      const shared_model::interface::types::DomainIdType &creator_domain,
      const shared_model::interface::types::DomainIdType
          &target_account_domain) {
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
    has_root_perm AS (%1%),
    has_indiv_perm AS (
      SELECT (COALESCE(bit_or(rp.permission), '0'::bit(%2%))
      & '%4%') = '%4%' FROM role_has_permissions AS rp
          JOIN account_has_roles AS ar on ar.role_id = rp.role_id
          WHERE ar.account_id = %3%
    ),
    has_all_perm AS (
      SELECT (COALESCE(bit_or(rp.permission), '0'::bit(%2%))
      & '%5%') = '%5%' FROM role_has_permissions AS rp
          JOIN account_has_roles AS ar on ar.role_id = rp.role_id
          WHERE ar.account_id = %3%
    ),
    has_domain_perm AS (
      SELECT (COALESCE(bit_or(rp.permission), '0'::bit(%2%))
      & '%6%') = '%6%' FROM role_has_permissions AS rp
          JOIN account_has_roles AS ar on ar.role_id = rp.role_id
          WHERE ar.account_id = %3%
    ),
    has_query_perm AS (
      SELECT (SELECT * from has_root_perm)
          OR (%3% = %7% AND (SELECT * FROM has_indiv_perm))
          OR (SELECT * FROM has_all_perm)
          OR (%8% = %9% AND (SELECT * FROM has_domain_perm)) AS perm
    )
    )");

    return (cmd % checkAccountRolePermission(Role::kRoot, creator) % bits
            % creator % perm_str % all_perm_str % domain_perm_str
            % target_account % creator_domain % target_account_domain)
        .str();
  }

  std::string checkAccountDomainRoleOrGlobalRolePermission(
      Role global_permission,
      Role domain_permission,
      const shared_model::interface::types::AccountIdType &creator_id,
      const shared_model::interface::types::AssetIdType
          &id_with_target_domain) {
    std::string query = (boost::format(R"(WITH
          has_global_role_perm AS (%1%),
          has_domain_role_perm AS (%2%)
          SELECT CASE
                           WHEN (SELECT * FROM has_global_role_perm) THEN true
                           WHEN ((split_part(%3%, '@', 2) = split_part(%4%, '#', 2))) THEN
                               CASE
                                   WHEN (SELECT * FROM has_domain_role_perm) THEN true
                                   ELSE false
                                END
                           ELSE false END
          )") % checkAccountRolePermission(global_permission, creator_id)
                         % checkAccountRolePermission(domain_permission,
                                                      creator_id)
                         % creator_id % id_with_target_domain)
                            .str();
    return query;
  }

  std::string checkAccountHasRoleOrGrantablePerm(
      Role role,
      Grantable grantable,
      const shared_model::interface::types::AccountIdType &creator_id,
      const shared_model::interface::types::AccountIdType &account_id) {
    return (boost::format(R"(WITH
          has_role_perm AS (%s),
          has_root_perm AS (%s),
          has_grantable_perm AS (%s)
          SELECT CASE
                           WHEN (SELECT * FROM has_root_perm) THEN true
                           WHEN (SELECT * FROM has_grantable_perm) THEN true
                           WHEN (%s = %s) THEN
                               CASE
                                   WHEN (SELECT * FROM has_role_perm) THEN true
                                   ELSE false
                                END
                           ELSE false END
          )")
            % checkAccountRolePermission(role, creator_id)
            % checkAccountRolePermission(Role::kRoot, creator_id)
            % checkAccountGrantablePermission(grantable, creator_id, account_id)
            % creator_id % account_id)
        .str();
  }
}  // namespace

namespace iroha {
  namespace ametsuchi {
    class PostgresCommandExecutor::CommandStatements {
     public:
      CommandStatements(soci::session &session,
                        const std::string &base_statement,
                        const std::vector<std::string> &permission_checks)
          : statement_with_validation([&] {
              // Create query with validation
              auto with_validation_str = boost::format(base_statement);

              // append all necessary checks to the query
              for (const auto &check : permission_checks) {
                with_validation_str = with_validation_str % check;
              }

              return (session.prepare << with_validation_str);
            }()),
            statement_without_validation([&] {
              // Create query without validation
              auto without_validation_str = boost::format(base_statement);

              // since checks are not needed, append empty strings to their
              // place
              for (size_t i = 0; i < permission_checks.size(); i++) {
                without_validation_str = without_validation_str % "";
              }

              return (session.prepare << without_validation_str);
            }()) {}

      soci::statement &getStatement(bool with_validation) {
        return with_validation ? statement_with_validation
                               : statement_without_validation;
      }

     private:
      soci::statement statement_with_validation;
      soci::statement statement_without_validation;
    };

    class PostgresCommandExecutor::StatementExecutor {
     public:
      StatementExecutor(
          std::unique_ptr<CommandStatements> &statements,
          bool enable_validation,
          std::string command_name,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter)
          : statement_(statements->getStatement(enable_validation)),
            command_name_(std::move(command_name)),
            perm_converter_(std::move(perm_converter)) {
        arguments_string_builder_.init(command_name_)
            .appendNamed("Validation", enable_validation);
      }

      template <typename T,
                typename = decltype(soci::use(std::declval<T>(),
                                              std::string{}))>
      void use(const std::string &argument_name, const T &value) {
        statement_.exchange(soci::use(value, argument_name));
        addArgumentToString(argument_name, value);
      }

      void use(const std::string &argument_name, const Role &permission) {
        temp_values_.emplace_front(
            shared_model::interface::RolePermissionSet({permission})
                .toBitstring());
        statement_.exchange(soci::use(temp_values_.front(), argument_name));
        addArgumentToString(argument_name,
                            perm_converter_->toString(permission));
      }

      void use(const std::string &argument_name, const Grantable &permission) {
        temp_values_.emplace_front(
            shared_model::interface::GrantablePermissionSet({permission})
                .toBitstring());
        statement_.exchange(soci::use(temp_values_.front(), argument_name));
        addArgumentToString(argument_name,
                            perm_converter_->toString(permission));
      }

      void use(
          const std::string &argument_name,
          const shared_model::interface::RolePermissionSet &permission_set) {
        temp_values_.emplace_front(permission_set.toBitstring());
        statement_.exchange(soci::use(temp_values_.front(), argument_name));
        addArgumentToString(
            argument_name,
            boost::algorithm::join(perm_converter_->toString(permission_set),
                                   ", "));
      }

      void use(const std::string &argument_name, bool value) {
        statement_.exchange(
            soci::use(value ? kPgTrue : kPgFalse, argument_name));
        addArgumentToString(argument_name, std::to_string(value));
      }

      // TODO IR-597 mboldyrev 2019.08.10: build args string on demand
      void addArgumentToString(std::string_view argument_name,
                               const std::optional<std::string_view> &value) {
        if (value) {
          arguments_string_builder_.appendNamed(argument_name, *value);
        }
      }

      template <typename T>
      std::enable_if_t<std::is_arithmetic<T>::value> addArgumentToString(
          std::string_view argument_name, const T &value) {
        addArgumentToString(argument_name, std::to_string(value));
      }

      iroha::ametsuchi::CommandResult execute() noexcept {
        try {
          soci::row r;
          statement_.define_and_bind();
          statement_.exchange_for_rowset(soci::into(r));
          statement_.execute();
          auto result = statement_.fetch() ? r.get<int>(0) : 1;
          statement_.bind_clean_up();
          temp_values_.clear();
          if (result != 0) {
            return makeCommandError(
                command_name_, result, arguments_string_builder_.finalize());
          }
          return {};
        } catch (const std::exception &e) {
          statement_.bind_clean_up();
          temp_values_.clear();
          return getCommandError(
              command_name_, e.what(), arguments_string_builder_.finalize());
        }
      }

     private:
      soci::statement &statement_;
      std::string command_name_;
      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter_;
      shared_model::detail::PrettyStringBuilder arguments_string_builder_;
      std::forward_list<std::string> temp_values_;
    };

    std::unique_ptr<PostgresCommandExecutor::CommandStatements>
    PostgresCommandExecutor::makeCommandStatements(
        const std::unique_ptr<soci::session> &session,
        const std::string &base_statement,
        const std::vector<std::string> &permission_checks) {
      return std::make_unique<CommandStatements>(
          *session, base_statement, permission_checks);
    }

    void PostgresCommandExecutor::initStatements() {
      // TODO [IR-1830] Akvinikym 31.10.18: make benchmarks to compare exception
      // parsing vs nested queries
      // 14.09.18 nickaleks: IR-1708 Load SQL from separate files
      add_asset_quantity_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
             new_quantity AS
             (
                 SELECT :quantity::decimal + coalesce(sum(amount), 0) as value
                 FROM account_has_asset
                 WHERE asset_id = :asset_id
                     AND account_id = :creator
             ),
             checks AS -- error code and check result
             (
                 -- account exists
                 SELECT 1 code, count(1) = 1 result
                 FROM account
                 WHERE account_id = :creator

                 -- asset exists
                 UNION
                 SELECT 3, count(1) = 1
                 FROM asset
                 WHERE asset_id = :asset_id
                    AND precision >= :precision

                 -- quantity overflow
                 UNION
                 SELECT
                    4,
                    value < (2::decimal ^ 256) / (10::decimal ^ precision)
                 FROM new_quantity, asset
                 WHERE asset_id = :asset_id
             ),
             inserted AS
             (
                INSERT INTO account_has_asset(account_id, asset_id, amount)
                (
                    SELECT :creator, :asset_id, value FROM new_quantity
                    WHERE (SELECT bool_and(checks.result) FROM checks) %s
                )
                ON CONFLICT (account_id, asset_id) DO UPDATE
                SET amount = EXCLUDED.amount
                RETURNING (1)
             )
          SELECT CASE
              %s
              WHEN EXISTS (SELECT * FROM inserted LIMIT 1) THEN 0
              ELSE (SELECT code FROM checks WHERE not result ORDER BY code ASC LIMIT 1)
          END AS result;)",
          {(boost::format(R"(has_perm AS (%s),)")
            % checkAccountDomainRoleOrGlobalRolePermission(
                  Role::kAddAssetQty,
                  Role::kAddDomainAssetQty,
                  ":creator",
                  ":asset_id"))
               .str(),
           "AND (SELECT * from has_perm)",
           "WHEN NOT (SELECT * from has_perm) THEN 2"});

      add_peer_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            inserted AS (
                INSERT INTO peer(public_key, address, tls_certificate)
                (
                    SELECT lower(:pubkey), :address, :tls_certificate
                    %s
                ) RETURNING (1)
            )
          SELECT CASE WHEN EXISTS (SELECT * FROM inserted) THEN 0
              %s
              ELSE 1 END AS result)",
          {(boost::format(R"(has_perm AS (%s),)")
            % checkAccountRolePermission(Role::kAddPeer, ":creator"))
               .str(),
           "WHERE (SELECT * FROM has_perm)",
           "WHEN NOT (SELECT * from has_perm) THEN 2"});

      add_signatory_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            insert_signatory AS
            (
                INSERT INTO signatory(public_key)
                (SELECT lower(:pubkey) %s)
                ON CONFLICT (public_key)
                  DO UPDATE SET public_key = excluded.public_key
                RETURNING (1)
            ),
            insert_account_signatory AS
            (
                INSERT INTO account_has_signatory(account_id, public_key)
                (
                    SELECT :target, lower(:pubkey)
                    WHERE EXISTS (SELECT * FROM insert_signatory)
                )
                RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM insert_account_signatory) THEN 0
            %s
            ELSE 1
          END AS RESULT;)",
          {(boost::format(R"(
                                has_perm AS (%s),)")
            % checkAccountHasRoleOrGrantablePerm(Role::kAddSignatory,
                                                 Grantable::kAddMySignatory,
                                                 ":creator",
                                                 ":target"))
               .str(),
           "WHERE (SELECT * FROM has_perm)",
           "WHEN NOT (SELECT * from has_perm) THEN 2"});

      append_role_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            role_exists AS (SELECT * FROM role WHERE role_id = :role),
            inserted AS (
                INSERT INTO account_has_roles(account_id, role_id)
                (
                    SELECT :target, :role %s) RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM inserted) THEN 0
            WHEN NOT EXISTS (SELECT * FROM role_exists) THEN 4
            %s
            ELSE 1
          END AS result)",
          {(boost::format(R"(
            has_perm AS (%1%),
            has_root_perm AS (%2%),
            role_permissions AS (
                SELECT permission FROM role_has_permissions
                WHERE role_id = :role
            ),
            account_roles AS (
                SELECT role_id FROM account_has_roles WHERE account_id = :creator
            ),
            account_has_role_permissions AS (
                SELECT COALESCE(bit_or(rp.permission), '0'::bit(%3%)) &
                    (SELECT * FROM role_permissions) =
                    (SELECT * FROM role_permissions)
                FROM role_has_permissions AS rp
                JOIN account_has_roles AS ar on ar.role_id = rp.role_id
                WHERE ar.account_id = :creator
            ),)")
            % checkAccountRolePermission(Role::kAppendRole, ":creator")
            % checkAccountRolePermission(Role::kRoot, ":creator")
            % kRolePermissionSetSize)
               .str(),
           R"(WHERE
              (SELECT * FROM has_root_perm)
              OR (EXISTS (SELECT * FROM account_roles) AND
              (SELECT * FROM account_has_role_permissions)
              AND (SELECT * FROM has_perm)))",
           R"(WHEN NOT EXISTS (SELECT * FROM account_roles)
                  AND NOT (SELECT * FROM has_root_perm) THEN 2
              WHEN NOT (SELECT * FROM account_has_role_permissions)
                  AND NOT (SELECT * FROM has_root_perm) THEN 2
              WHEN NOT (SELECT * FROM has_perm) THEN 2)"});

      add_sync_peer_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            inserted AS (
                INSERT INTO sync_peer(public_key, address, tls_certificate)
                (
                    SELECT lower(:pubkey), :address, :tls_certificate
                    %s
                ) RETURNING (1)
            )
          SELECT CASE WHEN EXISTS (SELECT * FROM inserted) THEN 0
              %s
              ELSE 1 END AS result)",
          {(boost::format(R"(has_perm AS (%s),)")
            % checkAccountRolePermission(Role::kAddPeer, ":creator"))
               .str(),
           "WHERE (SELECT * FROM has_perm)",
           "WHEN NOT (SELECT * from has_perm) THEN 2"});

      compare_and_set_account_detail_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            old_value AS
            (
                SELECT *
                FROM account
                WHERE
                  account_id = :target
                  AND CASE
                    WHEN data ? :creator AND data->:creator ?:key
                      THEN CASE
                        WHEN :have_expected_value::boolean
                            THEN data->:creator->:key = :expected_value::jsonb
                        ELSE FALSE
                        END
                    ELSE not (:check_empty::boolean and :have_expected_value::boolean)
                  END
            ),
            inserted AS
            (
                UPDATE account
                SET data = jsonb_set(
                  CASE
                    WHEN data ? :creator THEN data
                    ELSE jsonb_set(data, array[:creator], '{}')
                  END,
                  array[:creator, :key], :new_value::jsonb
                )
                WHERE
                  EXISTS (SELECT * FROM old_value)
                  AND account_id = :target
                  %s
                RETURNING (1)
            )
          SELECT CASE
              WHEN EXISTS (SELECT * FROM inserted) THEN 0
              WHEN NOT EXISTS
                  (SELECT * FROM account WHERE account_id=:target) THEN 3
              WHEN NOT EXISTS (SELECT * FROM old_value) THEN 4
              %s
              ELSE 1
          END AS result)",
          {(boost::format(R"(
              has_role_perm AS (%s),
              has_grantable_perm AS (%s),
              %s,
              has_perm AS
              (
                  SELECT CASE
                      WHEN (SELECT * FROM has_query_perm) THEN
                          CASE
                              WHEN (SELECT * FROM has_grantable_perm)
                                  THEN true
                              WHEN (:creator = :target) THEN true
                              WHEN (SELECT * FROM has_role_perm)
                                  THEN true
                              ELSE false END
                      ELSE false END
              ),
              )")
            % checkAccountRolePermission(Role::kSetDetail, ":creator")
            % checkAccountGrantablePermission(
                  Grantable::kSetMyAccountDetail, ":creator", ":target")
            % hasQueryPermission(":creator",
                                 ":target",
                                 Role::kGetMyAccDetail,
                                 Role::kGetAllAccDetail,
                                 Role::kGetDomainAccDetail,
                                 ":creator_domain",
                                 ":target_domain"))
               .str(),
           R"( AND (SELECT * FROM has_perm))",
           R"( WHEN NOT (SELECT * FROM has_perm) THEN 2 )"});

      create_account_statements_ =
          makeCommandStatements(
              sql_,
              R"(
          WITH get_domain_default_role AS (SELECT default_role FROM domain
                                             WHERE domain_id = :domain),
            %s
            insert_signatory AS
            (
                INSERT INTO signatory(public_key)
                (
                    SELECT lower(:pubkey)
                    WHERE EXISTS (SELECT * FROM get_domain_default_role)
                      %s
                )
                ON CONFLICT (public_key)
                  DO UPDATE SET public_key = excluded.public_key
                RETURNING (1)
            ),
            insert_account AS
            (
                INSERT INTO account(account_id, domain_id, quorum, data)
                (
                    SELECT :account_id, :domain, 1, '{}'
                    WHERE EXISTS (SELECT * FROM insert_signatory)
                      AND EXISTS (SELECT * FROM get_domain_default_role)
                ) RETURNING (1)
            ),
            insert_account_signatory AS
            (
                INSERT INTO account_has_signatory(account_id, public_key)
                (
                    SELECT :account_id, lower(:pubkey) WHERE
                       EXISTS (SELECT * FROM insert_account)
                )
                RETURNING (1)
            ),
            insert_account_role AS
            (
                INSERT INTO account_has_roles(account_id, role_id)
                (
                    SELECT :account_id, default_role FROM get_domain_default_role
                    WHERE EXISTS (SELECT * FROM get_domain_default_role)
                      AND EXISTS (SELECT * FROM insert_account_signatory)
                ) RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM insert_account_role) THEN 0
            WHEN NOT EXISTS (SELECT * FROM get_domain_default_role) THEN 3
            %s
            ELSE 1
          END AS result)",
              {(boost::format(R"(
           domain_role_permissions_bits AS (
                 SELECT COALESCE(bit_or(rhp.permission), '0'::bit(%1%)) AS bits
                 FROM role_has_permissions AS rhp
                 WHERE rhp.role_id = (SELECT * FROM get_domain_default_role)),
           account_permissions AS (
                 SELECT COALESCE(bit_or(rhp.permission), '0'::bit(%1%)) AS perm
                 FROM role_has_permissions AS rhp
                 JOIN account_has_roles AS ar ON ar.role_id = rhp.role_id
                 WHERE ar.account_id = :creator
           ),
           creator_has_enough_permissions AS (
                SELECT ap.perm & dpb.bits = dpb.bits OR has_root_perm.has_rp
                FROM
                    account_permissions AS ap
                  , domain_role_permissions_bits AS dpb
                  , (%3%) as has_root_perm

           ),
           has_perm AS (%2%),
          )") % kRolePermissionSetSize
                % checkAccountRolePermission(Role::kCreateAccount, ":creator")
                % checkAccountRolePermission(Role::kRoot, ":creator"))
                   .str(),
               R"(AND (SELECT * FROM has_perm)
                AND (SELECT * FROM creator_has_enough_permissions))",
               R"(WHEN NOT (SELECT * FROM has_perm) THEN 2
                WHEN NOT (SELECT * FROM creator_has_enough_permissions) THEN 2)"});

      create_asset_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            inserted AS
            (
                INSERT INTO asset(asset_id, domain_id, precision)
                (
                    SELECT :asset_id, :domain, :precision
                    %s
                ) RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM inserted) THEN 0
            %s
            ELSE 1
          END AS result)",
          {(boost::format(R"(
              has_perm AS (%s),)")
            % checkAccountRolePermission(Role::kCreateAsset, ":creator"))
               .str(),
           R"(WHERE (SELECT * FROM has_perm))",
           R"(WHEN NOT (SELECT * FROM has_perm) THEN 2)"});

      create_domain_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            inserted AS
            (
                INSERT INTO domain(domain_id, default_role)
                (
                    SELECT :domain, :default_role
                    %s
                ) RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM inserted) THEN 0
            %s
            ELSE 1
          END AS result)",
          {(boost::format(R"(
              has_perm AS (%s),)")
            % checkAccountRolePermission(Role::kCreateDomain, ":creator"))
               .str(),
           R"(WHERE (SELECT * FROM has_perm))",
           R"(WHEN NOT (SELECT * FROM has_perm) THEN 2)"});

      create_role_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            insert_role AS (INSERT INTO role(role_id)
                                (SELECT :role
                                %s) RETURNING (1)),
            insert_role_permissions AS
            (
                INSERT INTO role_has_permissions(role_id, permission)
                (
                    SELECT :role, :perms WHERE EXISTS
                        (SELECT * FROM insert_role)
                ) RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM insert_role_permissions) THEN 0
            %s
            WHEN EXISTS (SELECT * FROM role WHERE role_id = :role) THEN 2
            ELSE 1
          END AS result)",
          {(boost::format(R"(
          account_has_role_permissions AS (
                SELECT COALESCE(bit_or(rp.permission), '0'::bit(%s)) &
                    :perms = :perms
                FROM role_has_permissions AS rp
                JOIN account_has_roles AS ar on ar.role_id = rp.role_id
                WHERE ar.account_id = :creator),
          has_perm AS (%s),
          has_root_perm AS (%s),)")
            % kRolePermissionSetSize
            % checkAccountRolePermission(Role::kCreateRole, ":creator")
            % checkAccountRolePermission(Role::kRoot, ":creator"))
               .str(),
           R"(WHERE (SELECT * FROM has_root_perm) OR
                    ((SELECT * FROM account_has_role_permissions)
                     AND (SELECT * FROM has_perm)))",
           R"(WHEN NOT (SELECT * FROM account_has_role_permissions)
               AND NOT (SELECT * FROM has_root_perm) THEN 2
              WHEN NOT (SELECT * FROM has_perm) THEN 2)"});

      detach_role_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            deleted AS
            (
              DELETE FROM account_has_roles
              WHERE account_id=:target
              AND role_id=:role
              %s
              RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM deleted) THEN 0
            WHEN NOT EXISTS (SELECT * FROM account
                             WHERE account_id = :target) THEN 3
            WHEN NOT EXISTS (SELECT * FROM role
                             WHERE role_id = :role) THEN 5
            WHEN NOT EXISTS (SELECT * FROM account_has_roles
                             WHERE account_id=:target AND role_id=:role) THEN 4
            %s
            ELSE 1
          END AS result)",
          {(boost::format(R"(
            has_perm AS (%s),)")
            % checkAccountRolePermission(Role::kDetachRole, ":creator"))
               .str(),
           R"(AND (SELECT * FROM has_perm))",
           R"(WHEN NOT (SELECT * FROM has_perm) THEN 2)"});

      grant_permission_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            inserted AS (
              INSERT INTO account_has_grantable_permissions AS
              has_perm(permittee_account_id, account_id, permission)
              (SELECT :target, :creator, :granted_perm %s) ON CONFLICT
              (permittee_account_id, account_id)
              DO UPDATE SET permission=(SELECT has_perm.permission | :granted_perm
              WHERE (has_perm.permission & :granted_perm) <> :granted_perm)
              RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM inserted) THEN 0
            %s
            ELSE 1
          END AS result)",
          {(boost::format(R"(
            has_perm AS (%s),)")
            % checkAccountRolePermission(":required_perm", ":creator"))
               .str(),
           R"( WHERE (SELECT * FROM has_perm))",
           R"(WHEN NOT (SELECT * FROM has_perm) THEN 2)"});

      remove_peer_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
          removed AS (
              DELETE FROM peer WHERE public_key = lower(:pubkey)
              %s
              RETURNING (1)
          )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM removed) THEN 0
            %s
            ELSE 1
          END AS result)",
          {(boost::format(R"(
            has_perm AS (%s),
            get_peer AS (
              SELECT * from peer WHERE public_key = lower(:pubkey) LIMIT 1
            ),
            check_peers AS (
              SELECT 1 WHERE (SELECT COUNT(*) FROM peer) > 1
            ),)")
            % checkAccountRolePermission(
                  Role::kAddPeer, Role::kRemovePeer, ":creator"))
               .str(),
           R"(
             AND (SELECT * FROM has_perm)
             AND EXISTS (SELECT * FROM get_peer)
             AND EXISTS (SELECT * FROM check_peers))",
           R"(
             WHEN NOT EXISTS (SELECT * from get_peer) THEN 3
             WHEN NOT EXISTS (SELECT * from check_peers) THEN 4
             WHEN NOT (SELECT * from has_perm) THEN 2)"});

      remove_signatory_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            delete_account_signatory AS (DELETE FROM account_has_signatory
                WHERE account_id = :target
                AND public_key = lower(:pubkey)
                %s
                RETURNING (1)),
            delete_signatory AS
            (
                DELETE FROM signatory WHERE public_key = lower(:pubkey) AND
                    NOT EXISTS (SELECT 1 FROM account_has_signatory
                                WHERE public_key = lower(:pubkey))
                    AND NOT EXISTS (SELECT 1 FROM peer
                                    WHERE public_key = lower(:pubkey))
                RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM delete_account_signatory) THEN
            CASE
                WHEN EXISTS (SELECT * FROM delete_signatory) THEN 0
                WHEN EXISTS (SELECT 1 FROM account_has_signatory
                             WHERE public_key = lower(:pubkey)) THEN 0
                WHEN EXISTS (SELECT 1 FROM peer
                             WHERE public_key = lower(:pubkey)) THEN 0
                ELSE 1
            END
            %s
            ELSE 1
          END AS result)",
          {(boost::format(R"(
          has_perm AS (%s),
          get_account AS (
              SELECT quorum FROM account WHERE account_id = :target LIMIT 1
           ),
          get_signatories AS (
              SELECT public_key FROM account_has_signatory
              WHERE account_id = :target
          ),
          get_signatory AS (
              SELECT * FROM get_signatories
              WHERE public_key = lower(:pubkey)
          ),
          check_account_signatories AS (
              SELECT quorum FROM get_account
              WHERE quorum < (SELECT COUNT(*) FROM get_signatories)
          ),
          )")
            % checkAccountHasRoleOrGrantablePerm(Role::kRemoveSignatory,
                                                 Grantable::kRemoveMySignatory,
                                                 ":creator",
                                                 ":target"))
               .str(),
           R"(
              AND (SELECT * FROM has_perm)
              AND EXISTS (SELECT * FROM get_account)
              AND EXISTS (SELECT * FROM get_signatories)
              AND EXISTS (SELECT * FROM check_account_signatories)
          )",
           R"(
              WHEN NOT EXISTS (SELECT * FROM get_account) THEN 3
              WHEN NOT (SELECT * FROM has_perm) THEN 2
              WHEN NOT EXISTS (SELECT * FROM get_signatory) THEN 4
              WHEN NOT EXISTS (SELECT * FROM check_account_signatories) THEN 5
          )"});

      revoke_permission_statements_ = makeCommandStatements(
          sql_,
          (boost::format(R"(
          WITH %%s
            inserted AS (
                UPDATE account_has_grantable_permissions as has_perm
                SET permission=(
                  SELECT has_perm.permission & (~ :revoked_perm::bit(%1%))
                  WHERE has_perm.permission & :revoked_perm::bit(%1%)
                      = :revoked_perm::bit(%1%) AND
                  has_perm.permittee_account_id=:target AND
                  has_perm.account_id=:creator
                )
                WHERE
                permittee_account_id=:target AND
                account_id=:creator %%s
              RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM inserted) THEN 0
            %%s
            ELSE 1
          END AS result)")
           % kGrantablePermissionSetSize)
              .str(),
          {(boost::format(R"(
            has_perm AS (
              SELECT
                  (
                      COALESCE(bit_or(permission), '0'::bit(%1%))
                      & :revoked_perm::bit(%1%)
                  )
                  = :revoked_perm::bit(%1%)
              FROM account_has_grantable_permissions
              WHERE account_id = :creator AND
              permittee_account_id = :target),)")
            % kGrantablePermissionSetSize)
               .str(),
           R"( AND (SELECT * FROM has_perm))",
           R"( WHEN NOT (SELECT * FROM has_perm) THEN 2 )"});

      set_account_detail_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            inserted AS
            (
                UPDATE account SET data = jsonb_set(
                CASE WHEN data ? :creator THEN data ELSE
                jsonb_set(data, array[:creator], '{}') END,
                array[:creator, :key], :value::jsonb) WHERE account_id=:target %s
                RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM inserted) THEN 0
            WHEN NOT EXISTS
                    (SELECT * FROM account WHERE account_id=:target) THEN 3
            %s
            ELSE 1
          END AS result)",
          {(boost::format(R"(
              has_role_perm AS (%s),
              has_grantable_perm AS (%s),
              has_perm AS (SELECT CASE
                               WHEN (SELECT * FROM has_grantable_perm) THEN true
                               WHEN (:creator = :target) THEN true
                               WHEN (SELECT * FROM has_role_perm) THEN true
                               ELSE false END
              ),
              )")
            % checkAccountRolePermission(Role::kSetDetail, ":creator")
            % checkAccountGrantablePermission(
                  Grantable::kSetMyAccountDetail, ":creator", ":target"))
               .str(),
           R"( AND (SELECT * FROM has_perm))",
           R"( WHEN NOT (SELECT * FROM has_perm) THEN 2 )"});

      remove_sync_peer_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
          removed AS (
              DELETE FROM sync_peer WHERE public_key = lower(:pubkey)
              %s
              RETURNING (1)
          )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM removed) THEN 0
            %s
            ELSE 1
          END AS result)",
          {(boost::format(R"(
            has_perm AS (%s),
            get_peer AS (
              SELECT * from sync_peer WHERE public_key = lower(:pubkey) LIMIT 1
            ),
            check_peers AS (
              SELECT 1 WHERE (SELECT COUNT(*) FROM sync_peer) > 0
            ),)")
            % checkAccountRolePermission(
                  Role::kAddPeer, Role::kRemovePeer, ":creator"))
               .str(),
           R"(
             AND (SELECT * FROM has_perm)
             AND EXISTS (SELECT * FROM get_peer)
             AND EXISTS (SELECT * FROM check_peers))",
           R"(
             WHEN NOT EXISTS (SELECT * from get_peer) THEN 3
             WHEN NOT EXISTS (SELECT * from check_peers) THEN 4
             WHEN NOT (SELECT * from has_perm) THEN 2)"});

      set_quorum_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            updated AS (
                UPDATE account SET quorum=:quorum
                WHERE account_id=:target
                %s
                RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM updated) THEN 0
            %s
            ELSE 1
          END AS result)",
          {(boost::format(R"(
            get_signatories AS (
                SELECT public_key FROM account_has_signatory
                WHERE account_id = :target
            ),
            check_account_signatories AS (
                SELECT 1 FROM account
                WHERE :quorum <= (SELECT COUNT(*) FROM get_signatories)
                AND account_id = :target
            ),
            has_perm AS (%s),)")
            % checkAccountHasRoleOrGrantablePerm(Role::kSetQuorum,
                                                 Grantable::kSetMyQuorum,
                                                 ":creator",
                                                 ":target"))
               .str(),
           R"(AND EXISTS
              (SELECT * FROM get_signatories)
              AND EXISTS (SELECT * FROM check_account_signatories)
              AND (SELECT * FROM has_perm))",
           R"(
              WHEN NOT (SELECT * FROM has_perm) THEN 2
              WHEN NOT EXISTS (SELECT * FROM get_signatories) THEN 4
              WHEN NOT EXISTS (SELECT * FROM check_account_signatories) THEN 5
              )"});

      store_engine_response_statements_ = makeCommandStatements(sql_,
                                                                R"(
          WITH
            inserted AS (
              INSERT INTO engine_calls
              (
                tx_hash, cmd_index, engine_response,
                callee, created_address
              )
              VALUES
              (
                :tx_hash, :cmd_index, :engine_response,
                :callee, :created_address
              )
              ON CONFLICT (tx_hash, cmd_index)
              DO UPDATE SET
                engine_response = excluded.engine_response,
                callee = excluded.callee,
                created_address = excluded.created_address
              RETURNING (1)
            )
          SELECT CASE
            WHEN EXISTS (SELECT * FROM inserted) THEN 0
            ELSE 1
          END AS result)",
                                                                {});

      subtract_asset_quantity_statements_ = makeCommandStatements(
          sql_,
          R"(
          WITH %s
            has_account AS (SELECT account_id FROM account
                            WHERE account_id = :creator LIMIT 1),
            has_asset AS (SELECT asset_id FROM asset
                          WHERE asset_id = :asset_id
                          AND precision >= :precision LIMIT 1),
            amount AS (SELECT amount FROM account_has_asset
                       WHERE asset_id = :asset_id
                       AND account_id = :creator LIMIT 1),
            new_value AS (SELECT
                           (SELECT
                               CASE WHEN EXISTS
                                   (SELECT amount FROM amount LIMIT 1)
                                   THEN (SELECT amount FROM amount LIMIT 1)
                               ELSE 0::decimal
                           END) - :quantity::decimal AS value
                       ),
            inserted AS
            (
               INSERT INTO account_has_asset(account_id, asset_id, amount)
               (
                   SELECT :creator, :asset_id, value FROM new_value
                   WHERE EXISTS (SELECT * FROM has_account LIMIT 1) AND
                     EXISTS (SELECT * FROM has_asset LIMIT 1) AND
                     EXISTS (SELECT value FROM new_value WHERE value >= 0 LIMIT 1)
                     %s
               )
               ON CONFLICT (account_id, asset_id)
               DO UPDATE SET amount = EXCLUDED.amount
               RETURNING (1)
            )
          SELECT CASE
              WHEN EXISTS (SELECT * FROM inserted LIMIT 1) THEN 0
              %s
              WHEN NOT EXISTS (SELECT * FROM has_asset LIMIT 1) THEN 3
              WHEN NOT EXISTS
                  (SELECT value FROM new_value WHERE value >= 0 LIMIT 1) THEN 4
              ELSE 1
          END AS result)",
          {(boost::format(R"(
               has_perm AS (%s),)")
            % checkAccountDomainRoleOrGlobalRolePermission(
                  Role::kSubtractAssetQty,
                  Role::kSubtractDomainAssetQty,
                  ":creator",
                  ":asset_id"))
               .str(),
           R"( AND (SELECT * FROM has_perm))",
           R"( WHEN NOT (SELECT * FROM has_perm) THEN 2 )"});

      transfer_asset_statements_ = makeCommandStatements(
          sql_,
          fmt::format(
              R"(
          WITH %s
            new_src_quantity AS
            (
                SELECT coalesce(sum(amount), 0) - :quantity::decimal as value
                FROM account_has_asset
                   WHERE asset_id = :asset_id AND
                   account_id = :source_account_id
            ),
            new_dest_quantity AS
            (
                SELECT coalesce(sum(amount), 0) + :quantity::decimal as value
                FROM account_has_asset
                   WHERE asset_id = :asset_id AND
                   account_id = :dest_account_id
            ),
            checks AS -- error code and check result
            (
                -- source account exists
                SELECT 3 code, count(1) = 1 result
                FROM account
                WHERE account_id = :source_account_id

                -- dest account exists
                UNION
                SELECT 4, count(1) = 1
                FROM account
                WHERE account_id = :dest_account_id

                -- asset exists
                UNION
                SELECT 5, count(1) = 1
                FROM asset
                WHERE asset_id = :asset_id
                   AND precision >= :precision

                -- enough source quantity
                UNION
                SELECT 6, value >= 0
                FROM new_src_quantity

                -- dest quantity overflow
                UNION
                SELECT
                    7,
                    value < (2::decimal ^ 256) / (10::decimal ^ precision)
                FROM new_dest_quantity, asset
                WHERE asset_id = :asset_id

                -- description length
                UNION
                SELECT 8, :description_length <= setting_value::integer
                FROM setting
                WHERE setting_key = '{}'
            ),
            insert_src AS
            (
                UPDATE account_has_asset
                SET amount = value
                FROM new_src_quantity
                WHERE
                    account_id = :source_account_id
                    AND asset_id = :asset_id
                    AND (SELECT bool_and(checks.result) FROM checks) %s
            ),
            insert_dest AS
            (
                INSERT INTO account_has_asset(account_id, asset_id, amount)
                (
                    SELECT :dest_account_id, :asset_id, value
                    FROM new_dest_quantity
                    WHERE (SELECT bool_and(checks.result) FROM checks) %s
                )
                ON CONFLICT (account_id, asset_id)
                DO UPDATE SET amount = EXCLUDED.amount
                RETURNING (1)
            )
          SELECT CASE
              WHEN EXISTS (SELECT * FROM insert_dest LIMIT 1) THEN 0
              WHEN EXISTS (SELECT * FROM checks WHERE not result and code = 4) THEN 4
              %s
              ELSE (SELECT code FROM checks WHERE not result ORDER BY code ASC LIMIT 1)
          END AS result)",
              iroha::ametsuchi::kMaxDescriptionSizeKey),
          {(boost::format(R"(
              has_role_perm AS (%s),
              has_grantable_perm AS (%s),
              dest_can_receive AS (%s),
              has_perm AS
              (
                  SELECT
                      CASE WHEN (SELECT * FROM dest_can_receive) THEN
                          CASE WHEN NOT (:creator = :source_account_id) THEN
                              CASE WHEN (SELECT * FROM has_grantable_perm)
                                  THEN true
                              ELSE false END
                          ELSE
                              CASE WHEN (SELECT * FROM has_role_perm)
                                  THEN true
                              ELSE false END
                          END
                      ELSE false END
              ),
              )")
            % checkAccountRolePermission(Role::kTransfer, ":creator")
            % checkAccountGrantablePermission(Grantable::kTransferMyAssets,
                                              ":creator",
                                              ":source_account_id")
            % checkAccountRolePermission(Role::kReceive, ":dest_account_id"))
               .str(),
           R"( AND (SELECT * FROM has_perm))",
           R"( AND (SELECT * FROM has_perm))",
           R"( WHEN NOT (SELECT * FROM has_perm) THEN 2 )"});

      set_setting_value_statements_ = makeCommandStatements(
          sql_,
          R"(INSERT INTO setting(setting_key, setting_value)
             VALUES
             (
                 :setting_key,
                 :setting_value
             )
             ON CONFLICT (setting_key)
                 DO UPDATE SET setting_value = EXCLUDED.setting_value
             RETURNING 0)",
          {});
    }

    PostgresCommandExecutor::PostgresCommandExecutor(
        std::unique_ptr<soci::session> sql,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        std::shared_ptr<PostgresSpecificQueryExecutor> specific_query_executor,
        std::optional<std::reference_wrapper<const VmCaller>> vm_caller)
        : sql_(std::move(sql)),
          db_transaction_(*sql_),
          perm_converter_{std::move(perm_converter)},
          specific_query_executor_{std::move(specific_query_executor)},
          vm_caller_{std::move(vm_caller)} {
      initStatements();
    }

    PostgresCommandExecutor::~PostgresCommandExecutor() = default;

    void PostgresCommandExecutor::skipChanges() {}

    CommandResult PostgresCommandExecutor::execute(
        const shared_model::interface::Command &cmd,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      return boost::apply_visitor(
          [this, &creator_account_id, &tx_hash, cmd_index, do_validation](
              const auto &command) {
            return (*this)(
                command, creator_account_id, tx_hash, cmd_index, do_validation);
          },
          cmd.get());
    }

    soci::session &PostgresCommandExecutor::getSession() {
      return *sql_;
    }

    DatabaseTransaction &PostgresCommandExecutor::dbSession() {
      return db_transaction_;
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::AddAssetQuantity &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &asset_id = command.assetId();
      auto quantity = command.amount().toStringRepr();
      int precision = command.amount().precision();

      StatementExecutor executor(add_asset_quantity_statements_,
                                 do_validation,
                                 "AddAssetQuantity",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("asset_id", asset_id);
      executor.use("precision", precision);
      executor.use("quantity", quantity);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::AddPeer &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &peer = command.peer();

      StatementExecutor executor(peer.isSyncingPeer()
                                     ? add_sync_peer_statements_
                                     : add_peer_statements_,
                                 do_validation,
                                 "AddPeer",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("address", peer.address());
      executor.use("pubkey", peer.pubkey());
      executor.use("tls_certificate", peer.tlsCertificate());

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::AddSignatory &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &target = command.accountId();
      const auto &pubkey = command.pubkey();

      StatementExecutor executor(add_signatory_statements_,
                                 do_validation,
                                 "AddSignatory",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("target", target);
      executor.use("pubkey", pubkey);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::AppendRole &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &target = command.accountId();
      auto &role = command.roleName();

      StatementExecutor executor(append_role_statements_,
                                 do_validation,
                                 "AppendRole",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("target", target);
      executor.use("role", role);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CallEngine &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      try {
        if (vm_caller_) {
          if (do_validation) {  // check permissions
            int has_permission = 0;
            using namespace shared_model::interface::permissions;
            *sql_ << checkAccountHasRoleOrGrantablePerm(
                Role::kCallEngine,
                Grantable::kCallEngineOnMyBehalf,
                ":creator",
                ":caller"),
                soci::use(creator_account_id, "creator"),
                soci::use(command.caller(), "caller"),
                soci::into(has_permission);
            if (has_permission == 0) {
              return makeCommandError(
                  "CallEngine", 2, "Not enough permissions.");
            }
          }

          using namespace shared_model::interface::types;
          PostgresBurrowStorage burrow_storage(*sql_, tx_hash, cmd_index);
          return vm_caller_->get()
              .call(
                  tx_hash,
                  cmd_index,
                  EvmCodeHexStringView{command.input()},
                  command.caller(),
                  command.callee()
                      ? std::optional<EvmCalleeHexStringView>{command.callee()
                                                                  ->get()}
                      : std::optional<EvmCalleeHexStringView>{std::nullopt},
                  burrow_storage,
                  *this,
                  *specific_query_executor_)
              .match(
                  [&](const auto &value) -> CommandResult {
                    StatementExecutor executor(
                        store_engine_response_statements_,
                        false,
                        "StoreEngineReceiptsResponse",
                        perm_converter_);
                    executor.use("tx_hash", tx_hash);
                    executor.use("cmd_index", cmd_index);

                    if (command.callee()) {
                      // calling a deployed contract
                      executor.use("callee", command.callee()->get());
                      executor.use("engine_response", value.value);
                      executor.use("created_address", std::nullopt);
                    } else {
                      // deploying a new contract
                      executor.use("callee", std::nullopt);
                      executor.use("engine_response", std::nullopt);
                      executor.use("created_address", value.value);
                    }

                    return executor.execute();
                  },
                  [](auto &&error) -> CommandResult {
                    return makeCommandError(
                        "CallEngine", 3, std::move(error.error));
                  });

        } else {
          return makeCommandError("CallEngine", 1, "Engine is not configured.");
        }
      } catch (std::exception const &e) {
        return makeCommandError("CallEngine", 1, e.what());
      }
      return {};
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CompareAndSetAccountDetail &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      std::string new_json_value = makeJsonString(command.value());
      const std::string expected_json_value =
          makeJsonString(command.oldValue().value_or(""));

      StatementExecutor executor(compare_and_set_account_detail_statements_,
                                 do_validation,
                                 "CompareAndSetAccountDetail",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("target", command.accountId());
      executor.use("key", command.key());
      executor.use("new_value", new_json_value);
      executor.use("check_empty", command.checkEmpty());
      executor.use("have_expected_value",
                   static_cast<bool>(command.oldValue()));
      executor.use("expected_value", expected_json_value);
      auto creator_domain = getDomainFromName(creator_account_id);
      executor.use("creator_domain", creator_domain);
      auto target_domain = getDomainFromName(command.accountId());
      executor.use("target_domain", target_domain);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CreateAccount &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &account_name = command.accountName();
      auto &domain_id = command.domainId();
      auto &pubkey = command.pubkey();
      shared_model::interface::types::AccountIdType account_id =
          account_name + "@" + domain_id;

      StatementExecutor executor(create_account_statements_,
                                 do_validation,
                                 "CreateAccount",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("account_id", account_id);
      executor.use("domain", domain_id);
      executor.use("pubkey", pubkey);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CreateAsset &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &domain_id = command.domainId();
      auto asset_id = command.assetName() + "#" + domain_id;
      int precision = command.precision();

      StatementExecutor executor(create_asset_statements_,
                                 do_validation,
                                 "CreateAsset",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("asset_id", asset_id);
      executor.use("domain", domain_id);
      executor.use("precision", precision);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CreateDomain &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &domain_id = command.domainId();
      auto &default_role = command.userDefaultRole();

      StatementExecutor executor(create_domain_statements_,
                                 do_validation,
                                 "CreateDomain",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("domain", domain_id);
      executor.use("default_role", default_role);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CreateRole &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &role_id = command.roleName();
      auto &permissions = command.rolePermissions();
      auto perm_str = permissions.toBitstring();

      StatementExecutor executor(create_role_statements_,
                                 do_validation,
                                 "CreateRole",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("role", role_id);
      executor.use("perms", perm_str);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::DetachRole &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &account_id = command.accountId();
      auto &role_name = command.roleName();

      StatementExecutor executor(detach_role_statements_,
                                 do_validation,
                                 "DetachRole",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("target", account_id);
      executor.use("role", role_name);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::GrantPermission &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &permittee_account_id = command.accountId();
      auto granted_perm = command.permissionName();
      auto required_perm =
          shared_model::interface::permissions::permissionFor(granted_perm);

      StatementExecutor executor(grant_permission_statements_,
                                 do_validation,
                                 "GrantPermission",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("target", permittee_account_id);
      executor.use("granted_perm", granted_perm);
      executor.use("required_perm", required_perm);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::RemovePeer &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto pubkey = command.pubkey();

      {
        StatementExecutor executor(remove_sync_peer_statements_,
                                   do_validation,
                                   "RemovePeer",
                                   perm_converter_);
        executor.use("creator", creator_account_id);
        executor.use("pubkey", pubkey);
        executor.execute();
      }

      StatementExecutor executor(remove_peer_statements_,
                                 do_validation,
                                 "RemovePeer",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("pubkey", pubkey);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::RemoveSignatory &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &account_id = command.accountId();
      auto &pubkey = command.pubkey();

      StatementExecutor executor(remove_signatory_statements_,
                                 do_validation,
                                 "RemoveSignatory",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("target", account_id);
      executor.use("pubkey", pubkey);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::RevokePermission &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &permittee_account_id = command.accountId();
      auto revoked_perm = command.permissionName();

      StatementExecutor executor(revoke_permission_statements_,
                                 do_validation,
                                 "RevokePermission",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("target", permittee_account_id);
      executor.use("revoked_perm", revoked_perm);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::SetAccountDetail &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &account_id = command.accountId();
      auto &key = command.key();
      auto &value = command.value();
      std::string json_value = makeJsonString(value);

      StatementExecutor executor(set_account_detail_statements_,
                                 do_validation,
                                 "SetAccountDetail",
                                 perm_converter_);
      if (not creator_account_id.empty()) {
        executor.use("creator", creator_account_id);
      } else {
        // When creator is not known, it is genesis block
        static const std::string genesis_creator_account_id = "genesis";
        executor.use("creator", genesis_creator_account_id);
      }
      executor.use("target", account_id);
      executor.use("key", key);
      executor.use("value", json_value);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::SetQuorum &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &account_id = command.accountId();
      int quorum = command.newQuorum();

      StatementExecutor executor(
          set_quorum_statements_, do_validation, "SetQuorum", perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("target", account_id);
      executor.use("quorum", quorum);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::SubtractAssetQuantity &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &asset_id = command.assetId();
      auto quantity = command.amount().toStringRepr();
      uint32_t precision = command.amount().precision();

      StatementExecutor executor(subtract_asset_quantity_statements_,
                                 do_validation,
                                 "SubtractAssetQuantity",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("asset_id", asset_id);
      executor.use("quantity", quantity);
      executor.use("precision", precision);

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::TransferAsset &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) {
      auto &src_account_id = command.srcAccountId();
      auto &dest_account_id = command.destAccountId();
      auto &asset_id = command.assetId();
      auto quantity = command.amount().toStringRepr();
      uint32_t precision = command.amount().precision();

      StatementExecutor executor(transfer_asset_statements_,
                                 do_validation,
                                 "TransferAsset",
                                 perm_converter_);
      executor.use("creator", creator_account_id);
      executor.use("source_account_id", src_account_id);
      executor.use("dest_account_id", dest_account_id);
      executor.use("asset_id", asset_id);
      executor.use("quantity", quantity);
      executor.use("precision", precision);
      executor.use("description_length", command.description().size());

      return executor.execute();
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::SetSettingValue &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &,
        shared_model::interface::types::CommandIndexType,
        bool do_validation) {
      if (do_validation) {
        // when we decide to allow settings updates, we just add permissions
        return makeCommandError(
            "SetSettingValue",
            2,
            "Currently SetSettingValue is only allowed in genesis block.");
      }

      auto &key = command.key();
      auto &value = command.value();

      StatementExecutor executor(set_setting_value_statements_,
                                 do_validation,
                                 "SetSettingValue",
                                 perm_converter_);

      executor.use("setting_key", key);
      executor.use("setting_value", value);

      return executor.execute();
    }

  }  // namespace ametsuchi
}  // namespace iroha
