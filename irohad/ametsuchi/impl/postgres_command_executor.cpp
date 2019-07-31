/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_command_executor.hpp"

#include <soci/postgresql/soci-postgresql.h>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include "ametsuchi/impl/soci_utils.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/commands/add_asset_quantity.hpp"
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/commands/add_signatory.hpp"
#include "interfaces/commands/append_role.hpp"
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
#include "interfaces/commands/subtract_asset_quantity.hpp"
#include "interfaces/commands/transfer_asset.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/permission_to_string.hpp"
#include "utils/string_builder.hpp"

namespace {
  struct PreparedStatement {
    std::string command_name;
    std::string command_base;
    std::vector<std::string> permission_checks;

    static const std::string validationPrefix;
    static const std::string noValidationPrefix;
  };

  const std::string PreparedStatement::validationPrefix = "WithValidation";
  const std::string PreparedStatement::noValidationPrefix = "WithOutValidation";

  // Transforms prepared statement into two strings:
  //    1. SQL query with validation
  //    2. SQL query without validation
  std::pair<std::string, std::string> compileStatement(
      const PreparedStatement &statement) {
    // Create query with validation
    auto with_validation = boost::format(statement.command_base)
        % (statement.command_name + PreparedStatement::validationPrefix);

    // append all necessary checks to the query
    for (const auto &check : statement.permission_checks) {
      with_validation = with_validation % check;
    }

    // Create query without validation
    auto without_validation = boost::format(statement.command_base)
        % (statement.command_name + PreparedStatement::noValidationPrefix);

    // since checks are not needed, append empty strings to their place
    for (size_t i = 0; i < statement.permission_checks.size(); i++) {
      without_validation = without_validation % "";
    }

    return {with_validation.str(), without_validation.str()};
  }

  void prepareStatement(soci::session &sql,
                        const PreparedStatement &statement) {
    auto queries = compileStatement(statement);

    sql << queries.first;
    sql << queries.second;
  }

  template <typename QueryArgsCallable>
  iroha::expected::Error<iroha::ametsuchi::CommandError> makeCommandError(
      std::string &&command_name,
      const iroha::ametsuchi::CommandError::ErrorCodeType code,
      QueryArgsCallable &&query_args) noexcept {
    return iroha::expected::makeError(iroha::ametsuchi::CommandError{
        std::move(command_name), code, query_args()});
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
   * @tparam QueryArgsCallable - type of callable to get query arguments
   * @param command_name - name of the failed command
   * @param error - string error, which SQL gave out
   * @param query_args - callable to get a string representation of query
   * arguments
   * @return command_error structure
   */
  template <typename QueryArgsCallable>
  iroha::ametsuchi::CommandResult getCommandError(
      std::string &&command_name,
      const std::string &error,
      QueryArgsCallable &&query_args) noexcept {
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
          return makeCommandError(std::move(command_name),
                                  *real_error_code,
                                  std::forward<QueryArgsCallable>(query_args));
        }
        break;
      }
    }
    // parsing is not successful, return the general error
    return makeCommandError(std::move(command_name),
                            1,
                            std::forward<QueryArgsCallable>(query_args));
  }

  /**
   * Executes sql query
   * Assumes that statement query returns 0 in case of success
   * or error code in case of failure
   * @tparam QueryArgsCallable - type of callable to get query arguments
   * @param sql - connection on which to execute statement
   * @param cmd - sql query to be executed
   * @param command_name - which command executes a query
   * @param query_args - callable to get a string representation of query
   * arguments
   * @return CommandResult with command name and error message
   */
  template <typename QueryArgsCallable>
  iroha::ametsuchi::CommandResult executeQuery(
      soci::session &sql,
      const std::string &cmd,
      std::string command_name,
      QueryArgsCallable &&query_args) noexcept {
    uint32_t result;
    try {
      sql << cmd, soci::into(result);
      if (result != 0) {
        return makeCommandError(std::move(command_name),
                                result,
                                std::forward<QueryArgsCallable>(query_args));
      }
      return {};
    } catch (const std::exception &e) {
      return getCommandError(std::move(command_name),
                             e.what(),
                             std::forward<QueryArgsCallable>(query_args));
    }
  }

  std::string checkAccountRolePermission(
      shared_model::interface::permissions::Role permission,
      const shared_model::interface::types::AccountIdType &account_id) {
    const auto perm_str =
        shared_model::interface::RolePermissionSet({permission}).toBitstring();
    const auto bits = shared_model::interface::RolePermissionSet::size();
    std::string query = (boost::format(R"(
          SELECT COALESCE(bit_or(rp.permission), '0'::bit(%1%))
          & '%2%' = '%2%' FROM role_has_permissions AS rp
              JOIN account_has_roles AS ar on ar.role_id = rp.role_id
              WHERE ar.account_id = %3%)")
                         % bits % perm_str % account_id)
                            .str();
    return query;
  }

  std::string checkAccountGrantablePermission(
      shared_model::interface::permissions::Grantable permission,
      const shared_model::interface::types::AccountIdType &creator_id,
      const shared_model::interface::types::AccountIdType &account_id) {
    const auto perm_str =
        shared_model::interface::GrantablePermissionSet({permission})
            .toBitstring();
    const auto bits = shared_model::interface::GrantablePermissionSet::size();
    std::string query = (boost::format(R"(
          SELECT COALESCE(bit_or(permission), '0'::bit(%1%))
          & '%2%' = '%2%' FROM account_has_grantable_permissions
              WHERE account_id = %4% AND
              permittee_account_id = %3%
          )") % bits % perm_str
                         % creator_id % account_id)
                            .str();
    return query;
  }

  shared_model::interface::types::DomainIdType getDomainFromName(
      const shared_model::interface::types::AccountIdType &account_id) {
    // TODO 03.10.18 andrei: IR-1728 Move getDomainFromName to shared_model
    std::vector<std::string> res;
    boost::split(res, account_id, boost::is_any_of("@"));
    return res.at(1);
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
      shared_model::interface::permissions::Role indiv_permission_id,
      shared_model::interface::permissions::Role all_permission_id,
      shared_model::interface::permissions::Role domain_permission_id,
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
    has_indiv_perm AS (
      SELECT (COALESCE(bit_or(rp.permission), '0'::bit(%1%))
      & '%3%') = '%3%' FROM role_has_permissions AS rp
          JOIN account_has_roles AS ar on ar.role_id = rp.role_id
          WHERE ar.account_id = %2%
    ),
    has_all_perm AS (
      SELECT (COALESCE(bit_or(rp.permission), '0'::bit(%1%))
      & '%4%') = '%4%' FROM role_has_permissions AS rp
          JOIN account_has_roles AS ar on ar.role_id = rp.role_id
          WHERE ar.account_id = %2%
    ),
    has_domain_perm AS (
      SELECT (COALESCE(bit_or(rp.permission), '0'::bit(%1%))
      & '%5%') = '%5%' FROM role_has_permissions AS rp
          JOIN account_has_roles AS ar on ar.role_id = rp.role_id
          WHERE ar.account_id = %2%
    ),
    has_query_perm AS (
      SELECT (%2% = %6% AND (SELECT * FROM has_indiv_perm))
          OR (SELECT * FROM has_all_perm)
          OR (%7% = %8% AND (SELECT * FROM has_domain_perm)) AS perm
    )
    )");

    return (cmd % bits % creator % perm_str % all_perm_str % domain_perm_str
            % target_account % creator_domain % target_account_domain)
        .str();
  }

  std::string checkAccountDomainRoleOrGlobalRolePermission(
      shared_model::interface::permissions::Role global_permission,
      shared_model::interface::permissions::Role domain_permission,
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
      shared_model::interface::permissions::Role role,
      shared_model::interface::permissions::Grantable grantable,
      const shared_model::interface::types::AccountIdType &creator_id,
      const shared_model::interface::types::AccountIdType &account_id) {
    return (boost::format(R"(WITH
          has_role_perm AS (%s),
          has_grantable_perm AS (%s)
          SELECT CASE
                           WHEN (SELECT * FROM has_grantable_perm) THEN true
                           WHEN (%s = %s) THEN
                               CASE
                                   WHEN (SELECT * FROM has_role_perm) THEN true
                                   ELSE false
                                END
                           ELSE false END
          )")
            % checkAccountRolePermission(role, creator_id)
            % checkAccountGrantablePermission(grantable, creator_id, account_id)
            % creator_id % account_id)
        .str();
  }

  template <typename Format>
  void appendCommandName(const std::string &name,
                         Format &cmd,
                         bool do_validation) {
    auto command_name = name
        + (do_validation ? PreparedStatement::validationPrefix
                         : PreparedStatement::noValidationPrefix);
    cmd % command_name;
  }

  /**
   * Get a pretty string builder initialized for query arguments append
   * @return string builder
   */
  shared_model::detail::PrettyStringBuilder getQueryArgsStringBuilder() {
    return shared_model::detail::PrettyStringBuilder().init("Query arguments");
  }
}  // namespace

namespace iroha {
  namespace ametsuchi {
    // TODO [IR-1830] Akvinikym 31.10.18: make benchmarks to compare exception
    // parsing vs nested queries
    const std::string PostgresCommandExecutor::addAssetQuantityBase = R"(
          PREPARE %s (text, text, int, text) AS
          WITH %s
               new_quantity AS (
                   SELECT $4::decimal + coalesce(sum(amount), 0) as value
                   FROM account_has_asset
                   WHERE asset_id = $2
                       AND account_id = $1
               ),
               checks AS (
                   -- error code and check result
                   SELECT 1 code, count(1) = 1 result
                   FROM account
                   WHERE account_id = $1

                   UNION
                   SELECT 3, count(1) = 1
                   FROM asset
                   WHERE asset_id = $2
                      AND precision >= $3

                   UNION
                   SELECT 4, value < (2::decimal ^ 256) / (10::decimal ^ precision)
                   FROM new_quantity, asset
                   WHERE asset_id = $2
               ),
               inserted AS
               (
                  INSERT INTO account_has_asset(account_id, asset_id, amount)
                  (
                      SELECT $1, $2, value FROM new_quantity
                      WHERE (SELECT bool_and(checks.result) FROM checks) %s
                  )
                  ON CONFLICT (account_id, asset_id) DO UPDATE
                  SET amount = EXCLUDED.amount
                  RETURNING (1)
               )
          SELECT CASE
              %s
              WHEN EXISTS (SELECT * FROM inserted LIMIT 1) THEN 0
              ELSE (SELECT code FROM checks WHERE not result LIMIT 1)
          END AS result;)";

    const std::string PostgresCommandExecutor::addPeerBase = R"(
          PREPARE %s (text, text, text) AS
          WITH
          %s
          inserted AS (
              INSERT INTO peer(public_key, address)
              (
                  SELECT $2, $3
                  %s
              ) RETURNING (1)
          )
          SELECT CASE WHEN EXISTS (SELECT * FROM inserted) THEN 0
              %s
              ELSE 1 END AS result)";

    const std::string PostgresCommandExecutor::addSignatoryBase = R"(
          PREPARE %s (text, text, text) AS
          WITH %s
          insert_signatory AS
          (
              INSERT INTO signatory(public_key)
              (SELECT $3 %s) ON CONFLICT DO NOTHING RETURNING (1)
          ),
          has_signatory AS (SELECT * FROM signatory WHERE public_key = $3),
          insert_account_signatory AS
          (
              INSERT INTO account_has_signatory(account_id, public_key)
              (
                  SELECT $2, $3 WHERE (EXISTS
                  (SELECT * FROM insert_signatory) OR
                  EXISTS (SELECT * FROM has_signatory))
                  %s
              )
              RETURNING (1)
          )
          SELECT CASE
              WHEN EXISTS (SELECT * FROM insert_account_signatory) THEN 0
              %s
              ELSE 1
          END AS RESULT;)";

    const std::string PostgresCommandExecutor::appendRoleBase = R"(
            PREPARE %s (text, text, text) AS
            WITH %s
            role_exists AS (SELECT * FROM role WHERE role_id = $3),
            inserted AS (
                INSERT INTO account_has_roles(account_id, role_id)
                (
                    SELECT $2, $3 %s) RETURNING (1)
            )
            SELECT CASE
                WHEN EXISTS (SELECT * FROM inserted) THEN 0
                WHEN NOT EXISTS (SELECT * FROM role_exists) THEN 4
                %s
                ELSE 1
            END AS result)";

    const std::string PostgresCommandExecutor::createAccountBase = R"(
          PREPARE %s (text, text, text, text) AS
          WITH get_domain_default_role AS (SELECT default_role FROM domain
                                           WHERE domain_id = $3),
          %s
          insert_signatory AS
          (
              INSERT INTO signatory(public_key)
              (
                  SELECT $4 WHERE EXISTS
                  (SELECT * FROM get_domain_default_role)
              ) ON CONFLICT DO NOTHING RETURNING (1)
          ),
          has_signatory AS (SELECT * FROM signatory WHERE public_key = $4),
          insert_account AS
          (
              INSERT INTO account(account_id, domain_id, quorum, data)
              (
                  SELECT $2, $3, 1, '{}' WHERE (EXISTS
                      (SELECT * FROM insert_signatory) OR EXISTS
                      (SELECT * FROM has_signatory)
                  ) AND EXISTS (SELECT * FROM get_domain_default_role)
                  %s
              ) RETURNING (1)
          ),
          insert_account_signatory AS
          (
              INSERT INTO account_has_signatory(account_id, public_key)
              (
                  SELECT $2, $4 WHERE
                     EXISTS (SELECT * FROM insert_account)
              )
              RETURNING (1)
          ),
          insert_account_role AS
          (
              INSERT INTO account_has_roles(account_id, role_id)
              (
                  SELECT $2, default_role FROM get_domain_default_role
                  WHERE EXISTS (SELECT * FROM get_domain_default_role)
                    AND EXISTS (SELECT * FROM insert_account_signatory)
              ) RETURNING (1)
          )
          SELECT CASE
              WHEN EXISTS (SELECT * FROM insert_account_role) THEN 0
              WHEN NOT EXISTS (SELECT * FROM get_domain_default_role) THEN 3
              %s
              ELSE 1
              END AS result)";

    const std::string PostgresCommandExecutor::createAssetBase = R"(
              PREPARE %s (text, text, text, int) AS
              WITH %s
              inserted AS
              (
                  INSERT INTO asset(asset_id, domain_id, precision, data)
                  (
                      SELECT $2, $3, $4, NULL
                      %s
                  ) RETURNING (1)
              )
              SELECT CASE WHEN EXISTS (SELECT * FROM inserted) THEN 0
              %s
              ELSE 1 END AS result)";

    const std::string PostgresCommandExecutor::createDomainBase = R"(
              PREPARE %s (text, text, text) AS
              WITH %s
              inserted AS
              (
                  INSERT INTO domain(domain_id, default_role)
                  (
                      SELECT $2, $3
                      %s
                  ) RETURNING (1)
              )
              SELECT CASE WHEN EXISTS (SELECT * FROM inserted) THEN 0
              %s
              ELSE 1 END AS result)";

    const std::string PostgresCommandExecutor::createRoleBase = R"(
          PREPARE %s (text, text, bit) AS
          WITH %s
          insert_role AS (INSERT INTO role(role_id)
                              (SELECT $2
                              %s) RETURNING (1)),
          insert_role_permissions AS
          (
              INSERT INTO role_has_permissions(role_id, permission)
              (
                  SELECT $2, $3 WHERE EXISTS
                      (SELECT * FROM insert_role)
              ) RETURNING (1)
          )
          SELECT CASE
              WHEN EXISTS (SELECT * FROM insert_role_permissions) THEN 0
              %s
              WHEN EXISTS (SELECT * FROM role WHERE role_id = $2) THEN 2
              ELSE 1
              END AS result)";

    const std::string PostgresCommandExecutor::detachRoleBase = R"(
            PREPARE %s (text, text, text) AS
            WITH %s
            deleted AS
            (
              DELETE FROM account_has_roles
              WHERE account_id=$2
              AND role_id=$3
              %s
              RETURNING (1)
            )
            SELECT CASE WHEN EXISTS (SELECT * FROM deleted) THEN 0
            WHEN NOT EXISTS (SELECT * FROM account
                             WHERE account_id = $2) THEN 3
            WHEN NOT EXISTS (SELECT * FROM role
                             WHERE role_id = $3) THEN 5
            WHEN NOT EXISTS (SELECT * FROM account_has_roles
                             WHERE account_id=$2 AND role_id=$3) THEN 4
            %s
            ELSE 1 END AS result)";

    const std::string PostgresCommandExecutor::grantPermissionBase = R"(
          PREPARE %s (text, text, bit, bit) AS
          WITH %s
            inserted AS (
              INSERT INTO account_has_grantable_permissions AS
              has_perm(permittee_account_id, account_id, permission)
              (SELECT $2, $1, $3 %s) ON CONFLICT
              (permittee_account_id, account_id)
              DO UPDATE SET permission=(SELECT has_perm.permission | $3
              WHERE (has_perm.permission & $3) <> $3)
              RETURNING (1)
            )
            SELECT CASE WHEN EXISTS (SELECT * FROM inserted) THEN 0
              %s
              ELSE 1 END AS result)";

    const std::string PostgresCommandExecutor::removePeerBase = R"(
          PREPARE %s (text, text) AS
          WITH
          %s
          removed AS (
              DELETE FROM peer WHERE public_key = $2
              %s
              RETURNING (1)
          )
          SELECT CASE WHEN EXISTS (SELECT * FROM removed) THEN 0
              %s
              ELSE 1 END AS result)";

    const std::string PostgresCommandExecutor::removeSignatoryBase = R"(
          PREPARE %s (text, text, text) AS
          WITH
          %s
          delete_account_signatory AS (DELETE FROM account_has_signatory
              WHERE account_id = $2
              AND public_key = $3
              %s
              RETURNING (1)),
          delete_signatory AS
          (
              DELETE FROM signatory WHERE public_key = $3 AND
                  NOT EXISTS (SELECT 1 FROM account_has_signatory
                              WHERE public_key = $3)
                  AND NOT EXISTS (SELECT 1 FROM peer WHERE public_key = $3)
              RETURNING (1)
          )
          SELECT CASE
              WHEN EXISTS (SELECT * FROM delete_account_signatory) THEN
              CASE
                  WHEN EXISTS (SELECT * FROM delete_signatory) THEN 0
                  WHEN EXISTS (SELECT 1 FROM account_has_signatory
                               WHERE public_key = $3) THEN 0
                  WHEN EXISTS (SELECT 1 FROM peer
                               WHERE public_key = $3) THEN 0
                  ELSE 1
              END
              %s
              ELSE 1
          END AS result)";

    const std::string PostgresCommandExecutor::revokePermissionBase = R"(
          PREPARE %s (text, text, bit, bit) AS
          WITH %s
              inserted AS (
                  UPDATE account_has_grantable_permissions as has_perm
                  SET permission=(SELECT has_perm.permission & $4
                  WHERE has_perm.permission & $3 = $3 AND
                  has_perm.permittee_account_id=$2 AND
                  has_perm.account_id=$1) WHERE
                  permittee_account_id=$2 AND
                  account_id=$1 %s
                RETURNING (1)
              )
              SELECT CASE WHEN EXISTS (SELECT * FROM inserted) THEN 0
                  %s
                  ELSE 1 END AS result)";

    const std::string PostgresCommandExecutor::setAccountDetailBase = R"(
          PREPARE %s (text, text, text, text) AS
          WITH %s
              inserted AS
              (
                  UPDATE account SET data = jsonb_set(
                  CASE WHEN data ?$1 THEN data ELSE
                  jsonb_set(data, array[$1], '{}') END,
                  array[$1, $3], $4::jsonb) WHERE account_id=$2 %s
                  RETURNING (1)
              )
              SELECT CASE WHEN EXISTS (SELECT * FROM inserted) THEN 0
                  WHEN NOT EXISTS
                      (SELECT * FROM account WHERE account_id=$2) THEN 3
                  %s
                  ELSE 1 END AS result)";

    const std::string PostgresCommandExecutor::setQuorumBase = R"(
          PREPARE %s (text, text, int) AS
          WITH
          %s
          %s
          updated AS (
              UPDATE account SET quorum=$3
              WHERE account_id=$2
              %s
              RETURNING (1)
          )
          SELECT CASE WHEN EXISTS (SELECT * FROM updated) THEN 0
              %s
              ELSE 1
          END AS result)";

    const std::string PostgresCommandExecutor::subtractAssetQuantityBase = R"(
          PREPARE %s (text, text, int, text) AS
          WITH %s
               has_account AS (SELECT account_id FROM account
                               WHERE account_id = $1 LIMIT 1),
               has_asset AS (SELECT asset_id FROM asset
                             WHERE asset_id = $2
                             AND precision >= $3 LIMIT 1),
               amount AS (SELECT amount FROM account_has_asset
                          WHERE asset_id = $2
                          AND account_id = $1 LIMIT 1),
               new_value AS (SELECT
                              (SELECT
                                  CASE WHEN EXISTS
                                      (SELECT amount FROM amount LIMIT 1)
                                      THEN (SELECT amount FROM amount LIMIT 1)
                                  ELSE 0::decimal
                              END) - $4::decimal AS value
                          ),
               inserted AS
               (
                  INSERT INTO account_has_asset(account_id, asset_id, amount)
                  (
                      SELECT $1, $2, value FROM new_value
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
          END AS result)";

    const std::string PostgresCommandExecutor::transferAssetBase = R"(
          PREPARE %s (text, text, text, text, int, text) AS
          WITH
              %s
              new_src_quantity AS (
                  SELECT coalesce(sum(amount), 0) - $6::decimal as value
                  FROM account_has_asset
                     WHERE asset_id = $4 AND
                     account_id = $2
              ),
              new_dest_quantity AS (
                  SELECT coalesce(sum(amount), 0) + $6::decimal as value
                  FROM account_has_asset
                     WHERE asset_id = $4 AND
                     account_id = $3
              ),
              checks AS (
                  -- error code and check result
                  SELECT 3 code, count(1) = 1 result
                  FROM account
                  WHERE account_id = $2

                  UNION
                  SELECT 4, count(1) = 1
                  FROM account
                  WHERE account_id = $3

                  UNION
                  SELECT 5, count(1) = 1
                  FROM asset
                  WHERE asset_id = $4
                     AND precision >= $5

                  UNION
                  SELECT 6, value >= 0
                  FROM new_src_quantity

                  UNION
                  SELECT 7, value < (2::decimal ^ 256) / (10::decimal ^ precision)
                  FROM new_dest_quantity, asset
                  WHERE asset_id = $4
              ),
              insert_src AS
              (
                  UPDATE account_has_asset
                  SET amount = value
                  FROM new_src_quantity
                  WHERE
                      account_id = $2
                      AND asset_id = $4
                      AND (SELECT bool_and(checks.result) FROM checks) %s
              ),
              insert_dest AS
              (
                  INSERT INTO account_has_asset(account_id, asset_id, amount)
                  (
                      SELECT $3, $4, value
                      FROM new_dest_quantity
                      WHERE (SELECT bool_and(checks.result) FROM checks) %s
                  )
                  ON CONFLICT (account_id, asset_id)
                  DO UPDATE SET amount = EXCLUDED.amount
                  RETURNING (1)
               )
          SELECT CASE
              WHEN EXISTS (SELECT * FROM insert_dest LIMIT 1) THEN 0
              %s
              ELSE (SELECT code FROM checks WHERE not result LIMIT 1)
          END AS result)";

    const std::string PostgresCommandExecutor::compareAndSetAccountDetailBase =
        R"(PREPARE %s (text, text, text, text, text, text, text) AS
          WITH %s
              old_value AS
              (
                  SELECT *
                  FROM account
                  WHERE
                    account_id = $2
                    AND CASE
                      WHEN data ? $1 AND data->$1 ?$3
                        THEN
                          CASE
                            WHEN $5 IS NOT NULL THEN data->$1->$3 = $5::jsonb
                            ELSE FALSE
                          END
                      ELSE $5 IS NULL
                    END
              ),
              inserted AS
              (
                  UPDATE account
                  SET data = jsonb_set(
                    CASE
                      WHEN data ? $1 THEN data
                      ELSE jsonb_set(data, array[$1], '{}')
                    END,
                    array[$1, $3], $4::jsonb
                  )
                  WHERE
                    EXISTS (SELECT * FROM old_value)
                    AND account_id = $2
                    %s
                  RETURNING (1)
              )
              SELECT CASE
                  WHEN EXISTS (SELECT * FROM inserted) THEN 0
                  WHEN NOT EXISTS
                        (SELECT * FROM account WHERE account_id=$2) THEN 3
                  WHEN NOT EXISTS (SELECT * FROM old_value) THEN 4
                  %s
                  ELSE 1
                END
              AS result)";

    std::string CommandError::toString() const {
      return (boost::format("%s: %d with extra info '%s'") % command_name
              % error_code % error_extra)
          .str();
    }

    PostgresCommandExecutor::PostgresCommandExecutor(
        soci::session &sql,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter)
        : sql_(sql),
          do_validation_(true),
          perm_converter_{std::move(perm_converter)} {}

    void PostgresCommandExecutor::setCreatorAccountId(
        const shared_model::interface::types::AccountIdType
            &creator_account_id) {
      creator_account_id_ = creator_account_id;
    }

    void PostgresCommandExecutor::doValidation(bool do_validation) {
      do_validation_ = do_validation;
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::AddAssetQuantity &command) {
      auto &account_id = creator_account_id_;
      auto &asset_id = command.assetId();
      auto amount = command.amount().toStringRepr();
      int precision = command.amount().precision();

      // 14.09.2018 nickaleks: IR-1707 move common logic to separate function
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', %4%, '%5%')");

      appendCommandName("addAssetQuantity", cmd, do_validation_);

      cmd = (cmd % account_id % asset_id % precision % amount);

      auto str_args = [&account_id, &asset_id, &amount, precision] {
        return getQueryArgsStringBuilder()
            .append("account_id", account_id)
            .append("asset_id", asset_id)
            .append("amount", amount)
            .append("precision", std::to_string(precision))
            .finalize();
      };

      return executeQuery(
          sql_, cmd.str(), "AddAssetQuantity", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::AddPeer &command) {
      auto &peer = command.peer();

      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%')");

      appendCommandName("addPeer", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % peer.pubkey().hex() % peer.address());

      auto str_args = [&peer] {
        return getQueryArgsStringBuilder()
            .append("peer", peer.toString())
            .finalize();
      };

      return executeQuery(sql_, cmd.str(), "AddPeer", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::AddSignatory &command) {
      auto &account_id = command.accountId();
      auto pubkey = command.pubkey().hex();
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%')");

      appendCommandName("addSignatory", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % account_id % pubkey);

      auto str_args = [&account_id, &pubkey] {
        return getQueryArgsStringBuilder()
            .append("account_id", account_id)
            .append("pubkey", pubkey)
            .finalize();
      };

      return executeQuery(sql_, cmd.str(), "AddSignatory", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::AppendRole &command) {
      auto &account_id = command.accountId();
      auto &role_name = command.roleName();
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%')");

      appendCommandName("appendRole", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % account_id % role_name);

      auto str_args = [&account_id, &role_name] {
        return getQueryArgsStringBuilder()
            .append("account_id", account_id)
            .append("role_name", role_name)
            .finalize();
      };

      return executeQuery(sql_, cmd.str(), "AppendRole", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CreateAccount &command) {
      auto &account_name = command.accountName();
      auto &domain_id = command.domainId();
      auto &pubkey = command.pubkey().hex();
      shared_model::interface::types::AccountIdType account_id =
          account_name + "@" + domain_id;

      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%', '%5%')");

      appendCommandName("createAccount", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % account_id % domain_id % pubkey);

      auto str_args = [&account_id, &domain_id, &pubkey] {
        return getQueryArgsStringBuilder()
            .append("account_id", account_id)
            .append("domain_id", domain_id)
            .append("pubkey", pubkey)
            .finalize();
      };

      return executeQuery(
          sql_, cmd.str(), "CreateAccount", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CreateAsset &command) {
      auto &domain_id = command.domainId();
      auto asset_id = command.assetName() + "#" + domain_id;
      int precision = command.precision();
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%', %5%)");

      appendCommandName("createAsset", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % asset_id % domain_id % precision);

      auto str_args = [&domain_id, &asset_id, precision] {
        return getQueryArgsStringBuilder()
            .append("domain_id", domain_id)
            .append("asset_id", asset_id)
            .append("precision", std::to_string(precision))
            .finalize();
      };

      return executeQuery(sql_, cmd.str(), "CreateAsset", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CreateDomain &command) {
      auto &domain_id = command.domainId();
      auto &default_role = command.userDefaultRole();
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%')");

      appendCommandName("createDomain", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % domain_id % default_role);

      auto str_args = [&domain_id, &default_role] {
        return getQueryArgsStringBuilder()
            .append("domain_id", domain_id)
            .append("default_role", default_role)
            .finalize();
      };

      return executeQuery(sql_, cmd.str(), "CreateDomain", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CreateRole &command) {
      auto &role_id = command.roleName();
      auto &permissions = command.rolePermissions();
      auto perm_str = permissions.toBitstring();
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%')");

      appendCommandName("createRole", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % role_id % perm_str);

      auto str_args = [&role_id, &perm_str] {
        // TODO [IR-1889] Akvinikym 21.11.18: integrate
        // PermissionSet::toString() instead of bit string, when it is created
        return getQueryArgsStringBuilder()
            .append("role_id", role_id)
            .append("perm_str", perm_str)
            .finalize();
      };

      return executeQuery(sql_, cmd.str(), "CreateRole", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::DetachRole &command) {
      auto &account_id = command.accountId();
      auto &role_name = command.roleName();
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%')");

      appendCommandName("detachRole", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % account_id % role_name);

      auto str_args = [&account_id, &role_name] {
        return getQueryArgsStringBuilder()
            .append("account_id", account_id)
            .append("role_name", role_name)
            .finalize();
      };

      return executeQuery(sql_, cmd.str(), "DetachRole", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::GrantPermission &command) {
      auto &permittee_account_id = command.accountId();
      auto permission = command.permissionName();
      auto perm = shared_model::interface::RolePermissionSet(
                      {shared_model::interface::permissions::permissionFor(
                          command.permissionName())})
                      .toBitstring();
      const auto perm_str =
          shared_model::interface::GrantablePermissionSet({permission})
              .toBitstring();
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%', '%5%')");

      appendCommandName("grantPermission", cmd, do_validation_);

      cmd =
          (cmd % creator_account_id_ % permittee_account_id % perm_str % perm);

      auto str_args = [&creator_account_id = creator_account_id_,
                       &permittee_account_id,
                       permission = perm_converter_->toString(permission)] {
        return getQueryArgsStringBuilder()
            .append("creator_account_id_", creator_account_id)
            .append("permittee_account_id", permittee_account_id)
            .append("permission", permission)
            .finalize();
      };

      return executeQuery(
          sql_, cmd.str(), "GrantPermission", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::RemovePeer &command) {
      auto pubkey = command.pubkey();

      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%')");

      appendCommandName("removePeer", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % pubkey.hex());

      auto str_args = [&pubkey] {
        return getQueryArgsStringBuilder().append(pubkey.toString()).finalize();
      };

      return executeQuery(sql_, cmd.str(), "RemovePeer", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::RemoveSignatory &command) {
      auto &account_id = command.accountId();
      auto &pubkey = command.pubkey().hex();
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%')");

      appendCommandName("removeSignatory", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % account_id % pubkey);

      auto str_args = [&account_id, &pubkey] {
        return getQueryArgsStringBuilder()
            .append("account_id", account_id)
            .append("pubkey", pubkey)
            .finalize();
      };

      return executeQuery(
          sql_, cmd.str(), "RemoveSignatory", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::RevokePermission &command) {
      auto &permittee_account_id = command.accountId();
      auto permission = command.permissionName();
      const auto without_perm_str =
          shared_model::interface::GrantablePermissionSet()
              .setAll()
              .unset(permission)
              .toBitstring();
      const auto perms = shared_model::interface::GrantablePermissionSet()
                             .set(permission)
                             .toBitstring();

      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%', '%5%')");

      appendCommandName("revokePermission", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % permittee_account_id % perms
             % without_perm_str);

      auto str_args = [&creator_account_id = creator_account_id_,
                       &permittee_account_id,
                       permission = perm_converter_->toString(permission)] {
        return getQueryArgsStringBuilder()
            .append("creator_account_id_", creator_account_id)
            .append("permittee_account_id", permittee_account_id)
            .append("permission", permission)
            .finalize();
      };

      return executeQuery(
          sql_, cmd.str(), "RevokePermission", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::SetAccountDetail &command) {
      auto &account_id = command.accountId();
      auto &key = command.key();
      auto &value = command.value();
      if (creator_account_id_.empty()) {
        // When creator is not known, it is genesis block
        creator_account_id_ = "genesis";
      }
      std::string val = "\"" + value + "\"";

      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', '%4%', '%5%')");

      appendCommandName("setAccountDetail", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % account_id % key % val);

      auto str_args = [&account_id, &key, &value] {
        return getQueryArgsStringBuilder()
            .append("account_id", account_id)
            .append("key", key)
            .append("value", value)
            .finalize();
      };

      return executeQuery(
          sql_, cmd.str(), "SetAccountDetail", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::SetQuorum &command) {
      auto &account_id = command.accountId();
      int quorum = command.newQuorum();
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', %4%)");

      appendCommandName("setQuorum", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % account_id % quorum);

      auto str_args = [&account_id, quorum] {
        return getQueryArgsStringBuilder()
            .append("account_id", account_id)
            .append("quorum", std::to_string(quorum))
            .finalize();
      };

      return executeQuery(sql_, cmd.str(), "SetQuorum", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::SubtractAssetQuantity &command) {
      auto &asset_id = command.assetId();
      auto amount = command.amount().toStringRepr();
      uint32_t precision = command.amount().precision();
      auto cmd = boost::format("EXECUTE %1% ('%2%', '%3%', %4%, '%5%')");

      appendCommandName("subtractAssetQuantity", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % asset_id % precision % amount);

      auto str_args = [&creator_account_id = creator_account_id_,
                       &asset_id,
                       &amount,
                       precision] {
        return getQueryArgsStringBuilder()
            .append("creator_account_id", creator_account_id)
            .append("asset_id", asset_id)
            .append("amount", amount)
            .append("precision", std::to_string(precision))
            .finalize();
      };

      return executeQuery(
          sql_, cmd.str(), "SubtractAssetQuantity", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::TransferAsset &command) {
      auto &src_account_id = command.srcAccountId();
      auto &dest_account_id = command.destAccountId();
      auto &asset_id = command.assetId();
      auto amount = command.amount().toStringRepr();
      uint32_t precision = command.amount().precision();
      auto cmd =
          boost::format("EXECUTE %1% ('%2%', '%3%', '%4%', '%5%', %6%, '%7%')");

      appendCommandName("transferAsset", cmd, do_validation_);

      cmd = (cmd % creator_account_id_ % src_account_id % dest_account_id
             % asset_id % precision % amount);

      auto str_args =
          [&src_account_id, &dest_account_id, &asset_id, &amount, precision] {
            return getQueryArgsStringBuilder()
                .append("src_account_id", src_account_id)
                .append("dest_account_id", dest_account_id)
                .append("asset_id", asset_id)
                .append("amount", amount)
                .append("precision", std::to_string(precision))
                .finalize();
          };

      return executeQuery(
          sql_, cmd.str(), "TransferAsset", std::move(str_args));
    }

    CommandResult PostgresCommandExecutor::operator()(
        const shared_model::interface::CompareAndSetAccountDetail &command) {
      auto &account_id = command.accountId();
      auto &key = command.key();
      auto &value = command.value();
      auto &old_value = command.oldValue();

      auto cmd = boost::format(
          "EXECUTE %1% ('%2%', '%3%', '%4%', '%5%', %6%, '%7%', '%8%')");

      appendCommandName("compareAndSetAccountDetail", cmd, do_validation_);

      std::string new_json_value = "\"" + value + "\"";
      std::string expected_json_value = "NULL";

      if (old_value) {
        expected_json_value = "'\"" + old_value.get() + "\"'";
      }

      cmd = (cmd % creator_account_id_ % account_id % key % new_json_value
             % expected_json_value % getDomainFromName(creator_account_id_)
             % getDomainFromName(account_id));

      auto str_args = [&account_id, &key, &new_json_value, &old_value] {
        return getQueryArgsStringBuilder()
            .append("account_id", account_id)
            .append("key", key)
            .append("value", new_json_value)
            .append("old_value",
                    old_value ? "\"" + old_value.get() + "\"" : "NULL")
            .finalize();
      };

      return executeQuery(
          sql_, cmd.str(), "compareAndSetAccountDetail", std::move(str_args));
    }

    void PostgresCommandExecutor::prepareStatements(soci::session &sql) {
      std::vector<PreparedStatement> statements;

      statements.push_back(
          {"addAssetQuantity",
           addAssetQuantityBase,
           {(boost::format(R"(has_perm AS (%s),)")
             % checkAccountDomainRoleOrGlobalRolePermission(
                   shared_model::interface::permissions::Role::kAddAssetQty,
                   shared_model::interface::permissions::Role::
                       kAddDomainAssetQty,
                   "$1",
                   "$2"))
                .str(),
            "AND (SELECT * from has_perm)",
            "WHEN NOT (SELECT * from has_perm) THEN 2"}});

      statements.push_back(
          {"addPeer",
           addPeerBase,
           {(boost::format(R"(has_perm AS (%s),)")
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kAddPeer, "$1"))
                .str(),
            "WHERE (SELECT * FROM has_perm)",
            "WHEN NOT (SELECT * from has_perm) THEN 2"}});

      statements.push_back(
          {"addSignatory",
           addSignatoryBase,
           {(boost::format(R"(
                has_perm AS (%s),)")
             % checkAccountHasRoleOrGrantablePerm(
                   shared_model::interface::permissions::Role::kAddSignatory,
                   shared_model::interface::permissions::Grantable::
                       kAddMySignatory,
                   "$1",
                   "$2"))
                .str(),
            " WHERE (SELECT * FROM has_perm)",
            " AND (SELECT * FROM has_perm)",
            "WHEN NOT (SELECT * from has_perm) THEN 2"}});

      const auto bits = shared_model::interface::RolePermissionSet::size();
      const auto grantable_bits =
          shared_model::interface::GrantablePermissionSet::size();

      statements.push_back(
          {"appendRole",
           appendRoleBase,
           {(boost::format(R"(
            has_perm AS (%1%),
            role_permissions AS (
                SELECT permission FROM role_has_permissions
                WHERE role_id = $3
            ),
            account_roles AS (
                SELECT role_id FROM account_has_roles WHERE account_id = $1
            ),
            account_has_role_permissions AS (
                SELECT COALESCE(bit_or(rp.permission), '0'::bit(%2%)) &
                    (SELECT * FROM role_permissions) =
                    (SELECT * FROM role_permissions)
                FROM role_has_permissions AS rp
                JOIN account_has_roles AS ar on ar.role_id = rp.role_id
                WHERE ar.account_id = $1
            ),)")
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kAppendRole,
                   "$1")
             % bits)
                .str(),
            R"( WHERE
                    EXISTS (SELECT * FROM account_roles) AND
                    (SELECT * FROM account_has_role_permissions)
                    AND (SELECT * FROM has_perm))",
            R"(
                WHEN NOT EXISTS (SELECT * FROM account_roles) THEN 2
                WHEN NOT (SELECT * FROM account_has_role_permissions) THEN 2
                WHEN NOT (SELECT * FROM has_perm) THEN 2)"}});

      statements.push_back(
          {"createAccount",
           createAccountBase,
           {(boost::format(R"(
           domain_role_permissions_bits AS (
                 SELECT COALESCE(bit_or(rhp.permission), '0'::bit(%1%)) AS bits
                 FROM role_has_permissions AS rhp
                 WHERE rhp.role_id = (SELECT * FROM get_domain_default_role)),
           account_permissions AS (
                 SELECT COALESCE(bit_or(rhp.permission), '0'::bit(%1%)) AS perm
                 FROM role_has_permissions AS rhp
                 JOIN account_has_roles AS ar ON ar.role_id = rhp.role_id
                 WHERE ar.account_id = $1
           ),
           creator_has_enough_permissions AS (
                SELECT ap.perm & dpb.bits = dpb.bits
                FROM account_permissions AS ap, domain_role_permissions_bits AS dpb
           ),
           has_perm AS (%2%),
          )") % bits
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kCreateAccount,
                   "$1"))
                .str(),
            R"(AND (SELECT * FROM has_perm)
               AND (SELECT * FROM creator_has_enough_permissions))",
            R"(WHEN NOT (SELECT * FROM has_perm) THEN 2
               WHEN NOT (SELECT * FROM creator_has_enough_permissions) THEN 2)"}});

      statements.push_back(
          {"createAsset",
           createAssetBase,
           {(boost::format(R"(
              has_perm AS (%s),)")
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kCreateAsset,
                   "$1"))
                .str(),
            R"(WHERE (SELECT * FROM has_perm))",
            R"(WHEN NOT (SELECT * FROM has_perm) THEN 2)"}});

      statements.push_back(
          {"createDomain",
           createDomainBase,
           {(boost::format(R"(
              has_perm AS (%s),)")
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kCreateDomain,
                   "$1"))
                .str(),
            R"(WHERE (SELECT * FROM has_perm))",
            R"(WHEN NOT (SELECT * FROM has_perm) THEN 2)"}});

      statements.push_back(
          {"createRole",
           createRoleBase,
           {(boost::format(R"(
          account_has_role_permissions AS (
                SELECT COALESCE(bit_or(rp.permission), '0'::bit(%s)) &
                    $3 = $3
                FROM role_has_permissions AS rp
                JOIN account_has_roles AS ar on ar.role_id = rp.role_id
                WHERE ar.account_id = $1),
          has_perm AS (%s),)")
             % bits
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kCreateRole,
                   "$1"))
                .str(),
            R"(WHERE (SELECT * FROM account_has_role_permissions)
                          AND (SELECT * FROM has_perm))",
            R"(WHEN NOT (SELECT * FROM
                               account_has_role_permissions) THEN 2
                        WHEN NOT (SELECT * FROM has_perm) THEN 2)"}});

      statements.push_back(
          {"detachRole",
           detachRoleBase,
           {(boost::format(R"(
            has_perm AS (%s),)")
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kDetachRole,
                   "$1"))
                .str(),
            R"(AND (SELECT * FROM has_perm))",
            R"(WHEN NOT (SELECT * FROM has_perm) THEN 2)"}});

      statements.push_back({"grantPermission",
                            grantPermissionBase,
                            {(boost::format(R"(
            has_perm AS (
                SELECT
                    (
                        COALESCE(bit_or(rp.permission), '0'::bit(%1%))
                        & $4
                    ) = $4
                FROM role_has_permissions AS rp
                JOIN account_has_roles AS ar ON ar.role_id = rp.role_id
                WHERE ar.account_id = $1),)")
                              % bits)
                                 .str(),
                             R"( WHERE (SELECT * FROM has_perm))",
                             R"(WHEN NOT (SELECT * FROM has_perm) THEN 2)"}});

      statements.push_back(
          {"removePeer",
           removePeerBase,
           {(boost::format(R"(
            has_perm AS (%s),
            get_peer AS (
              SELECT * from peer WHERE public_key = $2 LIMIT 1
            ),
            check_peers AS (
              SELECT 1 WHERE (SELECT COUNT(*) FROM peer) > 1
            ),
            )")
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kRemovePeer,
                   "$1"))
                .str(),
            R"(
            AND (SELECT * FROM has_perm)
            AND EXISTS (SELECT * FROM get_peer)
            AND EXISTS (SELECT * FROM check_peers)
            )",
            R"(
            WHEN NOT EXISTS (SELECT * from get_peer) THEN 3
            WHEN NOT EXISTS (SELECT * from check_peers) THEN 4
            WHEN NOT (SELECT * from has_perm) THEN 2
            )"}});

      statements.push_back(
          {"removeSignatory",
           removeSignatoryBase,
           {(boost::format(R"(
          has_perm AS (%s),
          get_account AS (
              SELECT quorum FROM account WHERE account_id = $2 LIMIT 1
           ),
          get_signatories AS (
              SELECT public_key FROM account_has_signatory
              WHERE account_id = $2
          ),
          get_signatory AS (
              SELECT * FROM get_signatories
              WHERE public_key = $3
          ),
          check_account_signatories AS (
              SELECT quorum FROM get_account
              WHERE quorum < (SELECT COUNT(*) FROM get_signatories)
          ),
          )")
             % checkAccountHasRoleOrGrantablePerm(
                   shared_model::interface::permissions::Role::kRemoveSignatory,
                   shared_model::interface::permissions::Grantable::
                       kRemoveMySignatory,
                   "$1",
                   "$2"))
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
          )"}});

      statements.push_back({"revokePermission",
                            revokePermissionBase,
                            {(boost::format(R"(
            has_perm AS (SELECT COALESCE(bit_or(permission), '0'::bit(%1%))
          & $3 = $3 FROM account_has_grantable_permissions
              WHERE account_id = $1 AND
              permittee_account_id = $2),)")
                              % grantable_bits)
                                 .str(),
                             R"( AND (SELECT * FROM has_perm))",
                             R"( WHEN NOT (SELECT * FROM has_perm) THEN 2 )"}});

      statements.push_back(
          {"setAccountDetail",
           setAccountDetailBase,
           {(boost::format(R"(
              has_role_perm AS (%s),
              has_grantable_perm AS (%s),
              has_perm AS (SELECT CASE
                               WHEN (SELECT * FROM has_grantable_perm) THEN true
                               WHEN ($1 = $2) THEN true
                               WHEN (SELECT * FROM has_role_perm) THEN true
                               ELSE false END
              ),
              )")
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kSetDetail, "$1")
             % checkAccountGrantablePermission(
                   shared_model::interface::permissions::Grantable::
                       kSetMyAccountDetail,
                   "$1",
                   "$2"))
                .str(),
            R"( AND (SELECT * FROM has_perm))",
            R"( WHEN NOT (SELECT * FROM has_perm) THEN 2 )"}});

      statements.push_back(
          {"setQuorum",
           setQuorumBase,
           {R"( get_signatories AS (
                    SELECT public_key FROM account_has_signatory
                    WHERE account_id = $2
                ),
                check_account_signatories AS (
                    SELECT 1 FROM account
                    WHERE $3 <= (SELECT COUNT(*) FROM get_signatories)
                    AND account_id = $2
                ),)",
            (boost::format(R"(
          has_perm AS (%s),)")
             % checkAccountHasRoleOrGrantablePerm(
                   shared_model::interface::permissions::Role::kSetQuorum,
                   shared_model::interface::permissions::Grantable::
                       kSetMyQuorum,
                   "$1",
                   "$2"))
                .str(),
            R"(AND EXISTS
              (SELECT * FROM get_signatories)
              AND EXISTS (SELECT * FROM check_account_signatories)
              AND (SELECT * FROM has_perm))",
            R"(
              WHEN NOT (SELECT * FROM has_perm) THEN 2
              WHEN NOT EXISTS (SELECT * FROM get_signatories) THEN 4
              WHEN NOT EXISTS (SELECT * FROM check_account_signatories) THEN 5
              )"}});

      statements.push_back({"subtractAssetQuantity",
                            subtractAssetQuantityBase,
                            {(boost::format(R"(
               has_perm AS (%s),)")
                              % checkAccountDomainRoleOrGlobalRolePermission(
                                    shared_model::interface::permissions::Role::
                                        kSubtractAssetQty,
                                    shared_model::interface::permissions::Role::
                                        kSubtractDomainAssetQty,
                                    "$1",
                                    "$2"))
                                 .str(),
                             R"( AND (SELECT * FROM has_perm))",
                             R"( WHEN NOT (SELECT * FROM has_perm) THEN 2 )"}});

      statements.push_back(
          {"transferAsset",
           transferAssetBase,
           {(boost::format(R"(
              has_role_perm AS (%s),
              has_grantable_perm AS (%s),
              dest_can_receive AS (%s),
              has_perm AS (SELECT
                               CASE WHEN (SELECT * FROM dest_can_receive) THEN
                                   CASE WHEN NOT ($1 = $2) THEN
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
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kTransfer, "$1")
             % checkAccountGrantablePermission(
                   shared_model::interface::permissions::Grantable::
                       kTransferMyAssets,
                   "$1",
                   "$2")
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kReceive, "$3"))
                .str(),
            R"( AND (SELECT * FROM has_perm))",
            R"( AND (SELECT * FROM has_perm))",
            R"( WHEN NOT (SELECT * FROM has_perm) THEN 2 )"}});

      statements.push_back(
          {"compareAndSetAccountDetail",
           compareAndSetAccountDetailBase,
           {(boost::format(R"(
              has_role_perm AS (%s),
              has_grantable_perm AS (%s),
              %s,
              has_perm AS (SELECT CASE
                               WHEN (SELECT * FROM has_query_perm) THEN
                                   CASE
                                       WHEN (SELECT * FROM has_grantable_perm)
                                           THEN true
                                       WHEN ($1 = $2) THEN true
                                       WHEN (SELECT * FROM has_role_perm)
                                           THEN true
                                       ELSE false END
                               ELSE false END
              ),
              )")
             % checkAccountRolePermission(
                   shared_model::interface::permissions::Role::kSetDetail, "$1")
             % checkAccountGrantablePermission(
                   shared_model::interface::permissions::Grantable::
                       kSetMyAccountDetail,
                   "$1",
                   "$2")
             % hasQueryPermission(
                   "$1",
                   "$2",
                   shared_model::interface::permissions::Role::kGetMyAccDetail,
                   shared_model::interface::permissions::Role::kGetAllAccDetail,
                   shared_model::interface::permissions::Role::
                       kGetDomainAccDetail,
                   "$6",
                   "$7"))
                .str(),
            R"( AND (SELECT * FROM has_perm))",
            R"( WHEN NOT (SELECT * FROM has_perm) THEN 2 )"}});

      for (const auto &st : statements) {
        prepareStatement(sql, st);
      }
    };

  }  // namespace ametsuchi
}  // namespace iroha
