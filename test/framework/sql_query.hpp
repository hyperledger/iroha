/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SQL_QUERY_HPP
#define IROHA_SQL_QUERY_HPP

#include <string>

#include <soci/soci.h>
#include <boost/optional.hpp>
#include "framework/test_logger.hpp"
#include "interfaces/common_objects/account.hpp"
#include "interfaces/common_objects/account_asset.hpp"
#include "interfaces/common_objects/asset.hpp"
#include "interfaces/common_objects/common_objects_factory.hpp"
#include "interfaces/common_objects/domain.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/queries/query.hpp"
#include "interfaces/query_responses/query_response.hpp"
#include "interfaces/transaction.hpp"
#include "interfaces/transaction_responses/tx_response.hpp"
#include "logger/logger.hpp"

namespace framework {
  namespace ametsuchi {

    /**
     * Implements some of the SQL queries, which are needed only in tests
     */
    class SqlQuery {
     public:
      SqlQuery(soci::session &sql,
               std::shared_ptr<shared_model::interface::CommonObjectsFactory>
                   factory,
               logger::LoggerPtr log = getTestLogger("SqlQuery"));

      /**
       * Check if permitee has permission on account
       * @param permitee_account_id
       * @param account_id
       * @param permission
       * @return true if has permission, false otherwise
       */
      bool hasAccountGrantablePermission(
          const shared_model::interface::types::AccountIdType
              &permitee_account_id,
          const shared_model::interface::types::AccountIdType &account_id,
          shared_model::interface::permissions::Grantable permission);

      /**
       * Get iroha domain
       * @param domain_id - id in the system
       * @return Domain if exist, nullopt otherwise
       */
      boost::optional<std::shared_ptr<shared_model::interface::Domain>>
      getDomain(const shared_model::interface::types::DomainIdType &domain_id);

      /**
       * Get account's roles
       * @param account_id
       * @return
       */
      boost::optional<std::vector<shared_model::interface::types::RoleIdType>>
      getAccountRoles(
          const shared_model::interface::types::AccountIdType &account_id);
      /**
       * Get all permissions of a role
       * @param role_name
       * @return
       */
      boost::optional<shared_model::interface::RolePermissionSet>
      getRolePermissions(
          const shared_model::interface::types::RoleIdType &role_name);

      /**
       * @return All roles currently in the system
       */
      boost::optional<std::vector<shared_model::interface::types::RoleIdType>>
      getRoles();

      /**
       * Get account by user account_id
       * @param account_id
       * @return
       */
      boost::optional<std::shared_ptr<shared_model::interface::Account>>
      getAccount(
          const shared_model::interface::types::AccountIdType &account_id);

      /**
       * Get asset by its name
       * @param asset_id
       * @return
       */
      boost::optional<std::shared_ptr<shared_model::interface::Asset>> getAsset(
          const shared_model::interface::types::AssetIdType &asset_id);

      /**
       * Get account assets
       * @param account_id
       * @return
       */
      boost::optional<
          std::vector<std::shared_ptr<shared_model::interface::AccountAsset>>>
      getAccountAssets(
          const shared_model::interface::types::AccountIdType &account_id);
      /**
       *
       * @param account_id
       * @param asset_id
       * @return
       */
      boost::optional<std::shared_ptr<shared_model::interface::AccountAsset>>
      getAccountAsset(
          const shared_model::interface::types::AccountIdType &account_id,
          const shared_model::interface::types::AssetIdType &asset_id);

      /**
       * Get accounts information from its key-value storage
       * @param account_id - account to get details about
       * @param key - only values under this key from Json are returned; default
       * empty
       * @param writer - only values, added by the writer's account, are
       * returned; default empty
       * @return optional of account details
       */
      boost::optional<std::string> getAccountDetail(
          const shared_model::interface::types::AccountIdType &account_id,
          const shared_model::interface::types::AccountDetailKeyType &key = "",
          const shared_model::interface::types::AccountIdType &writer = "");

      /**
       * Get setting value by its key
       * @param setting_key
       * @return if key exist then value otherwise none
       */
      boost::optional<shared_model::interface::types::SettingValueType>
      getSettingValue(
          const shared_model::interface::types::SettingKeyType &setting_key);

     private:
      soci::session &sql_;
      std::shared_ptr<shared_model::interface::CommonObjectsFactory> factory_;
      logger::LoggerPtr log_;

      /**
       * Executes given lambda of type F, catches exceptions if any, logs the
       * message, and returns an optional rowset<T>
       */
      template <typename T, typename F>
      auto execute(F &&f) -> boost::optional<soci::rowset<T>>;

      /**
       * Transforms result to optional
       * value -> optional<value>
       * error -> nullopt
       * @tparam T type of object inside
       * @param result BuilderResult
       * @return optional<T>
       */
      template <typename T>
      boost::optional<std::shared_ptr<T>> fromResult(
          shared_model::interface::CommonObjectsFactory::FactoryResult<
              std::unique_ptr<T>> &&result);
    };

  }  // namespace ametsuchi
}  // namespace framework

#endif  // IROHA_SQL_QUERY_HPP
