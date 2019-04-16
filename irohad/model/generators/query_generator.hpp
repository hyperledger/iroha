/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memory>
#include <vector>

#include "model/queries/get_account.hpp"
#include "model/queries/get_account_assets.hpp"
#include "model/queries/get_account_detail.hpp"
#include "model/queries/get_signatories.hpp"
#include "model/queries/get_transactions.hpp"

#include "model/queries/get_asset_info.hpp"
#include "model/queries/get_roles.hpp"

#ifndef IROHA_QUERY_GENERATOR_HPP
#define IROHA_QUERY_GENERATOR_HPP
namespace iroha {
  namespace model {
    namespace generators {
      class QueryGenerator {
       public:
        std::shared_ptr<GetAccount> generateGetAccount(ts64_t timestamp,
                                                       std::string creator,
                                                       uint64_t query_counter,
                                                       std::string account_id);

        std::shared_ptr<GetAccountAssets> generateGetAccountAssets(
            ts64_t timestamp,
            std::string creator,
            uint64_t query_counter,
            std::string account_id,
            std::string asset_id);

        std::shared_ptr<GetAccountDetail> generateGetAccountDetail(
            ts64_t timestamp,
            std::string creator,
            uint64_t query_counter,
            std::string account_id,
            std::string creator_account_id);

        std::shared_ptr<GetSignatories> generateGetSignatories(
            ts64_t timestamp,
            std::string creator,
            uint64_t query_counter,
            std::string account_id);

        std::shared_ptr<GetAccountTransactions> generateGetAccountTransactions(
            ts64_t timestamp,
            std::string creator,
            uint64_t query_counter,
            std::string account_id);

        std::shared_ptr<GetAccountAssetTransactions>
        generateGetAccountAssetTransactions(ts64_t timestamp,
                                            std::string creator,
                                            uint64_t query_counter,
                                            std::string account_id,
                                            std::string asset_id);

        std::shared_ptr<GetTransactions> generateGetTransactions(
            ts64_t timestamp,
            const std::string &creator,
            uint64_t query_counter,
            const std::vector<iroha::hash256_t> &tx_hashes);

        /**
         * Generate default query GetAssetInfo
         * @return default GetAssetInfo
         */
        std::shared_ptr<GetAssetInfo> generateGetAssetInfo();

        /**
         * Generate default query GetRoles
         * @return default GetRoles
         */
        std::shared_ptr<GetRoles> generateGetRoles();

        /**
         * Generate default query GetRolePermissions
         * @return default GetRolePermissions
         */
        std::shared_ptr<GetRolePermissions> generateGetRolePermissions();

        void setQueryMetaData(std::shared_ptr<Query> query,
                              ts64_t timestamp,
                              std::string creator,
                              uint64_t query_counter);
      };
    }  // namespace generators
  }    // namespace model
}  // namespace iroha

#endif  // IROHA_QUERY_GENERATOR_HPP
