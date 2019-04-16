/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <memory>

#include "model/generators/query_generator.hpp"

namespace iroha {
  namespace model {
    namespace generators {

      void QueryGenerator::setQueryMetaData(std::shared_ptr<Query> query,
                                            ts64_t timestamp,
                                            std::string creator,
                                            uint64_t query_counter) {
        query->creator_account_id = creator;
        query->query_counter = query_counter;
        query->created_ts = timestamp;
      }

      std::shared_ptr<GetAccount> QueryGenerator::generateGetAccount(
          ts64_t timestamp,
          std::string creator,
          uint64_t query_counter,
          std::string account_id) {
        auto query = std::make_shared<GetAccount>();
        query->created_ts = timestamp;
        query->creator_account_id = creator;
        query->account_id = account_id;
        query->query_counter = query_counter;
        return query;
      }

      std::shared_ptr<GetAccountAssets>
      QueryGenerator::generateGetAccountAssets(ts64_t timestamp,
                                               std::string creator,
                                               uint64_t query_counter,
                                               std::string account_id,
                                               std::string asset_id) {
        auto query = std::make_shared<GetAccountAssets>();
        query->created_ts = timestamp;
        query->creator_account_id = creator;
        query->query_counter = query_counter;
        query->account_id = account_id;
        return query;
      }

      std::shared_ptr<GetAccountDetail>
      QueryGenerator::generateGetAccountDetail(ts64_t timestamp,
                                               std::string creator,
                                               uint64_t query_counter,
                                               std::string account_id,
                                               std::string creator_account_id) {
        auto query = std::make_shared<GetAccountDetail>();
        query->created_ts = timestamp;
        query->creator_account_id = creator;
        query->query_counter = query_counter;
        query->account_id = account_id;
        query->creator_account_id = creator_account_id;
        return query;
      }

      std::shared_ptr<GetSignatories> QueryGenerator::generateGetSignatories(
          ts64_t timestamp,
          std::string creator,
          uint64_t query_counter,
          std::string account_id) {
        auto query = std::make_shared<GetSignatories>();
        query->created_ts = timestamp;
        query->creator_account_id = creator;
        query->query_counter = query_counter;
        query->account_id = account_id;
        return query;
      }

      std::shared_ptr<GetAccountTransactions>
      QueryGenerator::generateGetAccountTransactions(ts64_t timestamp,
                                                     std::string creator,
                                                     uint64_t query_counter,
                                                     std::string account_id) {
        auto query = std::make_shared<GetAccountTransactions>();
        query->created_ts = timestamp;
        query->creator_account_id = creator;
        query->query_counter = query_counter;
        query->account_id = account_id;
        return query;
      }

      std::shared_ptr<GetAccountAssetTransactions>
      QueryGenerator::generateGetAccountAssetTransactions(
          ts64_t timestamp,
          std::string creator,
          uint64_t query_counter,
          std::string account_id,
          std::string asset_id) {
        auto query = std::make_shared<GetAccountAssetTransactions>();
        query->created_ts = timestamp;
        query->creator_account_id = creator;
        query->query_counter = query_counter;
        query->account_id = account_id;
        query->asset_id = asset_id;
        return query;
      }

      std::shared_ptr<GetTransactions> QueryGenerator::generateGetTransactions(
          ts64_t timestamp,
          const std::string &creator,
          uint64_t query_counter,
          const std::vector<iroha::hash256_t> &tx_hashes) {
        auto query = std::make_shared<GetTransactions>();
        query->created_ts = timestamp;
        query->creator_account_id = creator;
        query->query_counter = query_counter;
        query->tx_hashes = tx_hashes;
        return query;
      }

      std::shared_ptr<GetAssetInfo> QueryGenerator::generateGetAssetInfo() {
        auto query = std::make_shared<GetAssetInfo>("coin#test");
        query->created_ts = 0;
        query->creator_account_id = "admin@test";
        query->query_counter = 0;
        return query;
      }

      std::shared_ptr<GetRoles> QueryGenerator::generateGetRoles() {
        auto query = std::make_shared<GetRoles>();
        query->created_ts = 0;
        query->creator_account_id = "admin@test";
        query->query_counter = 0;
        return query;
      }

      std::shared_ptr<GetRolePermissions>
      QueryGenerator::generateGetRolePermissions() {
        auto query = std::make_shared<GetRolePermissions>("admin");
        query->created_ts = 0;
        query->creator_account_id = "admin@test";
        query->query_counter = 0;
        return query;
      }

    }  // namespace generators
  }    // namespace model
}  // namespace iroha
