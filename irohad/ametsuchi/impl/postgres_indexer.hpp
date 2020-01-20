/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AMETSUCHI_POSTGRES_INDEXER_HPP
#define AMETSUCHI_POSTGRES_INDEXER_HPP

#include "ametsuchi/indexer.hpp"

#include <string>
#include <vector>

namespace soci {
  class session;
}

namespace iroha {
  namespace ametsuchi {

    class PostgresIndexer : public Indexer {
     public:
      PostgresIndexer(soci::session &sql);

      void txHashPosition(const shared_model::interface::types::HashType &hash,
                          TxPosition position) override;

      void committedTxHash(const shared_model::interface::types::HashType
                               &committed_tx_hash) override;

      void rejectedTxHash(const shared_model::interface::types::HashType
                              &rejected_tx_hash) override;

      void txPositionByCreator(
          const shared_model::interface::types::AccountIdType creator,
          TxPosition position) override;

      void accountAssetTxPosition(
          const shared_model::interface::types::AccountIdType &account_id,
          const shared_model::interface::types::AssetIdType &asset_id,
          TxPosition position) override;

      iroha::expected::Result<void, std::string> flush() override;

     private:
      struct TxHashPosition {
        std::vector<std::string> hash;
        std::vector<size_t> height;
        std::vector<size_t> index;
      } tx_hash_position_;

      struct TxHashStatus {
        std::vector<std::string> hash;
        std::vector<std::string> status;
      } tx_hash_status_;

      struct TxPositionByCreator {
        std::vector<std::string> creator;
        std::vector<size_t> height;
        std::vector<size_t> index;
      } tx_position_by_creator_;

      struct AccountAssetTxPosition {
        std::vector<std::string> account_id;
        std::vector<std::string> asset_id;
        std::vector<size_t> height;
        std::vector<size_t> index;
      } account_asset_tx_position_;

      /// Index tx status by its hash.
      void txHashStatus(const shared_model::interface::types::HashType &tx_hash,
                        bool is_committed);

      soci::session &sql_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif /* AMETSUCHI_POSTGRES_INDEXER_HPP */
