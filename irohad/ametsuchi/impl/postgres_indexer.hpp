/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AMETSUCHI_POSTGRES_INDEXER_HPP
#define AMETSUCHI_POSTGRES_INDEXER_HPP

#include <string>
#include <vector>

#include "ametsuchi/indexer.hpp"

namespace soci {
  class session;
}

namespace iroha {
  namespace ametsuchi {

    class PostgresIndexer final : public Indexer {
     public:
      PostgresIndexer(std::weak_ptr<soci::session> wsql)
          : wsql_(std::move(wsql)) {}

      void committedTxHash(const shared_model::interface::types::HashType
                               &committed_tx_hash) override;

      void rejectedTxHash(const shared_model::interface::types::HashType
                              &rejected_tx_hash) override;

      void txPositions(
          shared_model::interface::types::AccountIdType const &account,
          shared_model::interface::types::HashType const &hash,
          boost::optional<shared_model::interface::types::AssetIdType>
              &&asset_id,
          shared_model::interface::types::TimestampType const ts,
          TxPosition const &position) override;

      iroha::expected::Result<void, std::string> flush() override;

     private:
      struct {
        std::vector<std::string> hash;
        std::vector<std::string> status;
      } tx_hash_status_;

      struct {
        std::vector<shared_model::interface::types::AccountIdType> account;
        std::vector<std::string> hash;
        std::vector<
            boost::optional<shared_model::interface::types::AssetIdType>>
            asset_id;
        std::vector<shared_model::interface::types::TimestampType> ts;
        std::vector<size_t> height;
        std::vector<size_t> index;
      } tx_positions_;

      /// Index tx status by its hash.
      void txHashStatus(const shared_model::interface::types::HashType &tx_hash,
                        bool is_committed);

      std::weak_ptr<soci::session> wsql_;
      std::string cache_;

      std::shared_ptr<soci::session> sql() const {
        return std::shared_ptr<soci::session>(wsql_);
      }
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif /* AMETSUCHI_POSTGRES_INDEXER_HPP */
