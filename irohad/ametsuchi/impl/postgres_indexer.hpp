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

    class PostgresIndexer final : public Indexer {
     public:
      PostgresIndexer(soci::session &sql);

      void committedTxHash(
          const TxPosition &position,
          shared_model::interface::types::TimestampType const ts,
          const shared_model::interface::types::HashType &committed_tx_hash)
          override;

      void rejectedTxHash(
          const TxPosition &position,
          shared_model::interface::types::TimestampType const ts,
          const shared_model::interface::types::HashType &rejected_tx_hash)
          override;

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

      soci::session &sql_;
      std::string cache_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif /* AMETSUCHI_POSTGRES_INDEXER_HPP */
