/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AMETSUCHI_ROCKSDB_INDEXER_HPP
#define AMETSUCHI_ROCKSDB_INDEXER_HPP

#include "ametsuchi/indexer.hpp"

#include <string>
#include <vector>

namespace iroha::ametsuchi {

  struct RocksDBPort;
  struct RocksDBContext;

  class RocksDBIndexer final : public Indexer {
   public:
    RocksDBIndexer(std::shared_ptr<RocksDBContext> db_context);

    void committedTxHash(const TxPosition &position,
                         shared_model::interface::types::TimestampType const ts,
                         const shared_model::interface::types::HashType
                             &committed_tx_hash) override;

    void rejectedTxHash(const TxPosition &position,
                        shared_model::interface::types::TimestampType const ts,
                        const shared_model::interface::types::HashType
                            &rejected_tx_hash) override;

    void txPositions(
        shared_model::interface::types::AccountIdType const &account,
        shared_model::interface::types::HashType const &hash,
        boost::optional<shared_model::interface::types::AssetIdType> &&asset_id,
        shared_model::interface::types::TimestampType const ts,
        TxPosition const &position) override;

    iroha::expected::Result<void, std::string> flush() override;

   private:
    std::shared_ptr<RocksDBContext> db_context_;

    /// Index tx status by its hash.
    void txHashStatus(const TxPosition &position,
                      shared_model::interface::types::TimestampType const ts,
                      const shared_model::interface::types::HashType &tx_hash,
                      bool is_committed);
  };

}  // namespace iroha::ametsuchi

#endif  // AMETSUCHI_ROCKSDB_INDEXER_HPP
