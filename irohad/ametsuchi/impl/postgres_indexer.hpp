/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AMETSUCHI_POSTGRES_INDEXER_HPP
#define AMETSUCHI_POSTGRES_INDEXER_HPP

#include "ametsuchi/indexer.hpp"

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
      /// Index tx status by its hash.
      void txHashStatus(
          const shared_model::interface::types::HashType &rejected_tx_hash,
          bool is_committed);

      soci::session &sql_;
      std::string statements_;  ///< A bunch of SQL to be committed on flush().
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif /* AMETSUCHI_POSTGRES_INDEXER_HPP */
