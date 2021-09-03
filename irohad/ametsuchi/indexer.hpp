/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AMETSUCHI_INDEXER_HPP
#define AMETSUCHI_INDEXER_HPP

#include <string>

#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  namespace ametsuchi {

    /** Stores transaction data in WSV.
     * \attention The effect of any change only gets into WSV storage after \see
     * Indexer::flush() is called!
     */
    class Indexer {
     public:
      virtual ~Indexer() = default;

      /// Position of a transaction in the ledger.
      struct TxPosition {
        shared_model::interface::types::HeightType
            height;    ///< the height of block containing this transaction
        size_t index;  ///< the number of this transaction in the block
      };

      /// Store a committed tx hash.
      virtual void committedTxHash(
          const TxPosition &position,
          shared_model::interface::types::TimestampType const ts,
          const shared_model::interface::types::HashType
              &committed_tx_hash) = 0;

      /// Store a rejected tx hash.
      virtual void rejectedTxHash(
          const TxPosition &position,
          shared_model::interface::types::TimestampType const ts,
          const shared_model::interface::types::HashType &rejected_tx_hash) = 0;

      /// Index tx info.
      virtual void txPositions(
          shared_model::interface::types::AccountIdType const &creator,
          shared_model::interface::types::HashType const &hash,
          boost::optional<shared_model::interface::types::AssetIdType>
              &&asset_id,
          shared_model::interface::types::TimestampType const ts,
          TxPosition const &position) = 0;

      /**
       * Flush the indices to storage.
       * Makes the effects of new indices (that were created before this call)
       * visible to other components. Discards indexer inner state on success.
       * @return Void Value on success, string Error on failure.
       */
      virtual iroha::expected::Result<void, std::string> flush() = 0;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif /* AMETSUCHI_INDEXER_HPP */
