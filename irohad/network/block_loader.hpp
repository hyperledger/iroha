/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_LOADER_HPP
#define IROHA_BLOCK_LOADER_HPP

#include <memory>
#include <rxcpp/rx.hpp>

#include "cryptography/public_key.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"

namespace iroha {
  namespace network {
    /**
     * Interface for downloading blocks from a network
     */
    class BlockLoader {
     public:
      /**
       * Retrieve block from given peer starting from current top
       * @param height - top block height in requester's peer storage
       * @param peer_pubkey - peer for requesting blocks
       * @return
       */
      virtual rxcpp::observable<std::shared_ptr<shared_model::interface::Block>>
      retrieveBlocks(const shared_model::interface::types::HeightType height,
                     const shared_model::crypto::PublicKey &peer_pubkey) = 0;

      /**
       * Retrieve block by its block_hash from given peer
       * @param peer_pubkey - peer for requesting blocks
       * @param block_hash - requested block hash
       * @return block on success, nullopt on failure
       * TODO 14/02/17 (@l4l) IR-960 rework method with returning result
       */
      virtual boost::optional<std::shared_ptr<shared_model::interface::Block>>
      retrieveBlock(
          const shared_model::crypto::PublicKey &peer_pubkey,
          const shared_model::interface::types::HashType &block_hash) = 0;

      virtual ~BlockLoader() = default;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_BLOCK_LOADER_HPP
