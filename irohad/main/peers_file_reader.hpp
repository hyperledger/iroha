/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEERS_FILE_READER_HPP
#define IROHA_PEERS_FILE_READER_HPP

#include <boost/optional.hpp>
#include "interfaces/common_objects/common_objects_factory.hpp"
#include "interfaces/common_objects/peer.hpp"

namespace iroha {
  namespace main {
    /**
     * Peers reader interface from a file
     */
    class PeersFileReader {
     public:
      /**
       * Parses peers from a provided string
       * @param name - file to read peers from
       * @return Result for collection of peers
       */
      virtual expected::Result<shared_model::interface::types::PeerList,
                               std::string>
      readPeers(const std::string &name) = 0;
    };
  }  // namespace main
}  // namespace iroha

#endif  // IROHA_PEERS_FILE_READER_HPP
