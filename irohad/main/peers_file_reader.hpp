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
       * Opens file with peers and returns its contents
       * @param name - file name to open
       * @return optional for a file contents or boost::none
       */
      virtual boost::optional<std::string> openFile(
          const std::string &name) = 0;

      /**
       * Parses peers from a provided string
       * @param peers_data - peers string to parse
       * @param common_objects_factory - factory to create peers
       * @return optional for collection of peers or boost::none
       */
      virtual boost::optional<
          std::vector<std::unique_ptr<shared_model::interface::Peer>>>
      readPeers(const std::string &peers_data,
                std::shared_ptr<shared_model::interface::CommonObjectsFactory>
                    common_objects_factory) = 0;
    };
  }  // namespace main
}  // namespace iroha

#endif  // IROHA_PEERS_FILE_READER_HPP
