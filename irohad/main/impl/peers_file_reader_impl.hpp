/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEERS_FILE_READER_IMPL_HPP
#define IROHA_PEERS_FILE_READER_IMPL_HPP

#include "main/peers_file_reader.hpp"

namespace iroha {
  namespace main {
    class PeersFileReaderImpl : public PeersFileReader {
     public:
      /**
       * Creates new PeersFileReaderImpl object
       * @param common_objects_factory - factory to create peers
       */
      explicit PeersFileReaderImpl(
          std::shared_ptr<shared_model::interface::CommonObjectsFactory>
              common_objects_factory);

      expected::Result<shared_model::interface::types::PeerList, std::string>
      readPeers(const std::string &name) override;

     private:
      boost::optional<std::string> openFile(const std::string &name);

      std::shared_ptr<shared_model::interface::CommonObjectsFactory>
          common_objects_factory_;
    };
  }  // namespace main
}  // namespace iroha

#endif  // IROHA_PEERS_FILE_READER_IMPL_HPP
