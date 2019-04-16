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
      boost::optional<std::string> openFile(const std::string &name) override;

      boost::optional<
          std::vector<std::unique_ptr<shared_model::interface::Peer>>>
      readPeers(const std::string &peers_data,
                std::shared_ptr<shared_model::interface::CommonObjectsFactory>
                    common_objects_factory) override;
    };
  }  // namespace main
}  // namespace iroha

#endif  // IROHA_PEERS_FILE_READER_IMPL_HPP
