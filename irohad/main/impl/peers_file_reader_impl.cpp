/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "peers_file_reader_impl.hpp"

#include <fstream>

#include "cryptography/public_key.hpp"
#include "interfaces/common_objects/types.hpp"
#include "parser/parser.hpp"

using namespace iroha::main;

boost::optional<std::string> PeersFileReaderImpl::openFile(
    const std::string &name) {
  std::ifstream file(name);
  if (not file) {
    return boost::none;
  }

  std::string str((std::istreambuf_iterator<char>(file)),
                  std::istreambuf_iterator<char>());
  return str;
}

boost::optional<std::vector<std::unique_ptr<shared_model::interface::Peer>>>
PeersFileReaderImpl::readPeers(
    const std::string &peers_data,
    std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        common_objects_factory) {
  auto strings = parser::split(peers_data);
  if (strings.size() % 2 != 0) {
    return boost::none;
  }

  std::vector<std::unique_ptr<shared_model::interface::Peer>> peers{};

  for (uint32_t i = 0; i < strings.size(); i += 2) {
    shared_model::interface::types::AddressType address = strings.at(i);
    shared_model::interface::types::PubkeyType key(
        shared_model::interface::types::PubkeyType::fromHexString(
            strings.at(i + 1)));
    auto peer = common_objects_factory->createPeer(address, key);

    if (auto e = boost::get<expected::Error<std::string>>(&peer)) {
      return boost::none;
    }

    peers.emplace_back(std::move(
        boost::get<
            expected::Value<std::unique_ptr<shared_model::interface::Peer>>>(
            &peer)
            ->value));
  }
  return boost::make_optional<
      std::vector<std::unique_ptr<shared_model::interface::Peer>>>(
      std::move(peers));
}
