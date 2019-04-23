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

PeersFileReaderImpl::PeersFileReaderImpl(
    std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        common_objects_factory)
    : common_objects_factory_(std::move(common_objects_factory)) {}

iroha::expected::Result<shared_model::interface::types::PeerList, std::string>
PeersFileReaderImpl::readPeers(const std::string &name) {
  auto peers_data = openFile(name);
  if (not peers_data) {
    return expected::makeError("Failed to read peers file " + name);
  }

  auto strings = parser::split(*peers_data);
  if (strings.size() % 2 != 0) {
    return expected::makeError(
        "Peers file should contain <address, public_key> pairs divided by "
        "space");
  }

  shared_model::interface::types::PeerList peers{};
  for (uint32_t i = 0; i < strings.size(); i += 2) {
    shared_model::interface::types::AddressType address = strings.at(i);
    shared_model::interface::types::PubkeyType key(
        shared_model::interface::types::PubkeyType::fromHexString(
            strings.at(i + 1)));
    auto peer = common_objects_factory_->createPeer(address, key);

    if (auto e = boost::get<expected::Error<std::string>>(&peer)) {
      return expected::makeError(e->error);
    }

    peers.emplace_back(std::move(
        boost::get<
            expected::Value<std::unique_ptr<shared_model::interface::Peer>>>(
            &peer)
            ->value));
  }
  return expected::makeValue(std::move(peers));
}

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
