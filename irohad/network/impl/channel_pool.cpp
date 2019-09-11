/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/channel_pool.hpp"

#include <fstream>
#include <sstream>

#include "interfaces/common_objects/peer.hpp"
#include "network/impl/channel_factory.hpp"

using namespace iroha::network;

ChannelPool::ChannelPool(std::unique_ptr<ChannelFactory> channel_factory)
    : channel_factory_(std::move(channel_factory)) {}

ChannelPool::~ChannelPool() = default;

std::shared_ptr<grpc::Channel> ChannelPool::getChannel(
    const std::string &service_full_name,
    const shared_model::interface::Peer &peer) {
  if (channels_.find(peer.pubkey()) == channels_.end()) {
    channels_[peer.pubkey()] =
        channel_factory_->createChannel(service_full_name, peer);
  }
  return channels_[peer.pubkey()];
}
