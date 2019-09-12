/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/channel_pool.hpp"

#include <fstream>
#include <sstream>

#include "interfaces/common_objects/peer.hpp"
#include "network/impl/channel_provider.hpp"

using namespace iroha::network;

ChannelPool::ChannelPool(std::unique_ptr<ChannelProvider> channel_provider)
    : channel_provider_(std::move(channel_provider)) {}

ChannelPool::~ChannelPool() = default;

std::shared_ptr<grpc::Channel> ChannelPool::getChannel(
    const std::string &service_full_name,
    const shared_model::interface::Peer &peer) {
  if (channels_.find(peer.pubkey()) == channels_.end()) {
    channels_[peer.pubkey()] =
        channel_provider_->getChannel(service_full_name, peer);
  }
  return channels_[peer.pubkey()];
}
