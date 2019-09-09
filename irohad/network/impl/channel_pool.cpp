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

std::shared_ptr<grpc::Channel> ChannelPool::getChannel(
    const std::string &service_full_name, const std::string &address) {
  if (channels_.find(address) == channels_.end()) {
    channels_[address] =
        // WORKAROUND
        iroha::expected::resultToOptionalValue(
            channel_factory_->createChannel(service_full_name, address))
            .value();
  }
  return channels_[address];
}
