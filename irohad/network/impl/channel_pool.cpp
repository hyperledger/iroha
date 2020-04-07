/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/channel_pool.hpp"

#include <shared_mutex>
#include <unordered_map>

#include "interfaces/common_objects/peer.hpp"
#include "interfaces/common_objects/types.hpp"
#include "network/impl/channel_provider.hpp"

using namespace iroha::expected;
using namespace iroha::network;

class ChannelPool::Impl {
 public:
  Impl(std::unique_ptr<ChannelProvider> channel_provider)
      : channel_provider_(std::move(channel_provider)) {}

  Result<std::shared_ptr<grpc::Channel>, std::string> getOrCreate(
      const std::string &service_full_name,
      const shared_model::interface::Peer &peer) {
    std::shared_lock<std::shared_timed_mutex> read_lock(mutex_);
    auto i = channels_.find(peer.pubkey());
    if (i != channels_.end()) {
      return i->second;
    }
    read_lock.unlock();

    return channel_provider_->getChannel(service_full_name, peer) |
        [this, &peer](auto &&new_channel) {
          std::unique_lock<std::shared_timed_mutex> write_lock(mutex_);
          channels_[peer.pubkey()] = new_channel;
          return std::move(new_channel);
        };
  }

 private:
  std::unique_ptr<ChannelProvider> channel_provider_;

  std::shared_timed_mutex mutex_;
  std::unordered_map<std::string, std::shared_ptr<grpc::Channel>> channels_;
};

ChannelPool::ChannelPool(std::unique_ptr<ChannelProvider> channel_provider)
    : impl_(std::make_unique<Impl>(std::move(channel_provider))) {}

ChannelPool::~ChannelPool() = default;

Result<std::shared_ptr<grpc::Channel>, std::string> ChannelPool::getChannel(
    const std::string &service_full_name,
    const shared_model::interface::Peer &peer) {
  return impl_->getOrCreate(service_full_name, peer);
}
