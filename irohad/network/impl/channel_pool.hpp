/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_POOL_HPP
#define IROHA_CHANNEL_POOL_HPP

#include "network/impl/channel_provider.hpp"

namespace iroha {
  namespace network {

    class ChannelPool : public ChannelProvider {
     public:
      /**
       * @param channel_provider - Factory that is used to create missing
       * channels.
       */
      explicit ChannelPool(std::unique_ptr<ChannelProvider> channel_provider);

      ~ChannelPool();

      iroha::expected::Result<std::shared_ptr<grpc::Channel>, std::string>
      getChannel(const std::string &service_full_name,
                 const shared_model::interface::Peer &peer) override;

     private:
      class Impl;
      std::unique_ptr<Impl> impl_;
    };

  }  // namespace network
}  // namespace iroha

#endif
