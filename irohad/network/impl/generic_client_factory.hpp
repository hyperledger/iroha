/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GENERIC_CLIENT_FACTORY_HPP
#define IROHA_GENERIC_CLIENT_FACTORY_HPP

#include <memory>

#include "common/result.hpp"
#include "network/impl/channel_provider.hpp"

namespace iroha {
  namespace network {

    class GenericClientFactory {
     public:
      GenericClientFactory(std::unique_ptr<ChannelProvider> channel_provider);

      /**
       * Creates client which is capable of sending and receiving
       * messages of INT_MAX bytes size
       * @tparam Service type for gRPC stub, e.g. proto::Yac
       * @param address ip address for connection, ipv4:port
       * @return gRPC stub of parametrized type
       */
      template <typename Service>
      iroha::expected::Result<std::unique_ptr<typename Service::StubInterface>,
                              std::string>
      createClient(const shared_model::interface::Peer &peer) const {
        using iroha::expected::operator|;
        return channel_provider_->getChannel(Service::service_full_name(), peer)
                   | [](auto &&channel)
                   -> std::unique_ptr<typename Service::StubInterface> {
          return Service::NewStub(channel);
        };
      }

     private:
      std::unique_ptr<ChannelProvider> channel_provider_;
    };

  }  // namespace network
}  // namespace iroha

#endif
