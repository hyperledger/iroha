/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLIENT_FACTORY_HPP
#define IROHA_CLIENT_FACTORY_HPP

#include <memory>

#include "network/impl/channel_provider.hpp"

namespace shared_model {
  namespace interface {
    class Peer;
  }
}  // namespace shared_model

namespace iroha {
  namespace network {

    class ClientFactory {
     public:
      ClientFactory(std::unique_ptr<ChannelProvider> channel_provider);

      /**
       * Creates client which is capable of sending and receiving
       * messages of INT_MAX bytes size
       * @tparam T type for gRPC stub, e.g. proto::Yac
       * @param address ip address for connection, ipv4:port
       * @return gRPC stub of parametrized type
       */
      template <typename T>
      std::unique_ptr<typename T::StubInterface> createClient(
          const shared_model::interface::Peer &peer) {
        auto channel =
            channel_provider_->getChannel(T::service_full_name(), peer);
        return T::NewStub(channel);
      }

     private:
      std::unique_ptr<ChannelProvider> channel_provider_;
    };
  }  // namespace network
}  // namespace iroha

#endif
