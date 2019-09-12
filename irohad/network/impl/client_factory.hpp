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
    class ChannelProvider;

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
      std::unique_ptr<typename Service::StubInterface> createClient(
          const shared_model::interface::Peer &peer) const {
        auto channel =
            channel_provider_->getChannel(Service::service_full_name(), peer);
        return Service::NewStub(channel);
      }

     private:
      std::unique_ptr<ChannelProvider> channel_provider_;
    };

    template <typename Service>
    class ClientFactory {
     public:
      virtual ~ClientFactory() = default;

      virtual std::unique_ptr<typename Service::StubInterface> createClient(
          const shared_model::interface::Peer &peer) const = 0;
    };

    template <typename Service>
    class ClientFactoryImpl : public ClientFactory<Service> {
     public:
      ClientFactoryImpl(
          std::shared_ptr<const GenericClientFactory> generic_factory)
          : generic_factory_(std::move(generic_factory)) {}

      std::unique_ptr<typename Service::StubInterface> createClient(
          const shared_model::interface::Peer &peer) const override {
        return generic_factory_->createClient<Service>(peer);
      }

     private:
      std::shared_ptr<const GenericClientFactory> generic_factory_;
    };

  }  // namespace network
}  // namespace iroha

#endif
