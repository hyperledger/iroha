/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLIENT_FACTORY_IMPL_HPP
#define IROHA_CLIENT_FACTORY_IMPL_HPP

#include "network/impl/client_factory.hpp"

#include <memory>

#include "network/impl/generic_client_factory.hpp"

namespace iroha {
  namespace network {

    template <typename Service>
    class ClientFactoryImpl : public ClientFactory<Service> {
     public:
      ClientFactoryImpl(
          std::shared_ptr<const GenericClientFactory> generic_factory)
          : generic_factory_(std::move(generic_factory)) {}

      iroha::expected::Result<std::unique_ptr<typename Service::StubInterface>,
                              std::string>
      createClient(const shared_model::interface::Peer &peer) const override {
        return generic_factory_->createClient<Service>(peer);
      }

     private:
      std::shared_ptr<const GenericClientFactory> generic_factory_;
    };

  }  // namespace network
}  // namespace iroha

#endif
