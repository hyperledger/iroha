/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLIENT_FACTORY_HPP
#define IROHA_CLIENT_FACTORY_HPP

#include <memory>

#include "common/result.hpp"

namespace shared_model {
  namespace interface {
    class Peer;
  }
}  // namespace shared_model

namespace iroha {
  namespace network {

    template <typename Service>
    class ClientFactory {
     public:
      virtual ~ClientFactory() = default;

      virtual iroha::expected::
          Result<std::unique_ptr<typename Service::StubInterface>, std::string>
          createClient(const shared_model::interface::Peer &peer) const = 0;
    };

  }  // namespace network
}  // namespace iroha

#endif
