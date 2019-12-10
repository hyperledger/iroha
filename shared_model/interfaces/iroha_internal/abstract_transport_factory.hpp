/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ABSTRACT_TRANSPORT_FACTORY_HPP
#define IROHA_ABSTRACT_TRANSPORT_FACTORY_HPP

#include <memory>

#include <fmt/core.h>
#include <boost/optional/optional.hpp>
#include "common/result.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    template <typename Interface, typename Transport>
    class AbstractTransportFactory {
     public:
      struct Error {
        std::string toString() const {
          if (hash) {
            return fmt::format("TransportFactory::Error, message: {}", error);
          }
          return fmt::format(
              "TransportFactory::Error, object hash: {}, message: {}",
              hash.value(),
              error);
        }

        boost::optional<types::HashType> hash;
        std::string error;
      };

      virtual iroha::expected::Result<std::unique_ptr<Interface>, Error> build(
          Transport transport) const = 0;

      virtual ~AbstractTransportFactory() = default;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_ABSTRACT_TRANSPORT_FACTORY_HPP
