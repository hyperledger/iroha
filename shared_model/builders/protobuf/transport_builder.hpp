/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSPORT_BUILDER_HPP
#define IROHA_TRANSPORT_BUILDER_HPP

#include "common/result.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace proto {

    /**
     * Class for building any shared model objects from corresponding transport
     * representation (e.g. protobuf object)
     * @tparam T Build type
     * @tparam SV Stateless validator type
     */
    template <typename T, typename SV>
    class /*[[deprecated]]*/ TransportBuilder {
      TransportBuilder(const SV &validator) : stateless_validator_(validator) {}

     public:
      TransportBuilder(std::shared_ptr<validation::ValidatorsConfig> config)
          : TransportBuilder(SV(config)) {}

      /**
       * Builds result from transport object
       * @return value if transport object is valid and error message otherwise
       */
      iroha::expected::Result<T, std::string> build(
          typename T::TransportType transport) {
        auto result = T(transport);
        if (auto error = stateless_validator_.validate(result)) {
          return iroha::expected::makeError(error->toString());
        }
        return iroha::expected::makeValue(T(std::move(transport)));
      }

     private:
      SV stateless_validator_;
    };

  }  // namespace proto
}  // namespace shared_model
#endif  // IROHA_TRANSPORT_BUILDER_HPP
