/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_YAC_HASH_PROVIDER_HPP
#define IROHA_MOCK_YAC_HASH_PROVIDER_HPP

#include <gmock/gmock.h>

#include "consensus/yac/yac_hash_provider.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      class MockYacHashProvider : public YacHashProvider {
       public:
        MOCK_CONST_METHOD1(makeHash,
                           YacHash(const simulator::BlockCreatorEvent &event));

        MOCK_CONST_METHOD1(
            toModelHash,
            shared_model::interface::types::HashType(const YacHash &));

        MockYacHashProvider() = default;

        MockYacHashProvider(const MockYacHashProvider &rhs){};

        MockYacHashProvider(MockYacHashProvider &&rhs){};

        MockYacHashProvider &operator=(const MockYacHashProvider &rhs) {
          return *this;
        };
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_MOCK_YAC_HASH_PROVIDER_HPP
