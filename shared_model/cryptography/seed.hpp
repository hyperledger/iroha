/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SEED_HPP
#define IROHA_SEED_HPP

#include "cryptography/blob.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * Class for seed representation.
     */
    class Seed : public Blob {
     public:
      explicit Seed(const std::string &seed);

      std::string toString() const override;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SEED_HPP
