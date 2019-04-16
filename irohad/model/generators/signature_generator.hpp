/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SIGNATURE_GENERATOR_HPP
#define IROHA_SIGNATURE_GENERATOR_HPP

#include "generator/generator.hpp"
#include "model/signature.hpp"

namespace iroha {
  namespace model {
    namespace generators {

      /**
       * Generate fake signature from given seed
       * @param seed
       * @return model Signature
       */
      Signature generateSignature(size_t seed);

    }  // namespace generators
  }    // namespace model
}  // namespace iroha

#endif  // IROHA_SIGNATURE_GENERATOR_HPP
