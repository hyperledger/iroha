/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_VERIFIER_HPP
#define IROHA_SHARED_MODEL_VERIFIER_HPP

#include "cryptography/blob.hpp"
#include "interfaces/common_objects/string_view_types.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * Class for signature verification.
     */
    class Verifier {
     public:
      static bool verify(
          shared_model::interface::types::SignatureByteRangeView signature,
          const Blob &orig,
          shared_model::interface::types::PublicKeyByteRangeView public_key);
    };

  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_VERIFIER_HPP
