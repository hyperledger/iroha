/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SIGNER_HPP
#define IROHA_SHARED_MODEL_SIGNER_HPP

#include "cryptography/blob.hpp"
#include "cryptography/keypair.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * Class which signs provided data with a provided private key.
     */
    class Signer {
     public:
      /**
       * Signs provided blob.
       * @param blob - to sign
       * @param keypair - keypair with public and private keys
       * @return hex signature data string
       */
      static std::string sign(const Blob &blob, const Keypair &keypair);
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_SIGNER_HPP
