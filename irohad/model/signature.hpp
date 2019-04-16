/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SIGNATURE_HPP
#define IROHA_SIGNATURE_HPP

#include "crypto/keypair.hpp"

namespace iroha {
  namespace model {

    /**
     * Signature is a Model structure to store crypto information
     */
    struct Signature {
      Signature() = default;
      Signature(sig_t signature, pubkey_t public_key)
          : signature(signature), pubkey(public_key) {}

      sig_t signature;

      using SignatureType = decltype(signature);

      pubkey_t pubkey;

      using KeyType = decltype(pubkey);

      bool operator==(const Signature &rhs) const;
      bool operator!=(const Signature &rhs) const;
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_SIGNATURE_HPP
