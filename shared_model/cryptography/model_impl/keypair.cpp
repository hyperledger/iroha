/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/keypair.hpp"

#include "utils/string_builder.hpp"

using namespace shared_model::interface::types;

namespace shared_model {
  namespace crypto {

    std::string const &Keypair::publicKey() const {
      return public_key_hex_;
    }

    const Keypair::PrivateKeyType &Keypair::privateKey() const {
      return private_key_;
    }

    bool Keypair::operator==(const Keypair &keypair) const {
      return publicKey() == keypair.publicKey()
          and privateKey() == keypair.privateKey();
    }

    std::string Keypair::toString() const {
      return detail::PrettyStringBuilder()
          .init("Keypair")
          .appendNamed("publicKey", publicKey())
          .appendNamed("privateKey", privateKey())
          .finalize();
    }

    Keypair::Keypair(PublicKeyHexStringView public_key_hex,
                     const Keypair::PrivateKeyType &private_key)
        : public_key_hex_(public_key_hex), private_key_(private_key) {}

  }  // namespace crypto
}  // namespace shared_model
