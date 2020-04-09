/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_KEYPAIR_HPP
#define IROHA_SHARED_MODEL_KEYPAIR_HPP

#include "cryptography/private_key.hpp"
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/string_view_types.hpp"

namespace shared_model {
  namespace crypto {

    /**
     * Class for holding a keypair: public key and private key
     */
    class Keypair : public interface::ModelPrimitive<Keypair> {
     public:
      /// Type of private key
      using PrivateKeyType = PrivateKey;

      explicit Keypair(
          shared_model::interface::types::PublicKeyHexStringView public_key_hex,
          const PrivateKeyType &private_key);

      /**
       * @return public key
       */
      std::string const &publicKey() const;

      /**
       * @return private key
       */
      const PrivateKeyType &privateKey() const;

      bool operator==(const Keypair &keypair) const override;

      std::string toString() const override;

     private:
      std::string public_key_hex_;
      PrivateKey private_key_;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_KEYPAIR_HPP
