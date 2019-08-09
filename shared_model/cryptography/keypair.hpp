/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_KEYPAIR_HPP
#define IROHA_SHARED_MODEL_KEYPAIR_HPP

#include "cryptography/private_key.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/base/model_primitive.hpp"

namespace shared_model {
  namespace crypto {

    /**
     * Class for holding a keypair: public key and private key
     */
    class Keypair : public interface::ModelPrimitive<Keypair> {
     public:
      /// Type of public key
      using PublicKeyType = PublicKey;

      /// Type of private key
      using PrivateKeyType = PrivateKey;

      explicit Keypair(const PublicKeyType &public_key,
                       const PrivateKeyType &private_key);

      /**
       * @return public key
       */
      const PublicKeyType &publicKey() const;

      /**
       * @return private key
       */
      const PrivateKeyType &privateKey() const;

      bool operator==(const Keypair &keypair) const override;

      std::string toString() const override;

     private:
      PublicKey public_key_;
      PrivateKey private_key_;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_KEYPAIR_HPP
