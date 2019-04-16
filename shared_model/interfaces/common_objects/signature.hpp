/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SIGNATURE_HPP
#define IROHA_SHARED_MODEL_SIGNATURE_HPP

#include "interfaces/base/model_primitive.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {

  namespace crypto {
    class PublicKey;
    class Signed;
  }  // namespace crypto

  namespace interface {

    /**
     * Class represents signature of high-level domain objects.
     */
    class Signature : public ModelPrimitive<Signature> {
     public:
      /**
       * Type of public key
       */
      using PublicKeyType = crypto::PublicKey;

      /**
       * @return public key of signatory
       */
      virtual const PublicKeyType &publicKey() const = 0;

      /**
       * Type of signed data
       */
      using SignedType = crypto::Signed;

      /**
       * @return signed data
       */
      virtual const SignedType &signedData() const = 0;

      bool operator==(const Signature &rhs) const override;

      std::string toString() const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_SIGNATURE_HPP
