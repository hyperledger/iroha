/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SIGNATURE_HPP
#define IROHA_SHARED_MODEL_SIGNATURE_HPP

#include "common/cloneable.hpp"
#include "interfaces/base/model_primitive.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Class represents signature of high-level domain objects.
     */
    class Signature : public ModelPrimitive<Signature>,
                      public Cloneable<Signature> {
     public:
      /**
       * @return public key of signatory
       */
      virtual const std::string &publicKey() const = 0;

      /**
       * @return signed data
       */
      virtual const std::string &signedData() const = 0;

      bool operator==(const Signature &rhs) const override;

      std::string toString() const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_SIGNATURE_HPP
