/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_REMOVE_SIGNATORY_HPP
#define IROHA_SHARED_MODEL_REMOVE_SIGNATORY_HPP

#include "interfaces/base/noncopyable_model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Remove signatory from the account
     */
    class RemoveSignatory : public NonCopyableModelPrimitive<RemoveSignatory> {
     public:
      /**
       * @return account from which remove signatory
       */
      virtual const types::AccountIdType &accountId() const = 0;
      /**
       * @return Public key to remove from account
       */
      virtual const types::PubkeyType &pubkey() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_REMOVE_SIGNATORY_HPP
