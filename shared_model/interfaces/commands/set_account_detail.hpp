/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SET_ACCOUNT_DETAIL_HPP
#define IROHA_SHARED_MODEL_SET_ACCOUNT_DETAIL_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Set key-value pair of given account
     */
    class SetAccountDetail : public ModelPrimitive<SetAccountDetail> {
     public:
      /**
       * @return Identity of user to set account detail
       */
      virtual const types::AccountIdType &accountId() const = 0;

      /**
       * @return key of data to store in the account
       */
      virtual const types::AccountDetailKeyType &key() const = 0;

      /**
       * @return detail value to store by given key
       */
      virtual const types::AccountDetailValueType &value() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_SET_ACCOUNT_DETAIL_HPP
