/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_COMPARE_AND_SET_ACCOUNT_DETAIL_HPP
#define IROHA_SHARED_MODEL_COMPARE_AND_SET_ACCOUNT_DETAIL_HPP

#include <optional>
#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Set key-value pair of given account if the current value matches provided
     * expectation
     */
    class CompareAndSetAccountDetail
        : public ModelPrimitive<CompareAndSetAccountDetail> {
     public:
      /**
       * @return Identity of user to set account detail to
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

      /**
       * @return true, if empty oldValue in command must match absent value in
       * WSV, false if any oldValue in command matches absent in WSV (legacy)
       */
      virtual bool checkEmpty() const = 0;

      /**
       * @return the value expected before the change
       */
      virtual const std::optional<types::AccountDetailValueType> oldValue()
          const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_COMPARE_AND_SET_ACCOUNT_DETAIL_HPP
