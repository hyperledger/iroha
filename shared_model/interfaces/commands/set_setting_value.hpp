/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SET_SETTING_VALUE_HPP
#define IROHA_SHARED_MODEL_SET_SETTING_VALUE_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Set key-value pair of settings
     */
    class SetSettingValue : public ModelPrimitive<SetSettingValue> {
     public:
      /**
       * @return key of data to store in settings
       */
      virtual const types::SettingKeyType &key() const = 0;

      /**
       * @return setting value to store by given key
       */
      virtual const types::SettingValueType &value() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_SET_SETTING_VALUE_HPP
