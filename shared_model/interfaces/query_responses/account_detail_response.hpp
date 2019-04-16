/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ACCOUNT_DETAIL_RESPONSE_HPP
#define IROHA_SHARED_MODEL_ACCOUNT_DETAIL_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Provide response with account asset
     */
    class AccountDetailResponse : public ModelPrimitive<AccountDetailResponse> {
     public:
      /**
       * @return Account has Asset model
       */
      virtual const types::DetailType &detail() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_ACCOUNT_DETAIL_RESPONSE_HPP
