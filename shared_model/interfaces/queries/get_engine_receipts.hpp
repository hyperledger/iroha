/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_ENGINE_RESPONSE_HPP
#define IROHA_SHARED_MODEL_GET_ENGINE_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Get EVM return value after execution of EngineCall command
     */
    class GetEngineReceipts : public ModelPrimitive<GetEngineReceipts> {
     public:
      /**
       * @return hash of transaction that is going to be queried
       */
      virtual const std::string &txHash() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_GET_ENGINE_RESPONSE_HPP
