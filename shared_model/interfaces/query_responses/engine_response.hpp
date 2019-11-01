/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ENGINE_RESPONSE_HPP
#define IROHA_SHARED_MODEL_ENGINE_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/range_types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Provide response with reponses to EngineCall commands within a single
     * transaction
     */
    class EngineResponse : public ModelPrimitive<EngineResponse> {
     public:
      /// Returns EVM responses to EngineCall commands
      virtual types::EngineResponseRecordCollectionType engineResponseRecords()
          const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_ENGINE_RESPONSE_HPP
