/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_INTERFACE_ENGINE_RESPONSE_RECORD_HPP
#define IROHA_SHARED_MODEL_INTERFACE_ENGINE_RESPONSE_RECORD_HPP

#include <boost/optional.hpp>
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /// Provides a response for a single corresponding EngineCall command
    class EngineResponseRecord : public ModelPrimitive<EngineResponseRecord> {
     public:
      /// Get the index
      virtual interface::types::CommandIndexType commandIndex() const = 0;

      /// Get the response
      virtual const interface::types::SmartContractCodeType &response()
          const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_INTERFACE_ENGINE_RESPONSE_RECORD_HPP
