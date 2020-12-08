/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ENGINE_RECEIPTS_RESPONSE_HPP
#define IROHA_SHARED_MODEL_ENGINE_RECEIPTS_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include <iosfwd>

#include "interfaces/common_objects/range_types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Provide response with reponses to EngineCall commands within a single
     * transaction
     */
    class EngineReceiptsResponse
        : public ModelPrimitive<EngineReceiptsResponse> {
     public:
      /// Returns EVM responses to EngineCall commands
      virtual types::EngineReceiptCollectionType engineReceipts() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

    std::ostream &operator<<(std::ostream &os, EngineReceiptsResponse const &);
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_ENGINE_RECEIPTS_RESPONSE_HPP
