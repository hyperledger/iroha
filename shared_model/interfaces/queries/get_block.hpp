/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_BLOCK_HPP
#define IROHA_SHARED_MODEL_GET_BLOCK_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class GetBlock : public ModelPrimitive<GetBlock> {
     public:
      /**
       * Get height of the block to be returned
       * @return block's height
       */
      virtual types::HeightType height() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_GET_BLOCK_HPP
