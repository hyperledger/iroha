/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ASSET_RESPONSE_HPP
#define IROHA_SHARED_MODEL_ASSET_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/asset.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Provide response with asset
     */
    class AssetResponse : public ModelPrimitive<AssetResponse> {
     public:
      /**
       * @return Attached asset
       */
      virtual const Asset &asset() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_ASSET_RESPONSE_HPP
