/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_ASSET_INFO_HPP
#define IROHA_SHARED_MODEL_GET_ASSET_INFO_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Get meta data of asset
     */
    class GetAssetInfo : public ModelPrimitive<GetAssetInfo> {
     public:
      /**
       * @return asset identifier to get asset's information
       */
      virtual const types::AssetIdType &assetId() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_GET_ASSET_INFO_HPP
