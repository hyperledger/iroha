/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ADD_ASSET_QUANTITY_HPP
#define IROHA_SHARED_MODEL_ADD_ASSET_QUANTITY_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/amount.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Add amount of asset to an account
     */
    class AddAssetQuantity : public ModelPrimitive<AddAssetQuantity> {
     public:
      /**
       * @return asset identifier
       */
      virtual const types::AssetIdType &assetId() const = 0;
      /**
       * @return quantity of asset for adding
       */
      virtual const Amount &amount() const = 0;

      virtual const std::string &description() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_ADD_ASSET_QUANTITY_HPP
