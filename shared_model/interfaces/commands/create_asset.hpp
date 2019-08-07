/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_CREATE_ASSET_HPP
#define IROHA_SHARED_MODEL_CREATE_ASSET_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Create asset in Iroha domain
     */
    class CreateAsset : public ModelPrimitive<CreateAsset> {
     public:
      /**
       * @return Asset name to create
       */
      virtual const types::AssetNameType &assetName() const = 0;
      /**
       * @return Iroha domain of the asset
       */
      virtual const types::DomainIdType &domainId() const = 0;
      /// Precision type
      using PrecisionType = uint8_t;
      /**
       * @return precision of the asset
       */
      virtual const PrecisionType &precision() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_CREATE_ASSET_HPP
