/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ASSET_HPP
#define IROHA_SHARED_MODEL_ASSET_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Representation of valuable goods in the system
     */
    class Asset : public ModelPrimitive<Asset> {
     public:
      /**
       * @return Identity of asset
       */
      virtual const types::AccountIdType &assetId() const = 0;

      /**
       * @return Identity of domain
       */
      virtual const types::DomainIdType &domainId() const = 0;

      /**
       * @return Asset's fixed precision
       */
      virtual types::PrecisionType precision() const = 0;

      /**
       * Stringify the data.
       * @return the content of asset.
       */
      std::string toString() const override {
        return detail::PrettyStringBuilder()
            .init("Asset")
            .appendNamed("assetId", assetId())
            .appendNamed("domainId", domainId())
            .appendNamed("precision", precision())
            .finalize();
      }

      /**
       * Checks equality of objects inside
       * @param rhs - other wrapped value
       * @return true, if wrapped objects are same
       */
      bool operator==(const ModelType &rhs) const override {
        return assetId() == rhs.assetId() and domainId() == rhs.domainId()
            and precision() == rhs.precision();
      }
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_ASSET_HPP
