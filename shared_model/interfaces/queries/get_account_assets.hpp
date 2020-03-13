/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_ACCOUNT_ASSETS_HPP
#define IROHA_SHARED_MODEL_GET_ACCOUNT_ASSETS_HPP

#include <optional>
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class AssetPaginationMeta;

    /**
     * Query for get all account's assets and balance
     */
    class GetAccountAssets : public ModelPrimitive<GetAccountAssets> {
     public:
      /**
       * @return account identifier
       */
      virtual const types::AccountIdType &accountId() const = 0;

      /// Get the query pagination metadata.
      // TODO 2019.05.24 mboldyrev IR-516 remove optional
      virtual std::optional<
          std::reference_wrapper<const interface::AssetPaginationMeta>>
      paginationMeta() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_GET_ACCOUNT_ASSETS_HPP
