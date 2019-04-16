/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_ACCOUNT_ASSET_TRANSACTIONS_HPP
#define IROHA_SHARED_MODEL_GET_ACCOUNT_ASSET_TRANSACTIONS_HPP

#include <memory>

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class TxPaginationMeta;

    /**
     * Query for getting transactions of given asset of an account
     */
    class GetAccountAssetTransactions
        : public ModelPrimitive<GetAccountAssetTransactions> {
     public:
      /**
       * @return account_id of requested transactions
       */
      virtual const types::AccountIdType &accountId() const = 0;
      /**
       * @return assetId of requested transactions
       */
      virtual const types::AccountIdType &assetId() const = 0;

      /// Get the query pagination metadata.
      virtual const TxPaginationMeta &paginationMeta() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_GET_ACCOUNT_ASSET_TRANSACTIONS_HPP
