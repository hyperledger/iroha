/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ACCOUNT_ASSET_HPP
#define IROHA_SHARED_MODEL_ACCOUNT_ASSET_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/amount.hpp"
#include "interfaces/common_objects/types.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Representation of wallet in system
     */
    class AccountAsset : public ModelPrimitive<AccountAsset> {
     public:
      /**
       * @return Identity of user, for fetching data
       */
      virtual const types::AccountIdType &accountId() const = 0;

      /**
       * @return Identity of asset, for fetching data
       */
      virtual const types::AssetIdType &assetId() const = 0;

      /**
       * @return Current balance
       */
      virtual const Amount &balance() const = 0;

      /**
       * Stringify the data.
       * @return the content of account asset.
       */
      std::string toString() const override {
        return detail::PrettyStringBuilder()
            .init("AccountAsset")
            .appendNamed("accountId", accountId())
            .appendNamed("assetId", assetId())
            .appendNamed("balance", balance())
            .finalize();
      }

      /**
       * Checks equality of objects inside
       * @param rhs - other wrapped value
       * @return true, if wrapped objects are same
       */
      bool operator==(const ModelType &rhs) const override {
        return accountId() == rhs.accountId() and assetId() == rhs.assetId()
            and balance() == rhs.balance();
      }
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_ACCOUNT_ASSET_HPP
