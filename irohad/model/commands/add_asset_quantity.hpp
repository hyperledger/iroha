/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ADD_ASSET_QUANTITY_HPP
#define IROHA_ADD_ASSET_QUANTITY_HPP

#include <string>
#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Add amount of asset to an account
     */
    struct AddAssetQuantity : public Command {
      /**
       * Asset to issue
       * Note: must exist in the system
       */
      std::string asset_id;

      /**
       * Amount to add to account asset
       */
      std::string amount;

      /**
       * Description
       */
      std::string description;

      bool operator==(const Command &command) const override;

      AddAssetQuantity() {}

      AddAssetQuantity(const std::string &asset_id, const std::string &amount, const std::string &description)
          : asset_id(asset_id), amount(amount), description(description) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_ADD_ASSET_QUANTITY_HPP
