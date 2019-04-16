/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSFER_ASSET_HPP
#define IROHA_TRANSFER_ASSET_HPP

#include <string>
#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Transfer asset from one account to another
     */
    struct TransferAsset : public Command {
      /**
       * Source account
       */
      std::string src_account_id;

      /**
       * Destination account
       */
      std::string dest_account_id;

      /**
       * Asset to transfer. Identifier is asset_id
       */
      std::string asset_id;

      /**
       * Transfer description
       */
      std::string description;

      /**
       * Amount of transferred asset
       */
      std::string amount;

      bool operator==(const Command &command) const override;

      TransferAsset() {}

      TransferAsset(const std::string &src_account_id,
                    const std::string &dest_account_id,
                    const std::string &asset_id,
                    const std::string &amount)
          : src_account_id(src_account_id),
            dest_account_id(dest_account_id),
            asset_id(asset_id),
            amount(amount) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_TRANSFER_ASSET_HPP
