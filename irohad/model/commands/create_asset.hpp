/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CREATE_ASSET_HPP
#define IROHA_CREATE_ASSET_HPP

#include <string>
#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Create new asset in the system
     */
    struct CreateAsset : public Command {
      /**
       * Asset to create in the system
       */
      std::string asset_name;

      /**
       * Domain id (full name)
       */
      std::string domain_id;

      /**
       * Asset precision
       */
      uint8_t precision;

      bool operator==(const Command &command) const override;

      CreateAsset() {}

      CreateAsset(const std::string &asset_name,
                  const std::string &domain_id,
                  uint8_t precision)
          : asset_name(asset_name),
            domain_id(domain_id),
            precision(precision) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_CREATE_ASSET_HPP
