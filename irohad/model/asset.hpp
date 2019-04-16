/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ASSET_HPP
#define IROHA_ASSET_HPP

#include <string>

namespace iroha {
  namespace model {

    /**
     * Asset Data Model
     */
    struct Asset {
      Asset() = default;

      Asset(std::string asset_id, std::string domain_id, uint8_t precision)
          : asset_id(asset_id), domain_id(domain_id), precision(precision) {}
      /**
       * Asset unique identifier
       */
      std::string asset_id;

      std::string domain_id;

      /**
       * Precision of asset
       */
      uint8_t precision;
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_ASSET_HPP
