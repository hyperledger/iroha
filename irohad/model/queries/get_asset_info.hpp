/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GET_ASSET_INFO_HPP
#define IROHA_GET_ASSET_INFO_HPP

#include <string>
#include "model/query.hpp"

namespace iroha {
  namespace model {
    /**
     * Get meta data of asset
     */
    struct GetAssetInfo : Query {
      GetAssetInfo() {}

      GetAssetInfo(std::string asset_id) : asset_id(asset_id) {}

      /**
       * Asset Id
       */
      std::string asset_id{};
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_GET_ASSET_INFO_HPP
