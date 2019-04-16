/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ASSET_RESPONSE_HPP
#define IROHA_ASSET_RESPONSE_HPP

#include "model/asset.hpp"
#include "model/query_response.hpp"

namespace iroha {
  namespace model {

    /**
     * Provide response with asset
     */
    struct AssetResponse : public QueryResponse {
      /**
       * Attached asset
       */
      Asset asset{};
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_ASSET_RESPONSE_HPP
