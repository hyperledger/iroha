/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/asset_response.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string AssetResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("AssetResponse")
          .append(asset())
          .finalize();
    }

    bool AssetResponse::operator==(const ModelType &rhs) const {
      return asset() == rhs.asset();
    }

  }  // namespace interface
}  // namespace shared_model
