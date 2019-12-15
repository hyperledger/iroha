/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/create_asset.hpp"

namespace shared_model {
  namespace interface {

    std::string CreateAsset::toString() const {
      return detail::PrettyStringBuilder()
          .init("CreateAsset")
          .appendNamed("asset_name", assetName())
          .appendNamed("domain_id", domainId())
          .appendNamed("precision", precision())
          .finalize();
    }

    bool CreateAsset::operator==(const ModelType &rhs) const {
      return assetName() == rhs.assetName() and domainId() == rhs.domainId()
          and precision() == rhs.precision();
    }

  }  // namespace interface
}  // namespace shared_model
