/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_block.hpp"

namespace shared_model {
  namespace interface {

    std::string GetBlock::toString() const {
      return detail::PrettyStringBuilder()
          .init("GetBlock")
          .appendNamed("height", height())
          .finalize();
    }

    bool GetBlock::operator==(const ModelType &rhs) const {
      return height() == rhs.height();
    }

  }  // namespace interface
}  // namespace shared_model
