/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/block_response.hpp"

#include "interfaces/iroha_internal/block.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {
    std::string BlockResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("BlockResponse")
          .append(block())
          .finalize();
    }

    bool BlockResponse::operator==(const ModelType &rhs) const {
      return block() == rhs.block();
    }
  }  // namespace interface
}  // namespace shared_model
