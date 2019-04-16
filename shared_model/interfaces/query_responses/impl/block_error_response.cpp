/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/block_error_response.hpp"

#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string BlockErrorResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("BlockErrorResponse")
          .append(message())
          .finalize();
    }

    bool BlockErrorResponse::operator==(const ModelType &rhs) const {
      return message() == rhs.message();
    }
  }  // namespace interface
}  // namespace shared_model
