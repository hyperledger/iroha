/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/signatories_response.hpp"

#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string SignatoriesResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("SignatoriesResponse")
          .append(keys())
          .finalize();
    }

    bool SignatoriesResponse::operator==(const ModelType &rhs) const {
      return keys() == rhs.keys();
    }

  }  // namespace interface
}  // namespace shared_model
