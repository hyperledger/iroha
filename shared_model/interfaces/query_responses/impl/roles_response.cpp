/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/roles_response.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string RolesResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("RolesResponse")
          .appendAll(roles(), [](auto s) { return s; })
          .finalize();
    }

    bool RolesResponse::operator==(const ModelType &rhs) const {
      return roles() == rhs.roles();
    }

  }  // namespace interface
}  // namespace shared_model
