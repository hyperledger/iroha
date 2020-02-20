/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/account_response.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string AccountResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("AccountResponse")
          .append(account())
          .appendNamed("roles", roles())
          .finalize();
    }

    bool AccountResponse::operator==(const ModelType &rhs) const {
      return account() == rhs.account() and roles() == rhs.roles();
    }

  }  // namespace interface
}  // namespace shared_model
