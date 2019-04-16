/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/account_detail_response.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string AccountDetailResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("AccountDetailResponse")
          .append(detail())
          .finalize();
    }

    bool AccountDetailResponse::operator==(const ModelType &rhs) const {
      return detail() == rhs.detail();
    }

  }  // namespace interface
}  // namespace shared_model
