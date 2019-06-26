/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/account_detail_pagination_meta.hpp"

using namespace shared_model::interface;

bool AccountDetailPaginationMeta::operator==(const ModelType &rhs) const {
  return pageSize() == rhs.pageSize()
      and firstRecordId() == rhs.firstRecordId();
}

std::string AccountDetailPaginationMeta::toString() const {
  const auto first_record_id = firstRecordId();
  return detail::PrettyStringBuilder()
      .init("AccountDetailPaginationMeta")
      .append("page_size", std::to_string(pageSize()))
      .append(
          "first_record_id",
          first_record_id ? first_record_id->toString() : std::string("(none)"))
      .finalize();
}
