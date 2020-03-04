/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/account_detail_pagination_meta.hpp"

#include "common/optional_reference_equal.hpp"

using namespace shared_model::interface;

bool AccountDetailPaginationMeta::operator==(const ModelType &rhs) const {
  return pageSize() == rhs.pageSize()
      and iroha::optionalReferenceEqual(firstRecordId(), rhs.firstRecordId());
}

std::string AccountDetailPaginationMeta::toString() const {
  const auto first_record_id = firstRecordId();
  return detail::PrettyStringBuilder()
      .init("AccountDetailPaginationMeta")
      .appendNamed("page_size", pageSize())
      .appendNamed("first_record_id", first_record_id)
      .finalize();
}
