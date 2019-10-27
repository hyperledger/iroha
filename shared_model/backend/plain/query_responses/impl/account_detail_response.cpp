/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/query_responses/account_detail_response.hpp"

using shared_model::plain::AccountDetailResponse;

AccountDetailResponse::AccountDetailResponse(
    shared_model::interface::types::DetailType account_detail,
    size_t total_number,
    boost::optional<
        std::unique_ptr<shared_model::interface::AccountDetailRecordId>>
        next_record_id)
    : account_detail_(std::move(account_detail)),
      total_number_(total_number),
      next_record_id_(std::move(next_record_id)) {}

const shared_model::interface::types::DetailType &
AccountDetailResponse::detail() const {
  return account_detail_;
}

size_t AccountDetailResponse::totalNumber() const {
  return total_number_;
}

boost::optional<const shared_model::interface::AccountDetailRecordId &>
AccountDetailResponse::nextRecordId() const {
  if (next_record_id_) {
    return *next_record_id_.value();
  }
  return boost::none;
}
