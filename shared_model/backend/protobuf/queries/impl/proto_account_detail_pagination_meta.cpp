/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_account_detail_pagination_meta.hpp"

using namespace shared_model::proto;

AccountDetailPaginationMeta::AccountDetailPaginationMeta(TransportType &proto)
    : proto_(proto), first_record_id_{[this]() -> decltype(first_record_id_) {
        if (proto_.has_first_record_id()) {
          return std::make_optional<const AccountDetailRecordId>(
              *this->proto_.mutable_first_record_id());
        }
        return std::nullopt;
      }()} {}

AccountDetailPaginationMeta::AccountDetailPaginationMeta(
    const AccountDetailPaginationMeta &o)
    : AccountDetailPaginationMeta(o.proto_) {}

size_t AccountDetailPaginationMeta::pageSize() const {
  return proto_.page_size();
}

std::optional<std::reference_wrapper<
    const shared_model::interface::AccountDetailRecordId>>
AccountDetailPaginationMeta::firstRecordId() const {
  if (first_record_id_) {
    return std::cref<shared_model::interface::AccountDetailRecordId>(
        first_record_id_.value());
  }
  return {};
}
