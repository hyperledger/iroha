/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_account_detail_response.hpp"

namespace shared_model {
  namespace proto {

    AccountDetailResponse::AccountDetailResponse(
        iroha::protocol::QueryResponse &query_response)
        : account_detail_response_{query_response.account_detail_response()},
          next_record_id_{
              [](auto &query_response) -> decltype(next_record_id_) {
                if (query_response.has_next_record_id()) {
                  return std::make_optional<const AccountDetailRecordId>(
                      *query_response.mutable_next_record_id());
                }
                return std::nullopt;
              }(*query_response.mutable_account_detail_response())} {}

    const interface::types::DetailType &AccountDetailResponse::detail() const {
      return account_detail_response_.detail();
    }

    size_t AccountDetailResponse::totalNumber() const {
      return account_detail_response_.total_number();
    }

    std::optional<std::reference_wrapper<
        const shared_model::interface::AccountDetailRecordId>>
    AccountDetailResponse::nextRecordId() const {
      if (next_record_id_) {
        return std::cref<shared_model::interface::AccountDetailRecordId>(
            next_record_id_.value());
      }
      return std::nullopt;
    }

  }  // namespace proto
}  // namespace shared_model
