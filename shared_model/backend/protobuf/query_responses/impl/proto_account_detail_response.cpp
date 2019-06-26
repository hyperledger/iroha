/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_account_detail_response.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    AccountDetailResponse::AccountDetailResponse(
        QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          account_detail_response_{proto_->account_detail_response()},
          next_record_id_{[this]() -> decltype(next_record_id_) {
            if (this->account_detail_response_.has_next_record_id()) {
              return AccountDetailRecordId{
                  *this->proto_->mutable_account_detail_response()
                       ->mutable_next_record_id()};
            }
            return boost::none;
          }()} {}

    template AccountDetailResponse::AccountDetailResponse(
        AccountDetailResponse::TransportType &);
    template AccountDetailResponse::AccountDetailResponse(
        const AccountDetailResponse::TransportType &);
    template AccountDetailResponse::AccountDetailResponse(
        AccountDetailResponse::TransportType &&);

    AccountDetailResponse::AccountDetailResponse(const AccountDetailResponse &o)
        : AccountDetailResponse(o.proto_) {}

    AccountDetailResponse::AccountDetailResponse(AccountDetailResponse &&o)
        : AccountDetailResponse(std::move(o.proto_)) {}

    const interface::types::DetailType &AccountDetailResponse::detail() const {
      return account_detail_response_.detail();
    }

    size_t AccountDetailResponse::totalNumber() const {
      return account_detail_response_.total_number();
    }

    boost::optional<const shared_model::interface::AccountDetailRecordId &>
    AccountDetailResponse::nextRecordId() const {
      if (next_record_id_) {
        return next_record_id_.value();
      }
      return boost::none;
    }

  }  // namespace proto
}  // namespace shared_model
