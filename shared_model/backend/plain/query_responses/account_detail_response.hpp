/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PLAIN_ACCOUNT_DETAIL_RESPONSE_HPP
#define IROHA_PLAIN_ACCOUNT_DETAIL_RESPONSE_HPP

#include "interfaces/query_responses/account_detail_response.hpp"

namespace shared_model {
  namespace plain {
    class AccountDetailResponse
        : public shared_model::interface::AccountDetailResponse {
     public:
      AccountDetailResponse(
          shared_model::interface::types::DetailType account_detail,
          size_t total_number,
          boost::optional<
              std::unique_ptr<shared_model::interface::AccountDetailRecordId>>
              next_record_id);

      const shared_model::interface::types::DetailType &detail() const override;

      size_t totalNumber() const override;

      boost::optional<const shared_model::interface::AccountDetailRecordId &>
      nextRecordId() const override;

     private:
      shared_model::interface::types::DetailType account_detail_;
      size_t total_number_;
      boost::optional<
          std::unique_ptr<shared_model::interface::AccountDetailRecordId>>
          next_record_id_;
    };
  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_PLAIN_ACCOUNT_DETAIL_RESPONSE_HPP
