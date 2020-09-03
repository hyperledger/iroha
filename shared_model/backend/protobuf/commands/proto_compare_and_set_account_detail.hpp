/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_COMPARE_AND_SET_ACCOUNT_DETAIL_HPP
#define IROHA_PROTO_COMPARE_AND_SET_ACCOUNT_DETAIL_HPP

#include "interfaces/commands/compare_and_set_account_detail.hpp"

#include "commands.pb.h"

namespace shared_model {
  namespace proto {
    class CompareAndSetAccountDetail final
        : public interface::CompareAndSetAccountDetail {
     public:
      explicit CompareAndSetAccountDetail(iroha::protocol::Command &command);

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::AccountDetailKeyType &key() const override;

      const interface::types::AccountDetailValueType &value() const override;

      bool checkEmpty() const override;

      const std::optional<interface::types::AccountDetailValueType> oldValue()
          const override;

     private:
      const iroha::protocol::CompareAndSetAccountDetail
          &compare_and_set_account_detail_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_COMPARE_AND_SET_ACCOUNT_DETAIL_HPP
