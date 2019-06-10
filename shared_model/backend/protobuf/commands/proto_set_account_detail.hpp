/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_SET_ACCOUNT_DETAIL_HPP
#define IROHA_PROTO_SET_ACCOUNT_DETAIL_HPP

#include "interfaces/commands/set_account_detail.hpp"

#include "commands.pb.h"

namespace shared_model {
  namespace proto {
    class SetAccountDetail final : public interface::SetAccountDetail {
     public:
      explicit SetAccountDetail(iroha::protocol::Command &command);

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::AccountDetailKeyType &key() const override;

      const interface::types::AccountDetailValueType &value() const override;

     private:
      const iroha::protocol::SetAccountDetail &set_account_detail_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_SET_ACCOUNT_DETAIL_HPP
