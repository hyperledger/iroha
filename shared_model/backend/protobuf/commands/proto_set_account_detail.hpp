/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_SET_ACCOUNT_DETAIL_HPP
#define IROHA_PROTO_SET_ACCOUNT_DETAIL_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "interfaces/commands/set_account_detail.hpp"

namespace shared_model {
  namespace proto {
    class SetAccountDetail final
        : public CopyableProto<interface::SetAccountDetail,
                               iroha::protocol::Command,
                               SetAccountDetail> {
     public:
      template <typename CommandType>
      explicit SetAccountDetail(CommandType &&command);

      SetAccountDetail(const SetAccountDetail &o);

      SetAccountDetail(SetAccountDetail &&o) noexcept;

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::AccountDetailKeyType &key() const override;

      const interface::types::AccountDetailValueType &value() const override;

     private:
      const iroha::protocol::SetAccountDetail &set_account_detail_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_SET_ACCOUNT_DETAIL_HPP
