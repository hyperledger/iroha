/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_set_account_detail.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    SetAccountDetail::SetAccountDetail(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          set_account_detail_{proto_->set_account_detail()} {}

    template SetAccountDetail::SetAccountDetail(
        SetAccountDetail::TransportType &);
    template SetAccountDetail::SetAccountDetail(
        const SetAccountDetail::TransportType &);
    template SetAccountDetail::SetAccountDetail(
        SetAccountDetail::TransportType &&);

    SetAccountDetail::SetAccountDetail(const SetAccountDetail &o)
        : SetAccountDetail(o.proto_) {}

    SetAccountDetail::SetAccountDetail(SetAccountDetail &&o) noexcept
        : SetAccountDetail(std::move(o.proto_)) {}

    const interface::types::AccountIdType &SetAccountDetail::accountId() const {
      return set_account_detail_.account_id();
    }

    const interface::types::AccountDetailKeyType &SetAccountDetail::key()
        const {
      return set_account_detail_.key();
    }

    const interface::types::AccountDetailValueType &SetAccountDetail::value()
        const {
      return set_account_detail_.value();
    }

  }  // namespace proto
}  // namespace shared_model
