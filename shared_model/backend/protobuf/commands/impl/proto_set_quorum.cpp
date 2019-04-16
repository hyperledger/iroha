/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_set_quorum.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    SetQuorum::SetQuorum(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          set_account_quorum_{proto_->set_account_quorum()} {}

    template SetQuorum::SetQuorum(SetQuorum::TransportType &);
    template SetQuorum::SetQuorum(const SetQuorum::TransportType &);
    template SetQuorum::SetQuorum(SetQuorum::TransportType &&);

    SetQuorum::SetQuorum(const SetQuorum &o) : SetQuorum(o.proto_) {}

    SetQuorum::SetQuorum(SetQuorum &&o) noexcept
        : SetQuorum(std::move(o.proto_)) {}

    const interface::types::AccountIdType &SetQuorum::accountId() const {
      return set_account_quorum_.account_id();
    }

    interface::types::QuorumType SetQuorum::newQuorum() const {
      return set_account_quorum_.quorum();
    }

  }  // namespace proto
}  // namespace shared_model
