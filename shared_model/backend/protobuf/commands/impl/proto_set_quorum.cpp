/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_set_quorum.hpp"

namespace shared_model {
  namespace proto {

    SetQuorum::SetQuorum(iroha::protocol::Command &command)
        : set_account_quorum_{command.set_account_quorum()} {}

    const interface::types::AccountIdType &SetQuorum::accountId() const {
      return set_account_quorum_.account_id();
    }

    interface::types::QuorumType SetQuorum::newQuorum() const {
      return set_account_quorum_.quorum();
    }

  }  // namespace proto
}  // namespace shared_model
