/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_remove_signatory.hpp"

#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {

    RemoveSignatory::RemoveSignatory(iroha::protocol::Command &command)
        : remove_signatory_{command.remove_signatory()} {}

    const interface::types::AccountIdType &RemoveSignatory::accountId() const {
      return remove_signatory_.account_id();
    }

    const std::string &RemoveSignatory::pubkey() const {
      return remove_signatory_.public_key();
    }

  }  // namespace proto
}  // namespace shared_model
