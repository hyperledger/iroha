/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_remove_signatory.hpp"
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    RemoveSignatory::RemoveSignatory(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          remove_signatory_{proto_->remove_signatory()},
          pubkey_{crypto::Hash::fromHexString(remove_signatory_.public_key())} {}

    template RemoveSignatory::RemoveSignatory(RemoveSignatory::TransportType &);
    template RemoveSignatory::RemoveSignatory(
        const RemoveSignatory::TransportType &);
    template RemoveSignatory::RemoveSignatory(
        RemoveSignatory::TransportType &&);

    RemoveSignatory::RemoveSignatory(const RemoveSignatory &o)
        : RemoveSignatory(o.proto_) {}

    RemoveSignatory::RemoveSignatory(RemoveSignatory &&o) noexcept
        : RemoveSignatory(std::move(o.proto_)) {}

    const interface::types::AccountIdType &RemoveSignatory::accountId() const {
      return remove_signatory_.account_id();
    }

    const interface::types::PubkeyType &RemoveSignatory::pubkey() const {
      return pubkey_;
    }

  }  // namespace proto
}  // namespace shared_model
