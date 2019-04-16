/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_add_signatory.hpp"
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    AddSignatory::AddSignatory(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          add_signatory_{proto_->add_signatory()},
          pubkey_{crypto::Hash::fromHexString(add_signatory_.public_key())} {}

    template AddSignatory::AddSignatory(AddSignatory::TransportType &);
    template AddSignatory::AddSignatory(const AddSignatory::TransportType &);
    template AddSignatory::AddSignatory(AddSignatory::TransportType &&);

    AddSignatory::AddSignatory(const AddSignatory &o)
        : AddSignatory(o.proto_) {}

    AddSignatory::AddSignatory(AddSignatory &&o) noexcept
        : AddSignatory(std::move(o.proto_)) {}

    const interface::types::AccountIdType &AddSignatory::accountId() const {
      return add_signatory_.account_id();
    }

    const interface::types::PubkeyType &AddSignatory::pubkey() const {
      return pubkey_;
    }

  }  // namespace proto
}  // namespace shared_model
