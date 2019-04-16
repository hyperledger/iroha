/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/add_peer.hpp"

#include "cryptography/public_key.hpp"

namespace shared_model {
  namespace interface {

    std::string AddPeer::toString() const {
      return detail::PrettyStringBuilder()
          .init("AddPeer")
          .append("peer_address", peer().address())
          .append("pubkey", peer().pubkey().toString())
          .finalize();
    }

    bool AddPeer::operator==(const ModelType &rhs) const {
      return peer() == rhs.peer();
    }

  }  // namespace interface
}  // namespace shared_model
