/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/remove_peer.hpp"

namespace shared_model {
  namespace interface {

    std::string RemovePeer::toString() const {
      return detail::PrettyStringBuilder()
          .init("RemovePeer")
          .append(pubkey())
          .finalize();
    }

    bool RemovePeer::operator==(const ModelType &rhs) const {
      return pubkey() == rhs.pubkey();
    }

  }  // namespace interface
}  // namespace shared_model
