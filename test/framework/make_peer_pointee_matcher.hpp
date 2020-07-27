/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_FRAMEWORK_MAKE_PEER_POINTEE_MATCHER_HPP
#define IROHA_TEST_FRAMEWORK_MAKE_PEER_POINTEE_MATCHER_HPP

#include <gtest/gtest.h>
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/common_objects/types.hpp"

inline auto makePeerPointeeMatcher(
    shared_model::interface::types::AddressType address,
    shared_model::interface::types::PublicKeyHexStringView pubkey) {
  return ::testing::Truly(
      [address = std::move(address), pubkey = std::string{pubkey}](
          std::shared_ptr<shared_model::interface::Peer> peer) {
        return peer->address() == address and peer->pubkey() == pubkey;
      });
}

inline auto makePeerPointeeMatcher(
    std::shared_ptr<shared_model::interface::Peer> peer) {
  // TODO [IR-658] artyom-yurin 30.09.2019: Rewrite using operator ==
  return makePeerPointeeMatcher(
      peer->address(),
      shared_model::interface::types::PublicKeyHexStringView{peer->pubkey()});
}

#endif  // IROHA_TEST_FRAMEWORK_MAKE_PEER_POINTEE_MATCHER_HPP
