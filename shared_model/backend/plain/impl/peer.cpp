/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/peer.hpp"

using namespace shared_model;
using namespace shared_model::plain;

Peer::Peer(const interface::types::AddressType &address,
           const interface::types::PubkeyType &public_key)
    : address_(address), public_key_(public_key) {}

const shared_model::interface::types::AddressType &Peer::address() const {
  return address_;
}

const shared_model::interface::types::PubkeyType &Peer::pubkey() const {
  return public_key_;
}
