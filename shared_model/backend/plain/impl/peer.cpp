/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/peer.hpp"

using namespace shared_model;
using namespace shared_model::plain;

Peer::Peer(
    const interface::types::AddressType &address,
    std::string public_key_hex,
    const std::optional<interface::types::TLSCertificateType> &tls_certificate)
    : address_(address),
      public_key_hex_(std::move(public_key_hex)),
      tls_certificate_(tls_certificate) {}

const shared_model::interface::types::AddressType &Peer::address() const {
  return address_;
}

const std::string &Peer::pubkey() const {
  return public_key_hex_;
}

const std::optional<shared_model::interface::types::TLSCertificateType>
    &Peer::tlsCertificate() const {
  return tls_certificate_;
}
