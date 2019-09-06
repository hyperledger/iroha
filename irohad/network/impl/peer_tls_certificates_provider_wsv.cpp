/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/peer_tls_certificates_provider_wsv.hpp"

#include "ametsuchi/peer_query.hpp"
#include "interfaces/common_objects/peer.hpp"

using namespace iroha::expected;
using namespace iroha::network;

PeerTlsCertificatesProviderWsv::PeerTlsCertificatesProviderWsv(
    std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query)
    : peer_query_(std::move(peer_query)) {}

Result<std::string, std::string> PeerTlsCertificatesProviderWsv::get(
    const std::string &address) const {
  auto opt_peer = peer_query_->getLedgerPeerByAddress(address);
  if (opt_peer) {
    return makeValue(opt_peer.value()->tlsCertificate());
  }
  return makeError(std::string{"Peer with address '"} + address
                   + "' not found.");
}
