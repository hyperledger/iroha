/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/peer_tls_certificates_provider_wsv.hpp"

#include "ametsuchi/peer_query.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/common_objects/peer.hpp"

using namespace iroha::expected;
using namespace iroha::network;
using namespace shared_model::interface::types;

PeerTlsCertificatesProviderWsv::PeerTlsCertificatesProviderWsv(
    std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query)
    : peer_query_(std::move(peer_query)) {}

Result<TLSCertificateType, std::string> PeerTlsCertificatesProviderWsv::get(
    const shared_model::interface::Peer &peer) const {
  return makeValue(peer.tlsCertificate());
}

Result<TLSCertificateType, std::string> PeerTlsCertificatesProviderWsv::get(
    const shared_model::interface::types::PubkeyType &public_key) const {
  auto opt_peer = peer_query_->getLedgerPeerByPublicKey(public_key);
  if (opt_peer) {
    return makeValue(opt_peer.value()->tlsCertificate());
  }
  return makeError(std::string{"Could not find peer by "}
                   + public_key.toString());
}
