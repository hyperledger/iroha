/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/peer_tls_certificates_provider_wsv.hpp"

#include <mutex>

#include "ametsuchi/peer_query.hpp"
#include "interfaces/common_objects/peer.hpp"

using namespace iroha::expected;
using namespace iroha::network;
using namespace shared_model::interface::types;

class PeerTlsCertificatesProviderWsv::Impl {
 public:
  Impl(std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query)
      : peer_query_(std::move(peer_query)) {}

  boost::optional<std::shared_ptr<shared_model::interface::Peer>>
  getPeerFromWsv(
      shared_model::interface::types::PublicKeyHexStringView public_key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return peer_query_->getLedgerPeerByPublicKey(public_key);
  }

 private:
  mutable std::mutex mutex_;
  std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query_;
};

PeerTlsCertificatesProviderWsv::PeerTlsCertificatesProviderWsv(
    std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query)
    : impl_(std::make_unique<Impl>(std::move(peer_query))) {}

PeerTlsCertificatesProviderWsv::~PeerTlsCertificatesProviderWsv() = default;

Result<TLSCertificateType, std::string> PeerTlsCertificatesProviderWsv::get(
    const shared_model::interface::Peer &peer) const {
  if (not peer.tlsCertificate()) {
    return makeError(peer.toString() + " does not have a certificate.");
  }
  return makeValue(peer.tlsCertificate().value());
}

Result<TLSCertificateType, std::string> PeerTlsCertificatesProviderWsv::get(
    shared_model::interface::types::PublicKeyHexStringView public_key) const {
  auto opt_peer = impl_->getPeerFromWsv(public_key);
  if (not opt_peer) {
    return makeError(std::string{"Could not find peer by "}
                     + iroha::to_string::toString(public_key));
  }
  return get(*opt_peer.value());
}
