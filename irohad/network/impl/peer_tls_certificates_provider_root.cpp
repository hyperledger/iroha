/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/peer_tls_certificates_provider_root.hpp"

#include "common/result.hpp"

using namespace iroha::network;
using namespace iroha::expected;
using namespace shared_model::interface::types;

PeerTlsCertificatesProviderRoot::PeerTlsCertificatesProviderRoot(
    TLSCertificateType root_certificate)
    : root_certificate_(std::move(root_certificate)) {}

Result<TLSCertificateType, std::string> PeerTlsCertificatesProviderRoot::get(
    const shared_model::interface::Peer &) const {
  return makeValue(root_certificate_);
}

Result<TLSCertificateType, std::string> PeerTlsCertificatesProviderRoot::get(
    const PubkeyType &) const {
  return makeValue(root_certificate_);
}
