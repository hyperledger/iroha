/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/peer_tls_certificates_provider_root.hpp"

using namespace iroha::network;
using namespace iroha::expected;

PeerTlsCertificatesProviderRoot::PeerTlsCertificatesProviderRoot(
    std::string root_certificate)
    : root_certificate_(std::move(root_certificate)) {}

Result<std::string, std::string> PeerTlsCertificatesProviderRoot::get(
    const std::string & /* address */) const {
  return makeValue(root_certificate_);
}
