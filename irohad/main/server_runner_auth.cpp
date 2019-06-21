/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "server_runner_auth.hpp"

#include <boost/algorithm/string/replace.hpp>

#include "shared_model/interfaces/common_objects/peer.hpp"

/**
 * Removes all space-symbols from PEM-encoded certificate
 * Probably should be enough to verify equality
 * @param certificate PEM-encoded certificate
 */
void normalizeCertificate(std::string &certificate) {
  boost::replace_all(certificate, " ", "");
  boost::replace_all(certificate, "\n", "");
}

PeerCertificateAuthMetadataProcessor::PeerCertificateAuthMetadataProcessor(
    std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query)
    : peer_query_(peer_query) {}

grpc::Status PeerCertificateAuthMetadataProcessor::Process(
    const grpc_impl::AuthMetadataProcessor::InputMetadata &auth_metadata,
    grpc::AuthContext *context,
    grpc_impl::AuthMetadataProcessor::OutputMetadata *consumed_auth_metadata,
    grpc_impl::AuthMetadataProcessor::OutputMetadata *response_metadata) {
  auto pem_cert_values = context->FindPropertyValues("x509_pem_cert");
  if (pem_cert_values.size() != 1) {
    return grpc::Status::CANCELLED;
  }
  std::string pem_cert{pem_cert_values[0].data()};
  normalizeCertificate(pem_cert);
  auto peers = peer_query_->getLedgerPeers();
  if (not peers) {
    return grpc::Status::CANCELLED;
  }
  for (const auto &peer : *peers) {
    auto certificate = peer->tlsCertificate();
    normalizeCertificate(certificate);
    if (certificate == pem_cert) {
      return grpc::Status::OK;
    }
  }

  return grpc::Status::CANCELLED;
}