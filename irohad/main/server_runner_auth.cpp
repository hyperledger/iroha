/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "server_runner_auth.hpp"

#include <boost/algorithm/cxx11/any_of.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/optional.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "common/range_tools.hpp"
#include "common/result.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger.hpp"
#include "main/impl/x509_utils.hpp"
#include "network/peer_tls_certificates_provider.hpp"

using shared_model::interface::types::PubkeyType;

namespace {

  boost::optional<grpc::string_ref> getRequestCertificate(
      grpc::AuthContext const *context) {
    auto pem_cert_values = context->FindPropertyValues("x509_pem_cert");
    if (pem_cert_values.size() != 1) {
      return boost::none;
    }
    return pem_cert_values[0];
  }

  const auto first = [](const auto &s) { return s.data(); };
  const auto last = [](const auto &s) { return s.data() + s.size(); };

  iroha::expected::Result<std::vector<PubkeyType>, std::string>
  getRequestCertificateIdentities(grpc::AuthContext const *context) {
    auto cert_props = context->FindPropertyValues("x509_pem_cert");
    if (cert_props.begin() != cert_props.end()) {
      if (std::next(cert_props.begin()) != cert_props.end()) {
        return "Client provided more than one certificate.";
      }
      return iroha::getIrohaPubKeysFromX509(cert_props.begin()->data(),
                                            cert_props.begin()->size());
    }
    return std::vector<shared_model::crypto::PublicKey>{};
  }

  bool compareCerts(const std::string &a, const grpc::string_ref &b) {
    static const auto is_compared = !boost::algorithm::is_any_of(" \n");
    return std::equal(
        boost::make_filter_iterator(is_compared, first(a), last(a)),
        boost::make_filter_iterator(is_compared, last(a), last(a)),
        boost::make_filter_iterator(is_compared, first(b), last(b)),
        boost::make_filter_iterator(is_compared, last(b), last(b)));
  }

}  // namespace

PeerCertificateAuthMetadataProcessor::PeerCertificateAuthMetadataProcessor(
    std::shared_ptr<const iroha::network::PeerTlsCertificatesProvider>
        peer_tls_certificates_provider,
    logger::LoggerPtr log)
    : peer_tls_certificates_provider_(
          std::move(peer_tls_certificates_provider)),
      log_(std::move(log)) {}

grpc::Status PeerCertificateAuthMetadataProcessor::Process(
    const grpc_impl::AuthMetadataProcessor::InputMetadata &auth_metadata,
    grpc::AuthContext *context,
    grpc_impl::AuthMetadataProcessor::OutputMetadata *consumed_auth_metadata,
    grpc_impl::AuthMetadataProcessor::OutputMetadata *response_metadata) {
  auto get_opt_cert = [this](const PubkeyType &pk) {
    auto cert_result = this->peer_tls_certificates_provider_->get(pk);
    if (auto e = iroha::expected::resultToOptionalError(cert_result)) {
      this->log_->error(
          "Could not get certificate for peer with public key '{}'", pk.hex());
    }
    return iroha::expected::resultToOptionalValue(cert_result);
  };

  auto opt_request_cert = getRequestCertificate(context);
  if (not opt_request_cert) {
    return grpc::Status::CANCELLED;
  }
  auto &request_cert = opt_request_cert.value();

  auto certified_keys = getRequestCertificateIdentities(context);
  if (auto e = iroha::expected::resultToOptionalError(certified_keys)) {
    this->log_->warn("Could not get keys from peer certificate: ", e.value());
    return grpc::Status::CANCELLED;
  }

  if (boost::algorithm::any_of(
          iroha::dereferenceOptionals(
              iroha::expected::resultToOptionalValue(certified_keys).value()
              | boost::adaptors::transformed(get_opt_cert)),
          [&request_cert](const auto &wsv_cert) {
            return compareCerts(wsv_cert, request_cert);
          })) {
    return grpc::Status::OK;
  }

  return grpc::Status::CANCELLED;
}
