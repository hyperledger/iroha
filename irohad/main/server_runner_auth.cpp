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
#include "network/impl/peer_tls_certificates_provider.hpp"

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

  std::vector<PubkeyType> getRequestCertificateIdentities(
      grpc::AuthContext const *context) {
    return boost::copy_range<std::vector<PubkeyType>>(
        context->FindPropertyValues("x509_subject_alternative_name")
        | boost::adaptors::filtered([](const grpc::string_ref &name) {
            return name.starts_with("");  // RFC 5280, RFC 8410 { 1 3 101 112 }
          })
        | boost::adaptors::transformed([](const grpc::string_ref &name) {
            return PubkeyType{name.data()};
          }));
  }

  bool compareCerts(const std::string &a, const grpc::string_ref &b) {
    static const auto is_compared = !boost::algorithm::is_any_of(" \n");
    // using FilteredIterator = boost::filter_iterator<is_compared, const char
    // *>;
    static const auto first = [](const auto &s) { return s.data(); };
    static const auto last = [](const auto &s) { return s.data() + s.size(); };
    return std::equal(
        boost::make_filter_iterator(is_compared, first(a), last(a)),
        boost::make_filter_iterator(is_compared, last(a), last(a)),
        boost::make_filter_iterator(is_compared, first(b), last(b)),
        boost::make_filter_iterator(is_compared, last(b), last(b)));
  }

}  // namespace

PeerCertificateAuthMetadataProcessor::PeerCertificateAuthMetadataProcessor(
    std::shared_ptr<const iroha::network::PeerTlsCertificatesProvider>
        peer_tls_certificates_provider)
    : peer_tls_certificates_provider_(
          std::move(peer_tls_certificates_provider)) {}

grpc::Status PeerCertificateAuthMetadataProcessor::Process(
    const grpc_impl::AuthMetadataProcessor::InputMetadata &auth_metadata,
    grpc::AuthContext *context,
    grpc_impl::AuthMetadataProcessor::OutputMetadata *consumed_auth_metadata,
    grpc_impl::AuthMetadataProcessor::OutputMetadata *response_metadata) {
  auto get_opt_cert = [this](const PubkeyType &pk) {
    auto cert_result = this->peer_tls_certificates_provider_->get(pk);
    if (auto e = iroha::expected::resultToOptionalError(cert_result)) {
      /*
      this->log_->error(
          "Could not get certificate for peer with public key '{}'", pk.hex());
      */
    }
    return iroha::expected::resultToOptionalValue(cert_result);
  };

  /*
  for (const auto &name in context->FindPropertyValues(
           "x509_subject_alternative_name")) {
    std::cout << "CERT ALT NAME: " << name.data() << std::endl;
  }
  */

  auto opt_request_cert = getRequestCertificate(context);
  if (not opt_request_cert) {
    return grpc::Status::CANCELLED;
  }
  auto &request_cert = opt_request_cert.value();

  if (boost::algorithm::any_of(
          iroha::dereferenceOptionals(
              getRequestCertificateIdentities(context)
              | boost::adaptors::transformed(get_opt_cert)),
          [&request_cert](const auto &wsv_cert) {
            return compareCerts(wsv_cert, request_cert);
          })) {
    return grpc::Status::OK;
  }

  return grpc::Status::CANCELLED;
}
