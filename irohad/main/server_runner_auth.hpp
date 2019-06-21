/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MAIN_SERVER_RUNNER_AUTH_HPP
#define MAIN_SERVER_RUNNER_AUTH_HPP

#include <memory>

#include "grpc++/security/auth_metadata_processor.h"

#include "ametsuchi/peer_query.hpp"

class PeerCertificateAuthMetadataProcessor
    : public grpc::AuthMetadataProcessor {
 public:
  explicit PeerCertificateAuthMetadataProcessor(
      std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query);

  grpc::Status Process(const InputMetadata &auth_metadata,
                       grpc::AuthContext *context,
                       OutputMetadata *consumed_auth_metadata,
                       OutputMetadata *response_metadata) final;

 private:
  std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query_;
};

#endif  // MAIN_SERVER_RUNNER_AUTH_HPP
