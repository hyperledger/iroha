/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fuzzing/ordering_service_fixture.hpp"

#include "ametsuchi/impl/tx_presence_cache_impl.hpp"
#include "backend/protobuf/proto_proposal_factory.hpp"
#include "fuzzing/grpc_servercontext_dtor_segv_workaround.hpp"
#include "logger/dummy_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_mocks.hpp"

struct RequestProposalFixture : public fuzzing::OrderingServiceFixture {
  std::unique_ptr<shared_model::proto::ProtoProposalFactory<
      shared_model::validation::DefaultProposalValidator>>
      proposal_factory_;
  std::shared_ptr<iroha::ametsuchi::MockStorage> storage_;
  std::shared_ptr<iroha::ametsuchi::TxPresenceCacheImpl> persistent_cache_;
  std::shared_ptr<OnDemandOrderingServiceImpl> ordering_service_;
  std::shared_ptr<OnDemandOsServerGrpc> server_;

  RequestProposalFixture() : OrderingServiceFixture() {
    proposal_factory_ =
        std::make_unique<shared_model::proto::ProtoProposalFactory<
            shared_model::validation::DefaultProposalValidator>>(
            iroha::test::kTestsValidatorsConfig);

    storage_ = std::make_shared<iroha::ametsuchi::MockStorage>();
    persistent_cache_ =
        std::make_shared<iroha::ametsuchi::TxPresenceCacheImpl>(storage_);
  }

  void init_with(size_t transaction_limit) {
    ordering_service_ = std::make_shared<OnDemandOrderingServiceImpl>(
        transaction_limit,
        std::move(proposal_factory_),
        std::move(persistent_cache_),
        logger::getDummyLoggerPtr());
    server_ =
        std::make_shared<OnDemandOsServerGrpc>(ordering_service_,
                                               transaction_factory_,
                                               batch_parser_,
                                               transaction_batch_factory_,
                                               logger::getDummyLoggerPtr(),
                                               std::chrono::seconds(0));
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size) {
  static RequestProposalFixture fixture;

  if (size < 1) {
    return 0;
  }

  fixture.init_with(data[0]);

  proto::ProposalRequest request;
  if (protobuf_mutator::libfuzzer::LoadProtoInput(
          true, data + 1, size - 1, &request)) {
    grpc::ServerContext context;
    proto::ProposalResponse response;
    fixture.server_->RequestProposal(&context, &request, &response);
  }

  return 0;
}
