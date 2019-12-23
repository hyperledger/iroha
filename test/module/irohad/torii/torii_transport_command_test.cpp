/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/impl/command_service_transport_grpc.hpp"

#include <algorithm>
#include <iterator>
#include <string>
#include <utility>

#include <grpcpp/impl/grpc_library.h>
#include "backend/protobuf/proto_transport_factory.hpp"
#include "backend/protobuf/proto_tx_status_factory.hpp"
#include "backend/protobuf/transaction.hpp"
#include "cryptography/public_key.hpp"
#include "endpoint.pb.h"
#include "endpoint_mock.grpc.pb.h"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "module/irohad/network/network_mocks.hpp"
#include "module/irohad/torii/torii_mocks.hpp"
#include "module/shared_model/interface/mock_transaction_batch_factory.hpp"
#include "module/shared_model/validators/validators.hpp"
#include "module/vendor/grpc_mocks.hpp"
#include "torii/impl/status_bus_impl.hpp"
#include "validators/protobuf/proto_transaction_validator.hpp"

using ::testing::_;
using ::testing::A;
using ::testing::AtLeast;
using ::testing::Invoke;
using ::testing::Property;
using ::testing::Return;
using ::testing::StrEq;

using namespace iroha::torii;
using namespace std::chrono_literals;

// required for g_core_codegen_interface intialization
static grpc::internal::GrpcLibraryInitializer g_gli_initializer;

class CommandServiceTransportGrpcTest : public testing::Test {
 private:
  using ProtoTxTransportFactory = shared_model::proto::ProtoTransportFactory<
      shared_model::interface::Transaction,
      shared_model::proto::Transaction>;
  using TxTransportFactory = shared_model::interface::AbstractTransportFactory<
      shared_model::interface::Transaction,
      shared_model::proto::Transaction::TransportType>;
  using MockTxValidator = shared_model::validation::MockValidator<
      shared_model::interface::Transaction>;
  using MockProtoTxValidator =
      shared_model::validation::MockValidator<iroha::protocol::Transaction>;

 public:
  /**
   * Initialize factory dependencies
   */
  void init() {
    status_factory =
        std::make_shared<shared_model::proto::ProtoTxStatusFactory>();

    auto validator = std::make_unique<MockTxValidator>();
    tx_validator = validator.get();
    auto proto_validator = std::make_unique<MockProtoTxValidator>();
    proto_tx_validator = proto_validator.get();
    transaction_factory = std::make_shared<ProtoTxTransportFactory>(
        std::move(validator), std::move(proto_validator));

    batch_parser =
        std::make_shared<shared_model::interface::TransactionBatchParserImpl>();
    batch_factory = std::make_shared<MockTransactionBatchFactory>();
  }

  void SetUp() override {
    init();

    status_bus = std::make_shared<MockStatusBus>();
    command_service = std::make_shared<MockCommandService>();

    transport_grpc = std::make_shared<CommandServiceTransportGrpc>(
        command_service,
        status_bus,
        status_factory,
        transaction_factory,
        batch_parser,
        batch_factory,
        rxcpp::observable<>::iterate(gate_objects),
        gate_objects.size(),
        getTestLogger("CommandServiceTransportGrpc"));
  }

  std::shared_ptr<MockStatusBus> status_bus;
  const MockTxValidator *tx_validator;
  const MockProtoTxValidator *proto_tx_validator;

  std::shared_ptr<TxTransportFactory> transaction_factory;
  std::shared_ptr<shared_model::interface::TransactionBatchParser> batch_parser;
  std::shared_ptr<MockTransactionBatchFactory> batch_factory;

  std::shared_ptr<shared_model::interface::TxStatusFactory> status_factory;

  std::shared_ptr<MockCommandService> command_service;
  std::shared_ptr<CommandServiceTransportGrpc> transport_grpc;

  rxcpp::subjects::subject<
      iroha::torii::CommandServiceTransportGrpc::ConsensusGateEvent>
      consensus_gate_objects;
  std::vector<iroha::torii::CommandServiceTransportGrpc::ConsensusGateEvent>
      gate_objects{2};

  const size_t kHashLength = 32;
  const size_t kTimes = 5;
};

/**
 * @given torii service
 * @when transaction status for given hash is requested
 * @then protobuf message with corresponding hash and status is returned
 */
TEST_F(CommandServiceTransportGrpcTest, Status) {
  grpc::ServerContext context;

  iroha::protocol::TxStatusRequest tx_request;
  const shared_model::crypto::Hash hash(std::string(kHashLength, '1'));
  tx_request.set_tx_hash(hash.hex());

  iroha::protocol::ToriiResponse toriiResponse;
  std::shared_ptr<shared_model::interface::TransactionResponse> response =
      status_factory->makeEnoughSignaturesCollected(hash, {});

  EXPECT_CALL(*command_service, getStatus(hash)).WillOnce(Return(response));

  transport_grpc->Status(&context, &tx_request, &toriiResponse);

  ASSERT_EQ(toriiResponse.tx_status(),
            iroha::protocol::TxStatus::ENOUGH_SIGNATURES_COLLECTED);
}

/**
 * @given torii service and number of transactions
 * @when calling ListTorii
 * @then ensure that CommandService called handleTransactionBatch as the tx num
 */
TEST_F(CommandServiceTransportGrpcTest, ListTorii) {
  grpc::ServerContext context;
  google::protobuf::Empty response;

  iroha::protocol::TxList request;
  for (size_t i = 0; i < kTimes; ++i) {
    request.add_transactions();
  }

  EXPECT_CALL(*proto_tx_validator, validate(_))
      .Times(kTimes)
      .WillRepeatedly(Return(boost::none));
  EXPECT_CALL(*tx_validator, validate(_))
      .Times(kTimes)
      .WillRepeatedly(Return(boost::none));
  EXPECT_CALL(
      *batch_factory,
      createTransactionBatch(
          A<const shared_model::interface::types::SharedTxsCollectionType &>()))
      .Times(kTimes);

  EXPECT_CALL(*command_service, handleTransactionBatch(_)).Times(kTimes);
  transport_grpc->ListTorii(&context, &request, &response);
}

/**
 * @given torii service and number of invalid transactions
 * @when calling ListTorii
 * @then ensure that CommandService haven't called handleTransactionBatch
 *       and StatusBus update status tx num times
 */
TEST_F(CommandServiceTransportGrpcTest, ListToriiInvalid) {
  grpc::ServerContext context;
  google::protobuf::Empty response;

  iroha::protocol::TxList request;
  for (size_t i = 0; i < kTimes; ++i) {
    request.add_transactions();
  }

  shared_model::validation::ValidationError error{"some error", {}};
  EXPECT_CALL(*proto_tx_validator, validate(_))
      .Times(AtLeast(1))
      .WillRepeatedly(Return(boost::none));
  EXPECT_CALL(*tx_validator, validate(_))
      .Times(AtLeast(1))
      .WillRepeatedly(Return(error));
  EXPECT_CALL(*command_service, handleTransactionBatch(_)).Times(0);
  EXPECT_CALL(*status_bus, publish(_)).Times(kTimes);

  transport_grpc->ListTorii(&context, &request, &response);
}

/**
 * @given torii service
 *        and some number of valid transactions
 *        and one stateless invalid tx
 * @when calling ListTorii
 * @then handleTransactionBatch is not called
 *       and statelessInvalid status is published for all transactions
 */
TEST_F(CommandServiceTransportGrpcTest, ListToriiPartialInvalid) {
  grpc::ServerContext context;
  google::protobuf::Empty response;
  const std::string kError = "some error";

  iroha::protocol::TxList request{};
  for (size_t i = 0; i < kTimes; ++i) {
    request.add_transactions();
  }

  size_t counter = 0;
  EXPECT_CALL(*proto_tx_validator, validate(_))
      .Times(kTimes)
      .WillRepeatedly(Return(boost::none));
  EXPECT_CALL(*tx_validator, validate(_))
      .Times(kTimes)
      .WillRepeatedly(
          Invoke([this, &counter, kError](const auto &) mutable
                 -> boost::optional<shared_model::validation::ValidationError> {
            if (counter++ == kTimes - 1) {
              return shared_model::validation::ValidationError{kError, {}};
            }
            return boost::none;
          }));
  EXPECT_CALL(
      *batch_factory,
      createTransactionBatch(
          A<const shared_model::interface::types::SharedTxsCollectionType &>()))
      .Times(0);

  EXPECT_CALL(*command_service, handleTransactionBatch(_)).Times(0);
  EXPECT_CALL(*status_bus, publish(_))
      .Times(kTimes)
      .WillRepeatedly(Invoke([&kError](auto status) {
        EXPECT_THAT(status->statelessErrorOrCommandName(),
                    testing::HasSubstr(kError));
      }));

  transport_grpc->ListTorii(&context, &request, &response);
}

/**
 * @given torii service and command_service with empty status stream
 * @when calling StatusStream on transport
 * @then Ok status is eventually returned without any fault
 *       and nothing is written to the status stream
 */
TEST_F(CommandServiceTransportGrpcTest, StatusStreamEmpty) {
  grpc::ServerContext context;
  iroha::protocol::TxStatusRequest request;

  EXPECT_CALL(*command_service, getStatusStream(_))
      .WillOnce(Return(rxcpp::observable<>::empty<std::shared_ptr<
                           shared_model::interface::TransactionResponse>>()));

  ASSERT_TRUE(transport_grpc->StatusStream(&context, &request, nullptr).ok());
}

/**
 * @given torii service with changed timeout, a transaction
 *        and a status stream with one NotRecieved status
 * @when calling StatusStream
 * @then ServerWriter calls Write method
 */
TEST_F(CommandServiceTransportGrpcTest, StatusStreamOnNotReceived) {
  grpc::ServerContext context;
  iroha::protocol::TxStatusRequest request;
  iroha::MockServerWriter<iroha::protocol::ToriiResponse> response_writer;

  std::vector<std::shared_ptr<shared_model::interface::TransactionResponse>>
      responses;
  shared_model::crypto::Hash hash("1");
  responses.emplace_back(status_factory->makeNotReceived(hash, {}));
  EXPECT_CALL(*command_service, getStatusStream(_))
      .WillOnce(Return(rxcpp::observable<>::iterate(responses)));
  EXPECT_CALL(response_writer,
              Write(Property(&iroha::protocol::ToriiResponse::tx_hash,
                             StrEq(hash.hex())),
                    _))
      .WillOnce(Return(true));

  ASSERT_TRUE(transport_grpc
                  ->StatusStream(
                      &context,
                      &request,
                      reinterpret_cast<
                          grpc::ServerWriter<iroha::protocol::ToriiResponse> *>(
                          &response_writer))
                  .ok());
}
