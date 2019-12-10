/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"

#include <thread>

#include <gtest/gtest.h>
#include <boost/mpl/copy.hpp>
#include <boost/mpl/find.hpp>
#include <boost/mpl/vector.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/irange.hpp>
#include <boost/variant.hpp>
#include "common/result.hpp"
#include "cryptography/bytes_view.hpp"
#include "cryptography/hash.hpp"
#include "endpoint.pb.h"
#include "framework/result_gtest_checkers.hpp"

namespace {

  using PbCommand = iroha::protocol::Command;
  using IfaceResponseVariantTypes = boost::mpl::copy<
      shared_model::interface::TransactionResponse::ResponseVariantType::types,
      boost::mpl::back_inserter<boost::mpl::vector<>>>::type;
  using iroha::protocol::TxStatus;
  using PbCommandCaseUnderlyingType =
      std::underlying_type_t<PbCommand::CommandCase>;

#define RESPONSE_VARIANT(PROTOBUF_VARIANT, IFACE_VARIANT)                     \
  {                                                                           \
    TxStatus::PROTOBUF_VARIANT,                                               \
        boost::mpl::find<                                                     \
            IfaceResponseVariantTypes,                                        \
            const shared_model::interface::IFACE_VARIANT &>::type::pos::value \
  }

  const std::map<PbCommandCaseUnderlyingType, int>
      kProtoResponseTypeToCommandType{
          RESPONSE_VARIANT(STATELESS_VALIDATION_FAILED,
                           StatelessFailedTxResponse),
          RESPONSE_VARIANT(STATELESS_VALIDATION_SUCCESS,
                           StatelessValidTxResponse),
          RESPONSE_VARIANT(STATEFUL_VALIDATION_FAILED,
                           StatefulFailedTxResponse),
          RESPONSE_VARIANT(STATEFUL_VALIDATION_SUCCESS,
                           StatefulValidTxResponse),
          RESPONSE_VARIANT(REJECTED, RejectedTxResponse),
          RESPONSE_VARIANT(COMMITTED, CommittedTxResponse),
          RESPONSE_VARIANT(MST_EXPIRED, MstExpiredResponse),
          RESPONSE_VARIANT(NOT_RECEIVED, NotReceivedTxResponse),
          RESPONSE_VARIANT(MST_PENDING, MstPendingResponse),
          RESPONSE_VARIANT(ENOUGH_SIGNATURES_COLLECTED,
                           EnoughSignaturesCollectedResponse)};

#undef COMMAND_VARIANT

}  // namespace

/**
 * @given protobuf's ToriiResponse with different tx_statuses and some hash
 * @when converting to shared model
 * @then ensure that status and hash remain the same
 */
TEST(ProtoTxResponse, TxResponseLoad) {
  iroha::protocol::ToriiResponse response;
  const std::string hash = "1234";
  response.set_tx_hash(hash);
  auto desc = response.GetDescriptor();
  auto tx_status = desc->FindFieldByName("tx_status");
  ASSERT_NE(nullptr, tx_status);
  auto tx_status_enum = tx_status->enum_type();
  ASSERT_NE(nullptr, tx_status_enum);

  boost::for_each(boost::irange(0, tx_status_enum->value_count()), [&](auto i) {
    const auto status_case = tx_status_enum->value(i)->number();
    response.GetReflection()->SetEnumValue(&response, tx_status, status_case);
    auto pb_status_name = tx_status_enum->value(i)->full_name();
    auto model_response_result =
        shared_model::proto::TransactionResponse::create(response);

    IROHA_ASSERT_RESULT_VALUE(model_response_result)
        << "Could not load with " << pb_status_name;
    auto model_response = std::move(model_response_result).assumeValue();

    EXPECT_EQ(model_response->transactionHash().blob().hex(), hash);
    ASSERT_GT(kProtoResponseTypeToCommandType.count(status_case), 0)
        << "Please add the missing transaction status to the test map: "
        << pb_status_name;
    EXPECT_EQ(kProtoResponseTypeToCommandType.at(status_case),
              model_response->get().which());
  });
}

/**
 * @given TransactionResponse that previously had lazy fields
 * @when those lazy fields are simultaneously accessed
 * @then there is no race condition and segfaults
 */
TEST(TxResponse, SafeToReadFromMultipleThreads) {
  const auto repetitions = 1000;
  // it usually throws a SIGSEGV during the first twenty iterations
  for (int counter = 0; counter < repetitions; ++counter) {
    iroha::protocol::ToriiResponse response;
    const std::string hash = "1234";
    response.set_tx_hash(hash);
    response.set_tx_status(iroha::protocol::TxStatus::COMMITTED);
    auto model_response_result =
        shared_model::proto::TransactionResponse::create(response);
    IROHA_ASSERT_RESULT_VALUE(model_response_result);
    auto model_response = std::move(model_response_result).assumeValue();

    auto multiple_access = [&model_response] {
      // old good way to cause race condition on lazy fields
      ASSERT_TRUE(model_response == model_response);
    };

    std::vector<std::thread> threads;
    const auto num_threads = 20;
    for (int i = 0; i < num_threads; ++i) {
      threads.emplace_back(multiple_access);
    }

    for (auto &thread : threads) {
      thread.join();
    }
  }
}
