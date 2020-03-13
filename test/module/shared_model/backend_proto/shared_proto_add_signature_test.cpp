/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "backend/protobuf/block.hpp"
#include "backend/protobuf/queries/proto_blocks_query.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "backend/protobuf/transaction.hpp"
#include "block.pb.h"
#include "framework/crypto_dummies.hpp"
#include "framework/result_gtest_checkers.hpp"

using namespace shared_model::crypto;
using namespace shared_model::proto;

template <typename T>
class SharedProtoAddSignatureTest : public ::testing::Test {};

using ModelTypes = ::testing::Types<Block, BlocksQuery, Transaction, Query>;
TYPED_TEST_SUITE(SharedProtoAddSignatureTest, ModelTypes, );

/// empty initializer
template <typename T>
auto initializeProto(T &proto) {}

/// initializes query with the first specific type
template <>
auto initializeProto(Query::TransportType &proto) {
  auto payload = proto.mutable_payload();
  payload->set_allocated_meta(new iroha::protocol::QueryPayloadMeta());
  auto refl = payload->GetReflection();
  auto desc = payload->GetDescriptor()->FindOneofByName("query");
  auto field = desc->field(0);
  refl->SetAllocatedMessage(
      payload, refl->GetMessage(*payload, field).New(), field);
}

/**
 * @given signable object with its shared model wrapper
 * @when a signature is added
 * @then it is reflected in wrapper blob getter result
 */
TYPED_TEST(SharedProtoAddSignatureTest, AddSignature) {
  typename TypeParam::TransportType proto;
  initializeProto(proto);
  auto model_result = TypeParam::create(proto);
  IROHA_ASSERT_RESULT_VALUE(model_result);
  auto model = std::move(model_result).assumeValue();

  Signed signature = iroha::createSigned();
  PublicKey public_key = iroha::createPublicKey();

  model->addSignature(signature, public_key);

  typename TypeParam::TransportType new_proto;
  new_proto.ParseFromArray(model->blob().data(), model->blob().size());
  auto new_model_result = TypeParam::create(new_proto);
  IROHA_ASSERT_RESULT_VALUE(new_model_result);
  auto new_model = std::move(new_model_result).assumeValue();

  auto signatures = new_model->signatures();
  ASSERT_EQ(1, boost::size(signatures));
  ASSERT_EQ(signature, signatures.front().signedData());
  ASSERT_EQ(public_key, signatures.front().publicKey());
}
