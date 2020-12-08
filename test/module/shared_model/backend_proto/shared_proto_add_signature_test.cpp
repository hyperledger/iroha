/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "backend/protobuf/block.hpp"
#include "backend/protobuf/queries/proto_blocks_query.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "backend/protobuf/transaction.hpp"

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
  using namespace std::literals;
  typename TypeParam::TransportType proto;
  initializeProto(proto);
  TypeParam model{proto};

  shared_model::interface::types::SignedHexStringView signature{"0A"sv};
  shared_model::interface::types::PublicKeyHexStringView public_key{"0B"sv};

  model.addSignature(signature, public_key);

  typename TypeParam::TransportType new_proto;
  new_proto.ParseFromString(toBinaryString(model.blob()));
  TypeParam new_model{new_proto};

  auto signatures = new_model.signatures();
  ASSERT_EQ(1, boost::size(signatures));
  ASSERT_EQ(signature,
            shared_model::interface::types::SignedHexStringView{
                signatures.front().signedData()});
  ASSERT_EQ(public_key,
            shared_model::interface::types::PublicKeyHexStringView{
                signatures.front().publicKey()});
}
