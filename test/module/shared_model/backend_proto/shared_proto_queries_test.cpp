/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_query.hpp"
#include "builders/protobuf/queries.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

#include <gtest/gtest.h>

#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/irange.hpp>
#include "framework/common_constants.hpp"

/**
 * For each protobuf query type
 * @given protobuf query object
 * @when create shared model query object
 * @then corresponding shared model object is created
 */

TEST(ProtoQuery, QueryLoad) {
  iroha::protocol::Query query;
  auto payload = query.mutable_payload();
  auto refl = payload->GetReflection();
  auto desc = payload->GetDescriptor()->FindOneofByName("query");
  boost::for_each(boost::irange(0, desc->field_count()), [&](auto i) {
    auto field = desc->field(i);
    refl->SetAllocatedMessage(
        payload, refl->GetMessage(*payload, field).New(), field);
    ASSERT_EQ(i, shared_model::proto::Query(query).get().which());
  });
}

/**
 * @given query field values and sample command values, reference query
 * @when create query with sample command using query builder
 * @then query is built correctly
 */
TEST(ProtoQueryBuilder, Builder) {
  uint64_t created_time = iroha::time::now(), query_counter = 1;
  std::string account_id = "admin@test", asset_id = "coin#test";

  iroha::protocol::Query proto_query;
  auto &payload = *proto_query.mutable_payload();
  auto *meta = payload.mutable_meta();
  meta->set_created_time(created_time);
  meta->set_creator_account_id(account_id);
  meta->set_query_counter(query_counter);
  {
    auto &query = *payload.mutable_get_account_assets();
    query.set_account_id(account_id);
    auto pagination_meta = query.mutable_pagination_meta();
    pagination_meta->set_page_size(kMaxPageSize);
    pagination_meta->set_first_asset_id(asset_id);
  }

  auto keypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  auto signedProto = shared_model::crypto::CryptoSigner::sign(
      shared_model::crypto::Blob(proto_query.payload().SerializeAsString()),
      keypair);

  auto sig = proto_query.mutable_signature();
  sig->set_public_key(keypair.publicKey());
  sig->set_signature(signedProto);

  auto query = shared_model::proto::QueryBuilder()
                   .createdTime(created_time)
                   .creatorAccountId(account_id)
                   .getAccountAssets(account_id, kMaxPageSize, asset_id)
                   .queryCounter(query_counter)
                   .build();

  auto proto = query.signAndAddSignature(keypair).finish().getTransport();
  ASSERT_EQ(proto_query.SerializeAsString(), proto.SerializeAsString());
}

/**
 * @given query field values and sample command values, reference query
 * @when create query with sample command using query builder
 * @then query is built correctly
 */
TEST(ProtoQueryBuilder, BlocksQueryBuilder) {
  uint64_t created_time = iroha::time::now(), query_counter = 1;
  std::string account_id = "admin@test", asset_id = "coin#test";

  iroha::protocol::BlocksQuery proto_query;
  auto *meta = proto_query.mutable_meta();
  meta->set_created_time(created_time);
  meta->set_creator_account_id(account_id);
  meta->set_query_counter(query_counter);

  auto keypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  auto signedProto = shared_model::crypto::CryptoSigner::sign(
      shared_model::crypto::Blob(proto_query.meta().SerializeAsString()),
      keypair);

  auto sig = proto_query.mutable_signature();
  sig->set_public_key(keypair.publicKey());
  sig->set_signature(signedProto);

  auto query = shared_model::proto::BlocksQueryBuilder()
                   .createdTime(created_time)
                   .creatorAccountId(account_id)
                   .queryCounter(query_counter)
                   .build();

  auto proto = query.signAndAddSignature(keypair).finish().getTransport();
  ASSERT_EQ(proto_query.SerializeAsString(), proto.SerializeAsString());
}
