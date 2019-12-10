/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_query.hpp"
#include "builders/protobuf/queries.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"

#include <gtest/gtest.h>

#include <boost/mpl/copy.hpp>
#include <boost/mpl/find.hpp>
#include <boost/mpl/vector.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/irange.hpp>
#include "framework/common_constants.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "module/shared_model/backend_proto/common.hpp"
#include "queries.pb.h"

namespace {

  using PbQueryCase = iroha::protocol::Query_Payload::QueryCase;
  using IfaceQueryVariantTypes =
      boost::mpl::copy<shared_model::interface::Query::QueryVariantType::types,
                       boost::mpl::back_inserter<boost::mpl::vector<>>>::type;
  using PbQueryCaseUnderlyingType = std::underlying_type_t<PbQueryCase>;

#define QUERY_VARIANT(PROTOBUF_VARIANT, IFACE_VARIANT)                        \
  {                                                                           \
    PbQueryCase::PROTOBUF_VARIANT,                                            \
        boost::mpl::find<                                                     \
            IfaceQueryVariantTypes,                                           \
            const shared_model::interface::IFACE_VARIANT &>::type::pos::value \
  }

  const std::map<PbQueryCaseUnderlyingType, int> kProtoQueryTypeToQueryType{
      QUERY_VARIANT(kGetAccount, GetAccount),
      QUERY_VARIANT(kGetSignatories, GetSignatories),
      QUERY_VARIANT(kGetAccountTransactions, GetAccountTransactions),
      QUERY_VARIANT(kGetAccountAssetTransactions, GetAccountAssetTransactions),
      QUERY_VARIANT(kGetTransactions, GetTransactions),
      QUERY_VARIANT(kGetAccountAssets, GetAccountAssets),
      QUERY_VARIANT(kGetAccountDetail, GetAccountDetail),
      QUERY_VARIANT(kGetRoles, GetRoles),
      QUERY_VARIANT(kGetRolePermissions, GetRolePermissions),
      QUERY_VARIANT(kGetAssetInfo, GetAssetInfo),
      QUERY_VARIANT(kGetPendingTransactions, GetPendingTransactions),
      QUERY_VARIANT(kGetBlock, GetBlock),
      QUERY_VARIANT(kGetPeers, GetPeers)};

#undef QUERY_VARIANT

}  // namespace

/**
 * For each protobuf query type
 * @given protobuf query object
 * @when create shared model query object
 * @then corresponding shared model object is created
 */

TEST(ProtoQuery, QueryLoad) {
  iroha::protocol::Query proto;
  auto payload = proto.mutable_payload();
  payload->set_allocated_meta(new iroha::protocol::QueryPayloadMeta());
  auto refl = payload->GetReflection();
  auto desc = payload->GetDescriptor()->FindOneofByName("query");
  boost::for_each(boost::irange(0, desc->field_count()), [&](auto i) {
    auto field = desc->field(i);
    auto pb_query_name = field->full_name();
    auto *msg = refl->GetMessage(*payload, field).New();
    iroha::setDummyFieldValues(msg);
    refl->SetAllocatedMessage(payload, msg, field);

    auto query_result = shared_model::proto::Query::create(proto);
    IROHA_ASSERT_RESULT_VALUE(query_result)
        << "Failed to load query " << pb_query_name;

    auto query = std::move(query_result).assumeValue();
    const PbQueryCaseUnderlyingType query_case = proto.payload().query_case();
    ASSERT_GT(kProtoQueryTypeToQueryType.count(query_case), 0)
        << "Please add the missing query type to the test map: "
        << pb_query_name;
    EXPECT_EQ(kProtoQueryTypeToQueryType.at(query_case), query->get().which());
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
  auto signedProto = shared_model::crypto::CryptoSigner<>::sign(
      *shared_model::crypto::Blob::fromBinaryString(
          proto_query.payload().SerializeAsString()),
      keypair);

  auto sig = proto_query.mutable_signature();
  sig->set_public_key(keypair.publicKey().hex());
  sig->set_signature(signedProto.hex());

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
  auto signedProto = shared_model::crypto::CryptoSigner<>::sign(
      *shared_model::crypto::Blob::fromBinaryString(
          proto_query.meta().SerializeAsString()),
      keypair);

  auto sig = proto_query.mutable_signature();
  sig->set_public_key(keypair.publicKey().hex());
  sig->set_signature(signedProto.hex());

  auto query = shared_model::proto::BlocksQueryBuilder()
                   .createdTime(created_time)
                   .creatorAccountId(account_id)
                   .queryCounter(query_counter)
                   .build();

  auto proto = query.signAndAddSignature(keypair).finish().getTransport();
  ASSERT_EQ(proto_query.SerializeAsString(), proto.SerializeAsString());
}
