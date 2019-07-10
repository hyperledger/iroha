/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_query_response.hpp"

#include <gtest/gtest.h>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/irange.hpp>
#include <boost/variant.hpp>
#include "common/byteutils.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/query_responses/error_query_response.hpp"

/**
 * @given protobuf's QueryResponse with different responses and some hash
 * @when converting to shared model
 * @then ensure that status and hash remain the same
 */
TEST(QueryResponse, QueryResponseLoad) {
  iroha::protocol::QueryResponse response;
  const std::string hash = "123";
  response.set_query_hash(iroha::bytestringToHexstring(hash));
  auto refl = response.GetReflection();
  auto desc = response.GetDescriptor();
  auto resp_status = desc->FindOneofByName("response");
  ASSERT_NE(nullptr, resp_status);

  boost::for_each(boost::irange(0, resp_status->field_count()), [&](auto i) {
    auto field = desc->field(i);
    refl->SetAllocatedMessage(
        &response, refl->GetMessage(response, field).New(), field);
    shared_model::proto::QueryResponse shared_response{
        iroha::protocol::QueryResponse{response}};
    ASSERT_EQ(i, shared_response.get().which());
    ASSERT_EQ(shared_response.queryHash(), shared_model::crypto::Hash(hash));
  });
}

/**
 * @given protobuf's ErrorResponse with different reasons and some hash
 * @when converting to shared model
 * @then ensure that reason and hash remain the same
 */
TEST(QueryResponse, ErrorResponseLoad) {
  iroha::protocol::QueryResponse response;
  const std::string hash = "123";
  response.set_query_hash(iroha::bytestringToHexstring(hash));
  auto error_resp = response.mutable_error_response();
  auto refl = error_resp->GetReflection();
  auto desc = error_resp->GetDescriptor();
  auto resp_reason = desc->FindFieldByName("reason");
  ASSERT_NE(nullptr, resp_reason);
  auto resp_reason_enum = resp_reason->enum_type();
  ASSERT_NE(nullptr, resp_reason_enum);

  boost::for_each(
      boost::irange(0, resp_reason_enum->value_count()), [&](auto i) {
        refl->SetEnumValue(
            error_resp, resp_reason, resp_reason_enum->value(i)->number());
        shared_model::proto::QueryResponse shared_response{
            iroha::protocol::QueryResponse{response}};
        ASSERT_NO_THROW({
          ASSERT_EQ(
              i,
              boost::get<const shared_model::interface::ErrorQueryResponse &>(
                  shared_response.get())
                  .get()
                  .which());
          ASSERT_EQ(shared_response.queryHash(),
                    shared_model::crypto::Hash(hash));
        });
      });
}
