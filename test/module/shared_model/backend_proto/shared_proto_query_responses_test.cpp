/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_query_response.hpp"

#include <gtest/gtest.h>
#include <boost/mpl/copy.hpp>
#include <boost/mpl/find.hpp>
#include <boost/mpl/vector.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/irange.hpp>
#include <boost/variant.hpp>
#include "common/byteutils.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/hash.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "interfaces/iroha_internal/error_query_response_reason.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "qry_responses.pb.h"

using PbQueryResponse = iroha::protocol::QueryResponse;
using IfaceQueryResponseVariant =
    shared_model::interface::QueryResponse::QueryResponseVariantType;
using IfaceQueryResponseVariantTypes =
    boost::mpl::copy<IfaceQueryResponseVariant::types,
                     boost::mpl::back_inserter<boost::mpl::vector<>>>::type;
using PbResponseCaseUnderlyingType =
    std::underlying_type_t<PbQueryResponse::ResponseCase>;

#define RESPONSE_VARIANT(PROTOBUF_VARIANT, IFACE_VARIANT)                     \
  {                                                                           \
    PbQueryResponse::PROTOBUF_VARIANT,                                        \
        boost::mpl::find<                                                     \
            IfaceQueryResponseVariantTypes,                                   \
            const shared_model::interface::IFACE_VARIANT &>::type::pos::value \
  }

static const std::map<PbResponseCaseUnderlyingType, int>
    kProtoQueryResponseTypeToQueryResponseType{
        RESPONSE_VARIANT(kAccountAssetsResponse, AccountAssetResponse),
        RESPONSE_VARIANT(kAccountDetailResponse, AccountDetailResponse),
        RESPONSE_VARIANT(kAccountResponse, AccountResponse),
        RESPONSE_VARIANT(kErrorResponse, ErrorQueryResponse),
        RESPONSE_VARIANT(kSignatoriesResponse, SignatoriesResponse),
        RESPONSE_VARIANT(kTransactionsResponse, TransactionsResponse),
        RESPONSE_VARIANT(kAssetResponse, AssetResponse),
        RESPONSE_VARIANT(kRolesResponse, RolesResponse),
        RESPONSE_VARIANT(kRolePermissionsResponse, RolePermissionsResponse),
        RESPONSE_VARIANT(kTransactionsPageResponse, TransactionsPageResponse),
        RESPONSE_VARIANT(kPendingTransactionsPageResponse,
                         PendingTransactionsPageResponse),
        RESPONSE_VARIANT(kBlockResponse, BlockResponse),
        RESPONSE_VARIANT(kPeersResponse, PeersResponse)};

#undef RESPONSE_VARIANT

using ProtoQueryErrorType = iroha::protocol::ErrorResponse;
using shared_model::interface::QueryErrorType;
using PbErrorReasonUnderlyingType =
    std::underlying_type_t<ProtoQueryErrorType::Reason>;

// clang-format off
static const std::unordered_map<PbErrorReasonUnderlyingType, QueryErrorType>
    kProtoQueryErrorTypeToErrorQueryType{
  {ProtoQueryErrorType::STATELESS_INVALID,  QueryErrorType::kStatelessFailed},
  {ProtoQueryErrorType::STATEFUL_INVALID,   QueryErrorType::kStatefulFailed},
  {ProtoQueryErrorType::NO_ACCOUNT,         QueryErrorType::kNoAccount},
  {ProtoQueryErrorType::NO_ACCOUNT_ASSETS,  QueryErrorType::kNoAccountAssets},
  {ProtoQueryErrorType::NO_ACCOUNT_DETAIL,  QueryErrorType::kNoAccountDetail},
  {ProtoQueryErrorType::NO_SIGNATORIES,     QueryErrorType::kNoSignatories},
  {ProtoQueryErrorType::NOT_SUPPORTED,      QueryErrorType::kNotSupported},
  {ProtoQueryErrorType::NO_ASSET,           QueryErrorType::kNoAsset},
  {ProtoQueryErrorType::NO_ROLES,           QueryErrorType::kNoRoles}
};
// clang-format on

/**
 * @given protobuf's QueryResponse with different responses and some hash
 * @when converting to shared model
 * @then ensure that status and hash remain the same
 */
TEST(QueryResponse, QueryResponseLoad) {
  iroha::protocol::QueryResponse response;
  const shared_model::crypto::Hash hash{
      shared_model::crypto::Blob::fromBinaryString("123")};
  response.set_query_hash(hash.blob().hex());
  auto refl = response.GetReflection();
  auto desc = response.GetDescriptor();
  auto resp_status = desc->FindOneofByName("response");
  ASSERT_NE(nullptr, resp_status);

  boost::for_each(boost::irange(0, resp_status->field_count()), [&](auto i) {
    auto field = desc->field(i);
    auto pb_response_name = field->full_name();

    auto *msg = refl->GetMessage(response, field).New();
    refl->SetAllocatedMessage(&response, msg, field);
    const PbResponseCaseUnderlyingType response_case = response.response_case();

    auto shared_response_result = shared_model::proto::QueryResponse::create(
        iroha::protocol::QueryResponse{response});
    IROHA_ASSERT_RESULT_VALUE(shared_response_result)
        << "Failed to load response " << pb_response_name;
    auto shared_response = std::move(shared_response_result).assumeValue();

    ASSERT_GT(kProtoQueryResponseTypeToQueryResponseType.count(response_case),
              0)
        << "Please add the missing query response type to the test map: "
        << pb_response_name;
    ASSERT_EQ(kProtoQueryResponseTypeToQueryResponseType.at(response_case),
              shared_response->get().which());
    ASSERT_EQ(shared_response->queryHash(), hash);
  });
}

/**
 * @given protobuf's ErrorResponse with different reasons and some hash
 * @when converting to shared model
 * @then ensure that reason and hash remain the same
 */
TEST(QueryResponse, ErrorResponseLoad) {
  iroha::protocol::QueryResponse response;
  const shared_model::crypto::Hash hash{
      shared_model::crypto::Blob::fromBinaryString("123")};
  response.set_query_hash(hash.blob().hex());
  auto error_resp = response.mutable_error_response();
  const shared_model::interface::ErrorQueryResponse::ErrorCodeType error_code =
      123;
  error_resp->set_error_code(error_code);
  auto refl = error_resp->GetReflection();
  auto desc = error_resp->GetDescriptor();
  auto resp_reason = desc->FindFieldByName("reason");
  ASSERT_NE(nullptr, resp_reason);
  auto resp_reason_enum = resp_reason->enum_type();
  ASSERT_NE(nullptr, resp_reason_enum);

  boost::for_each(
      boost::irange(0, resp_reason_enum->value_count()), [&](auto i) {
        const auto reason_case = resp_reason_enum->value(i)->number();
        refl->SetEnumValue(error_resp, resp_reason, reason_case);
        auto reason_name = resp_reason_enum->value(i)->full_name();

        auto shared_response_result =
            shared_model::proto::QueryResponse::create(
                iroha::protocol::QueryResponse{response});
        IROHA_ASSERT_RESULT_VALUE(shared_response_result)
            << "Could not load with " << reason_name;
        auto shared_response = std::move(shared_response_result).assumeValue();

        EXPECT_EQ(shared_response->queryHash(), hash);
        ASSERT_GT(kProtoQueryErrorTypeToErrorQueryType.count(reason_case), 0)
            << "Please add the missing error reason to the test map: "
            << reason_name;
        EXPECT_NO_THROW({
          EXPECT_EQ(
              kProtoQueryErrorTypeToErrorQueryType.at(reason_case),
              boost::get<const shared_model::interface::ErrorQueryResponse &>(
                  shared_response->get())
                  .reason());
        });
      });
}
