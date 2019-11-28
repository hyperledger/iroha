/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_error_query_response.hpp"

#include <unordered_map>

#include "common/result.hpp"
#include "qry_responses.pb.h"

using namespace shared_model::proto;

using shared_model::interface::QueryErrorType;

namespace {
  using ProtoQueryErrorType = iroha::protocol::ErrorResponse;
  // clang-format off
  const std::unordered_map<ProtoQueryErrorType::Reason, QueryErrorType>
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
}  // namespace

iroha::expected::Result<std::unique_ptr<ErrorQueryResponse>, std::string>
ErrorQueryResponse::create(
    const iroha::protocol::QueryResponse &query_response) {
  auto it = kProtoQueryErrorTypeToErrorQueryType.find(
      query_response.error_response().reason());
  if (it == kProtoQueryErrorTypeToErrorQueryType.end()) {
    return "Unknown error type.";
  }
  return std::make_unique<ErrorQueryResponse>(query_response, it->second);
}

ErrorQueryResponse::ErrorQueryResponse(
    const iroha::protocol::QueryResponse &query_response,
    QueryErrorType error_reason)
    : error_response_{query_response.error_response()},
      error_reason_(error_reason),
      error_message_(error_response_.message()),
      error_code_(error_response_.error_code()) {}

ErrorQueryResponse::~ErrorQueryResponse() = default;

QueryErrorType ErrorQueryResponse::reason() const {
  return error_reason_;
}

const ErrorQueryResponse::ErrorMessageType &ErrorQueryResponse::errorMessage()
    const {
  return error_message_;
}

ErrorQueryResponse::ErrorCodeType ErrorQueryResponse::errorCode() const {
  return error_code_;
}
