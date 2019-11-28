/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/error_query_response.hpp"

#include <cassert>
#include <unordered_map>

using namespace shared_model::interface;

namespace {
  const std::unordered_map<QueryErrorType, std::string> kReasonToString{
      {QueryErrorType::kStatelessFailed, "StatelessFailed"},
      {QueryErrorType::kStatefulFailed, "StatefulFailed"},
      {QueryErrorType::kNoAccount, "NoAccount"},
      {QueryErrorType::kNoAccountAssets, "NoAccountAssets"},
      {QueryErrorType::kNoAccountDetail, "NoAccountDetail"},
      {QueryErrorType::kNoSignatories, "NoSignatories"},
      {QueryErrorType::kNotSupported, "NotSupported"},
      {QueryErrorType::kNoAsset, "NoAsset"},
      {QueryErrorType::kNoRoles, "NoRoles"}};

  const std::string kUnknownErrorType = "(unknown error type)";
  const std::string &reasonToString(QueryErrorType reason) {
    auto it = kReasonToString.find(reason);
    if (it == kReasonToString.end()) {
      assert(false);
      return kUnknownErrorType;
    }
    return it->second;
  }
}  // namespace

std::string ErrorQueryResponse::toString() const {
  return detail::PrettyStringBuilder()
      .init("ErrorQueryResponse")
      .append(reasonToString(reason()))
      .appendNamed("errorMessage", errorMessage())
      .finalize();
}

bool ErrorQueryResponse::operator==(const ModelType &rhs) const {
  return reason() == rhs.reason() and errorCode() == rhs.errorCode()
      and errorMessage() == rhs.errorMessage();
}
