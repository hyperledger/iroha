/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/query_responses/query_response.hpp"

#include "interfaces/query_responses/account_asset_response.hpp"
#include "interfaces/query_responses/account_detail_response.hpp"
#include "interfaces/query_responses/account_response.hpp"
#include "interfaces/query_responses/asset_response.hpp"
#include "interfaces/query_responses/block_error_response.hpp"
#include "interfaces/query_responses/block_query_response.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "interfaces/query_responses/peers_response.hpp"
#include "interfaces/query_responses/pending_transactions_page_response.hpp"
#include "interfaces/query_responses/query_response.hpp"
#include "interfaces/query_responses/query_response_variant.hpp"
#include "interfaces/query_responses/role_permissions.hpp"
#include "interfaces/query_responses/roles_response.hpp"
#include "interfaces/query_responses/signatories_response.hpp"
#include "interfaces/query_responses/transactions_page_response.hpp"
#include "interfaces/query_responses/transactions_response.hpp"

using shared_model::plain::QueryResponse;

namespace {
  const auto get_specific_response_constref =
      [](const auto &specific_response_ptr)
      -> QueryResponse::QueryResponseVariantType {
    return QueryResponse::QueryResponseVariantType{*specific_response_ptr};
  };
}  // namespace

QueryResponse::QueryResponse(VariantHolder specific_response,
                             shared_model::crypto::Hash query_hash)
    : specific_response_holder(std::move(specific_response)),
      specific_response_constref(boost::apply_visitor(
          get_specific_response_constref, specific_response_holder)),
      query_hash(std::move(query_hash)) {}

QueryResponse::~QueryResponse() = default;

const QueryResponse::QueryResponseVariantType &QueryResponse::get() const {
  return specific_response_constref;
}

const shared_model::interface::types::HashType &QueryResponse::queryHash()
    const {
  return query_hash;
}
