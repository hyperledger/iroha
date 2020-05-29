/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/query_response_variant.hpp"

#include "interfaces/query_responses/account_asset_response.hpp"
#include "interfaces/query_responses/account_detail_response.hpp"
#include "interfaces/query_responses/account_response.hpp"
#include "interfaces/query_responses/asset_response.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "interfaces/query_responses/engine_receipts_response.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "interfaces/query_responses/peers_response.hpp"
#include "interfaces/query_responses/pending_transactions_page_response.hpp"
#include "interfaces/query_responses/role_permissions.hpp"
#include "interfaces/query_responses/roles_response.hpp"
#include "interfaces/query_responses/signatories_response.hpp"
#include "interfaces/query_responses/transactions_page_response.hpp"
#include "interfaces/query_responses/transactions_response.hpp"
#include "utils/visitor_apply_for_all.hpp"

using Variant =
    shared_model::interface::QueryResponse::QueryResponseVariantType;
template Variant::~variant();
template Variant::variant(Variant &&);
template bool Variant::operator==(const Variant &) const;
template void Variant::destroy_content() noexcept;
template int Variant::which() const noexcept;
template void Variant::indicate_which(int) noexcept;
template bool Variant::using_backup() const noexcept;
template Variant::convert_copy_into::convert_copy_into(void *) noexcept;

namespace shared_model {
  namespace interface {

    std::string QueryResponse::toString() const {
      return boost::apply_visitor(detail::ToStringVisitor(), get());
    }

    bool QueryResponse::operator==(const ModelType &rhs) const {
      return queryHash() == rhs.queryHash() and get() == rhs.get();
    }

  }  // namespace interface
}  // namespace shared_model
