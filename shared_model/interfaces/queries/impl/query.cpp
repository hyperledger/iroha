/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/query_variant.hpp"

#include "interfaces/queries/get_account.hpp"
#include "interfaces/queries/get_account_asset_transactions.hpp"
#include "interfaces/queries/get_account_assets.hpp"
#include "interfaces/queries/get_account_detail.hpp"
#include "interfaces/queries/get_account_transactions.hpp"
#include "interfaces/queries/get_asset_info.hpp"
#include "interfaces/queries/get_block.hpp"
#include "interfaces/queries/get_engine_receipts.hpp"
#include "interfaces/queries/get_peers.hpp"
#include "interfaces/queries/get_pending_transactions.hpp"
#include "interfaces/queries/get_role_permissions.hpp"
#include "interfaces/queries/get_roles.hpp"
#include "interfaces/queries/get_signatories.hpp"
#include "interfaces/queries/get_transactions.hpp"
#include "interfaces/queries/query_payload_meta.hpp"
#include "utils/visitor_apply_for_all.hpp"

using Variant = shared_model::interface::Query::QueryVariantType;
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

    std::string Query::toString() const {
      return detail::PrettyStringBuilder()
          .init("Query")
          .appendNamed("creatorId", creatorAccountId())
          .appendNamed("queryCounter", queryCounter())
          .append(Signable::toString())
          .append(boost::apply_visitor(detail::ToStringVisitor(), get()))
          .finalize();
    }

    bool Query::operator==(const ModelType &rhs) const {
      return this->get() == rhs.get();
    }

  }  // namespace interface
}  // namespace shared_model
