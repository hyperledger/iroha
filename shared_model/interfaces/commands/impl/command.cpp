/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/command_variant.hpp"

#include "interfaces/commands/add_asset_quantity.hpp"
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/commands/add_signatory.hpp"
#include "interfaces/commands/append_role.hpp"
#include "interfaces/commands/call_engine.hpp"
#include "interfaces/commands/compare_and_set_account_detail.hpp"
#include "interfaces/commands/create_account.hpp"
#include "interfaces/commands/create_asset.hpp"
#include "interfaces/commands/create_domain.hpp"
#include "interfaces/commands/create_role.hpp"
#include "interfaces/commands/detach_role.hpp"
#include "interfaces/commands/grant_permission.hpp"
#include "interfaces/commands/remove_peer.hpp"
#include "interfaces/commands/remove_signatory.hpp"
#include "interfaces/commands/revoke_permission.hpp"
#include "interfaces/commands/set_account_detail.hpp"
#include "interfaces/commands/set_quorum.hpp"
#include "interfaces/commands/set_setting_value.hpp"
#include "interfaces/commands/subtract_asset_quantity.hpp"
#include "interfaces/commands/transfer_asset.hpp"
#include "utils/visitor_apply_for_all.hpp"

using Variant = shared_model::interface::Command::CommandVariantType;
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

    std::string Command::toString() const {
      return boost::apply_visitor(detail::ToStringVisitor(), get());
    }

    bool Command::operator==(const ModelType &rhs) const {
      return this->get() == rhs.get();
    }

  }  // namespace interface
}  // namespace shared_model
