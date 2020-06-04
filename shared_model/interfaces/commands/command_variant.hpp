/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_COMMAND_VARIANT_HPP
#define IROHA_SHARED_MODEL_COMMAND_VARIANT_HPP

#include "interfaces/commands/command.hpp"

#include <boost/variant.hpp>

namespace boost {
  extern template class variant<
      const shared_model::interface::AddAssetQuantity &,
      const shared_model::interface::AddPeer &,
      const shared_model::interface::AddSignatory &,
      const shared_model::interface::AppendRole &,
      const shared_model::interface::CallEngine &,
      const shared_model::interface::CompareAndSetAccountDetail &,
      const shared_model::interface::CreateAccount &,
      const shared_model::interface::CreateAsset &,
      const shared_model::interface::CreateDomain &,
      const shared_model::interface::CreateRole &,
      const shared_model::interface::DetachRole &,
      const shared_model::interface::GrantPermission &,
      const shared_model::interface::RemoveSignatory &,
      const shared_model::interface::RevokePermission &,
      const shared_model::interface::SetAccountDetail &,
      const shared_model::interface::SetQuorum &,
      const shared_model::interface::SetSettingValue &,
      const shared_model::interface::SubtractAssetQuantity &,
      const shared_model::interface::TransferAsset &>;
}  // namespace boost

#endif  // IROHA_SHARED_MODEL_COMMAND_VARIANT_HPP
