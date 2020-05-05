/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_QUERY_VARIANT_HPP
#define IROHA_SHARED_MODEL_QUERY_VARIANT_HPP

#include "interfaces/queries/query.hpp"

#include <boost/variant.hpp>

namespace boost {
  extern template class variant<
      const shared_model::interface::GetAccount &,
      const shared_model::interface::GetSignatories &,
      const shared_model::interface::GetAccountTransactions &,
      const shared_model::interface::GetAccountAssetTransactions &,
      const shared_model::interface::GetTransactions &,
      const shared_model::interface::GetAccountAssets &,
      const shared_model::interface::GetAccountDetail &,
      const shared_model::interface::GetRoles &,
      const shared_model::interface::GetRolePermissions &,
      const shared_model::interface::GetAssetInfo &,
      const shared_model::interface::GetPendingTransactions &,
      const shared_model::interface::GetPeers &,
      const shared_model::interface::GetEngineReceipts &>;
}  // namespace boost

#endif  // IROHA_SHARED_MODEL_QUERY_VARIANT_HPP
