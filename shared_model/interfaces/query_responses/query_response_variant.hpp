/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_QUERY_RESPONSE_VARIANT_HPP
#define IROHA_SHARED_MODEL_QUERY_RESPONSE_VARIANT_HPP

#include "interfaces/query_responses/query_response.hpp"

#include <boost/variant.hpp>

namespace boost {
  extern template class variant<
      const shared_model::interface::AccountAssetResponse &,
      const shared_model::interface::AccountDetailResponse &,
      const shared_model::interface::AccountResponse &,
      const shared_model::interface::ErrorQueryResponse &,
      const shared_model::interface::SignatoriesResponse &,
      const shared_model::interface::TransactionsResponse &,
      const shared_model::interface::AssetResponse &,
      const shared_model::interface::RolesResponse &,
      const shared_model::interface::RolePermissionsResponse &,
      const shared_model::interface::TransactionsPageResponse &,
      const shared_model::interface::PendingTransactionsPageResponse &,
      const shared_model::interface::PeersResponse &>;
}

#endif  // IROHA_SHARED_MODEL_QUERY_RESPONSE_VARIANT_HPP
