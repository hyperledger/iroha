/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_account_detail.hpp"

#include "common/optional_reference_equal.hpp"

namespace shared_model {
  namespace interface {

    std::string GetAccountDetail::toString() const {
      return detail::PrettyStringBuilder()
          .init("GetAccountDetail")
          .appendNamed("account_id", accountId())
          .appendNamed("key", key())
          .appendNamed("writer", writer())
          .appendNamed("pagination_meta", paginationMeta())
          .finalize();
    }

    bool GetAccountDetail::operator==(const ModelType &rhs) const {
      return accountId() == rhs.accountId() and key() == rhs.key()
          and writer() == rhs.writer()
          and iroha::optionalReferenceEqual(paginationMeta(),
                                            rhs.paginationMeta());
    }

  }  // namespace interface
}  // namespace shared_model
