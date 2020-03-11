/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_ACCOUNT_DETAIL_HPP
#define IROHA_SHARED_MODEL_GET_ACCOUNT_DETAIL_HPP

#include <optional>

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/queries/account_detail_pagination_meta.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Query for get all account's details; the algorithm of retrieving them is
     * the following:
     *  - if query has only accountId, all details about the specified account
     *    will be returned
     *  - if there is a key in a query, details written by all writers under
     *    this key will be returned
     *  - if there is a writer in a query, all details written by this writer
     *    will be returned
     *  - if there are both key and writer in a query, details written by this
     *    writer AND under this key will be returned
     */
    class GetAccountDetail : public ModelPrimitive<GetAccountDetail> {
     public:
      /**
       * @return account identifier
       */
      virtual const types::AccountIdType &accountId() const = 0;

      /**
       * @return key from key-value storage
       */
      virtual std::optional<types::AccountDetailKeyType> key() const = 0;

      /**
       * @return account identifier of writer
       */
      virtual std::optional<types::AccountIdType> writer() const = 0;

      /// Get the query pagination metadata.
      virtual std::optional<
          std::reference_wrapper<const AccountDetailPaginationMeta>>
      paginationMeta() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_GET_ACCOUNT_DETAIL_HPP
