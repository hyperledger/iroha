/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_QUERY_HPP
#define IROHA_SHARED_MODEL_QUERY_HPP

#include <boost/variant/variant_fwd.hpp>
#include "interfaces/base/signable.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    class GetAccount;
    class GetBlock;
    class GetSignatories;
    class GetAccountTransactions;
    class GetAccountAssetTransactions;
    class GetTransactions;
    class GetAccountAssets;
    class GetAccountDetail;
    class GetRoles;
    class GetRolePermissions;
    class GetAssetInfo;
    class GetPendingTransactions;
    class GetPeers;
    class GetEngineReceipts;

    /**
     * Class Query provides container with one of concrete query available in
     * system.
     * General note: this class is container for queries but not a base class.
     */
    class Query : public Signable<Query> {
     private:
      /// Shortcut type for const reference
      template <typename... Value>
      using wrap = boost::variant<const Value &...>;

     public:
      /// Type of variant, that handle concrete query
      using QueryVariantType = wrap<GetAccount,
                                    GetSignatories,
                                    GetAccountTransactions,
                                    GetAccountAssetTransactions,
                                    GetTransactions,
                                    GetAccountAssets,
                                    GetAccountDetail,
                                    GetRoles,
                                    GetRolePermissions,
                                    GetAssetInfo,
                                    GetPendingTransactions,
                                    GetBlock,
                                    GetPeers,
                                    GetEngineReceipts>;

      /**
       * @return reference to const variant with concrete command
       */
      virtual const QueryVariantType &get() const = 0;

      /**
       * @return id of query creator
       */
      virtual const types::AccountIdType &creatorAccountId() const = 0;

      /**
       * Query counter - incremental variable reflect for number of sent to
       * system queries plus 1. Required for preventing replay attacks.
       * @return attached query counter
       */
      virtual types::CounterType queryCounter() const = 0;

      // ------------------------| Primitive override |-------------------------

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_QUERY_HPP
