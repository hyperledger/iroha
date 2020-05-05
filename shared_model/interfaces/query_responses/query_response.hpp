/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_QUERY_RESPONSE_HPP
#define IROHA_SHARED_MODEL_QUERY_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include <boost/variant/variant_fwd.hpp>
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    class AccountAssetResponse;
    class AccountDetailResponse;
    class AccountResponse;
    class BlockResponse;
    class ErrorQueryResponse;
    class SignatoriesResponse;
    class TransactionsResponse;
    class PendingTransactionsPageResponse;
    class AssetResponse;
    class RolesResponse;
    class RolePermissionsResponse;
    class TransactionsPageResponse;
    class PeersResponse;
    class EngineReceiptsResponse;
    /**
     * Class QueryResponse(qr) provides container with concrete query responses
     * available in the system.
     * General note: this class is container for QRs but not a base class.
     */
    class QueryResponse : public ModelPrimitive<QueryResponse> {
     private:
      /// Shortcut type for const reference
      template <typename... Value>
      using w = boost::variant<const Value &...>;

     public:
      /// Type of container with all concrete query response
      using QueryResponseVariantType = w<AccountAssetResponse,
                                         AccountDetailResponse,
                                         AccountResponse,
                                         ErrorQueryResponse,
                                         SignatoriesResponse,
                                         TransactionsResponse,
                                         AssetResponse,
                                         RolesResponse,
                                         RolePermissionsResponse,
                                         TransactionsPageResponse,
                                         PendingTransactionsPageResponse,
                                         BlockResponse,
                                         PeersResponse,
                                         EngineReceiptsResponse>;

      /**
       * @return reference to const variant with concrete qr
       */
      virtual const QueryResponseVariantType &get() const = 0;

      /**
       * @return hash of corresponding query
       */
      virtual const interface::types::HashType &queryHash() const = 0;

      // ------------------------| Primitive override |-------------------------

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_QUERY_RESPONSE_HPP
