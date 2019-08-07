/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_QUERY_ERROR_RESPONSE_HPP
#define IROHA_SHARED_MODEL_QUERY_ERROR_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include <boost/variant.hpp>
#include "interfaces/query_responses/error_responses/no_account_assets_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_account_detail_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_account_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_asset_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_roles_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_signatories_error_response.hpp"
#include "interfaces/query_responses/error_responses/not_supported_error_response.hpp"
#include "interfaces/query_responses/error_responses/stateful_failed_error_response.hpp"
#include "interfaces/query_responses/error_responses/stateless_failed_error_response.hpp"

namespace shared_model {
  namespace interface {

    /**
     * QueryErrorResponse interface container for all concrete error responses
     * possible achieved in the system.
     */
    class ErrorQueryResponse : public ModelPrimitive<ErrorQueryResponse> {
     private:
      /// Shortcut type for const reference
      template <typename... Value>
      using w = boost::variant<const Value &...>;

     public:
      /// Type of container with all concrete error query responses
      using QueryErrorResponseVariantType = w<StatelessFailedErrorResponse,
                                              StatefulFailedErrorResponse,
                                              NoAccountErrorResponse,
                                              NoAccountAssetsErrorResponse,
                                              NoAccountDetailErrorResponse,
                                              NoSignatoriesErrorResponse,
                                              NotSupportedErrorResponse,
                                              NoAssetErrorResponse,
                                              NoRolesErrorResponse>;

      /// Type list with all concrete query error responses
      using QueryResponseListType = QueryErrorResponseVariantType::types;

      /**
       * @return reference to const variant with concrete error response
       */
      virtual const QueryErrorResponseVariantType &get() const = 0;

      /// Message type
      using ErrorMessageType = std::string;

      /**
       * @return error message if present, otherwise - an empty string
       */
      virtual const ErrorMessageType &errorMessage() const = 0;

      /// Error code type
      using ErrorCodeType = uint32_t;

      /**
       * @return stateful error code of this query response:
       *    0 - error is in query's type, it is not a stateful one
       *    1 - internal error
       *    2 - not enough permissions
       *    3 - invalid signatures
       */
      virtual ErrorCodeType errorCode() const = 0;

      // ------------------------| Primitive override |-------------------------

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_QUERY_ERROR_RESPONSE_HPP
