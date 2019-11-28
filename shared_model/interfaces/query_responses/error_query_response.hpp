/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_QUERY_ERROR_RESPONSE_HPP
#define IROHA_SHARED_MODEL_QUERY_ERROR_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/iroha_internal/error_query_response_reason.hpp"

namespace shared_model {
  namespace interface {

    /**
     * QueryErrorResponse interface container for all concrete error responses
     * possible achieved in the system.
     */
    class ErrorQueryResponse : public ModelPrimitive<ErrorQueryResponse> {
     public:
      /**
       * @return general error reason
       */
      virtual QueryErrorType reason() const = 0;

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
