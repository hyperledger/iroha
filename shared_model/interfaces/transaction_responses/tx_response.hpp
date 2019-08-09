/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TX_RESPONSE_HPP
#define IROHA_TX_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include <boost/variant/variant_fwd.hpp>
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    class StatelessFailedTxResponse;
    class StatelessValidTxResponse;
    class StatefulFailedTxResponse;
    class StatefulValidTxResponse;
    class RejectedTxResponse;
    class CommittedTxResponse;
    class MstExpiredResponse;
    class NotReceivedTxResponse;
    class MstPendingResponse;
    class EnoughSignaturesCollectedResponse;

    /**
     * TransactionResponse is a status of transaction in system
     */
    class TransactionResponse : public ModelPrimitive<TransactionResponse> {
     private:
      /// const reference shortcut type
      template <typename... Value>
      using wrap = boost::variant<const Value &...>;

     protected:
      /**
       * @return priority of this transaction response; transaction response can
       * only be replaced with one with higher priority
       */
      virtual int priority() const noexcept = 0;

     public:
      /// Type of variant, that handle all concrete tx responses in the system
      using ResponseVariantType = wrap<StatelessFailedTxResponse,
                                       StatelessValidTxResponse,
                                       StatefulFailedTxResponse,
                                       StatefulValidTxResponse,
                                       RejectedTxResponse,
                                       CommittedTxResponse,
                                       MstExpiredResponse,
                                       NotReceivedTxResponse,
                                       MstPendingResponse,
                                       EnoughSignaturesCollectedResponse>;

      /// Type of transaction hash
      using TransactionHashType = interface::types::HashType;

      /**
       * @return hash of corresponding transaction
       */
      virtual const TransactionHashType &transactionHash() const = 0;

      /**
       * @return attached concrete tx response
       */
      virtual const ResponseVariantType &get() const = 0;

      /// Type of stateless validation error or command name, which failed
      /// validation
      using StatelessErrorOrFailedCommandNameType = std::string;
      /**
       * @return name of the failed command, if present; empty string otherwise
       */
      virtual const StatelessErrorOrFailedCommandNameType &
      statelessErrorOrCommandName() const = 0;

      /// Type of command index, which failed validation
      using FailedCommandIndexType = size_t;
      /**
       * @return index of failed command
       */
      virtual FailedCommandIndexType failedCommandIndex() const = 0;

      /// Type of command error code
      using ErrorCodeType = uint32_t;
      /**
       * @return error code, with which the command failed
       */
      virtual ErrorCodeType errorCode() const = 0;

      /**
       * Enumeration for holding result of priorities comparison
       */
      enum class PrioritiesComparisonResult { kLess, kEqual, kGreater };
      /**
       * Compare priorities of two transaction responses
       * @param other response
       * @return enumeration result of that comparison
       */
      PrioritiesComparisonResult comparePriorities(const ModelType &other) const
          noexcept;

      // ------------------------| Primitive override |-------------------------

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_TX_RESPONSE_HPP
