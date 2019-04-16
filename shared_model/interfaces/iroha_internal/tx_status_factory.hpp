/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TX_STATUS_FACTORY_HPP
#define IROHA_TX_STATUS_FACTORY_HPP

#include <memory>

#include "interfaces/transaction_responses/tx_response.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Factory which creates transaction status response
     */
    class TxStatusFactory {
     public:
      /// return type of all generative methods
      using FactoryReturnType = std::unique_ptr<TransactionResponse>;

      /// type of transaction hash
      using TransactionHashType =
          const TransactionResponse::TransactionHashType &;

      /// type of failed command name attached to \class TransactionResponse
      /// instance
      using StatelessErrorOrFailedCommandNameType =
          const TransactionResponse::StatelessErrorOrFailedCommandNameType &;

      /// type of failed command index attached to \class TransactionResponse
      /// instance
      using FailedCommandIndexType =
          TransactionResponse::FailedCommandIndexType;

      /// type of error code, with which command failed, attached to \class
      /// TransactionResponse instance
      using ErrorCodeType = TransactionResponse::ErrorCodeType;

      /// represents transaction error, empty or not
      struct TransactionError {
        std::decay_t<StatelessErrorOrFailedCommandNameType> cmd_name_;
        FailedCommandIndexType cmd_index_;
        ErrorCodeType error_code_;

        TransactionError() : cmd_name_{}, cmd_index_{}, error_code_{} {}
        TransactionError(StatelessErrorOrFailedCommandNameType cmd_name,
                         FailedCommandIndexType cmd_index,
                         ErrorCodeType error_code)
            : cmd_name_{cmd_name},
              cmd_index_{cmd_index},
              error_code_{error_code} {}
      };

      // ------------------------| Stateless statuses |-------------------------

      /// Creates stateless failed transaction status
      virtual FactoryReturnType makeStatelessFail(
          TransactionHashType,
          TransactionError tx_error = TransactionError()) = 0;

      /// Creates stateless valid transaction status
      virtual FactoryReturnType makeStatelessValid(
          TransactionHashType,
          TransactionError tx_error = TransactionError()) = 0;

      // ------------------------| Stateful statuses |--------------------------

      /// Creates stateful failed transaction status
      virtual FactoryReturnType makeStatefulFail(
          TransactionHashType,
          TransactionError tx_error = TransactionError()) = 0;
      /// Creates stateful valid transaction status
      virtual FactoryReturnType makeStatefulValid(
          TransactionHashType,
          TransactionError tx_error = TransactionError()) = 0;

      // --------------------------| Final statuses |---------------------------

      /// Creates committed transaction status
      virtual FactoryReturnType makeCommitted(
          TransactionHashType,
          TransactionError tx_error = TransactionError()) = 0;

      /// Creates rejected transaction status
      virtual FactoryReturnType makeRejected(
          TransactionHashType,
          TransactionError tx_error = TransactionError()) = 0;

      // --------------------------| Rest statuses |----------------------------

      /// Creates transaction expired status
      virtual FactoryReturnType makeMstExpired(
          TransactionHashType,
          TransactionError tx_error = TransactionError()) = 0;

      /// Creates transaction pending status
      virtual FactoryReturnType makeMstPending(
          TransactionHashType,
          TransactionError tx_error = TransactionError()) = 0;

      /// Creates transaction is not received status
      virtual FactoryReturnType makeNotReceived(
          TransactionHashType,
          TransactionError tx_error = TransactionError()) = 0;

      /// Creates status which shows that enough signatures were collected
      virtual FactoryReturnType makeEnoughSignaturesCollected(
          TransactionHashType,
          TransactionError tx_error = TransactionError()) = 0;

      virtual ~TxStatusFactory() = default;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_TX_STATUS_FACTORY_HPP
