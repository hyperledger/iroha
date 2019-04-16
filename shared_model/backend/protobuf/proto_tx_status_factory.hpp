/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TX_STATUS_FACTORY_HPP
#define IROHA_PROTO_TX_STATUS_FACTORY_HPP

#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"
#include "interfaces/iroha_internal/tx_status_factory.hpp"

namespace shared_model {
  namespace proto {
    class ProtoTxStatusFactory : public interface::TxStatusFactory {
     public:
      using FactoryReturnType = interface::TxStatusFactory::FactoryReturnType;

      // ------------------------| Stateless statuses |-------------------------

      FactoryReturnType makeStatelessFail(TransactionHashType,
                                          TransactionError) override;

      FactoryReturnType makeStatelessValid(TransactionHashType,
                                           TransactionError) override;

      // ------------------------| Stateful statuses |--------------------------

      FactoryReturnType makeStatefulFail(TransactionHashType,
                                         TransactionError) override;
      FactoryReturnType makeStatefulValid(TransactionHashType,
                                          TransactionError) override;

      // --------------------------| Final statuses |---------------------------

      FactoryReturnType makeCommitted(TransactionHashType,
                                      TransactionError) override;

      FactoryReturnType makeRejected(TransactionHashType,
                                     TransactionError) override;

      // --------------------------| Rest statuses |----------------------------

      FactoryReturnType makeMstExpired(TransactionHashType,
                                       TransactionError) override;

      FactoryReturnType makeMstPending(TransactionHashType,
                                       TransactionError) override;

      FactoryReturnType makeNotReceived(TransactionHashType,
                                        TransactionError) override;

      FactoryReturnType makeEnoughSignaturesCollected(
          TransactionHashType, TransactionError) override;
    };
  }  // namespace proto
}  // namespace shared_model
#endif  // IROHA_PROTO_TX_STATUS_FACTORY_HPP
