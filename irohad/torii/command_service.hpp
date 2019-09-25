/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TORII_COMMAND_SERVICE_HPP
#define TORII_COMMAND_SERVICE_HPP

#include <rxcpp/rx-observable-fwd.hpp>
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class TransactionBatch;
    class TransactionResponse;
  }  // namespace interface

  namespace crypto {
    class Hash;
  }  // namespace crypto
}  // namespace shared_model

namespace iroha {
  namespace torii {

    class CommandService {
     public:
      virtual ~CommandService() = default;

      /**
       * Actual implementation of sync Torii in CommandService
       * @param batch - transactions we've received
       */
      virtual void handleTransactionBatch(
          std::shared_ptr<shared_model::interface::TransactionBatch> batch) = 0;

      /**
       * Request to retrieve a status of any particular transaction
       * @param request - TxStatusRequest object which identifies transaction
       * uniquely
       * @return response which contains a current state of requested
       * transaction
       */
      virtual std::shared_ptr<shared_model::interface::TransactionResponse>
      getStatus(const shared_model::crypto::Hash &request) = 0;

      /**
       * Streaming call which will repeatedly send all statuses of requested
       * transaction from its status at the moment of receiving this request to
       * the some final transaction status (which cannot change anymore)
       * @param request- TxStatusRequest object which identifies transaction
       * uniquely
       * @return observable with transaction statuses
       */
      virtual rxcpp::observable<
          std::shared_ptr<shared_model::interface::TransactionResponse>>
      getStatusStream(const shared_model::crypto::Hash &hash) = 0;
    };

  }  // namespace torii
}  // namespace iroha

#endif  // TORII_COMMAND_SERVICE_HPP
