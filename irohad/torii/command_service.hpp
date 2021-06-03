/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TORII_COMMAND_SERVICE_HPP
#define TORII_COMMAND_SERVICE_HPP

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

      virtual void processTransactionResponse(
          std::shared_ptr<shared_model::interface::TransactionResponse>
              response) = 0;
    };

  }  // namespace torii
}  // namespace iroha

#endif  // TORII_COMMAND_SERVICE_HPP
