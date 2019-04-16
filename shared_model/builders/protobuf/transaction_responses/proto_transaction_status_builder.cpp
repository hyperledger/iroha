/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "builders/protobuf/transaction_responses/proto_transaction_status_builder.hpp"
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {

    shared_model::proto::TransactionResponse TransactionStatusBuilder::build()
        && {
      return shared_model::proto::TransactionResponse(std::move(tx_response_));
    }

    shared_model::proto::TransactionResponse TransactionStatusBuilder::build()
        & {
      return shared_model::proto::TransactionResponse(
          iroha::protocol::ToriiResponse(tx_response_));
    }

    TransactionStatusBuilder
    TransactionStatusBuilder::statelessValidationSuccess() {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_tx_status(
          iroha::protocol::TxStatus::STATELESS_VALIDATION_SUCCESS);
      return copy;
    }

    TransactionStatusBuilder
    TransactionStatusBuilder::statelessValidationFailed() {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_tx_status(
          iroha::protocol::TxStatus::STATELESS_VALIDATION_FAILED);
      return copy;
    }

    TransactionStatusBuilder TransactionStatusBuilder::mstPending() {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_tx_status(iroha::protocol::TxStatus::MST_PENDING);
      return copy;
    }

    TransactionStatusBuilder
    TransactionStatusBuilder::enoughSignaturesCollected() {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_tx_status(
          iroha::protocol::TxStatus::ENOUGH_SIGNATURES_COLLECTED);
      return copy;
    }

    TransactionStatusBuilder
    TransactionStatusBuilder::statefulValidationSuccess() {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_tx_status(
          iroha::protocol::TxStatus::STATEFUL_VALIDATION_SUCCESS);
      return copy;
    }

    TransactionStatusBuilder
    TransactionStatusBuilder::statefulValidationFailed() {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_tx_status(
          iroha::protocol::TxStatus::STATEFUL_VALIDATION_FAILED);
      return copy;
    }

    TransactionStatusBuilder TransactionStatusBuilder::committed() {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_tx_status(iroha::protocol::TxStatus::COMMITTED);
      return copy;
    }

    TransactionStatusBuilder TransactionStatusBuilder::notReceived() {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_tx_status(iroha::protocol::TxStatus::NOT_RECEIVED);
      return copy;
    }

    TransactionStatusBuilder TransactionStatusBuilder::mstExpired() {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_tx_status(iroha::protocol::TxStatus::MST_EXPIRED);
      return copy;
    }

    TransactionStatusBuilder TransactionStatusBuilder::txHash(
        const crypto::Hash &hash) {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_tx_hash(hash.hex());
      return copy;
    }

    TransactionStatusBuilder TransactionStatusBuilder::statelessErrorOrCmdName(
        const std::string &err_or_cmd) {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_err_or_cmd_name(err_or_cmd);
      return copy;
    }

    TransactionStatusBuilder TransactionStatusBuilder::failedCmdIndex(
        uint32_t index) {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_failed_cmd_index(index);
      return copy;
    }

    TransactionStatusBuilder TransactionStatusBuilder::errorCode(
        uint32_t code) {
      TransactionStatusBuilder copy(*this);
      copy.tx_response_.set_error_code(code);
      return copy;
    }

  }  // namespace proto
}  // namespace shared_model
