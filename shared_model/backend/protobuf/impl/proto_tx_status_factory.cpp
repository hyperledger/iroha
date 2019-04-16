/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/proto_tx_status_factory.hpp"

#include "cryptography/hash.hpp"
#include "interfaces/common_objects/types.hpp"

using namespace shared_model::proto;

// -------------------------------| Private API |-------------------------------

namespace {
  /**
   * Fills common fields for all statuses
   */
  iroha::protocol::ToriiResponse fillCommon(
      ProtoTxStatusFactory::TransactionHashType hash,
      ProtoTxStatusFactory::TransactionError tx_error,
      iroha::protocol::TxStatus status) {
    iroha::protocol::ToriiResponse response;
    response.set_tx_hash(hash.hex());
    response.set_err_or_cmd_name(tx_error.cmd_name_);
    response.set_failed_cmd_index(tx_error.cmd_index_);
    response.set_error_code(tx_error.error_code_);
    response.set_tx_status(status);
    return response;
  }

  /**
   * Wraps status with model object
   */
  ProtoTxStatusFactory::FactoryReturnType wrap(
      iroha::protocol::ToriiResponse &&value) {
    return std::make_unique<shared_model::proto::TransactionResponse>(
        std::move(value));
  }
}  // namespace

// ---------------------------| Stateless statuses |----------------------------

ProtoTxStatusFactory::FactoryReturnType ProtoTxStatusFactory::makeStatelessFail(
    TransactionHashType hash, TransactionError tx_error) {
  return wrap(fillCommon(
      hash, tx_error, iroha::protocol::TxStatus::STATELESS_VALIDATION_FAILED));
}

ProtoTxStatusFactory::FactoryReturnType
ProtoTxStatusFactory::makeStatelessValid(TransactionHashType hash,
                                         TransactionError tx_error) {
  return wrap(fillCommon(
      hash, tx_error, iroha::protocol::TxStatus::STATELESS_VALIDATION_SUCCESS));
}

// ---------------------------| Stateful statuses |-----------------------------

ProtoTxStatusFactory::FactoryReturnType ProtoTxStatusFactory::makeStatefulFail(
    TransactionHashType hash, TransactionError tx_error) {
  return wrap(fillCommon(
      hash, tx_error, iroha::protocol::TxStatus::STATEFUL_VALIDATION_FAILED));
}
ProtoTxStatusFactory::FactoryReturnType ProtoTxStatusFactory::makeStatefulValid(
    TransactionHashType hash, TransactionError tx_error) {
  return wrap(fillCommon(
      hash, tx_error, iroha::protocol::TxStatus::STATEFUL_VALIDATION_SUCCESS));
}

// -----------------------------| Final statuses |------------------------------

ProtoTxStatusFactory::FactoryReturnType ProtoTxStatusFactory::makeCommitted(
    TransactionHashType hash, TransactionError tx_error) {
  return wrap(fillCommon(hash, tx_error, iroha::protocol::TxStatus::COMMITTED));
}

ProtoTxStatusFactory::FactoryReturnType ProtoTxStatusFactory::makeRejected(
    TransactionHashType hash, TransactionError tx_error) {
  return wrap(fillCommon(hash, tx_error, iroha::protocol::TxStatus::REJECTED));
}

// -----------------------------| Rest statuses |-------------------------------

ProtoTxStatusFactory::FactoryReturnType ProtoTxStatusFactory::makeMstExpired(
    TransactionHashType hash, TransactionError tx_error) {
  return wrap(
      fillCommon(hash, tx_error, iroha::protocol::TxStatus::MST_EXPIRED));
}

ProtoTxStatusFactory::FactoryReturnType ProtoTxStatusFactory::makeMstPending(
    TransactionHashType hash, TransactionError tx_error) {
  return wrap(
      fillCommon(hash, tx_error, iroha::protocol::TxStatus::MST_PENDING));
}

ProtoTxStatusFactory::FactoryReturnType ProtoTxStatusFactory::makeNotReceived(
    TransactionHashType hash, TransactionError tx_error) {
  return wrap(
      fillCommon(hash, tx_error, iroha::protocol::TxStatus::NOT_RECEIVED));
}

ProtoTxStatusFactory::FactoryReturnType
ProtoTxStatusFactory::makeEnoughSignaturesCollected(TransactionHashType hash,
                                                    TransactionError tx_error) {
  return wrap(fillCommon(
      hash, tx_error, iroha::protocol::TxStatus::ENOUGH_SIGNATURES_COLLECTED));
}
