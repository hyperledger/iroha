/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_query_validator.hpp"

#include <google/protobuf/util/time_util.h>
#include <ciso646>

#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

using namespace shared_model::validation;

namespace {
  std::optional<ValidationError> validateTxPaginationMeta(
      const iroha::protocol::TxPaginationMeta &paginationMeta) {
    if (paginationMeta.opt_first_tx_hash_case()
        != iroha::protocol::TxPaginationMeta::OPT_FIRST_TX_HASH_NOT_SET) {
      if (not validateHexString(paginationMeta.first_tx_hash())) {
        return shared_model::validation::ValidationError{
            "TxPaginationMeta",
            {"First tx hash from pagination meta is not a hex string."}};
      }
    }
    if (paginationMeta.opt_first_tx_time_case()
        != iroha::protocol::TxPaginationMeta::OPT_FIRST_TX_TIME_NOT_SET) {
      if (not validateTimeStamp(
              google::protobuf::util::TimeUtil::TimestampToMilliseconds(
                  paginationMeta.first_tx_time()))) {
        return shared_model::validation::ValidationError{
            "TxPaginationMeta",
            {"First tx time from pagination meta is not a "
             "proper value."}};
      }
    }
    if (paginationMeta.opt_last_tx_time_case()
        != iroha::protocol::TxPaginationMeta::OPT_LAST_TX_TIME_NOT_SET) {
      if (not validateTimeStamp(
              google::protobuf::util::TimeUtil::TimestampToMilliseconds(
                  paginationMeta.last_tx_time()))) {
        return shared_model::validation::ValidationError{
            "TxPaginationMeta",
            {"Last tx time from pagination meta is not a proper value."}};
      }
    }
    if (paginationMeta.opt_first_tx_height_case()
        != iroha::protocol::TxPaginationMeta::OPT_FIRST_TX_HEIGHT_NOT_SET) {
      if (not validateHeight(paginationMeta.first_tx_height())) {
        return shared_model::validation::ValidationError{
            "TxPaginationMeta",
            {"First tx Height from pagination meta is not a proper value."}};
      }
    }
    if (paginationMeta.opt_last_tx_height_case()
        != iroha::protocol::TxPaginationMeta::OPT_LAST_TX_HEIGHT_NOT_SET) {
      if (not validateHeight(paginationMeta.last_tx_height())) {
        return shared_model::validation::ValidationError{
            "TxPaginationMeta",
            {"Last tx Height from pagination meta is not a proper value."}};
      }
    }
    if (paginationMeta.opt_first_tx_height_case()
            != iroha::protocol::TxPaginationMeta::OPT_FIRST_TX_HEIGHT_NOT_SET
        && paginationMeta.opt_last_tx_height_case()
            != iroha::protocol::TxPaginationMeta::OPT_LAST_TX_HEIGHT_NOT_SET) {
      if (not validateHeightOrder(paginationMeta.first_tx_height(),
              paginationMeta.last_tx_height())) {
        return shared_model::validation::ValidationError{
            "TxPaginationMeta",
            {"Last tx Height from pagination meta should be equal or greater than first tx height"}};
      }
    }
    if (paginationMeta.opt_first_tx_time_case()
            != iroha::protocol::TxPaginationMeta::OPT_FIRST_TX_TIME_NOT_SET
        && paginationMeta.opt_last_tx_time_case()
            != iroha::protocol::TxPaginationMeta::OPT_LAST_TX_TIME_NOT_SET) {
      if (not validateTimeOrder(
              google::protobuf::util::TimeUtil::TimestampToMilliseconds(
                  paginationMeta.first_tx_time()),
              google::protobuf::util::TimeUtil::TimestampToMilliseconds(
                  paginationMeta.last_tx_time()))) {
        return shared_model::validation::ValidationError{
            "TxPaginationMeta",
            {"Last tx time from pagination meta should be equal or greater "
             "than first tx time"}};
      }
    }
    return std::nullopt;
  }
}  // namespace

namespace shared_model {
  namespace validation {

    std::optional<ValidationError> validateProtoQuery(
        const iroha::protocol::Query &qry) {
      ValidationErrorCreator error_creator;

      switch (qry.payload().query_case()) {
        case iroha::protocol::Query_Payload::QUERY_NOT_SET: {
          error_creator.addReason("Query is undefined.");
          break;
        }
        case iroha::protocol::Query_Payload::kGetAccountTransactions: {
          const auto &gat = qry.payload().get_account_transactions();
          error_creator |= validateTxPaginationMeta(gat.pagination_meta());
          break;
        }
        case iroha::protocol::Query_Payload::kGetAccountAssetTransactions: {
          const auto &gaat = qry.payload().get_account_asset_transactions();
          error_creator |= validateTxPaginationMeta(gaat.pagination_meta());
          break;
        }
        //this lines validate TxPaginationMeta in GetPendingTransactions
        case iroha::protocol::Query_Payload::kGetPendingTransactions: {
          const auto &gaat = qry.payload().get_pending_transactions();
          error_creator |= validateTxPaginationMeta(gaat.pagination_meta());
          break;
        }
        default:
          break;
      }

      return std::move(error_creator).getValidationError("Protobuf Query");
    }

    std::optional<ValidationError> ProtoQueryValidator::validate(
        const iroha::protocol::Query &query) const {
      return validateProtoQuery(query);
    }

    std::optional<ValidationError> ProtoBlocksQueryValidator::validate(
        const iroha::protocol::BlocksQuery &) const {
      return std::nullopt;
    }

  }  // namespace validation
}  // namespace shared_model
