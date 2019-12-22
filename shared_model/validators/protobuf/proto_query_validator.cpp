/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_query_validator.hpp"

#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

using namespace shared_model::validation;

namespace {
  boost::optional<ValidationError> validateTxPaginationMeta(
      const iroha::protocol::TxPaginationMeta &paginationMeta) {
    if (paginationMeta.opt_first_tx_hash_case()
        != iroha::protocol::TxPaginationMeta::OPT_FIRST_TX_HASH_NOT_SET) {
      if (not validateHexString(paginationMeta.first_tx_hash())) {
        return shared_model::validation::ValidationError{
            "TxPaginationMeta",
            {"First tx hash from pagination meta is not a hex string."}};
      }
    }
    return boost::none;
  }
}  // namespace

namespace shared_model {
  namespace validation {

    boost::optional<ValidationError> validateProtoQuery(
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
        default:
          break;
      }

      return std::move(error_creator).getValidationError("Protobuf Query");
    }

    boost::optional<ValidationError> ProtoQueryValidator::validate(
        const iroha::protocol::Query &query) const {
      return validateProtoQuery(query);
    }

    boost::optional<ValidationError> ProtoBlocksQueryValidator::validate(
        const iroha::protocol::BlocksQuery &) const {
      return boost::none;
    }

  }  // namespace validation
}  // namespace shared_model
