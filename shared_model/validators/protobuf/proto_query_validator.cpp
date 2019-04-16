/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_query_validator.hpp"

#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    void validatePaginationMeta(
        const iroha::protocol::TxPaginationMeta &paginationMeta,
        ReasonsGroupType &reason) {
      if (paginationMeta.opt_first_tx_hash_case()
          != iroha::protocol::TxPaginationMeta::OPT_FIRST_TX_HASH_NOT_SET) {
        if (not validateHexString(paginationMeta.first_tx_hash())) {
          reason.second.emplace_back(
              "First tx hash from pagination meta has invalid format");
        }
      }
    }

    Answer validateProtoQuery(const iroha::protocol::Query &qry) {
      Answer answer;
      std::string tx_reason_name = "Protobuf Query";
      ReasonsGroupType reason(tx_reason_name, GroupedReasons());
      switch (qry.payload().query_case()) {
        case iroha::protocol::Query_Payload::QUERY_NOT_SET: {
          reason.second.emplace_back("query is undefined");
          break;
        }
        case iroha::protocol::Query_Payload::kGetAccountTransactions: {
          const auto &gat = qry.payload().get_account_transactions();
          validatePaginationMeta(gat.pagination_meta(), reason);
          break;
        }
        case iroha::protocol::Query_Payload::kGetAccountAssetTransactions: {
          const auto &gaat = qry.payload().get_account_asset_transactions();
          validatePaginationMeta(gaat.pagination_meta(), reason);
          break;
        }
        default:
          break;
      }
      if (not reason.second.empty()) {
        answer.addReason(std::move(reason));
      }
      return answer;
    }

    Answer ProtoQueryValidator::validate(
        const iroha::protocol::Query &query) const {
      return validateProtoQuery(query);
    }

    Answer ProtoBlocksQueryValidator::validate(
        const iroha::protocol::BlocksQuery &) const {
      return {};
    }

  }  // namespace validation
}  // namespace shared_model
