/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/proto_query_response_factory.hpp"

#include "backend/protobuf/block.hpp"
#include "backend/protobuf/permissions.hpp"
#include "backend/protobuf/query_responses/proto_block_query_response.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction.hpp"
#include "interfaces/common_objects/amount.hpp"
#include "interfaces/common_objects/peer.hpp"

namespace {
  /**
   * Creates a query response using provided lambda and returns unique_ptr to it
   * @tparam QueryResponseCreatorLambda - lambda, which specifies, how to create
   * a query response
   * @param response_creator - that lambda
   * @param query_hash - hash of query, for which response is created
   * @return unique_ptr to created query response
   */
  template <typename QueryResponseCreatorLambda>
  std::unique_ptr<shared_model::interface::QueryResponse> createQueryResponse(
      QueryResponseCreatorLambda response_creator,
      const shared_model::crypto::Hash &query_hash) {
    iroha::protocol::QueryResponse protocol_query_response;
    protocol_query_response.set_query_hash(query_hash.hex());

    response_creator(protocol_query_response);

    return std::make_unique<shared_model::proto::QueryResponse>(
        std::move(protocol_query_response));
  }

  /**
   * Creates a block query response using provided lambda and returns unique_ptr
   * to it
   * @tparam QueryResponseCreatorLambda  - lambda, which specifies, how to
   * create a block query response
   * @param response_creator - that lambda
   * @return unique_ptr to created block query response
   */
  template <typename QueryResponseCreatorLambda>
  std::unique_ptr<shared_model::interface::BlockQueryResponse>
  createQueryResponse(QueryResponseCreatorLambda response_creator) {
    iroha::protocol::BlockQueryResponse protocol_query_response;

    response_creator(protocol_query_response);

    return std::make_unique<shared_model::proto::BlockQueryResponse>(
        std::move(protocol_query_response));
  }
}  // namespace

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createAccountAssetResponse(
    std::vector<std::tuple<interface::types::AccountIdType,
                           interface::types::AssetIdType,
                           shared_model::interface::Amount>> assets,
    size_t total_assets_number,
    std::optional<shared_model::interface::types::AssetIdType> next_asset_id,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [assets = std::move(assets),
       total_assets_number,
       next_asset_id = std::move(next_asset_id)](
          iroha::protocol::QueryResponse &protocol_query_response) {
        iroha::protocol::AccountAssetResponse *protocol_specific_response =
            protocol_query_response.mutable_account_assets_response();
        for (size_t i = 0; i < assets.size(); i++) {
          auto *asset = protocol_specific_response->add_account_assets();
          asset->set_account_id(std::move(std::get<0>(assets.at(i))));
          asset->set_asset_id(std::move(std::get<1>(assets.at(i))));
          asset->set_balance(std::get<2>(assets.at(i)).toStringRepr());
        }
        protocol_specific_response->set_total_number(total_assets_number);
        if (next_asset_id) {
          protocol_specific_response->set_next_asset_id(*next_asset_id);
        }
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createAccountDetailResponse(
    shared_model::interface::types::DetailType account_detail,
    size_t total_number,
    std::optional<std::reference_wrapper<
        const shared_model::interface::AccountDetailRecordId>> next_record_id,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [&account_detail, total_number, &next_record_id](
          iroha::protocol::QueryResponse &protocol_query_response) {
        iroha::protocol::AccountDetailResponse *protocol_specific_response =
            protocol_query_response.mutable_account_detail_response();
        protocol_specific_response->set_detail(account_detail);
        protocol_specific_response->set_total_number(total_number);
        if (next_record_id) {
          auto protocol_next_record_id =
              protocol_specific_response->mutable_next_record_id();
          protocol_next_record_id->set_writer(next_record_id->get().writer());
          protocol_next_record_id->set_key(next_record_id->get().key());
        }
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createAccountResponse(
    const shared_model::interface::types::AccountIdType account_id,
    const shared_model::interface::types::DomainIdType domain_id,
    shared_model::interface::types::QuorumType quorum,
    const shared_model::interface::types::JsonType jsonData,
    std::vector<shared_model::interface::types::RoleIdType> roles,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [account_id = std::move(account_id),
       domain_id = std::move(domain_id),
       jsonData = std::move(jsonData),
       quorum,
       roles = std::move(roles)](
          iroha::protocol::QueryResponse &protocol_query_response) {
        iroha::protocol::AccountResponse *protocol_specific_response =
            protocol_query_response.mutable_account_response();
        auto *account = protocol_specific_response->mutable_account();
        account->set_account_id(std::move(account_id));
        account->set_domain_id(std::move(domain_id));
        account->set_quorum(quorum);
        account->set_json_data(std::move(jsonData));
        for (const auto &role : roles) {
          protocol_specific_response->add_account_roles(std::move(role));
        }
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createBlockResponse(
    std::unique_ptr<shared_model::interface::Block> block,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [block = std::move(block)](
          iroha::protocol::QueryResponse &protocol_query_response) {
        iroha::protocol::BlockResponse *protocol_specific_response =
            protocol_query_response.mutable_block_response();
        *protocol_specific_response->mutable_block()->mutable_block_v1() =
            static_cast<shared_model::proto::Block *>(block.get())
                ->getTransport();
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createErrorQueryResponse(
    ErrorQueryType error_type,
    interface::ErrorQueryResponse::ErrorMessageType error_msg,
    interface::ErrorQueryResponse::ErrorCodeType error_code,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [error_type, error_msg = std::move(error_msg), error_code](
          iroha::protocol::QueryResponse &protocol_query_response) mutable {
        iroha::protocol::ErrorResponse_Reason reason;
        switch (error_type) {
          case ErrorQueryType::kStatelessFailed:
            reason = iroha::protocol::ErrorResponse_Reason_STATELESS_INVALID;
            break;
          case ErrorQueryType::kStatefulFailed:
            reason = iroha::protocol::ErrorResponse_Reason_STATEFUL_INVALID;
            break;
          case ErrorQueryType::kNoAccount:
            reason = iroha::protocol::ErrorResponse_Reason_NO_ACCOUNT;
            break;
          case ErrorQueryType::kNoAccountAssets:
            reason = iroha::protocol::ErrorResponse_Reason_NO_ACCOUNT_ASSETS;
            break;
          case ErrorQueryType::kNoAccountDetail:
            reason = iroha::protocol::ErrorResponse_Reason_NO_ACCOUNT_DETAIL;
            break;
          case ErrorQueryType::kNoSignatories:
            reason = iroha::protocol::ErrorResponse_Reason_NO_SIGNATORIES;
            break;
          case ErrorQueryType::kNotSupported:
            reason = iroha::protocol::ErrorResponse_Reason_NOT_SUPPORTED;
            break;
          case ErrorQueryType::kNoAsset:
            reason = iroha::protocol::ErrorResponse_Reason_NO_ASSET;
            break;
          case ErrorQueryType::kNoRoles:
            reason = iroha::protocol::ErrorResponse_Reason_NO_ROLES;
            break;
        }
        iroha::protocol::ErrorResponse *protocol_specific_response =
            protocol_query_response.mutable_error_response();
        protocol_specific_response->set_reason(reason);
        protocol_specific_response->set_message(std::move(error_msg));
        protocol_specific_response->set_error_code(error_code);
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createSignatoriesResponse(
    std::vector<std::string> signatories,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [signatories = std::move(signatories)](
          iroha::protocol::QueryResponse &protocol_query_response) {
        iroha::protocol::SignatoriesResponse *protocol_specific_response =
            protocol_query_response.mutable_signatories_response();
        for (const auto &key : signatories) {
          protocol_specific_response->add_keys(key);
        }
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createTransactionsResponse(
    std::vector<std::unique_ptr<shared_model::interface::Transaction>>
        transactions,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [transactions = std::move(transactions)](
          iroha::protocol::QueryResponse &protocol_query_response) {
        iroha::protocol::TransactionsResponse *protocol_specific_response =
            protocol_query_response.mutable_transactions_response();
        for (const auto &tx : transactions) {
          *protocol_specific_response->add_transactions() =
              static_cast<shared_model::proto::Transaction *>(tx.get())
                  ->getTransport();
        }
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createTransactionsPageResponse(
    std::vector<std::unique_ptr<shared_model::interface::Transaction>>
        transactions,
    std::optional<std::reference_wrapper<const crypto::Hash>> next_tx_hash,
    interface::types::TransactionsNumberType all_transactions_size,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [transactions = std::move(transactions),
       &next_tx_hash,
       &all_transactions_size](
          iroha::protocol::QueryResponse &protocol_query_response) {
        auto *protocol_specific_response =
            protocol_query_response.mutable_transactions_page_response();
        for (const auto &tx : transactions) {
          *protocol_specific_response->add_transactions() =
              static_cast<shared_model::proto::Transaction *>(tx.get())
                  ->getTransport();
        }
        if (next_tx_hash) {
          protocol_specific_response->set_next_tx_hash(
              next_tx_hash.value().get().hex());
        }
        protocol_specific_response->set_all_transactions_size(
            all_transactions_size);
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse> shared_model::proto::
    ProtoQueryResponseFactory::createPendingTransactionsPageResponse(
        std::vector<std::unique_ptr<shared_model::interface::Transaction>>
            transactions,
        interface::types::TransactionsNumberType all_transactions_size,
        std::optional<interface::PendingTransactionsPageResponse::BatchInfo>
            next_batch_info,
        const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [transactions = std::move(transactions),
       &all_transactions_size,
       &next_batch_info](
          iroha::protocol::QueryResponse &protocol_query_response) {
        auto *protocol_specific_response =
            protocol_query_response
                .mutable_pending_transactions_page_response();
        for (const auto &tx : transactions) {
          *protocol_specific_response->add_transactions() =
              static_cast<shared_model::proto::Transaction *>(tx.get())
                  ->getTransport();
        }
        protocol_specific_response->set_all_transactions_size(
            all_transactions_size);
        if (next_batch_info) {
          auto *next_batch_info_message =
              protocol_specific_response->mutable_next_batch_info();
          next_batch_info_message->set_first_tx_hash(
              next_batch_info->first_tx_hash.hex());
          next_batch_info_message->set_batch_size(next_batch_info->batch_size);
        }
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createAssetResponse(
    const interface::types::AssetIdType asset_id,
    const interface::types::DomainIdType domain_id,
    const interface::types::PrecisionType precision,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [asset_id = std::move(asset_id),
       domain_id = std::move(domain_id),
       precision](iroha::protocol::QueryResponse &protocol_query_response) {
        iroha::protocol::AssetResponse *protocol_specific_response =
            protocol_query_response.mutable_asset_response();
        auto *asset = protocol_specific_response->mutable_asset();
        asset->set_asset_id(std::move(asset_id));
        asset->set_domain_id(std::move(domain_id));
        asset->set_precision(precision);
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createRolesResponse(
    std::vector<shared_model::interface::types::RoleIdType> roles,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [roles = std::move(roles)](
          iroha::protocol::QueryResponse &protocol_query_response) mutable {
        iroha::protocol::RolesResponse *protocol_specific_response =
            protocol_query_response.mutable_roles_response();
        for (auto &&role : roles) {
          protocol_specific_response->add_roles(std::move(role));
        }
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createRolePermissionsResponse(
    shared_model::interface::RolePermissionSet role_permissions,
    const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [role_permissions](
          iroha::protocol::QueryResponse &protocol_query_response) {
        iroha::protocol::RolePermissionsResponse *protocol_specific_response =
            protocol_query_response.mutable_role_permissions_response();
        for (size_t i = 0; i < role_permissions.size(); ++i) {
          auto perm = static_cast<interface::permissions::Role>(i);
          if (role_permissions.isSet(perm)) {
            protocol_specific_response->add_permissions(
                shared_model::proto::permissions::toTransport(perm));
          }
        }
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createPeersResponse(
    interface::types::PeerList peers, const crypto::Hash &query_hash) const {
  return createQueryResponse(
      [peers](iroha::protocol::QueryResponse &protocol_query_response) {
        auto *protocol_specific_response =
            protocol_query_response.mutable_peers_response();
        for (const auto &peer : peers) {
          auto *proto_peer = protocol_specific_response->add_peers();
          proto_peer->set_address(peer->address());
          proto_peer->set_peer_key(peer->pubkey());
        }
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::QueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createEngineReceiptsResponse(
    std::vector<std::unique_ptr<shared_model::interface::EngineReceipt>> const
        &engine_receipts,
    crypto::Hash const &query_hash) const {
  return createQueryResponse(
      [&](iroha::protocol::QueryResponse &protocol_query_response) {
        auto *protocol_specific_response =
            protocol_query_response.mutable_engine_receipts_response();

        for (auto const &receipt : engine_receipts) {
          auto *proto_receipt =
              protocol_specific_response->add_engine_receipts();

          /// assign logs
          for (auto const &e_log : receipt->getEngineLogs()) {
            assert(!!e_log);
            auto *p_log = proto_receipt->add_logs();
            p_log->set_address(e_log->getAddress());
            p_log->set_data(e_log->getData());
            for (auto &topic : e_log->getTopics()) {
              p_log->add_topics(topic);
            }
          }

          proto_receipt->set_command_index(receipt->getCommandIndex());
          proto_receipt->set_caller(receipt->getCaller());

          if (interface::EngineReceipt::PayloadType::kPayloadTypeCallResult
              == receipt->getPayloadType()) {
            auto *ptr_call_result = proto_receipt->mutable_call_result();
            ptr_call_result->set_callee(receipt->getResponseData()->callee);
            if (!!receipt->getResponseData()->response_data)
              ptr_call_result->set_result_data(
                  *receipt->getResponseData()->response_data);
          }

          if (interface::EngineReceipt::PayloadType::kPayloadTypeContractAddress
              == receipt->getPayloadType()) {
            proto_receipt->set_contract_address(*receipt->getContractAddress());
          }
        }
      },
      query_hash);
}

std::unique_ptr<shared_model::interface::BlockQueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createBlockQueryResponse(
    std::shared_ptr<const shared_model::interface::Block> block) const {
  return createQueryResponse(
      [block = std::move(block)](
          iroha::protocol::BlockQueryResponse &protocol_query_response) {
        iroha::protocol::BlockResponse *protocol_specific_response =
            protocol_query_response.mutable_block_response();
        *protocol_specific_response->mutable_block()->mutable_block_v1() =
            static_cast<const shared_model::proto::Block *>(block.get())
                ->getTransport();
      });
}

std::unique_ptr<shared_model::interface::BlockQueryResponse>
shared_model::proto::ProtoQueryResponseFactory::createBlockQueryResponse(
    std::string error_message) const {
  return createQueryResponse(
      [error_message = std::move(error_message)](
          iroha::protocol::BlockQueryResponse &protocol_query_response) {
        iroha::protocol::BlockErrorResponse *protocol_specific_response =
            protocol_query_response.mutable_block_error_response();
        protocol_specific_response->set_message(error_message);
      });
}
