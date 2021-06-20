/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "client.hpp"

#include "backend/protobuf/queries/proto_query.hpp"
#include "backend/protobuf/transaction.hpp"
#include "model/converters/json_query_factory.hpp"
#include "model/converters/json_transaction_factory.hpp"
#include "model/converters/pb_query_factory.hpp"
#include "model/converters/pb_transaction_factory.hpp"
#include "network/impl/channel_factory.hpp"

template <typename Service>
std::unique_ptr<typename Service::StubInterface> makeStub(std::string target_ip,
                                                          int port) {
  using namespace iroha::network;
  return createInsecureClient<Service>(target_ip, port, std::nullopt);
}

namespace iroha_cli {

  CliClient::CliClient(std::string target_ip,
                       int port,
                       logger::LoggerPtr pb_qry_factory_log)
      : command_client_(
            makeStub<torii::CommandSyncClient::Service>(target_ip, port),
            pb_qry_factory_log),
        query_client_(
            makeStub<torii_utils::QuerySyncClient::Service>(target_ip, port)),
        pb_qry_factory_log_(std::move(pb_qry_factory_log)) {}

  CliClient::Response<CliClient::TxStatus> CliClient::sendTx(
      const shared_model::interface::Transaction &tx) {
    const auto proto_tx =
        static_cast<const shared_model::proto::Transaction &>(tx);
    CliClient::Response<CliClient::TxStatus> response;
    // Send to iroha:
    response.status = command_client_.Torii(proto_tx.getTransport());

    // TODO 12/10/2017 neewy implement return of real transaction status IR-494
    response.answer = TxStatus::OK;

    return response;
  }

  CliClient::Response<iroha::protocol::ToriiResponse> CliClient::getTxStatus(
      std::string tx_hash) {
    CliClient::Response<iroha::protocol::ToriiResponse> response;
    // Send to iroha:
    iroha::protocol::TxStatusRequest statusRequest;
    statusRequest.set_tx_hash(tx_hash);
    iroha::protocol::ToriiResponse toriiResponse;
    response.status = command_client_.Status(statusRequest, toriiResponse);
    response.answer = toriiResponse;

    return response;
  }

  CliClient::Response<iroha::protocol::QueryResponse> CliClient::sendQuery(
      const shared_model::interface::Query &query) {
    CliClient::Response<iroha::protocol::QueryResponse> response;
    // Convert to proto and send to Iroha
    iroha::model::converters::PbQueryFactory pb_factory(pb_qry_factory_log_);
    auto proto_query = static_cast<const shared_model::proto::Query &>(query);
    iroha::protocol::QueryResponse query_response;
    response.status =
        query_client_.Find(proto_query.getTransport(), query_response);
    response.answer = query_response;
    return response;
  }

}  // namespace iroha_cli
