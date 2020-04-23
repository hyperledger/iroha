/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/default_constructible_unary_fn.hpp"  // non-copyable value workaround

#include "multi_sig_transactions/transport/mst_transport_grpc.hpp"

#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <rxcpp/rx-lite.hpp>
#include "ametsuchi/tx_presence_cache.hpp"
#include "ametsuchi/tx_presence_cache_utils.hpp"
#include "backend/protobuf/deserialize_repeated_transactions.hpp"
#include "backend/protobuf/transaction.hpp"
#include "interfaces/iroha_internal/parse_and_create_batches.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "multi_sig_transactions/mst_types.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"
#include "network/impl/grpc_channel_builder.hpp"
#include "validators/field_validator.hpp"

using namespace iroha;
using namespace iroha::network;

using shared_model::interface::types::PublicKeyHexStringView;

namespace {
  auto default_sender_factory = [](const shared_model::interface::Peer &to) {
    return createClient<transport::MstTransportGrpc>(to.address());
  };
}
void sendStateAsyncImpl(
    const shared_model::interface::Peer &to,
    MstState const &state,
    PublicKeyHexStringView sender_key,
    AsyncGrpcClient<google::protobuf::Empty> &async_call,
    std::function<void(grpc::Status &, google::protobuf::Empty &)> on_response =
        {},
    MstTransportGrpc::SenderFactory sender_factory = default_sender_factory);

MstTransportGrpc::MstTransportGrpc(
    std::shared_ptr<AsyncGrpcClient<google::protobuf::Empty>> async_call,
    std::shared_ptr<TransportFactoryType> transaction_factory,
    std::shared_ptr<shared_model::interface::TransactionBatchParser>
        batch_parser,
    std::shared_ptr<shared_model::interface::TransactionBatchFactory>
        transaction_batch_factory,
    std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache,
    std::shared_ptr<Completer> mst_completer,
    PublicKeyHexStringView my_key,
    logger::LoggerPtr mst_state_logger,
    logger::LoggerPtr log,
    boost::optional<SenderFactory> sender_factory)
    : async_call_(std::move(async_call)),
      transaction_factory_(std::move(transaction_factory)),
      batch_parser_(std::move(batch_parser)),
      batch_factory_(std::move(transaction_batch_factory)),
      tx_presence_cache_(std::move(tx_presence_cache)),
      mst_completer_(std::move(mst_completer)),
      my_key_(my_key),
      mst_state_logger_(std::move(mst_state_logger)),
      log_(std::move(log)),
      sender_factory_(sender_factory) {}

grpc::Status MstTransportGrpc::SendState(
    ::grpc::ServerContext *context,
    const ::iroha::network::transport::MstState *request,
    ::google::protobuf::Empty *response) {
  log_->info("MstState Received");

  auto transactions = shared_model::proto::deserializeTransactions(
      *transaction_factory_, request->transactions());
  if (auto e = expected::resultToOptionalError(transactions)) {
    log_->warn(
        "Transaction deserialization failed: hash {}, {}", e->hash, e->error);
    return ::grpc::Status::OK;
  }

  auto batches = shared_model::interface::parseAndCreateBatches(
      *batch_parser_, *batch_factory_, std::move(transactions).assumeValue());
  if (auto e = expected::resultToOptionalError(batches)) {
    log_->warn("Batch deserialization failed: {}", *e);
    return ::grpc::Status::OK;
  }
  MstState new_state = MstState::empty(mst_state_logger_, mst_completer_);
  auto opt_batches = expected::resultToOptionalValue(std::move(batches));
  for (auto &batch : *opt_batches) {
    auto cache_presence = tx_presence_cache_->check(*batch);
    if (not cache_presence) {
      // TODO andrei 30.11.18 IR-51 Handle database error
      log_->warn("Check tx presence database error. Batch: {}", *batch);
      continue;
    }
    auto is_replay = std::any_of(
        cache_presence->begin(),
        cache_presence->end(),
        &iroha::ametsuchi::isAlreadyProcessed);

    if (not is_replay) {
      new_state += std::move(batch);
    }
  }

  log_->info("batches in MstState: {}", new_state.getBatches().size());

  const auto &source_key = request->source_peer_key();
  auto key_invalid_reason =
      shared_model::validation::validatePubkey(source_key);
  if (key_invalid_reason) {
    log_->info("Dropping received MST State due to invalid public key: {}",
               *key_invalid_reason);
    return grpc::Status::OK;
  }

  if (new_state.isEmpty()) {
    log_->info(
        "All transactions from received MST state have been processed already, "
        "nothing to propagate to MST processor");
    return grpc::Status::OK;
  }

  if (auto subscriber = subscriber_.lock()) {
    subscriber->onNewState(PublicKeyHexStringView{source_key},
                           std::move(new_state));
  } else {
    log_->warn("No subscriber for MST SendState event is set");
  }

  return grpc::Status::OK;
}

void MstTransportGrpc::subscribe(
    std::shared_ptr<MstTransportNotification> notification) {
  subscriber_ = notification;
}

rxcpp::observable<bool> MstTransportGrpc::sendState(
    std::shared_ptr<shared_model::interface::Peer const> to,
    MstState const &providing_state) {
  return rxcpp::observable<>::create<bool>(
      [log_ = std::weak_ptr<logger::Logger>(log_),
       to = std::move(to),
       providing_state,
       my_key = my_key_,
       async_call_ =
           std::weak_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>(
               async_call_),
       sender_factory =
           sender_factory_.value_or(default_sender_factory)](auto s) {
        auto log = log_.lock();
        auto async_call = async_call_.lock();

        if (log and async_call) {
          log->info("Propagate MstState to peer {}", to->address());
          sendStateAsyncImpl(*to,
                             providing_state,
                             PublicKeyHexStringView{my_key},
                             *async_call,
                             [s](auto &status, auto &) {
                               s.on_next(status.ok());
                               s.on_completed();
                             },
                             sender_factory);
        }
      });
}

void iroha::network::sendStateAsync(
    const shared_model::interface::Peer &to,
    MstState const &state,
    PublicKeyHexStringView sender_key,
    AsyncGrpcClient<google::protobuf::Empty> &async_call,
    std::function<void(grpc::Status &, google::protobuf::Empty &)>
        on_response) {
  sendStateAsyncImpl(to, state, sender_key, async_call, std::move(on_response));
}

void sendStateAsyncImpl(
    shared_model::interface::Peer const &to,
    MstState const &state,
    PublicKeyHexStringView sender_key,
    AsyncGrpcClient<google::protobuf::Empty> &async_call,
    std::function<void(grpc::Status &, google::protobuf::Empty &)> on_response,
    MstTransportGrpc::SenderFactory sender_factory) {
  transport::MstState proto_state;
  std::string_view sender_key_sv = sender_key;
  proto_state.set_source_peer_key(sender_key_sv.data(), sender_key_sv.size());
  state.iterateTransactions([&proto_state](auto const &tx) {
    // TODO (@l4l) 04/03/18 simplify with IR-1040
    *proto_state.add_transactions() =
        std::static_pointer_cast<shared_model::proto::Transaction>(tx)
            ->getTransport();
  });
  async_call.Call(
      [client = sender_factory(to), proto_state = std::move(proto_state)](
          auto context, auto cq) {
        return client->AsyncSendState(context, proto_state, cq);
      },
      std::move(on_response));
}
