/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/query_service.hpp"

#include "backend/protobuf/block.hpp"
#include "backend/protobuf/query_responses/proto_block_query_response.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/util.hpp"
#include "cryptography/default_hash_provider.hpp"
#include "interfaces/iroha_internal/abstract_transport_factory.hpp"
#include "logger/logger.hpp"
#include "main/subscription.hpp"
#include "subscription/scheduler_impl.hpp"
#include "validators/default_validator.hpp"

using iroha::torii::QueryService;

QueryService::QueryService(
    std::shared_ptr<iroha::torii::QueryProcessor> query_processor,
    std::shared_ptr<QueryFactoryType> query_factory,
    std::shared_ptr<BlocksQueryFactoryType> blocks_query_factory,
    logger::LoggerPtr log,
    std::shared_ptr<iroha::BaseSubscriber<
        iroha::utils::ReadWriteObject<iroha::IrohaStoredStatus, std::mutex>,
        iroha::IrohaStatus>> iroha_status_subscription)
    : query_processor_{std::move(query_processor)},
      query_factory_{std::move(query_factory)},
      blocks_query_factory_{std::move(blocks_query_factory)},
      log_{std::move(log)},
      iroha_status_subscription_(std::move(iroha_status_subscription)) {}

void QueryService::Find(iroha::protocol::Query const &request,
                        iroha::protocol::QueryResponse &response) {
  shared_model::crypto::Hash hash;
  auto blobPayload = shared_model::proto::makeBlob(request.payload());
  hash = shared_model::crypto::DefaultHashProvider::makeHash(blobPayload);

  if (cache_.findItem(hash)) {
    // Query was already processed
    response.mutable_error_response()->set_reason(
        iroha::protocol::ErrorResponse::STATELESS_INVALID);
    return;
  }

  query_factory_->build(request).match(
      [this, &hash, &response](const auto &query) {
        query_processor_->queryHandle(*query.value) |
            [&](auto &&iface_response) {
              // Send query to iroha
              response = static_cast<shared_model::proto::QueryResponse &>(
                             *iface_response)
                             .getTransport();
              // TODO 18.02.2019 lebdron: IR-336 Replace cache
              // 0 is used as a dummy value
              cache_.addItem(hash, 0);
              return iroha::expected::Value<void>{};
            };
      },
      [&hash, &response](auto &&error) {
        response.set_query_hash(hash.hex());
        response.mutable_error_response()->set_reason(
            iroha::protocol::ErrorResponse::STATELESS_INVALID);
        response.mutable_error_response()->set_message(
            std::move(error.error.error));
      });
}

grpc::Status QueryService::Find(grpc::ServerContext *context,
                                const iroha::protocol::Query *request,
                                iroha::protocol::QueryResponse *response) {
  Find(*request, *response);
  return grpc::Status::OK;
}

grpc::Status QueryService::Healthcheck(
    grpc::ServerContext *context,
    const google::protobuf::Empty *request,
    iroha::protocol::HealthcheckData *response) {
  if (iroha_status_subscription_)
    iroha_status_subscription_->get().exclusiveAccess(
        [&](iroha::IrohaStoredStatus &status) {
          if (status.status.is_syncing)
            response->set_is_syncing(*status.status.is_syncing);
          if (status.status.is_healthy)
            response->set_is_healthy(*status.status.is_healthy);
          if (status.status.memory_consumption)
            response->set_memory_consumption(*status.status.memory_consumption);
          if (status.status.last_round) {
            response->set_last_block_height(
                status.status.last_round->block_round);
            response->set_last_block_reject(
                status.status.last_round->reject_round);
          }
        });
  return grpc::Status::OK;
}

grpc::Status QueryService::FetchCommits(
    grpc::ServerContext *context,
    const iroha::protocol::BlocksQuery *request,
    grpc::ServerWriter<iroha::protocol::BlockQueryResponse> *writer) {
  log_->debug("Fetching commits");

  auto maybe_query = blocks_query_factory_->build(*request);
  if (iroha::expected::hasError(maybe_query)) {
    log_->debug("Stateless invalid: {}", maybe_query.assumeError().error);
    iroha::protocol::BlockQueryResponse response;
    response.mutable_block_error_response()->set_message(
        std::move(maybe_query.assumeError().error));
    writer->WriteLast(response, grpc::WriteOptions());
    return grpc::Status::OK;
  }

  auto maybe_result =
      query_processor_->blocksQueryHandle(*maybe_query.assumeValue());
  if (iroha::expected::hasError(maybe_result)) {
    log_->debug("Query processor error: {}", maybe_result.assumeError());
    iroha::protocol::BlockQueryResponse response;
    response.mutable_block_error_response()->set_message(
        std::move(maybe_result.assumeError()));
    writer->WriteLast(response, grpc::WriteOptions());
    return grpc::Status::OK;
  }

  std::string client_id = fmt::format("Peer: '{}'", context->peer());

  auto scheduler = std::make_shared<iroha::subscription::SchedulerBase>();
  auto tid = iroha::getSubscription()->dispatcher()->bind(scheduler);

  auto batches_subscription =
      SubscriberCreator<bool,
                        std::shared_ptr<shared_model::interface::Block const>>::
          template create<EventTypes::kOnBlock>(
              static_cast<iroha::SubscriptionEngineHandlers>(*tid),
              [&](auto, auto block) {
                if (context->IsCancelled()) {
                  log_->debug("Unsubscribed from block stream");
                  scheduler->dispose();
                  return;
                }

                log_->debug("{} receives {}",
                            request->meta().creator_account_id(),
                            *block);

                iroha::protocol::BlockQueryResponse response;
                *response.mutable_block_response()
                     ->mutable_block()
                     ->mutable_block_v1() =
                    std::static_pointer_cast<shared_model::proto::Block const>(
                        block)
                        ->getTransport();

                if (not writer->Write(response)) {
                  log_->error("write to stream has failed to client {}",
                              client_id);
                  scheduler->dispose();
                  return;
                }
              });

  scheduler->process();

  getSubscription()->dispatcher()->unbind(*tid);

  log_->debug("block stream done, {}", client_id);

  return grpc::Status::OK;
}
