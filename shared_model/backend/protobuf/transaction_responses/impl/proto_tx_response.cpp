/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"

#include <limits>

#include "backend/protobuf/transaction_responses/proto_concrete_tx_response.hpp"
#include "common/result.hpp"
#include "common/variant_transform.hpp"
#include "common/visitor.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/hash.hpp"
#include "endpoint.pb.h"

using namespace shared_model::proto;

namespace {
  using PbTxResponse = iroha::protocol::ToriiResponse;
  /// Variant type, that contains all concrete tx responses in the system
  using ProtoResponseVariantType =
      iroha::VariantOfUniquePtr<StatelessFailedTxResponse,
                                StatelessValidTxResponse,
                                StatefulFailedTxResponse,
                                StatefulValidTxResponse,
                                RejectedTxResponse,
                                CommittedTxResponse,
                                MstExpiredResponse,
                                NotReceivedTxResponse,
                                MstPendingResponse,
                                EnoughSignaturesCollectedResponse>;

  constexpr int kMaxPriority = std::numeric_limits<int>::max();

  iroha::expected::Result<ProtoResponseVariantType, std::string> load(
      PbTxResponse &proto) {
    using iroha::protocol::TxStatus;
    switch (proto.tx_status()) {
      case TxStatus::STATELESS_VALIDATION_FAILED:
        return std::make_unique<StatelessFailedTxResponse>(proto);
      case TxStatus::STATELESS_VALIDATION_SUCCESS:
        return std::make_unique<StatelessValidTxResponse>(proto);
      case TxStatus::STATEFUL_VALIDATION_FAILED:
        return std::make_unique<StatefulFailedTxResponse>(proto);
      case TxStatus::STATEFUL_VALIDATION_SUCCESS:
        return std::make_unique<StatefulValidTxResponse>(proto);
      case TxStatus::REJECTED:
        return std::make_unique<RejectedTxResponse>(proto);
      case TxStatus::COMMITTED:
        return std::make_unique<CommittedTxResponse>(proto);
      case TxStatus::MST_EXPIRED:
        return std::make_unique<MstExpiredResponse>(proto);
      case TxStatus::NOT_RECEIVED:
        return std::make_unique<NotReceivedTxResponse>(proto);
      case TxStatus::MST_PENDING:
        return std::make_unique<MstPendingResponse>(proto);
      case TxStatus::ENOUGH_SIGNATURES_COLLECTED:
        return std::make_unique<EnoughSignaturesCollectedResponse>(proto);
      default:
        return "Unknown response.";
    };
  }
}  // namespace

struct TransactionResponse::Impl {
  explicit Impl(TransportType proto,
                ProtoResponseVariantType response_holder,
                crypto::Hash hash)
      : proto_(std::move(proto)),
        response_holder_(std::move(response_holder)),
        response_constref_(boost::apply_visitor(
            iroha::indirecting_visitor<ResponseVariantType>, response_holder_)),
        hash_(std::move(hash)) {}

  TransportType proto_;
  ProtoResponseVariantType response_holder_;
  ResponseVariantType response_constref_;
  crypto::Hash hash_;
};

iroha::expected::Result<std::unique_ptr<TransactionResponse>, std::string>
TransactionResponse::create(TransportType proto) {
  return load(proto) | [&](auto &&response) {
    return shared_model::crypto::Blob::fromHexString(proto.tx_hash()) |
        [&](auto &&hash) {
          return std::unique_ptr<TransactionResponse>(
              new TransactionResponse(std::make_unique<Impl>(
                  std::move(proto),
                  std::move(response),
                  shared_model::crypto::Hash{std::move(hash)})));
        };
  };
}

TransactionResponse::TransactionResponse(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

TransactionResponse::~TransactionResponse() = default;

const shared_model::interface::types::HashType &
TransactionResponse::transactionHash() const {
  return impl_->hash_;
}

const TransactionResponse::ResponseVariantType &TransactionResponse::get()
    const {
  return impl_->response_constref_;
}

const TransactionResponse::StatelessErrorOrFailedCommandNameType &
TransactionResponse::statelessErrorOrCommandName() const {
  return impl_->proto_.err_or_cmd_name();
}

TransactionResponse::FailedCommandIndexType
TransactionResponse::failedCommandIndex() const {
  return impl_->proto_.failed_cmd_index();
}

TransactionResponse::ErrorCodeType TransactionResponse::errorCode() const {
  return impl_->proto_.error_code();
}

int TransactionResponse::priority() const noexcept {
  using namespace shared_model;
  return iroha::visit_in_place(
      impl_->response_constref_,
      // not received can be changed to any response
      [](const interface::NotReceivedTxResponse &) { return 0; },
      // following types are sequential in pipeline
      [](const interface::StatelessValidTxResponse &) { return 1; },
      [](const interface::MstPendingResponse &) { return 2; },
      [](const interface::EnoughSignaturesCollectedResponse &) { return 3; },
      [](const interface::StatefulValidTxResponse &) { return 4; },
      // following types are local on this peer and can be substituted by
      // final ones, if consensus decides so
      [](const interface::StatelessFailedTxResponse &) { return 5; },
      [](const interface::StatefulFailedTxResponse &) { return 5; },
      [](const interface::MstExpiredResponse &) { return 5; },
      // following types are the final ones
      [](const interface::CommittedTxResponse &) { return kMaxPriority; },
      [](const interface::RejectedTxResponse &) { return kMaxPriority; });
}

const TransactionResponse::TransportType &TransactionResponse::getTransport()
    const {
  return impl_->proto_;
}
