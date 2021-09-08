/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"

#include <boost/variant/variant.hpp>
#include <limits>

#include "backend/protobuf/transaction_responses/proto_concrete_tx_response.hpp"
#include "common/report_abort.h"
#include "common/visitor.hpp"
#include "cryptography/hash.hpp"

namespace {
  /// Variant type, that contains all concrete tx responses in the system
  using ProtoResponseVariantType =
      boost::variant<shared_model::proto::StatelessFailedTxResponse,
                     shared_model::proto::StatelessValidTxResponse,
                     shared_model::proto::StatefulFailedTxResponse,
                     shared_model::proto::StatefulValidTxResponse,
                     shared_model::proto::RejectedTxResponse,
                     shared_model::proto::CommittedTxResponse,
                     shared_model::proto::MstExpiredResponse,
                     shared_model::proto::NotReceivedTxResponse,
                     shared_model::proto::MstPendingResponse,
                     shared_model::proto::EnoughSignaturesCollectedResponse>;

  constexpr int kMaxPriority = std::numeric_limits<int>::max();
}  // namespace

namespace shared_model::proto {

  struct TransactionResponse::Impl {
    explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}
    explicit Impl(const TransportType &ref) : proto_{ref} {}

    TransportType proto_;

    const ProtoResponseVariantType variant_{[this] {
      using namespace shared_model::proto;
      using iroha::protocol::TxStatus;
      switch (proto_.tx_status()) {
        case TxStatus::STATELESS_VALIDATION_FAILED:
          return ProtoResponseVariantType(StatelessFailedTxResponse(proto_));
        case TxStatus::STATELESS_VALIDATION_SUCCESS:
          return ProtoResponseVariantType(StatelessValidTxResponse(proto_));
        case TxStatus::STATEFUL_VALIDATION_FAILED:
          return ProtoResponseVariantType(StatefulFailedTxResponse(proto_));
        case TxStatus::STATEFUL_VALIDATION_SUCCESS:
          return ProtoResponseVariantType(StatefulValidTxResponse(proto_));
        case TxStatus::REJECTED:
          return ProtoResponseVariantType(RejectedTxResponse(proto_));
        case TxStatus::COMMITTED:
          return ProtoResponseVariantType(CommittedTxResponse(proto_));
        case TxStatus::MST_EXPIRED:
          return ProtoResponseVariantType(MstExpiredResponse(proto_));
        case TxStatus::NOT_RECEIVED:
          return ProtoResponseVariantType(NotReceivedTxResponse(proto_));
        case TxStatus::MST_PENDING:
          return ProtoResponseVariantType(MstPendingResponse(proto_));
        case TxStatus::ENOUGH_SIGNATURES_COLLECTED:
          return ProtoResponseVariantType(
              EnoughSignaturesCollectedResponse(proto_));
        default:
          report_abort("Unexpected transaction response case.");
      }
    }()};

    const ResponseVariantType ivariant_{variant_};

    // stub hash
    const crypto::Hash hash_ = crypto::Hash::fromHexString(proto_.tx_hash());
  };

  TransactionResponse::TransactionResponse(const TransactionResponse &r)
      : TransactionResponse(r.impl_->proto_) {}
  TransactionResponse::TransactionResponse(TransactionResponse &&r) noexcept =
      default;

  TransactionResponse::TransactionResponse(const TransportType &ref) {
    impl_ = std::make_unique<Impl>(ref);
  }
  TransactionResponse::TransactionResponse(TransportType &&ref) {
    impl_ = std::make_unique<Impl>(std::move(ref));
  }

  TransactionResponse::~TransactionResponse() = default;

  const interface::types::HashType &TransactionResponse::transactionHash()
      const {
    return impl_->hash_;
  }

  const TransactionResponse::ResponseVariantType &TransactionResponse::get()
      const {
    return impl_->ivariant_;
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
    return iroha::visit_in_place(
        impl_->variant_,
        // not received can be changed to any response
        [](const NotReceivedTxResponse &) { return 0; },
        // following types are sequential in pipeline
        [](const StatelessValidTxResponse &) { return 1; },
        [](const MstPendingResponse &) { return 2; },
        [](const EnoughSignaturesCollectedResponse &) { return 3; },
        [](const StatefulValidTxResponse &) { return 4; },
        // following types are local on this peer and can be substituted by
        // final ones, if consensus decides so
        [](const StatelessFailedTxResponse &) { return 5; },
        [](const StatefulFailedTxResponse &) { return 5; },
        [](const MstExpiredResponse &) { return 5; },
        // following types are the final ones
        [](const CommittedTxResponse &) { return kMaxPriority; },
        [](const RejectedTxResponse &) { return kMaxPriority; });
  }

  const TransactionResponse::TransportType &TransactionResponse::getTransport()
      const {
    return impl_->proto_;
  }

}  // namespace shared_model::proto

#undef IROHA_BIND_TYPE
