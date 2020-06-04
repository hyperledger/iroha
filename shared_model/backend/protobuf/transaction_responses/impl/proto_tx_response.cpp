/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"

#include <limits>

#include <boost/variant/variant.hpp>
#include "backend/protobuf/transaction_responses/proto_concrete_tx_response.hpp"
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

#ifdef IROHA_BIND_TYPE
#error IROHA_BIND_TYPE defined.
#endif  // IROHA_BIND_TYPE
#define IROHA_BIND_TYPE(val, type, ...) \
  case iroha::protocol::TxStatus::val:  \
    return ProtoResponseVariantType(shared_model::proto::type(__VA_ARGS__))

namespace shared_model::proto {

  struct TransactionResponse::Impl {
    explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}
    explicit Impl(const TransportType &ref) : proto_{ref} {}

    TransportType proto_;

    const ProtoResponseVariantType variant_{[this] {
      auto &ar = proto_;
      switch (ar.tx_status()) {
        IROHA_BIND_TYPE(
            STATELESS_VALIDATION_FAILED, StatelessFailedTxResponse, ar);
        IROHA_BIND_TYPE(
            STATELESS_VALIDATION_SUCCESS, StatelessValidTxResponse, ar);
        IROHA_BIND_TYPE(
            STATEFUL_VALIDATION_FAILED, StatefulFailedTxResponse, ar);
        IROHA_BIND_TYPE(
            STATEFUL_VALIDATION_SUCCESS, StatefulValidTxResponse, ar);
        IROHA_BIND_TYPE(REJECTED, RejectedTxResponse, ar);
        IROHA_BIND_TYPE(COMMITTED, CommittedTxResponse, ar);
        IROHA_BIND_TYPE(MST_EXPIRED, MstExpiredResponse, ar);
        IROHA_BIND_TYPE(NOT_RECEIVED, NotReceivedTxResponse, ar);
        IROHA_BIND_TYPE(MST_PENDING, MstPendingResponse, ar);
        IROHA_BIND_TYPE(
            ENOUGH_SIGNATURES_COLLECTED, EnoughSignaturesCollectedResponse, ar);

        default:
          assert(!"Unexpected transaction response case.");
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
