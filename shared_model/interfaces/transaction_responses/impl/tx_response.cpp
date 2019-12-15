/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/transaction_responses/tx_response_variant.hpp"

#include "interfaces/transaction.hpp"
#include "interfaces/transaction_responses/committed_tx_response.hpp"
#include "interfaces/transaction_responses/enough_signatures_collected_response.hpp"
#include "interfaces/transaction_responses/mst_expired_response.hpp"
#include "interfaces/transaction_responses/mst_pending_response.hpp"
#include "interfaces/transaction_responses/not_received_tx_response.hpp"
#include "interfaces/transaction_responses/rejected_tx_response.hpp"
#include "interfaces/transaction_responses/stateful_failed_tx_response.hpp"
#include "interfaces/transaction_responses/stateful_valid_tx_response.hpp"
#include "interfaces/transaction_responses/stateless_failed_tx_response.hpp"
#include "interfaces/transaction_responses/stateless_valid_tx_response.hpp"
#include "utils/visitor_apply_for_all.hpp"

using Variant =
    shared_model::interface::TransactionResponse::ResponseVariantType;
template Variant::~variant();
template Variant::variant(Variant &&);
template bool Variant::operator==(const Variant &) const;
template void Variant::destroy_content() noexcept;
template int Variant::which() const noexcept;
template void Variant::indicate_which(int) noexcept;
template bool Variant::using_backup() const noexcept;
template Variant::convert_copy_into::convert_copy_into(void *) noexcept;

namespace shared_model {
  namespace interface {
    TransactionResponse::PrioritiesComparisonResult
    TransactionResponse::comparePriorities(const ModelType &other) const
        noexcept {
      if (this->priority() < other.priority()) {
        return PrioritiesComparisonResult::kLess;
      } else if (this->priority() == other.priority()) {
        return PrioritiesComparisonResult::kEqual;
      }
      return PrioritiesComparisonResult::kGreater;
    };

    std::string TransactionResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("TransactionResponse")
          .appendNamed("transactionHash", transactionHash().hex())
          .append(boost::apply_visitor(detail::ToStringVisitor(), get()))
          .appendNamed("statelessErrorOrCmdName", statelessErrorOrCommandName())
          .appendNamed("failedCmdIndex", failedCommandIndex())
          .appendNamed("errorCode", errorCode())
          .finalize();
    }

    bool TransactionResponse::operator==(const ModelType &rhs) const {
      return transactionHash() == rhs.transactionHash()
          and statelessErrorOrCommandName() == rhs.statelessErrorOrCommandName()
          and failedCommandIndex() == rhs.failedCommandIndex()
          and errorCode() == rhs.errorCode() and get() == rhs.get();
    }
  }  // namespace interface
}  // namespace shared_model
