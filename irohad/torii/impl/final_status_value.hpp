/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_FINAL_STATUS_VALUE_HPP
#define IROHA_FINAL_STATUS_VALUE_HPP

#include "common/is_any.hpp"
#include "interfaces/transaction_responses/tx_response.hpp"

/**
 * Statuses considered final for streaming. Observable stops value emission
 * after receiving a value of one of the following types
 * @tparam T concrete response type
 *
 * StatefulFailedTxResponse and MstExpiredResponse were removed from the
 * list of final statuses.
 *
 * StatefulFailedTxResponse is not a final status because the node might be
 * in non-synchronized state and the transaction may be stateful valid from
 * the viewpoint of up to date nodes.
 *
 * MstExpiredResponse is not a final status in general case because it will
 * depend on MST expiration timeout. The transaction might expire in MST,
 * but remain valid in terms of Iroha validation rules. Thus, it may be
 * resent and committed successfully. As the result the final status may
 * differ from MstExpiredResponse.
 */
template <typename T>
constexpr bool FinalStatusValue =
    iroha::is_any<std::decay_t<T>,
                  shared_model::interface::StatelessFailedTxResponse,
                  shared_model::interface::CommittedTxResponse,
                  shared_model::interface::RejectedTxResponse>::value;

#endif  // IROHA_FINAL_STATUS_VALUE_HPP
