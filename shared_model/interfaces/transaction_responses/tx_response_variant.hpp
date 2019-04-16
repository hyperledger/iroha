/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_TX_RESPONSE_VARIANT_HPP
#define IROHA_SHARED_MODEL_TX_RESPONSE_VARIANT_HPP

#include "interfaces/transaction_responses/tx_response.hpp"

#include <boost/variant.hpp>

namespace boost {
  extern template class variant<
      const shared_model::interface::StatelessFailedTxResponse &,
      const shared_model::interface::StatelessValidTxResponse &,
      const shared_model::interface::StatefulFailedTxResponse &,
      const shared_model::interface::StatefulValidTxResponse &,
      const shared_model::interface::RejectedTxResponse &,
      const shared_model::interface::CommittedTxResponse &,
      const shared_model::interface::MstExpiredResponse &,
      const shared_model::interface::NotReceivedTxResponse &,
      const shared_model::interface::MstPendingResponse &,
      const shared_model::interface::EnoughSignaturesCollectedResponse &>;
}

#endif  // IROHA_SHARED_MODEL_TX_RESPONSE_VARIANT_HPP
