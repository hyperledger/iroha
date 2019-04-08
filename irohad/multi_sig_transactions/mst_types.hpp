/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_TYPES_HPP
#define IROHA_MST_TYPES_HPP

#include <memory>

#include "interfaces/common_objects/types.hpp"
#include "storage_shared_limit/moved_item.hpp"

namespace shared_model {
  namespace interface {
    class TransactionBatch;
    class TransactionResponse;
    class Peer;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {

  using BatchPtr = std::shared_ptr<shared_model::interface::TransactionBatch>;
  using MovedBatch = MovedItem<BatchPtr>;
  using ConstPeer = const shared_model::interface::Peer;
  using TimeType = shared_model::interface::types::TimestampType;
  using TxResponse =
      std::shared_ptr<shared_model::interface::TransactionResponse>;

  template <typename T>
  using ConstRefT = const T &;

  using ConstRefBatch = ConstRefT<BatchPtr>;
  using ConstRefPeer = ConstRefT<shared_model::interface::Peer>;
  using ConstRefTime = ConstRefT<TimeType>;

  class MstState;

  using ConstRefState = ConstRefT<MstState>;

  using DataType = BatchPtr;
}  // namespace iroha

#endif  // IROHA_MST_TYPES_HPP
