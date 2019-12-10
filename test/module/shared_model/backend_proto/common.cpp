/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/backend_proto/common.hpp"

#include <unordered_set>

#include <google/protobuf/message.h>

namespace {
  const std::unordered_set<std::string> kHexFields{
      "iroha.protocol.AddSignatory.public_key",
      "iroha.protocol.Block_v1.Payload.prev_block_hash",
      "iroha.protocol.CreateAccount.public_key",
      "iroha.protocol.Peer.peer_key",
      "iroha.protocol.PendingTransactionsPageResponse.BatchInfo.first_tx_hash",
      "iroha.protocol.RemovePeer.public_key",
      "iroha.protocol.RemoveSignatory.public_key"};

  std::string kHexString{"abba"};

  void setHexFields(google::protobuf::Message *msg) {
    using namespace google::protobuf;
    auto msg_desc = msg->GetDescriptor();
    auto refl = msg->GetReflection();
    for (int fn = 0; fn < msg_desc->field_count(); ++fn) {
      auto field_desc = msg_desc->field(fn);
      if (field_desc->type() == FieldDescriptor::TYPE_STRING) {
        if (kHexFields.count(field_desc->full_name())) {
          refl->SetString(msg, field_desc, kHexString);
        }
      } else if (field_desc->type() == FieldDescriptor::TYPE_MESSAGE
                 and not field_desc->is_repeated()) {
        setHexFields(refl->MutableMessage(msg, field_desc));
      }
    }
  }
}  // namespace

void iroha::setDummyFieldValues(google::protobuf::Message *msg) {
  setHexFields(msg);
}
