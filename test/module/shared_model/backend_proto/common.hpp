/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

namespace google {
  namespace protobuf {
    class Message;
  }
}  // namespace google

namespace iroha {
  /// Set the fields that have their default value invalid to some valid value.
  void setDummyFieldValues(google::protobuf::Message *msg);
}  // namespace iroha
