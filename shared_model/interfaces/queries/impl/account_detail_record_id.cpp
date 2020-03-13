/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/account_detail_record_id.hpp"

using namespace shared_model::interface;

bool AccountDetailRecordId::operator==(const ModelType &rhs) const {
  return writer() == rhs.writer() and key() == rhs.key();
}

std::string AccountDetailRecordId::toString() const {
  return detail::PrettyStringBuilder()
      .init("AccountDetailRecordId")
      .appendNamed("writer", writer())
      .appendNamed("key", key())
      .finalize();
}
