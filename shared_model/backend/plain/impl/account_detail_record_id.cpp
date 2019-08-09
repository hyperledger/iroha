/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/account_detail_record_id.hpp"

using namespace shared_model::interface::types;
using namespace shared_model::plain;

AccountDetailRecordId::AccountDetailRecordId(AccountIdType writer,
                                             AccountDetailKeyType key)
    : writer_(std::move(writer)), key_(std::move(key)) {}

AccountIdType AccountDetailRecordId::writer() const {
  return writer_;
}

AccountDetailKeyType AccountDetailRecordId::key() const {
  return key_;
}
