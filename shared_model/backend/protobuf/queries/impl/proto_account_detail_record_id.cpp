/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_account_detail_record_id.hpp"

using namespace shared_model::proto;

AccountDetailRecordId::AccountDetailRecordId(TransportType &proto)
    : proto_(proto) {}

AccountDetailRecordId::AccountDetailRecordId(const AccountDetailRecordId &o)
    : AccountDetailRecordId(o.proto_) {}

shared_model::interface::types::AccountIdType AccountDetailRecordId::writer()
    const {
  return proto_.writer();
}

shared_model::interface::types::AccountDetailKeyType
AccountDetailRecordId::key() const {
  return proto_.key();
}
