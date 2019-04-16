/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/gate_object.hpp"

using GateObject = iroha::consensus::GateObject;

template GateObject::~variant();
template GateObject::variant(GateObject &&) noexcept;
template GateObject::variant(const GateObject &);
template void GateObject::destroy_content() noexcept;
template int GateObject::which() const noexcept;
template void GateObject::indicate_which(int) noexcept;
template bool GateObject::using_backup() const noexcept;
template GateObject::convert_copy_into::convert_copy_into(void *) noexcept;
