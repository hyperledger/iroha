/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_command.hpp"

#include <gtest/gtest.h>

#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/irange.hpp>
#include <boost/variant.hpp>

/**
 * For each protobuf command type
 * @given protobuf command object
 * @when create shared model command object
 * @then corresponding shared model object is created
 */
TEST(ProtoCommand, CommandLoad) {
  iroha::protocol::Command command;
  auto refl = command.GetReflection();
  auto desc = command.GetDescriptor();
  boost::for_each(boost::irange(0, desc->field_count()), [&](auto i) {
    auto field = desc->field(i);
    refl->SetAllocatedMessage(
        &command, refl->GetMessage(command, field).New(), field);
    ASSERT_EQ(i, shared_model::proto::Command(command).get().which());
  });
}
