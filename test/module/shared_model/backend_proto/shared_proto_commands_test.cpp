/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_command.hpp"

#include <gtest/gtest.h>

#include <boost/mpl/copy.hpp>
#include <boost/mpl/find.hpp>
#include <boost/mpl/vector.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/irange.hpp>
#include <boost/variant.hpp>
#include "commands.pb.h"
#include "framework/result_gtest_checkers.hpp"
#include "module/shared_model/backend_proto/common.hpp"

namespace {

  using PbCommand = iroha::protocol::Command;
  using IfaceCommandVariantTypes = boost::mpl::copy<
      shared_model::interface::Command::CommandVariantType::types,
      boost::mpl::back_inserter<boost::mpl::vector<>>>::type;
  using PbCommandCaseUnderlyingType =
      std::underlying_type_t<PbCommand::CommandCase>;

#define COMMAND_VARIANT(PROTOBUF_VARIANT, IFACE_VARIANT)                      \
  {                                                                           \
    PbCommand::PROTOBUF_VARIANT,                                              \
        boost::mpl::find<                                                     \
            IfaceCommandVariantTypes,                                         \
            const shared_model::interface::IFACE_VARIANT &>::type::pos::value \
  }

  const std::map<PbCommandCaseUnderlyingType, int>
      kProtoCommandTypeToCommandType{
          COMMAND_VARIANT(kAddAssetQuantity, AddAssetQuantity),
          COMMAND_VARIANT(kAddPeer, AddPeer),
          COMMAND_VARIANT(kAddSignatory, AddSignatory),
          COMMAND_VARIANT(kAppendRole, AppendRole),
          COMMAND_VARIANT(kCreateAccount, CreateAccount),
          COMMAND_VARIANT(kCreateAsset, CreateAsset),
          COMMAND_VARIANT(kCreateDomain, CreateDomain),
          COMMAND_VARIANT(kCreateRole, CreateRole),
          COMMAND_VARIANT(kDetachRole, DetachRole),
          COMMAND_VARIANT(kGrantPermission, GrantPermission),
          COMMAND_VARIANT(kRemoveSignatory, RemoveSignatory),
          COMMAND_VARIANT(kRevokePermission, RevokePermission),
          COMMAND_VARIANT(kSetAccountDetail, SetAccountDetail),
          COMMAND_VARIANT(kSetAccountQuorum, SetQuorum),
          COMMAND_VARIANT(kSubtractAssetQuantity, SubtractAssetQuantity),
          COMMAND_VARIANT(kTransferAsset, TransferAsset),
          COMMAND_VARIANT(kRemovePeer, RemovePeer),
          COMMAND_VARIANT(kCompareAndSetAccountDetail,
                          CompareAndSetAccountDetail),
          COMMAND_VARIANT(kSetSettingValue, SetSettingValue)};

#undef COMMAND_VARIANT

}  // namespace

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
    if (i == PbCommand::COMMAND_NOT_SET) {
      return;
    }
    auto field = desc->field(i);
    auto pb_command_name = field->full_name();
    auto *msg = refl->GetMessage(command, field).New();
    iroha::setDummyFieldValues(msg);
    refl->SetAllocatedMessage(&command, msg, field);

    auto command_result = shared_model::proto::Command::create(command);
    IROHA_ASSERT_RESULT_VALUE(command_result)
        << "Failed to load command " << pb_command_name;

    const PbCommandCaseUnderlyingType command_case = command.command_case();
    auto command = std::move(command_result).assumeValue();
    ASSERT_GT(kProtoCommandTypeToCommandType.count(command_case), 0)
        << "Please add the missing command type to the test map: "
        << pb_command_name;
    EXPECT_EQ(kProtoCommandTypeToCommandType.at(command_case),
              command->get().which());
  });
}
