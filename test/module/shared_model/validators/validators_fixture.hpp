/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATORS_FIXTURE_HPP
#define IROHA_VALIDATORS_FIXTURE_HPP

#include <gtest/gtest.h>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/irange.hpp>

#include "datetime/time.hpp"
#include "interfaces/permissions.hpp"
#include "primitive.pb.h"
#include "queries.pb.h"
#include "transaction.pb.h"

class ValidatorsTest : public ::testing::Test {
 public:
  ValidatorsTest() {
    // Generate protobuf reflection setter for given type and value
    auto setField = [&](auto setter) {
      return [setter](const auto &value) {
        return [setter, &value](auto refl, auto msg, auto field) {
          (refl->*setter)(msg, field, value);
        };
      };
    };

    auto setString = setField(&google::protobuf::Reflection::SetString);
    auto addString = setField(&google::protobuf::Reflection::AddString);
    auto setUInt32 = setField(&google::protobuf::Reflection::SetUInt32);
    auto setUInt64 = setField(&google::protobuf::Reflection::SetUInt64);
    auto addEnum = setField(&google::protobuf::Reflection::AddEnumValue);
    auto setEnum = setField(&google::protobuf::Reflection::SetEnumValue);

    field_setters = {
        {"iroha.protocol.GetAccount.account_id", setString(account_id)},
        {"iroha.protocol.GetSignatories.account_id", setString(account_id)},
        {"iroha.protocol.GetAccountTransactions.account_id",
         setString(account_id)},
        {"iroha.protocol.GetAccountAssetTransactions.account_id",
         setString(account_id)},
        {"iroha.protocol.GetAccountAssets.account_id", setString(account_id)},
        {"iroha.protocol.GetAccountDetail.account_id", setString(account_id)},
        {"iroha.protocol.TransferAsset.src_account_id", setString(account_id)},
        {"iroha.protocol.AddSignatory.account_id", setString(account_id)},
        {"iroha.protocol.AppendRole.account_id", setString(account_id)},
        {"iroha.protocol.DetachRole.account_id", setString(account_id)},
        {"iroha.protocol.GrantPermission.account_id", setString(account_id)},
        {"iroha.protocol.RemoveSignatory.account_id", setString(account_id)},
        {"iroha.protocol.RevokePermission.account_id", setString(account_id)},
        {"iroha.protocol.SetAccountDetail.account_id", setString(account_id)},
        {"iroha.protocol.SetAccountQuorum.account_id", setString(account_id)},
        {"iroha.protocol.AppendRole.role_name", setString(role_name)},
        {"iroha.protocol.DetachRole.role_name", setString(role_name)},
        {"iroha.protocol.CreateRole.role_name", setString(role_name)},
        {"iroha.protocol.CreateDomain.default_role", setString(role_name)},
        {"iroha.protocol.GetRolePermissions.role_id", setString(role_name)},
        {"iroha.protocol.AddSignatory.public_key", setString(public_key)},
        {"iroha.protocol.CreateAccount.public_key", setString(public_key)},
        {"iroha.protocol.RemoveSignatory.public_key", setString(public_key)},
        {"iroha.protocol.TransferAsset.dest_account_id", setString(dest_id)},
        {"iroha.protocol.AddAssetQuantity.asset_id", setString(asset_id)},
        {"iroha.protocol.TransferAsset.asset_id", setString(asset_id)},
        {"iroha.protocol.SubtractAssetQuantity.asset_id", setString(asset_id)},
        {"iroha.protocol.GetAccountAssetTransactions.asset_id",
         setString(asset_id)},
        {"iroha.protocol.GetAssetInfo.asset_id", setString(asset_id)},
        {"iroha.protocol.CreateAccount.account_name", setString(account_name)},
        {"iroha.protocol.CreateAsset.domain_id", setString(domain_id)},
        {"iroha.protocol.CreateAccount.domain_id", setString(domain_id)},
        {"iroha.protocol.CreateDomain.domain_id", setString(domain_id)},
        {"iroha.protocol.CreateAsset.asset_name", setString(asset_name)},
        {"iroha.protocol.CreateAsset.precision", setUInt32(precision)},
        {"iroha.protocol.CreateRole.permissions", addEnum(role_permission)},
        {"iroha.protocol.GrantPermission.permission",
         setEnum(grantable_permission)},
        {"iroha.protocol.RevokePermission.permission",
         setEnum(grantable_permission)},
        {"iroha.protocol.SetAccountDetail.key", setString(detail_key)},
        {"iroha.protocol.GetAccountDetail.key", setString(detail_key)},
        {"iroha.protocol.GetAccountDetail.writer", setString(writer)},
        {"iroha.protocol.SetAccountDetail.value", setString("")},
        {"iroha.protocol.GetTransactions.tx_hashes", addString(hash)},
        {"iroha.protocol.SetAccountQuorum.quorum", setUInt32(quorum)},
        {"iroha.protocol.TransferAsset.description", setString("")},
        {"iroha.protocol.AddAssetQuantity.amount", setString(amount)},
        {"iroha.protocol.TransferAsset.amount", setString(amount)},
        {"iroha.protocol.SubtractAssetQuantity.amount", setString(amount)},
        {"iroha.protocol.AddPeer.peer",
         [&](auto refl, auto msg, auto field) {
           refl->MutableMessage(msg, field)->CopyFrom(peer);
         }},
        {"iroha.protocol.GetAccountTransactions.pagination_meta",
         [&](auto refl, auto msg, auto field) {
           refl->MutableMessage(msg, field)->CopyFrom(tx_pagination_meta);
         }},
        {"iroha.protocol.GetAccountAssetTransactions.pagination_meta",
         [&](auto refl, auto msg, auto field) {
           refl->MutableMessage(msg, field)->CopyFrom(tx_pagination_meta);
         }},
        {"iroha.protocol.GetAccountAssets.pagination_meta",
         [&](auto refl, auto msg, auto field) {
           refl->MutableMessage(msg, field)
               ->CopyFrom(account_assets_pagination_meta);
         }},
        {"iroha.protocol.GetBlock.height", setUInt64(height)}};
  }

  /**
   * Iterate the container (transaction or query), generating concrete subtypes
   * and doing operation on concrete subtype fields. Call validator after each
   * subtype
   * @tparam DescGen oneof descriptor generator type
   * @tparam ConcreteGen concrete subtype generator type
   * @tparam FieldOp field operation type
   * @tparam Validator validator type
   * @param desc_gen descriptor generator callable object
   * @param concrete_gen concrete subtype generator callable object
   * @param field_op field operation callable object
   * @param validator validator callable object
   */
  template <typename DescGen,
            typename ConcreteGen,
            typename FieldOp,
            typename Validator>
  void iterateContainer(DescGen &&desc_gen,
                        ConcreteGen &&concrete_gen,
                        FieldOp &&field_op,
                        Validator &&validator) {
    auto desc = desc_gen();
    // Get field descriptor for concrete type
    const auto &range = boost::irange(0, desc->field_count())
        | boost::adaptors::transformed([&](auto i) { return desc->field(i); });
    // Iterate through all concrete types
    boost::for_each(range, [&](auto field) {
      auto concrete = concrete_gen(field);

      // Iterate through all fields of concrete type
      auto concrete_desc = concrete->GetDescriptor();
      // Get field descriptor for concrete type field
      const auto &range = boost::irange(0, concrete_desc->field_count())
          | boost::adaptors::transformed(
                              [&](auto i) { return concrete_desc->field(i); });
      boost::for_each(range, [&](auto field) { field_op(field, concrete); });
      validator();
    });
  }
  // TODO: IR-1490 02.07.2018 Rewrite interator for all containters
  /**
   * Iterate the container recursively (transaction or query),
   * generating concrete subtypes
   * and doing operation on concrete subtype fields. Call validator after each
   * subtype
   * @tparam FieldMap map of validators which are not nessery to traverse but
   * validate as a whole
   * @tparam FieldOp field operation type
   * @tparam Validator validator type
   * @param m protobuf message to iterate
   * @param field_validators map of validators which are not nessery to traverse
   * but validate as a whole
   * @param field_op field operation callable object
   * @param validator validator callable object
   */
  template <typename FieldOp, typename FieldMap, typename Validator>
  void iterateContainerRecursive(std::shared_ptr<google::protobuf::Message> m,
                                 FieldMap &field_validators,
                                 FieldOp &&field_op,
                                 Validator &&validator) {
    const google::protobuf::Descriptor *desc = m->GetDescriptor();
    const google::protobuf::Reflection *refl = m->GetReflection();
    // Get field descriptor for concrete type
    const auto &range = boost::irange(0, desc->field_count())
        | boost::adaptors::transformed([&](auto i) { return desc->field(i); });
    // Iterate through all concrete types
    boost::for_each(range, [&](auto field) {
      if (field->type() != google::protobuf::FieldDescriptor::TYPE_MESSAGE
          or field_validators.count(field->name())) {
        field_op(field, m);
        validator();
      } else {
        const google::protobuf::Message *mfield = field->is_repeated()
            ? refl->MutableRepeatedMessage(m.get(), field, 0)
            : refl->MutableMessage(m.get(), field);
        google::protobuf::Message *mcopy = mfield->New();
        mcopy->CopyFrom(*mfield);
        void *ptr = new std::shared_ptr<google::protobuf::Message>(mcopy);
        std::shared_ptr<google::protobuf::Message> *m =
            static_cast<std::shared_ptr<google::protobuf::Message> *>(ptr);
        this->iterateContainerRecursive(
            *m, field_validators, field_op, validator);
      }
    });
  }

 protected:
  void SetUp() override {
    // Fill fields with valid values
    created_time = iroha::time::now();
    precision = 2;
    amount = "10.00";
    public_key_size = 32;
    hash_size = 32;
    counter = 1048576;
    account_id = "account@domain";
    dest_id = "dest@domain";
    asset_name = "asset";
    asset_id = "asset#domain";
    address_localhost = "localhost:65535";
    address_ipv4 = "192.168.255.1:8080";
    address_hostname = "google.ru:8080";
    role_name = "user";
    account_name = "admin";
    domain_id = "ru";
    detail_key = "key";
    writer = "account@domain";

    // size of public_key and hash are twice bigger `public_key_size` because it
    // is hex representation
    public_key = std::string(public_key_size * 2, '0');
    hash = std::string(public_key_size * 2, '0');

    role_permission = iroha::protocol::RolePermission::can_append_role;
    grantable_permission =
        iroha::protocol::GrantablePermission::can_add_my_signatory;
    quorum = 2;
    peer.set_address(address_localhost);
    peer.set_peer_key(public_key);
    tx_pagination_meta.set_page_size(10);
    account_assets_pagination_meta.set_page_size(10);
  }

  size_t public_key_size{0};
  size_t hash_size{0};
  uint64_t counter{0};
  uint64_t height{42};
  std::string account_id;
  std::string dest_id;
  std::string asset_name;
  std::string asset_id;
  std::string address_localhost;
  std::string address_ipv4;
  std::string address_hostname;
  std::string role_name;
  std::string account_name;
  std::string domain_id;
  std::string detail_key;
  std::string detail_value;
  std::string description;
  std::string public_key;
  std::string hash;
  std::string writer;
  iroha::protocol::Transaction::Payload::BatchMeta batch_meta;
  shared_model::interface::permissions::Role model_role_permission;
  shared_model::interface::permissions::Grantable model_grantable_permission;
  iroha::protocol::RolePermission role_permission;
  iroha::protocol::GrantablePermission grantable_permission;
  uint8_t quorum;
  uint8_t precision;
  std::string amount;
  iroha::protocol::Peer peer;
  decltype(iroha::time::now()) created_time;
  iroha::protocol::QueryPayloadMeta meta;
  iroha::protocol::TxPaginationMeta tx_pagination_meta;
  iroha::protocol::AccountAssetPaginationMeta account_assets_pagination_meta;

  // List all used fields in commands
  std::unordered_map<
      std::string,
      std::function<void(const google::protobuf::Reflection *,
                         google::protobuf::Message *,
                         const google::protobuf::FieldDescriptor *)>>
      field_setters;
};

#endif  // IROHA_VALIDATORS_FIXTURE_HPP
