/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include DEFAULT_VM_CALL_INCLUDE_IMPL

#include <unordered_map>

#include <gtest/gtest.h>
#include <boost/mpl/back_inserter.hpp>
#include <boost/mpl/copy.hpp>
#include <boost/mpl/count.hpp>
#include <boost/mpl/find.hpp>
#include <boost/mpl/vector.hpp>
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "interfaces/commands/add_asset_quantity.hpp"
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/commands/add_signatory.hpp"
#include "interfaces/commands/append_role.hpp"
#include "interfaces/commands/call_engine.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/commands/compare_and_set_account_detail.hpp"
#include "interfaces/commands/create_account.hpp"
#include "interfaces/commands/create_asset.hpp"
#include "interfaces/commands/create_domain.hpp"
#include "interfaces/commands/create_role.hpp"
#include "interfaces/commands/detach_role.hpp"
#include "interfaces/commands/grant_permission.hpp"
#include "interfaces/commands/remove_peer.hpp"
#include "interfaces/commands/remove_signatory.hpp"
#include "interfaces/commands/revoke_permission.hpp"
#include "interfaces/commands/set_account_detail.hpp"
#include "interfaces/commands/set_quorum.hpp"
#include "interfaces/commands/subtract_asset_quantity.hpp"
#include "interfaces/commands/transfer_asset.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "interfaces/queries/get_account.hpp"
#include "interfaces/queries/get_account_detail.hpp"
#include "interfaces/queries/query.hpp"
#include "module/irohad/ametsuchi/mock_burrow_storage.hpp"
#include "module/irohad/ametsuchi/mock_command_executor.hpp"
#include "module/irohad/ametsuchi/mock_query_executor_visitor.hpp"

template <typename T>
class VariantTypeMatcher {
 public:
  template <typename Variant>
  bool MatchAndExplain(const Variant &value,
                       ::testing::MatchResultListener *listener) const {
    using VariantTypes = typename std::decay_t<decltype(value.get())>::types;
    using VariantTypesVector = typename boost::mpl::copy<
        VariantTypes,
        boost::mpl::back_inserter<boost::mpl::vector<>>>::type;
    static_assert(
        boost::mpl::count<VariantTypesVector, T>::type::value == 1,
        "The type must occur exactly once in the list of variant alternatives");
    return value.get().which()
        == boost::mpl::find<VariantTypesVector, T>::type::pos::value;
  }

  virtual void DescribeTo(::std::ostream *os) const {
    *os << "Tested variant contains expected type.";
  }

  virtual void DescribeNegationTo(::std::ostream *os) const {
    *os << "Tested variant does not contain expected type.";
  }
};

template <typename T>
inline auto VariantWithType() {
  return ::testing::MakePolymorphicMatcher(VariantTypeMatcher<T>());
}

using ::testing::_;

struct StringViewOrString {
  std::string s;
  std::string_view v;

  explicit StringViewOrString(std::string_view v) : v(v) {}
  explicit StringViewOrString(std::string s) : s(s), v(this->s) {}

  StringViewOrString(StringViewOrString const &o)
      : s(o.s), v(not this->s.empty() ? this->s : o.v) {}
  StringViewOrString(StringViewOrString &&o) noexcept
      : s(std::move(o).s), v(not this->s.empty() ? this->s : std::move(o).v) {}

  bool operator==(StringViewOrString const &x) const {
    return v == x.v;
  }

  struct Hash {
    std::size_t operator()(StringViewOrString const &x) const {
      return std::hash<std::string_view>()(x.v);
    }
  };
};

using AccountName = StringViewOrString;
using Key = StringViewOrString;
using Value = std::string;

struct TestAccount {
  std::string account;
  std::unordered_map<Key, Value, Key::Hash> storage;
};

using namespace iroha;

TEST(VmCallTest, UsageTest) {
  /*

deploySCdata is bytecode from the following Solidity code using online Remix IDE
with compiler version 0.4.0

pragma solidity ^0.4.0;

contract C {
  uint256 a;
  function setA(uint256 _a) {
    a = _a;
  }

  function getA() returns(uint256) {
    return a;
  }
}

*/

  const shared_model::crypto::Hash query_hash{"query_hash"};

  char *deploySCdata = const_cast<char *>(
      "606060405260a18060106000396000f360606040526000357c0100000000000000000000"
      "00000000000000000000000000000000000090048063d46300fd146043578063ee919d50"
      "14606857603f565b6002565b34600257605260048050506082565b604051808281526020"
      "0191505060405180910390f35b3460025760806004808035906020019091905050609356"
      "5b005b600060006000505490506090565b90565b806000600050819055505b5056");

  /*
    calling setA(uint256), bytes4(keccak256(setA(uint256))) == ee919d50, and
    append uint256 equal to 1 as the parameter
  */

  char *inputCallSetter = const_cast<char *>(
      "ee919d50"
      "0000000000000000000000000000000000000000000000000000000000000001");

  /*
    calling getA(), bytes4(keccak256(getA())) == d46300fd
  */

  char *inputCallGetter = const_cast<char *>("d46300fd");

  char *caller = const_cast<char *>("caller"),
       *callee = const_cast<char *>("Callee");

  // Emulate accounts' storages for the smart contract engine
  std::unordered_map<AccountName, TestAccount, AccountName::Hash> accounts;

  iroha::ametsuchi::MockCommandExecutor command_executor;
  iroha::ametsuchi::MockSpecificQueryExecutor specific_query_executor;

  iroha::ametsuchi::MockReaderWriter reader_writer;

  EXPECT_CALL(reader_writer, getAccount(_))
      .WillRepeatedly(
          [&accounts](auto address)
              -> expected::Result<std::optional<std::string>, std::string> {
            auto it = accounts.find(StringViewOrString{address});
            if (it == accounts.end()) {
              return expected::Value<std::optional<std::string>>();
            }
            return expected::Value<std::optional<std::string>>(
                it->second.account);
          });

  EXPECT_CALL(reader_writer, updateAccount(_, _))
      .WillRepeatedly(
          [&accounts](auto address,
                      auto account) -> expected::Result<void, std::string> {
            auto it = accounts.find(StringViewOrString{address});
            if (it == accounts.end()) {
              it = accounts
                       .emplace(StringViewOrString{std::string{address}},
                                TestAccount{})
                       .first;
            }
            it->second.account = account;
            return expected::Value<void>();
          });

  EXPECT_CALL(reader_writer, removeAccount(_))
      .WillRepeatedly(
          [&accounts](auto address) -> expected::Result<void, std::string> {
            accounts.erase(StringViewOrString{address});
            return expected::Value<void>();
          });

  EXPECT_CALL(reader_writer, getStorage(_, _))
      .WillRepeatedly(
          [&accounts](auto address, auto key)
              -> expected::Result<std::optional<std::string>, std::string> {
            auto it = accounts.find(StringViewOrString{address});
            if (it == accounts.end()) {
              return expected::Error<std::string>("No account");
            }

            auto vit = it->second.storage.find(StringViewOrString{key});
            if (vit == it->second.storage.end()) {
              return expected::Value<std::optional<std::string>>();
            }
            return expected::Value<std::optional<std::string>>(vit->second);
          });

  EXPECT_CALL(reader_writer, setStorage(_, _, _))
      .WillRepeatedly([&accounts](auto address, auto key, auto value)
                          -> expected::Result<void, std::string> {
        auto it = accounts.find(StringViewOrString{address});
        if (it == accounts.end()) {
          return expected::Error<std::string>("No account");
        }

        auto vit = it->second.storage.find(StringViewOrString{key});
        if (vit == it->second.storage.end()) {
          vit =
              it->second.storage
                  .emplace(StringViewOrString{std::string{key}}, std::string{})
                  .first;
        }
        vit->second = value;
        return expected::Value<void>();
      });

  auto res = VmCall(deploySCdata,
                    caller,
                    callee,
                    &command_executor,
                    &specific_query_executor,
                    &reader_writer);
  std::cout << "Vm output: " << res.r0 << std::endl;
  ASSERT_TRUE(res.r1);

  res = VmCall(inputCallSetter,
               caller,
               callee,
               &command_executor,
               &specific_query_executor,
               &reader_writer);
  std::cout << "Vm output: " << res.r0 << std::endl;
  ASSERT_TRUE(res.r1);

  res = VmCall(inputCallGetter,
               caller,
               callee,
               &command_executor,
               &specific_query_executor,
               &reader_writer);
  std::cout << "Vm output: " << res.r0 << std::endl;
  ASSERT_TRUE(res.r1);
}
