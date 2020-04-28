#include <string_view>

#include <gtest/gtest.h>
#include "framework/common_constants.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"

using namespace std::literals;

using namespace integration_framework;
using namespace shared_model;
using namespace shared_model::interface::types;
using namespace common_constants;

class EngineCall : public AcceptanceFixture {
 public:
  // TODO(IvanTyulyandin): add permissions for engine_call
  auto makeUserWithPerms(const interface::RolePermissionSet &perms =
                             shared_model::interface::RolePermissionSet()) {
    return AcceptanceFixture::makeUserWithPerms(perms);
  }

  const crypto::Keypair kEvmKeypair =
      crypto::DefaultCryptoAlgorithmType::generateKeypair();

  const std::string callee_str{[] {
    std::string callee{"ca11ee"};
    callee.resize(40, '0');
    return callee;
  }()};

  interface::types::EvmCalleeHexStringView callee{callee_str};

  /*

  code is bytecode from the following Solidity code using online Remix IDE with
  compiler version 0.4.0

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

  interface::types::EvmCodeHexStringView code{
      "606060405260a18060106000396000f360606040526000357c01000000000000000"
      "0000000000000000000000000000000000000000090048063d46300fd1460435780"
      "63ee919d5014606857603f565b6002565b34600257605260048050506082565b604"
      "0518082815260200191505060405180910390f35b34600257608060048080359060"
      "200190919050506093565b005b600060006000505490506090565b90565b8060006"
      "00050819055505b5056"sv};

  /*
    calling setA(uint256), bytes4(keccak256(setA(uint256))) == ee919d50, and
    append uint256 equal to 1 as the parameter
  */

  interface::types::EvmCodeHexStringView inputCallSetter{
      "ee919d50"
      "0000000000000000000000000000000000000000000000000000000000000001"sv};

  /*
    calling getA(), bytes4(keccak256(getA())) == d46300fd
  */

  interface::types::EvmCodeHexStringView inputCallGetter{"d46300fd"sv};

  /*
  pragma solidity^0.5.10;

  contract test {
      address creator;

      constructor() public {
          creator = msg.sender;
      }

      function getCreator() public view returns (address) {
          return creator;
      }

      function getMsgSender() public view returns (address) {
          return msg.sender;
      }
  }
  */
  interface::types::EvmCodeHexStringView creatorStorageCode{
      "608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffff"
      "ffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffff"
      "ffffffff16021790555061012d806100606000396000f3fe6080604052348015600f5760"
      "0080fd5b506004361060325760003560e01c80630ee2cb101460375780637a6ce2e11460"
      "7f575b600080fd5b603d60c7565b604051808273ffffffffffffffffffffffffffffffff"
      "ffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060"
      "405180910390f35b608560f0565b604051808273ffffffffffffffffffffffffffffffff"
      "ffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060"
      "405180910390f35b60008060009054906101000a900473ffffffffffffffffffffffffff"
      "ffffffffffffff16905090565b60003390509056fea265627a7a72315820336325bf5922"
      "e2c7c3f12efcc8283ba81942be490be9e05c0414d5b028b279b464736f6c634300050b00"
      "32"sv};

  // getCreator()
  interface::types::EvmCodeHexStringView getCreator{"0ee2cb10"sv};
  // getMsgSender()
  interface::types::EvmCodeHexStringView getMsgSender{"7a6ce2e1"sv};
};

/**
 * @given some user
 * @when execute tx with EngineCall command
 * @then there is the tx in proposal
 */
TEST_F(EngineCall, Basic) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTx(complete(
          baseTx(kAdminId)
              .createRole("evm", interface::RolePermissionSet().setAll())
              .createDomain("evm", "evm")
              .createAccount("evm",
                             "evm",
                             PublicKeyHexStringView{kEvmKeypair.publicKey()}),
          kAdminKeypair))
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          complete(baseTx().callEngine(kAdminId, callee, code)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().callEngine(kAdminId, callee, inputCallSetter)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().callEngine(kAdminId, callee, inputCallGetter)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

TEST_F(EngineCall, CreatorStorageSmartContract) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTx(complete(
          baseTx(kAdminId)
              .createRole("evm", interface::RolePermissionSet().setAll())
              .createDomain("evm", "evm")
              .createAccount("evm",
                             "evm",
                             PublicKeyHexStringView{kEvmKeypair.publicKey()}),
          kAdminKeypair))
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          complete(baseTx().callEngine(kAdminId, callee, creatorStorageCode)),

          //   complete(baseTx().callEngine(
          //       caller, callee, creatorStorageCode, "")),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().callEngine(kAdminId, callee, getCreator)),
          //   complete(baseTx().callEngine(caller, callee, "",
          //   getCreator)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().callEngine(kAdminId, callee, getMsgSender)),
          //   complete(baseTx().callEngine(caller, callee, "",
          //   getMsgSender)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}
