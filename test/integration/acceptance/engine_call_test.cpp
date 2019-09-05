#include <gtest/gtest.h>
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"

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

  std::string callee = "callee";

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

  std::string code =
      "606060405260a18060106000396000f360606040526000357c01000000000000000"
      "0000000000000000000000000000000000000000090048063d46300fd1460435780"
      "63ee919d5014606857603f565b6002565b34600257605260048050506082565b604"
      "0518082815260200191505060405180910390f35b34600257608060048080359060"
      "200190919050506093565b005b600060006000505490506090565b90565b8060006"
      "00050819055505b5056";

  /*
    calling setA(uint256), bytes4(keccak256(setA(uint256))) == ee919d50, and
    append uint256 equal to 1 as the parameter
  */

  std::string inputCallSetter =
      "ee919d50"
      "0000000000000000000000000000000000000000000000000000000000000001";

  /*
    calling getA(), bytes4(keccak256(getA())) == d46300fd
  */

  std::string inputCallGetter = "d46300fd";

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
  std::string creatorStorageCode =  "608060405234801561001057600080fd5b50336000"
    "806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffff"
    "ffffffffffffffffffffffffffffffffffff16021790555061012d806100606000396000f3"
    "fe6080604052348015600f57600080fd5b506004361060325760003560e01c80630ee2cb10"
    "1460375780637a6ce2e114607f575b600080fd5b603d60c7565b604051808273ffffffffff"
    "ffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff"
    "16815260200191505060405180910390f35b608560f0565b604051808273ffffffffffffff"
    "ffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681"
    "5260200191505060405180910390f35b60008060009054906101000a900473ffffffffffff"
    "ffffffffffffffffffffffffffff16905090565b60003390509056fea265627a7a72315820"
    "336325bf5922e2c7c3f12efcc8283ba81942be490be9e05c0414d5b028b279b464736f6c63"
    "4300050b0032";

// getCreator()
  std::string getCreator = "0ee2cb10";
// getMsgSender()
  std::string getMsgSender = "7a6ce2e1";
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
          complete(baseTx().addSmartContract(callee, code)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().addSmartContract(
              callee, inputCallSetter)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().addSmartContract(
              callee,inputCallGetter)),
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
          complete(baseTx().addSmartContract(caller, callee, creatorStorageCode, "")),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().addSmartContract(
              caller, callee, "", getCreator)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().addSmartContract(
              caller, callee, "", getMsgSender)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}
