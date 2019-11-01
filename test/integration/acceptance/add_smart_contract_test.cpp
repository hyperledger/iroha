#include <gtest/gtest.h>
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

class AddSmartContract : public AcceptanceFixture {
  public:
    // TODO(IvanTyulyandin): add permissions for add_smart_contract
    auto makeUserWithPerms(const interface::RolePermissionSet &perms =
                           shared_model::interface::RolePermissionSet()) {
      return AcceptanceFixture::makeUserWithPerms(perms);
    }

/*

code is bytecode from the following Solidity code using online Remix IDE with compiler version 0.4.0

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

    std::string code = "606060405260a18060106000396000f360606040526000357c01000000000000000"
           "0000000000000000000000000000000000000000090048063d46300fd1460435780"
           "63ee919d5014606857603f565b6002565b34600257605260048050506082565b604"
           "0518082815260200191505060405180910390f35b34600257608060048080359060"
           "200190919050506093565b005b600060006000505490506090565b90565b8060006"
           "00050819055505b5056";

/*
  calling setA(uint256), bytes4(keccak256(setA(uint256))) == ee919d50, and append uint256 equal to 1 as the parameter
*/

    std::string inputCallSetter = "ee919d50"
        "0000000000000000000000000000000000000000000000000000000000000001";

/*
  calling getA(), bytes4(keccak256(getA())) == d46300fd
*/

    std::string inputCallGetter = "d46300fd";
};

/**
 * @given some user
 * @when execute tx with AddSmartContract command
 * @then there is the tx in proposal
 */
TEST_F(AddSmartContract, Basic) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          complete(baseTx().addSmartContract("caller","Callee", code, "")),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().addSmartContract("caller","Callee", "", inputCallSetter)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().addSmartContract("caller","Callee", "", inputCallGetter)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });

}

