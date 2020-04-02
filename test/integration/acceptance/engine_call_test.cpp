#include <string_view>

#include <gtest/gtest.h>
#include <boost/variant.hpp>

#include "backend/protobuf/query_responses/proto_engine_receipt.hpp"
#include "backend/protobuf/query_responses/proto_engine_receipts_response.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "framework/common_constants.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/query_responses/engine_receipts_response.hpp"

using namespace std::literals;

using namespace integration_framework;
using namespace shared_model;
using namespace shared_model::interface::types;
using namespace common_constants;

using shared_model::interface::permissions::Role;

class EngineCall : public AcceptanceFixture {
 public:
  auto makeUserWithPerms(const interface::RolePermissionSet &perms =
                             shared_model::interface::RolePermissionSet()) {
    return AcceptanceFixture::makeUserWithPerms(perms);
  }

  const std::string kRole2 = "user2_role";
  const std::string kOtherAssetName = "valuable_stock";
  const std::string kOtherAssetId = kOtherAssetName + "#" + kDomain;
  auto makeSecondUser(const interface::RolePermissionSet &perms =
                          shared_model::interface::RolePermissionSet()) {
    return AcceptanceFixture::createUserWithPerms(
               kSecondUser, kSameDomainUserSigner->publicKey(), kRole2, perms)
        .build()
        .signAndAddSignature(*kAdminSigner)
        .finish();
  }

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

  interface::types::EvmCodeHexStringView dummyCode{
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

  /*
  Contract that queries an account balance in Iroha

  contract TestIrohaQuery {

      function getBalance(string memory _account, string memory _asset) public
              returns (bytes memory result) {
          bytes memory payload = abi.encodeWithSignature(
            "getAssetBalance(string,string)", _account, _asset);
          (bool success, bytes memory ret) = address(
            0xA6Abc17819738299B3B2c1CE46d55c74f04E290C).delegatecall(payload);
          require(success, "Error calling service contract function");
          result = ret;
      }
  }
  */
  interface::types::EvmCodeHexStringView queryIrohaCode{
      "608060405234801561001057600080fd5b506104ec806100206000396000f3fe60806040"
      "5234801561001057600080fd5b506004361061002b5760003560e01c80636ac3d07b1461"
      "0030575b600080fd5b6101806004803603604081101561004657600080fd5b8101908080"
      "35906020019064010000000081111561006357600080fd5b820183602082011115610075"
      "57600080fd5b803590602001918460018302840111640100000000831117156100975760"
      "0080fd5b91908080601f0160208091040260200160405190810160405280939291908181"
      "52602001838380828437600081840152601f19601f820116905080830192505050505050"
      "509192919290803590602001906401000000008111156100fa57600080fd5b8201836020"
      "8201111561010c57600080fd5b8035906020019184600183028401116401000000008311"
      "171561012e57600080fd5b91908080601f01602080910402602001604051908101604052"
      "8093929190818152602001838380828437600081840152601f19601f8201169050808301"
      "925050505050505091929192905050506101fb565b604051808060200182810382528381"
      "8151815260200191508051906020019080838360005b838110156101c057808201518184"
      "01526020810190506101a5565b50505050905090810190601f1680156101ed5780820380"
      "516001836020036101000a031916815260200191505b509250505060405180910390f35b"
      "606080838360405160240180806020018060200183810383528581815181526020019150"
      "8051906020019080838360005b8381101561024757808201518184015260208101905061"
      "022c565b50505050905090810190601f1680156102745780820380516001836020036101"
      "000a031916815260200191505b5083810382528481815181526020019150805190602001"
      "9080838360005b838110156102ad578082015181840152602081019050610292565b5050"
      "5050905090810190601f1680156102da5780820380516001836020036101000a03191681"
      "5260200191505b509450505050506040516020818303038152906040527f260b5d520000"
      "00000000000000000000000000000000000000000000000000007bffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffff83818316178352505050509050600060"
      "6073a6abc17819738299b3b2c1ce46d55c74f04e290c73ffffffffffffffffffffffffff"
      "ffffffffffffff16836040518082805190602001908083835b602083106103c357805182"
      "526020820191506020810190506020830392506103a0565b6001836020036101000a0380"
      "19825116818451168082178552505050505050905001915050600060405180830381855a"
      "f49150503d8060008114610423576040519150601f19603f3d011682016040523d82523d"
      "6000602084013e610428565b606091505b509150915081610483576040517f08c379a000"
      "000000000000000000000000000000000000000000000000000000815260040180806020"
      "01828103825260278152602001806104906027913960400191505060405180910390fd5b"
      "8093505050509291505056fe4572726f722063616c6c696e67207365727669636520636f"
      "6e74726163742066756e6374696f6ea2646970667358221220dbdcb87d896faf57a69cd8"
      "23a9dc5a9b1c6de73f82eba3350338ca1cd4fb469364736f6c63430006080033"sv};

  // getBalance()
  interface::types::EvmCodeHexStringView getBalance{
      "6ac3d07b"
      "0000000000000000000000000000000000000000000000000000000000000040"
      "0000000000000000000000000000000000000000000000000000000000000080"
      "000000000000000000000000000000000000000000000000000000000000000c"
      "61646d696e40646f6d61696e0000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000b"
      "636f696e23646f6d61696e000000000000000000000000000000000000000000"sv};

  /*
  Contract code for transferring Iroha assets

  pragma solidity >=0.4.22 <0.7.0;

  contract TestIrohaCommand {

      function transfer(string memory _src, string memory _dst, string memory
  _asset, string memory _amount) public returns (bytes memory result) { bytes
  memory payload =
  abi.encodeWithSignature("transferAsset(string,string,string,string)", _src,
  _dst, _asset, _amount); (bool success, bytes memory ret) =
  address(0xA6Abc17819738299B3B2c1CE46d55c74f04E290C).delegatecall(payload);
          require(success, "Error calling service contract function");
          result = ret;
      }
  }
  */
  interface::types::EvmCodeHexStringView transferAssetCode{
      "608060405234801561001057600080fd5b506106f6806100206000396000f3fe60806040"
      "5234801561001057600080fd5b506004361061002b5760003560e01c80631457aac01461"
      "0030575b600080fd5b6102ae6004803603608081101561004657600080fd5b8101908080"
      "35906020019064010000000081111561006357600080fd5b820183602082011115610075"
      "57600080fd5b803590602001918460018302840111640100000000831117156100975760"
      "0080fd5b91908080601f0160208091040260200160405190810160405280939291908181"
      "52602001838380828437600081840152601f19601f820116905080830192505050505050"
      "509192919290803590602001906401000000008111156100fa57600080fd5b8201836020"
      "8201111561010c57600080fd5b8035906020019184600183028401116401000000008311"
      "171561012e57600080fd5b91908080601f01602080910402602001604051908101604052"
      "8093929190818152602001838380828437600081840152601f19601f8201169050808301"
      "925050505050505091929192908035906020019064010000000081111561019157600080"
      "fd5b8201836020820111156101a357600080fd5b80359060200191846001830284011164"
      "0100000000831117156101c557600080fd5b91908080601f016020809104026020016040"
      "519081016040528093929190818152602001838380828437600081840152601f19601f82"
      "011690508083019250505050505050919291929080359060200190640100000000811115"
      "61022857600080fd5b82018360208201111561023a57600080fd5b803590602001918460"
      "0183028401116401000000008311171561025c57600080fd5b91908080601f0160208091"
      "040260200160405190810160405280939291908181526020018383808284376000818401"
      "52601f19601f820116905080830192505050505050509192919290505050610329565b60"
      "40518080602001828103825283818151815260200191508051906020019080838360005b"
      "838110156102ee5780820151818401526020810190506102d3565b505050509050908101"
      "90601f16801561031b5780820380516001836020036101000a031916815260200191505b"
      "509250505060405180910390f35b60608085858585604051602401808060200180602001"
      "806020018060200185810385528981815181526020019150805190602001908083836000"
      "5b8381101561037f578082015181840152602081019050610364565b5050505090509081"
      "0190601f1680156103ac5780820380516001836020036101000a03191681526020019150"
      "5b50858103845288818151815260200191508051906020019080838360005b8381101561"
      "03e55780820151818401526020810190506103ca565b50505050905090810190601f1680"
      "156104125780820380516001836020036101000a031916815260200191505b5085810383"
      "5287818151815260200191508051906020019080838360005b8381101561044b57808201"
      "5181840152602081019050610430565b50505050905090810190601f1680156104785780"
      "820380516001836020036101000a031916815260200191505b5085810382528681815181"
      "5260200191508051906020019080838360005b838110156104b157808201518184015260"
      "2081019050610496565b50505050905090810190601f1680156104de5780820380516001"
      "836020036101000a031916815260200191505b5098505050505050505050604051602081"
      "8303038152906040527f2cddc41100000000000000000000000000000000000000000000"
      "0000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19"
      "166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "838183161783525050505090506000606073a6abc17819738299b3b2c1ce46d55c74f04e"
      "290c73ffffffffffffffffffffffffffffffffffffffff16836040518082805190602001"
      "908083835b602083106105cb578051825260208201915060208101905060208303925061"
      "05a8565b6001836020036101000a03801982511681845116808217855250505050505090"
      "5001915050600060405180830381855af49150503d806000811461062b57604051915060"
      "1f19603f3d011682016040523d82523d6000602084013e610630565b606091505b509150"
      "91508161068b576040517f08c379a0000000000000000000000000000000000000000000"
      "00000000000000815260040180806020018281038252602781526020018061069a602791"
      "3960400191505060405180910390fd5b80935050505094935050505056fe4572726f7220"
      "63616c6c696e67207365727669636520636f6e74726163742066756e6374696f6ea26469"
      "70667358221220879db2a49bf580a5f9d378b675127a2c81de867960e302ace46b8592b4"
      "b50ed964736f6c63430006080033"sv};

  /*
     transfer("user@domain", "user2@domain", "valuable_stock#domain", "63.99")
  */
  interface::types::EvmCodeHexStringView transferAsset{
      "1457aac0"
      "0000000000000000000000000000000000000000000000000000000000000080"
      "00000000000000000000000000000000000000000000000000000000000000c0"
      "0000000000000000000000000000000000000000000000000000000000000100"
      "0000000000000000000000000000000000000000000000000000000000000140"
      "000000000000000000000000000000000000000000000000000000000000000b"
      "7573657240646f6d61696e000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000c"
      "757365723240646f6d61696e0000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000015"
      "76616c7561626c655f73746f636b23646f6d61696e0000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000005"
      "36332e3939000000000000000000000000000000000000000000000000000000"sv};
};

/**
 * @given some user
 * @when execute tx with CallEngine command
 * @then there is the tx in proposal
 */
TEST_F(EngineCall, Basic) {
  IntegrationTestFramework itf(1);
  itf.setInitialState(kAdminSigner)
      .sendTx(
          makeUserWithPerms({Role::kCallEngine, Role::kGetMyEngineReceipts}))
      .skipProposal()
      .skipBlock();

  auto deploy_tx =
      complete(baseTx().callEngine(kUserId, std::nullopt, dummyCode));

  itf.sendTxAwait(deploy_tx, [](auto &block) {
    ASSERT_EQ(block->transactions().size(), 1);
  });
  std::vector<std::string> deployed_addresses;

  itf.sendQuery(
      complete(baseQry().getEngineReceipts(deploy_tx.hash().hex())),
      [&deployed_addresses](const auto &response) {
        auto *receipts_response =
            boost::get<const shared_model::interface::EngineReceiptsResponse &>(
                &response.get());
        ASSERT_NE(receipts_response, nullptr);
        const auto &receipts = receipts_response->engineReceipts();
        std::transform(receipts.begin(),
                       receipts.end(),
                       std::back_inserter(deployed_addresses),
                       [](auto const &receipt) {
                         EXPECT_NE(receipt.getContractAddress(), std::nullopt);
                         return receipt.getContractAddress().value();
                       });
      });

  ASSERT_NE(deployed_addresses.size(), 0);
  interface::types::EvmCalleeHexStringView callee{deployed_addresses[0]};
  itf.sendTxAwait(
         complete(baseTx().callEngine(kUserId, callee, inputCallSetter)),
         [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().callEngine(kUserId, callee, inputCallGetter)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

TEST_F(EngineCall, CreatorStorageSmartContract) {
  IntegrationTestFramework itf(1);
  itf.setInitialState(kAdminSigner)
      .sendTx(
          makeUserWithPerms({Role::kCallEngine, Role::kGetMyEngineReceipts}))
      .skipProposal()
      .skipBlock();

  auto deploy_tx =
      complete(baseTx().callEngine(kUserId, std::nullopt, creatorStorageCode));

  itf.sendTxAwait(deploy_tx, [](auto &block) {
    ASSERT_EQ(block->transactions().size(), 1);
  });
  std::vector<std::string> deployed_addresses;

  itf.sendQuery(
      complete(baseQry().getEngineReceipts(deploy_tx.hash().hex())),
      [&deployed_addresses](const auto &response) {
        auto *receipts_response =
            boost::get<const shared_model::interface::EngineReceiptsResponse &>(
                &response.get());
        ASSERT_NE(receipts_response, nullptr);
        const auto &receipts = receipts_response->engineReceipts();
        std::transform(receipts.begin(),
                       receipts.end(),
                       std::back_inserter(deployed_addresses),
                       [](auto const &receipt) {
                         EXPECT_NE(receipt.getContractAddress(), std::nullopt);
                         return receipt.getContractAddress().value();
                       });
      });

  ASSERT_NE(deployed_addresses.size(), 0);
  interface::types::EvmCalleeHexStringView callee{deployed_addresses[0]};
  itf.sendTxAwait(
         complete(baseTx().callEngine(kUserId, callee, getCreator)),
         [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          complete(baseTx().callEngine(kUserId, callee, getMsgSender)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * @given some user in Iroha in possession of some asset
 * @when execute a CallEngine command with a tx that makes
 * a query to Iroha to fetch balance
 * @then the tx successfully makes it into the proposal
 */
TEST_F(EngineCall, QueryAccountBalance) {
  IntegrationTestFramework itf(1);
  itf.setInitialState(kAdminSigner)
      .sendTx(makeUserWithPerms({Role::kCallEngine,
                                 Role::kGetMyEngineReceipts,
                                 Role::kCreateAsset,
                                 Role::kAddAssetQty,
                                 Role::kGetAllAccAst}))
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().createAsset(kAssetName, kDomain, 2)))
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().addAssetQuantity(kAssetId, "1000.00")))
      .skipProposal()
      .skipBlock();

  auto deploy_tx =
      complete(baseTx().callEngine(kUserId, std::nullopt, queryIrohaCode));

  itf.sendTxAwait(deploy_tx, [](auto &block) {
    ASSERT_EQ(block->transactions().size(), 1);
  });
  std::vector<std::string> deployed_addresses;

  itf.sendQuery(
      complete(baseQry().getEngineReceipts(deploy_tx.hash().hex())),
      [&deployed_addresses](const auto &response) {
        auto *receipts_response =
            boost::get<const shared_model::interface::EngineReceiptsResponse &>(
                &response.get());
        ASSERT_NE(receipts_response, nullptr);
        const auto &receipts = receipts_response->engineReceipts();
        std::transform(receipts.begin(),
                       receipts.end(),
                       std::back_inserter(deployed_addresses),
                       [](auto const &receipt) {
                         EXPECT_NE(receipt.getContractAddress(), std::nullopt);
                         return receipt.getContractAddress().value();
                       });
      });

  ASSERT_NE(deployed_addresses.size(), 0);
  interface::types::EvmCalleeHexStringView callee{deployed_addresses[0]};
  itf.sendTxAwait(
      complete(baseTx().callEngine(kUserId, callee, getBalance)),
      [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * @given some user in Iroha in possession of some asset
 * @when execute a transfer of some amount of this asset to another account
 * @then the tx gets to the block and the resulting accounts balances tally
 */
TEST_F(EngineCall, TransferAsset) {
  IntegrationTestFramework itf(1);
  itf.setInitialState(kAdminSigner)
      .sendTx(makeUserWithPerms({Role::kCallEngine,
                                 Role::kGetMyEngineReceipts,
                                 Role::kCreateAsset,
                                 Role::kAddAssetQty,
                                 Role::kGetAllAccAst,
                                 Role::kTransfer}))
      .skipProposal()
      .skipBlock()
      .sendTx(makeSecondUser({Role::kReceive}))
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().createAsset(kOtherAssetName, kDomain, 2)))
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().addAssetQuantity(kOtherAssetId, "1000.00")))
      .skipProposal()
      .skipBlock();

  auto deploy_tx =
      complete(baseTx().callEngine(kUserId, std::nullopt, transferAssetCode));

  itf.sendTxAwait(deploy_tx, [](auto &block) {
    ASSERT_EQ(block->transactions().size(), 1);
  });
  std::vector<std::string> deployed_addresses;

  itf.sendQuery(
      complete(baseQry().getEngineReceipts(deploy_tx.hash().hex())),
      [&deployed_addresses](const auto &response) {
        auto *receipts_response =
            boost::get<const shared_model::interface::EngineReceiptsResponse &>(
                &response.get());
        ASSERT_NE(receipts_response, nullptr);
        const auto &receipts = receipts_response->engineReceipts();
        std::transform(receipts.begin(),
                       receipts.end(),
                       std::back_inserter(deployed_addresses),
                       [](auto const &receipt) {
                         EXPECT_NE(receipt.getContractAddress(), std::nullopt);
                         return receipt.getContractAddress().value();
                       });
      });

  ASSERT_NE(deployed_addresses.size(), 0);
  interface::types::EvmCalleeHexStringView callee{deployed_addresses[0]};

  itf.sendTxAwait(
      complete(baseTx().callEngine(kUserId, callee, transferAsset)),
      [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * @given some user in Iroha in possession of some asset
 * @when attempt to transfer asset to an non-existent account
 * @then the tx is not included in the block
 */
TEST_F(EngineCall, AccountMissingError) {
  IntegrationTestFramework itf(1);
  itf.setInitialState(kAdminSigner)
      .sendTx(makeUserWithPerms({Role::kCallEngine,
                                 Role::kGetMyEngineReceipts,
                                 Role::kCreateAsset,
                                 Role::kAddAssetQty,
                                 Role::kGetAllAccAst,
                                 Role::kTransfer}))
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().createAsset(kOtherAssetName, kDomain, 2)))
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().addAssetQuantity(kOtherAssetId, "1000.00")))
      .skipProposal()
      .skipBlock();

  auto deploy_tx =
      complete(baseTx().callEngine(kUserId, std::nullopt, transferAssetCode));

  itf.sendTxAwait(deploy_tx, [](auto &block) {
    ASSERT_EQ(block->transactions().size(), 1);
  });
  std::vector<std::string> deployed_addresses;

  itf.sendQuery(
      complete(baseQry().getEngineReceipts(deploy_tx.hash().hex())),
      [&deployed_addresses](const auto &response) {
        auto *receipts_response =
            boost::get<const shared_model::interface::EngineReceiptsResponse &>(
                &response.get());
        ASSERT_NE(receipts_response, nullptr);
        const auto &receipts = receipts_response->engineReceipts();
        std::transform(receipts.begin(),
                       receipts.end(),
                       std::back_inserter(deployed_addresses),
                       [](auto const &receipt) {
                         EXPECT_NE(receipt.getContractAddress(), std::nullopt);
                         return receipt.getContractAddress().value();
                       });
      });

  ASSERT_NE(deployed_addresses.size(), 0);
  interface::types::EvmCalleeHexStringView callee{deployed_addresses[0]};

  itf.sendTxAwait(
      complete(baseTx().callEngine(kUserId, callee, transferAsset)),
      [](auto &block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * @given some user in Iroha without a permission for transfer
 * @when attempt to transfer asset to another account
 * @then the tx is discarded
 */
TEST_F(EngineCall, PermissionError) {
  IntegrationTestFramework itf(1);
  itf.setInitialState(kAdminSigner)
      .sendTx(makeUserWithPerms({Role::kCallEngine,
                                 Role::kGetMyEngineReceipts,
                                 Role::kCreateAsset,
                                 Role::kAddAssetQty,
                                 Role::kGetAllAccAst}))
      .skipProposal()
      .skipBlock()
      .sendTx(makeSecondUser({Role::kReceive}))
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().createAsset(kOtherAssetName, kDomain, 2)))
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().addAssetQuantity(kOtherAssetId, "1000.00")))
      .skipProposal()
      .skipBlock();

  auto deploy_tx =
      complete(baseTx().callEngine(kUserId, std::nullopt, transferAssetCode));

  itf.sendTxAwait(deploy_tx, [](auto &block) {
    ASSERT_EQ(block->transactions().size(), 1);
  });
  std::vector<std::string> deployed_addresses;

  itf.sendQuery(
      complete(baseQry().getEngineReceipts(deploy_tx.hash().hex())),
      [&deployed_addresses](const auto &response) {
        auto *receipts_response =
            boost::get<const shared_model::interface::EngineReceiptsResponse &>(
                &response.get());
        ASSERT_NE(receipts_response, nullptr);
        const auto &receipts = receipts_response->engineReceipts();
        std::transform(receipts.begin(),
                       receipts.end(),
                       std::back_inserter(deployed_addresses),
                       [](auto const &receipt) {
                         EXPECT_NE(receipt.getContractAddress(), std::nullopt);
                         return receipt.getContractAddress().value();
                       });
      });

  ASSERT_NE(deployed_addresses.size(), 0);
  interface::types::EvmCalleeHexStringView callee{deployed_addresses[0]};

  itf.sendTxAwait(
      complete(baseTx().callEngine(kUserId, callee, transferAsset)),
      [](auto &block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * @given some user in Iroha holding some asset
 * @when attempt to transfer to some other account more asset than he has got
 * @then the tx is discarded
 */
TEST_F(EngineCall, InsufficientBalanceError) {
  IntegrationTestFramework itf(1);
  itf.setInitialState(kAdminSigner)
      .sendTx(makeUserWithPerms({Role::kCallEngine,
                                 Role::kGetMyEngineReceipts,
                                 Role::kCreateAsset,
                                 Role::kAddAssetQty,
                                 Role::kGetAllAccAst}))
      .skipProposal()
      .skipBlock()
      .sendTx(makeSecondUser({Role::kReceive}))
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().createAsset(kOtherAssetName, kDomain, 2)))
      .skipProposal()
      .skipBlock()
      .sendTx(complete(baseTx().addAssetQuantity(kOtherAssetId, "50.00")))
      .skipProposal()
      .skipBlock();

  auto deploy_tx =
      complete(baseTx().callEngine(kUserId, std::nullopt, transferAssetCode));

  itf.sendTxAwait(deploy_tx, [](auto &block) {
    ASSERT_EQ(block->transactions().size(), 1);
  });
  std::vector<std::string> deployed_addresses;

  itf.sendQuery(
      complete(baseQry().getEngineReceipts(deploy_tx.hash().hex())),
      [&deployed_addresses](const auto &response) {
        auto *receipts_response =
            boost::get<const shared_model::interface::EngineReceiptsResponse &>(
                &response.get());
        ASSERT_NE(receipts_response, nullptr);
        const auto &receipts = receipts_response->engineReceipts();
        std::transform(receipts.begin(),
                       receipts.end(),
                       std::back_inserter(deployed_addresses),
                       [](auto const &receipt) {
                         EXPECT_NE(receipt.getContractAddress(), std::nullopt);
                         return receipt.getContractAddress().value();
                       });
      });

  ASSERT_NE(deployed_addresses.size(), 0);
  interface::types::EvmCalleeHexStringView callee{deployed_addresses[0]};

  itf.sendTxAwait(
      complete(baseTx().callEngine(kUserId, callee, transferAsset)),
      [](auto &block) { ASSERT_EQ(block->transactions().size(), 0); });
}
