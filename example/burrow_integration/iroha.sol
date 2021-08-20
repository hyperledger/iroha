// SPDX-License-Identifier: Apache-2.0

pragma solidity >=0.7.0 <0.9.0;

contract Iroha {
    address public serviceContractAddress;

    event Created(string indexed name, string indexed domain);
    event Transferred(string indexed source, string indexed destination, string amount);
    event Added(string indexed asset, string amount);


    // Initializing service contract address in constructor
    constructor(){
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }

    // Creates an iroha ccount
    function createAccount(string memory name, string memory domain, string memory key) public  returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "createAccount(string,string,string)",
            name,
            domain,
            key);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        emit Created(name, domain);
        result = ret;
    }

    //Transfers asset from one iroha account to another
    function transferAsset(string memory src, string memory dst, string memory asset, string memory description, string memory amount) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "transferAsset(string,string,string,string,string)",
            src,
            dst,
            asset,
            description,
            amount);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");

        emit Transferred(src, dst, amount);
        result = ret;
    }
    // Adds asset to iroha account
    function addAssetQuantity(string memory asset, string memory amount) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "addAssetQuantity(string,string)",
            asset,
            amount);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");

        emit Added(asset, amount);
        result = ret;
    }
    //Queries balance of an iroha account
    function queryBalance(string memory _account, string memory _asset) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getAssetBalance(string,string)",
            _account,
            _asset);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success,"Error calling service contract function ");
        result = ret;
    }
}
