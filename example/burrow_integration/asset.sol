// SPDX-License-Identifier: Apache-2.0

pragma solidity >=0.7.0 <0.9.0;

contract Asset {
    address public serviceContractAddress;

    event CreatedDomain(string indexed domain, string indexed role);
    event CreatedAsset(string indexed name,string indexed domain, string indexed precision);
    event Added(string indexed asset, string amount);
    event Subtracted(string indexed asset, string amount);

    // Initializing service contract address in constructor
    constructor(){
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }

    //Creates a new domain
    function createDomain(string memory domain, string memory role) public  returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "createDomain(string,string)",
            domain,
            role);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        emit CreatedDomain(domain, role);
        result = ret;
    }

    // Creates a new asset
    function createAsset(string memory name, string memory domain, string memory precision) public  returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "createAsset(string,string,string)",
            name,
            domain,
            precision);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        emit CreatedAsset(name, domain, precision);
        result = ret;
    }

    // Gets asset info
    function getAssetInfo(string memory name) public  returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getAssetInfo(string)",
            name);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
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

    // Subtracts asset to iroha account
    function subtractAssetQuantity(string memory asset, string memory amount) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "subtractAssetQuantity(string,string)",
            asset,
            amount);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");

        emit Subtracted(asset, amount);
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
