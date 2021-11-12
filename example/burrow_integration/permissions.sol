// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.7.0 <0.9.0;

contract Transaction {
    address public serviceContractAddress;

    // Initializing service contract address in constructor
    constructor() {
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }

    // Queries the balance in _asset of an Iroha _account
    function grantPermission(string memory _account, string memory _permission) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "grantPermission(string,string)",
            _account,
            _permission);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }

    function revokePermission(string memory _account, string memory _permission) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "revokePermission(string,string)",
            _account,
            _permission);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }

    function createRole(string memory _name, string memory _permissions) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "createRole(string,string)",
            _name,
            _permissions);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }
}
