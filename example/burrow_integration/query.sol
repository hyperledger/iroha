// SPDX-License-Identifier: Apache-2.0

pragma solidity >=0.7.0 <0.9.0;

contract Query {
    address public serviceContractAddress;

    // Initializing service contract address in constructor
    constructor() {
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }

    // Queries peers details
    function getPeers() public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getPeers()");
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }

    // Queries a block details
    function getBlock(string memory height) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getBlock(string)",
            height);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }

    // Queries roles details
    function getRoles() public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getRoles()");
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }

     // Queries permissions of a role 
    function getRolePermissions(string memory role) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getRolePermissions(string)",
            role);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }
}
