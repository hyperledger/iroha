// SPDX-License-Identifier: Apache-2.0

pragma solidity >=0.7.0 <0.9.0;

contract Role {
    address public serviceContractAddress;

    // Initializing service contract address in constructor
    constructor() {
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }

    // Appends the role of an Iroha _account
    function appendRole(string memory _account, string memory role) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "appendRole(string,string)",
            _account,
            role);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }

    // Detaches the role of an Iroha _account
    function detachRole(string memory _account, string memory role) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "detachRole(string,string)",
            _account,
            role);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }
}
