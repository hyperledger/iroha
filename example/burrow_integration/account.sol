// SPDX-License-Identifier: Apache-2.0

pragma solidity >=0.7.0 <0.9.0;

contract Account {
    address public serviceContractAddress;

    event Created(string indexed name, string indexed domain);

    // Initializing service contract address in constructor
    constructor(){
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }

    // Queries the balance in _asset of an Iroha _account
    function createAccount(string memory name, string memory domain, string memory key) public returns (bytes memory result) {
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
    function getAccount(string memory name) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getAccount(string)",
            name);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }
}
