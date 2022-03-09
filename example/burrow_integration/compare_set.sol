// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.7.0 <0.9.0;

contract Transaction {
    address public serviceContractAddress;

    // Initializing service contract address in constructor
    constructor() {
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }
    function compareAndSetAccountDetail(string memory account, string memory key, string memory value, string memory old_value, string memory check_empty) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "compareAndSetAccountDetail(string,string,string,string,string)",
            account,
            key,
            value,
            old_value,
            check_empty);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }
}
