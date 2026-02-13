// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VulnerableVault
 * @notice Example contract with intentional vulnerabilities for ShieldScan testing.
 * @dev DO NOT deploy this contract. It is intentionally insecure.
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;

    constructor() {
        owner = msg.sender;
    }

    // [CRITICAL] Reentrancy: external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    // [HIGH] tx.origin used for authentication
    function setOwner(address _new) public {
        require(tx.origin == owner, "Not owner");
        owner = _new;
    }

    // [MEDIUM] Missing event emission on state change
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // [MEDIUM] Timestamp dependence
    function isLocked() public view returns (bool) {
        return block.timestamp > 1700000000;
    }

    receive() external payable {}
}
