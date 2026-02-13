// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/**
 * @title SafeVault
 * @notice Example of a secure vault contract following best practices.
 */
contract SafeVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // Checks-Effects-Interactions pattern
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount; // Effect before interaction
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        emit Withdrawal(msg.sender, amount);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function setOwner(address _new) external onlyOwner {
        require(_new != address(0), "Invalid address");
        emit OwnershipTransferred(owner, _new);
        owner = _new;
    }

    receive() external payable {}
}
