// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title HumanMusicToken
 * @notice Mock ERC20 token for testing and local development
 * @dev This token is used for local testing on Anvil
 */
contract HumanMusicToken is ERC20 {
    constructor() ERC20("HumanMusic", "HUMANMUSIC") {
        // Mint initial supply to deployer (1 billion tokens)
        _mint(msg.sender, 1_000_000_000 * 10 ** decimals());
    }

    /**
     * @notice Mint tokens to a specific address (for testing purposes)
     * @param to Address to mint tokens to
     * @param amount Amount of tokens to mint (in wei)
     */
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
