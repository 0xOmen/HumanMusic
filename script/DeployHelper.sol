// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {HumanMusicDAO} from "../src/humanmusic.sol";
import {HumanMusicToken} from "../src/mocks/HumanMusicToken.sol";

/**
 * @title DeployHelper
 * @notice Helper contract for deployment operations
 * @dev Separates deployment logic from script execution
 */
library DeployHelper {
    /**
     * @notice Deploy HumanMusicToken mock contract
     * @return token The deployed token contract address
     */
    function deployToken() external returns (address token) {
        HumanMusicToken tokenContract = new HumanMusicToken();
        return address(tokenContract);
    }

    /**
     * @notice Deploy HumanMusicDAO contract
     * @param tokenAddress The address of the HUMANMUSIC token contract
     * @return dao The deployed DAO contract address
     */
    function deployDAO(address tokenAddress) external returns (address dao) {
        HumanMusicDAO daoContract = new HumanMusicDAO(tokenAddress);
        return address(daoContract);
    }
}
