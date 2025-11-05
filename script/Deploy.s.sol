// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {HumanMusicDAO} from "../src/humanmusic.sol";
import {HumanMusicToken} from "../src/mocks/HumanMusicToken.sol";

/**
 * @title Deploy
 * @notice Multi-chain deployment script for HumanMusicDAO
 * @dev Supports deployment to:
 *      - Anvil (local): Deploys mock token first
 *      - Base Mainnet: Uses existing token address
 *      - Base Sepolia: Uses existing token address
 *      - Ethereum Mainnet: Uses existing token address
 */
contract Deploy is Script {
    // Chain IDs
    uint256 private constant ANVIL_CHAIN_ID = 31337;
    uint256 private constant BASE_MAINNET_CHAIN_ID = 8453;
    uint256 private constant BASE_SEPOLIA_CHAIN_ID = 84532;
    uint256 private constant ETHEREUM_MAINNET_CHAIN_ID = 1;

    // Token addresses per chain (set these before deploying to mainnets)
    address private constant BASE_MAINNET_TOKEN = address(0); // TODO: Set actual token address
    address private constant BASE_SEPOLIA_TOKEN = address(0); // TODO: Set actual token address
    address private constant ETHEREUM_MAINNET_TOKEN = address(0); // TODO: Set actual token address

    // Deployment addresses (will be populated after deployment)
    address public tokenAddress;
    address public daoAddress;

    function run() external {
        uint256 chainId = block.chainid;
        address token;

        console.log("==========================================");
        console.log("Deploying HumanMusicDAO");
        console.log("Chain ID:", chainId);
        console.log("==========================================");

        // Determine token address based on chain
        if (chainId == ANVIL_CHAIN_ID) {
            // Deploy mock token for local testing
            console.log("Detected Anvil - deploying mock token...");
            token = deployMockToken();
        } else if (chainId == BASE_MAINNET_CHAIN_ID) {
            console.log("Detected Base Mainnet");
            require(BASE_MAINNET_TOKEN != address(0), "Token address not set for Base Mainnet");
            token = BASE_MAINNET_TOKEN;
        } else if (chainId == BASE_SEPOLIA_CHAIN_ID) {
            console.log("Detected Base Sepolia");
            require(BASE_SEPOLIA_TOKEN != address(0), "Token address not set for Base Sepolia");
            token = BASE_SEPOLIA_TOKEN;
        } else if (chainId == ETHEREUM_MAINNET_CHAIN_ID) {
            console.log("Detected Ethereum Mainnet");
            require(ETHEREUM_MAINNET_TOKEN != address(0), "Token address not set for Ethereum Mainnet");
            token = ETHEREUM_MAINNET_TOKEN;
        } else {
            revert("Unsupported chain");
        }

        console.log("Token address:", token);

        // Deploy HumanMusicDAO
        address dao = deployDAO(token);

        // Store addresses
        tokenAddress = token;
        daoAddress = dao;

        // Log deployment info
        console.log("==========================================");
        console.log("Deployment Complete!");
        console.log("Token Address:", token);
        console.log("DAO Address:", dao);
        console.log("Chain ID:", chainId);
        console.log("==========================================");

        // Save deployment info to file
        //saveDeploymentInfo(chainId, token, dao);
    }

    /**
     * @notice Deploy mock ERC20 token for local testing
     */
    function deployMockToken() internal returns (address) {
        console.log("Deploying HumanMusicToken...");
        vm.broadcast();
        HumanMusicToken token = new HumanMusicToken();
        console.log("HumanMusicToken deployed at:", address(token));
        return address(token);
    }

    /**
     * @notice Deploy HumanMusicDAO contract
     * @param token The address of the HUMANMUSIC token contract
     */
    function deployDAO(address token) internal returns (address) {
        console.log("Deploying HumanMusicDAO...");
        vm.broadcast();
        HumanMusicDAO dao = new HumanMusicDAO(token);
        console.log("HumanMusicDAO deployed at:", address(dao));
        return address(dao);
    }

    /**
     * @notice Save deployment information to a JSON file
     */
    function saveDeploymentInfo(uint256 chainId, address token, address dao) internal {
        string memory chainName = getChainName(chainId);
        string memory root = vm.projectRoot();
        string memory filename = string.concat(root, "/deployments/", chainName, ".json");

        string memory json = "deployment";
        vm.serializeAddress(json, "tokenAddress", token);
        vm.serializeAddress(json, "daoAddress", dao);
        vm.serializeUint(json, "chainId", chainId);
        vm.serializeString(json, "chainName", chainName);
        string memory deploymentJson = vm.serializeString(json, "deployedAt", vm.toString(block.timestamp));

        vm.writeFile(filename, deploymentJson);
        console.log("Deployment info saved to:", filename);
    }

    /**
     * @notice Get chain name from chain ID
     */
    function getChainName(uint256 chainId) internal pure returns (string memory) {
        if (chainId == ANVIL_CHAIN_ID) return "anvil";
        if (chainId == BASE_MAINNET_CHAIN_ID) return "base-mainnet";
        if (chainId == BASE_SEPOLIA_CHAIN_ID) return "base-sepolia";
        if (chainId == ETHEREUM_MAINNET_CHAIN_ID) return "ethereum-mainnet";
        // For unknown chains, return chain ID as string (fallback)
        if (chainId == 0) return "unknown";
        // Note: For other chain IDs, we'd need to convert to string, but for our supported chains this is sufficient
        return "unknown";
    }
}
