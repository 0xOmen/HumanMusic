// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {SignatureHelper} from "../src/SignatureHelper.sol";

/**
 * @title DeploySignatureHelper
 * @notice Deployment script for SignatureHelper contract
 * @dev Deploys SignatureHelper and provides utilities to generate registration signatures
 */
contract DeploySignatureHelper is Script {
    SignatureHelper public signatureHelper;

    // Default signer private key (Anvil's first account)
    // You can override this by setting PRIVATE_KEY environment variable
    uint256 private constant DEFAULT_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run() external {
        console.log("==========================================");
        console.log("Deploying SignatureHelper");
        console.log("Chain ID:", block.chainid);
        console.log("==========================================");

        vm.broadcast();
        signatureHelper = new SignatureHelper();

        console.log("SignatureHelper deployed at:", address(signatureHelper));
        console.log("Domain Separator:", vm.toString(signatureHelper.getDomainSeparator()));

        // Get domain info
        (bytes32 domainTypehash, bytes32 domainSeparator, uint256 chainId, address contractAddress) =
            signatureHelper.getDomainInfo();
        console.log("Domain Typehash:", vm.toString(domainTypehash));
        console.log("Chain ID:", chainId);
        console.log("Contract Address:", contractAddress);
        console.log("==========================================");

        // Example: Generate a registration signature
        // You can modify these values or call generateSignature() separately
        uint256 fid = 1;
        address userAddress = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // Anvil's second account
        uint256 deadline = block.timestamp + 1 days;

        console.log("\nGenerating example registration signature...");
        console.log("FID:", fid);
        console.log("User Address:", userAddress);
        console.log("Deadline:", deadline);

        bytes memory signature = generateSignature(fid, userAddress, deadline);
        console.log("\n==========================================");
        console.log("SIGNATURE GENERATED:");
        console.log("==========================================");
        console.log("Hex:", vm.toString(signature));
        console.log("==========================================");
    }

    /**
     * @notice Generate a registration signature
     * @param fid The Farcaster ID
     * @param userAddress The user's Ethereum address
     * @param deadline The signature deadline (unix timestamp)
     * @return signature The EIP-712 signature
     */
    function generateSignature(uint256 fid, address userAddress, uint256 deadline)
        public
        view
        returns (bytes memory signature)
    {
        // Get the private key from environment or use default
        uint256 privateKey = vm.envOr("PRIVATE_KEY", DEFAULT_PRIVATE_KEY);

        // Get domain separator from the deployed contract
        bytes32 domainSeparator = signatureHelper.getDomainSeparator();

        // Create struct hash (same as in the contract)
        bytes32 userRegistrationTypehash =
            keccak256("UserRegistration(uint256 fid,address userAddress,uint256 deadline)");
        bytes32 structHash = keccak256(abi.encode(userRegistrationTypehash, fid, userAddress, deadline));

        // Create EIP-712 digest
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        // Sign with the private key using Foundry's vm.sign()
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // Encode signature (r, s, v)
        signature = abi.encodePacked(r, s, v);

        // Log the signer address for verification
        address signer = vm.addr(privateKey);
        console.log("Signer Address:", signer);
    }

    /**
     * @notice Generate and display a registration signature with custom parameters
     * @param fid The Farcaster ID
     * @param userAddress The user's Ethereum address
     * @param deadline The signature deadline (unix timestamp)
     * @param privateKeyHex The private key as a hex string (optional, uses env var or default if empty)
     */
    function generateAndDisplaySignature(
        uint256 fid,
        address userAddress,
        uint256 deadline,
        string memory privateKeyHex
    ) external view {
        uint256 privateKey;
        if (bytes(privateKeyHex).length == 0) {
            privateKey = vm.envOr("PRIVATE_KEY", DEFAULT_PRIVATE_KEY);
        } else {
            privateKey = uint256(vm.parseBytes32(privateKeyHex));
        }

        // Get domain separator
        bytes32 domainSeparator = signatureHelper.getDomainSeparator();

        // Create struct hash
        bytes32 userRegistrationTypehash =
            keccak256("UserRegistration(uint256 fid,address userAddress,uint256 deadline)");
        bytes32 structHash = keccak256(abi.encode(userRegistrationTypehash, fid, userAddress, deadline));

        // Create digest
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        // Sign
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Display
        address signer = vm.addr(privateKey);
        console.log("==========================================");
        console.log("REGISTRATION SIGNATURE");
        console.log("==========================================");
        console.log("FID:", fid);
        console.log("User Address:", userAddress);
        console.log("Deadline:", deadline);
        console.log("Signer Address:", signer);
        console.log("Signature (hex):", vm.toString(signature));
        console.log("==========================================");
    }
}

