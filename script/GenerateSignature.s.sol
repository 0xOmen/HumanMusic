// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {SignatureHelper} from "../src/SignatureHelper.sol";

/**
 * @title GenerateSignature
 * @notice Simple script to generate registration signatures using a deployed SignatureHelper
 * @dev This script assumes SignatureHelper is already deployed. Use DeploySignatureHelper.s.sol to deploy first.
 *
 * Usage:
 * 1. Deploy SignatureHelper: forge script script/DeploySignatureHelper.s.sol:DeploySignatureHelper --rpc-url http://localhost:8545 --broadcast
 * 2. Set environment variables:
 *    - SIGNATURE_HELPER_ADDRESS (required): Address of deployed SignatureHelper contract
 *    - FID (optional): Farcaster ID (defaults to 212074 if not set)
 *    - USER_ADDRESS (optional): User's Ethereum address (defaults to 0xa25CB4e9e15680220d2b9c23E6bde63E487c5b1D if not set)
 *    - PRIVATE_KEY (optional): Private key for signing (defaults to Anvil's first account)
 * 3. Run this script: forge script script/GenerateSignature.s.sol:GenerateSignature --rpc-url http://localhost:8545 -vvvv
 *
 * Example with environment variables:
 *    FID=123 USER_ADDRESS=0x... SIGNATURE_HELPER_ADDRESS=0x... forge script script/GenerateSignature.s.sol:GenerateSignature --rpc-url http://localhost:8545 -vvvv
 */
contract GenerateSignature is Script {
    // Update this address after deploying SignatureHelper, or set SIGNATURE_HELPER_ADDRESS env var
    address private constant DEFAULT_SIGNATURE_HELPER = address(0);

    // Default signer private key (Anvil's first account)
    uint256 private constant DEFAULT_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run() external view {
        // Get SignatureHelper address from env or use default
        address helperAddress = vm.envOr("SIGNATURE_HELPER_ADDRESS", DEFAULT_SIGNATURE_HELPER);
        require(helperAddress != address(0), "SIGNATURE_HELPER_ADDRESS not set");

        SignatureHelper signatureHelper = SignatureHelper(helperAddress);

        // Get parameters from environment variables with defaults
        // To require these values (no defaults), use: vm.envUint("FID") and vm.envAddress("USER_ADDRESS")
        uint256 fid = vm.envOr("FID", uint256(212074));
        address userAddress = vm.envOr("USER_ADDRESS", address(0xa25CB4e9e15680220d2b9c23E6bde63E487c5b1D));
        uint256 deadline = block.timestamp + 1 days;

        // Get private key from env or use default
        uint256 privateKey = vm.envOr("PRIVATE_KEY", DEFAULT_PRIVATE_KEY);

        // Generate signature
        bytes memory signature = generateSignature(signatureHelper, fid, userAddress, deadline, privateKey);

        // Display results
        address signer = vm.addr(privateKey);
        console.log("==========================================");
        console.log("REGISTRATION SIGNATURE");
        console.log("==========================================");
        console.log("SignatureHelper Address:", helperAddress);
        console.log("FID:", fid);
        console.log("User Address:", userAddress);
        console.log("Deadline:", deadline);
        console.log("Signer Address:", signer);
        console.log("Signature (hex):", vm.toString(signature));
        console.log("==========================================");
    }

    function generateSignature(
        SignatureHelper signatureHelper,
        uint256 fid,
        address userAddress,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (bytes memory signature) {
        // Get domain separator from the deployed contract
        bytes32 domainSeparator = signatureHelper.getDomainSeparator();

        // Create struct hash
        bytes32 userRegistrationTypehash =
            keccak256("UserRegistration(uint256 fid,address userAddress,uint256 deadline)");
        bytes32 structHash = keccak256(abi.encode(userRegistrationTypehash, fid, userAddress, deadline));

        // Create EIP-712 digest
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        // Sign with the private key using Foundry's vm.sign()
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // Encode signature (r, s, v)
        signature = abi.encodePacked(r, s, v);
    }
}

