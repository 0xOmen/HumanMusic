// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {SignatureHelper} from "../src/SignatureHelper.sol";

/**
 * @title GenerateSignature
 * @notice Script to generate EIP-712 signatures for registration and duration verification
 * @dev This script assumes SignatureHelper is already deployed. Use DeploySignatureHelper.s.sol to deploy first.
 *
 * Registration Signature Usage:
 * 1. Deploy SignatureHelper: forge script script/DeploySignatureHelper.s.sol:DeploySignatureHelper --rpc-url http://localhost:8545 --broadcast
 * 2. Set environment variables:
 *    - SIGNATURE_HELPER_ADDRESS (required): Address of deployed SignatureHelper contract
 *    - FID (optional): Farcaster ID (defaults to 212074 if not set)
 *    - USER_ADDRESS (optional): User's Ethereum address (defaults to 0xa25CB4e9e15680220d2b9c23E6bde63E487c5b1D if not set)
 *    - PRIVATE_KEY (optional): Private key for signing (defaults to Anvil's first account)
 * 3. Run: forge script script/GenerateSignature.s.sol:GenerateSignature --sig "run()" --rpc-url http://localhost:8545 -vvvv
 *
 * Duration Signature Usage:
 * 1. Set environment variables:
 *    - SIGNATURE_HELPER_ADDRESS (required): Address of deployed SignatureHelper contract
 *    - YOUTUBE_VIDEO_ID (required): YouTube video ID (11 characters)
 *    - DURATION (optional): Duration in seconds (defaults to 180 if not set)
 *    - DEADLINE (optional): Signature expiration timestamp (defaults to block.timestamp + 1 day if not set)
 *    - PRIVATE_KEY (optional): Private key for signing (defaults to Anvil's first account)
 * 2. Run: forge script script/GenerateSignature.s.sol:GenerateSignature --sig "runDurationSignature()" --rpc-url http://localhost:8545 -vvvv
 *
 * Examples:
 *    # Registration signature
 *    FID=123 USER_ADDRESS=0x... SIGNATURE_HELPER_ADDRESS=0x... forge script script/GenerateSignature.s.sol:GenerateSignature --sig "run()" --rpc-url http://localhost:8545 -vvvv
 *
 *    # Duration signature
 *    YOUTUBE_VIDEO_ID=dQw4w9WgXcQ DURATION=240 SIGNATURE_HELPER_ADDRESS=0x... forge script script/GenerateSignature.s.sol:GenerateSignature --sig "runDurationSignature()" --rpc-url http://localhost:8545 -vvvv
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

    /**
     * @notice Generate a duration verification signature
     * @dev This function generates an EIP-712 signature for video duration verification
     */
    function runDurationSignature() external view {
        // Get SignatureHelper address from env or use default
        address helperAddress = vm.envOr("SIGNATURE_HELPER_ADDRESS", DEFAULT_SIGNATURE_HELPER);
        require(helperAddress != address(0), "SIGNATURE_HELPER_ADDRESS not set");

        SignatureHelper signatureHelper = SignatureHelper(helperAddress);

        // Get parameters from environment variables
        // YouTube video ID is required (must be 11 characters)
        string memory youtubeVideoId = vm.envString("YOUTUBE_VIDEO_ID");
        require(bytes(youtubeVideoId).length == 11, "YOUTUBE_VIDEO_ID must be 11 characters");

        // Duration defaults to 180 seconds (3 minutes) if not provided
        uint256 duration = vm.envOr("DURATION", uint256(180));
        require(duration > 0 && duration <= 600, "Duration must be 1-600 seconds");

        // Deadline defaults to block.timestamp + 1 day if not provided
        uint256 deadline = vm.envOr("DEADLINE", uint256(block.timestamp + 1 days));

        // Get private key from env or use default
        uint256 privateKey = vm.envOr("PRIVATE_KEY", DEFAULT_PRIVATE_KEY);

        // Generate signature
        bytes memory signature =
            generateDurationSignature(signatureHelper, youtubeVideoId, duration, deadline, privateKey);

        // Display results
        address signer = vm.addr(privateKey);
        console.log("==========================================");
        console.log("DURATION VERIFICATION SIGNATURE");
        console.log("==========================================");
        console.log("SignatureHelper Address:", helperAddress);
        console.log("YouTube Video ID:", youtubeVideoId);
        console.log("Duration (seconds):", duration);
        console.log("Deadline (timestamp):", deadline);
        console.log("Signer Address:", signer);
        console.log("Signature (hex):", vm.toString(signature));
        console.log("==========================================");
    }

    /**
     * @notice Generate a duration verification signature
     * @param signatureHelper The SignatureHelper contract instance
     * @param youtubeVideoId The YouTube video ID (11 characters)
     * @param duration The duration in seconds (1-600)
     * @param deadline The signature expiration timestamp
     * @param privateKey The private key to sign with
     * @return signature The EIP-712 signature
     */
    function generateDurationSignature(
        SignatureHelper signatureHelper,
        string memory youtubeVideoId,
        uint256 duration,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (bytes memory signature) {
        // Get domain separator from the deployed contract
        bytes32 domainSeparator = signatureHelper.getDomainSeparator();

        // Create struct hash (matches contract: keccak256(bytes(youtubeVideoId)) is used)
        bytes32 durationTypehash =
            keccak256("DurationVerification(string youtubeVideoId,uint256 duration,uint256 deadline)");
        bytes32 structHash =
            keccak256(abi.encode(durationTypehash, keccak256(bytes(youtubeVideoId)), duration, deadline));

        // Create EIP-712 digest
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        // Sign with the private key using Foundry's vm.sign()
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // Encode signature (r, s, v)
        signature = abi.encodePacked(r, s, v);
    }
}

