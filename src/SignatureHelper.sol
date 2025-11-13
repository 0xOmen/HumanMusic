// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureHelper {
    using ECDSA for bytes32;

    // ============ EIP-712 DOMAIN CONSTANTS ============

    /// @dev EIP-712 domain typehash for signature verification
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev EIP-712 typehash for duration verification signatures
    bytes32 private constant DURATION_TYPEHASH =
        keccak256("DurationVerification(string youtubeVideoId,uint256 duration,uint256 deadline)");

    /// @dev EIP-712 typehash for user registration verification signatures
    bytes32 private constant USER_REGISTRATION_TYPEHASH =
        keccak256("UserRegistration(uint256 fid,address userAddress,uint256 deadline)");

    /// @dev EIP-712 domain separator, computed at deployment
    bytes32 private immutable DOMAIN_SEPARATOR;

    uint256 private immutable BASE_CHAIN_ID = 8453;
    address private immutable BASE_CONTRACT_ADDRESS = 0x1660a4E6c62d22FC5387622119cd60AB6A2B5efE;

    constructor() {
        // Initialize EIP-712 domain separator
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH, keccak256("HumanMusicDAO"), keccak256("1"), BASE_CHAIN_ID, BASE_CONTRACT_ADDRESS
            )
        );
    }

    // Note: Signature generation must be done off-chain (e.g., in Foundry scripts using vm.sign())
    // Contracts cannot sign because they don't have access to private keys.
    // Use the deployment script (DeploySignatureHelper.s.sol) to generate signatures.

    function getDomainSeparator() public view returns (bytes32) {
        return DOMAIN_SEPARATOR;
    }

    function getDomainInfo() public view returns (bytes32, bytes32, uint256, address) {
        return (DOMAIN_TYPEHASH, DOMAIN_SEPARATOR, BASE_CHAIN_ID, BASE_CONTRACT_ADDRESS);
    }
}
