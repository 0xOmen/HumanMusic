// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {HumanMusicDAO} from "../src/humanmusic.sol";
import {HumanMusicToken} from "../src/mocks/HumanMusicToken.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title UnitTests
 * @notice Unit tests for individual HumanMusicDAO functions
 */
contract UnitTests is Test {
    using ECDSA for bytes32;

    HumanMusicDAO public dao;
    HumanMusicToken public token;

    // Test addresses
    address public deployer;
    address public user1;
    address public user2;
    address public newBackendSigner;
    address public nonOwner;

    // Test user data
    uint256 public constant FID_1 = 12345;
    uint256 public constant FID_2 = 67890;
    string public constant USERNAME_1 = "testuser1";
    string public constant USERNAME_2 = "testuser2";
    string public constant COUNTRY_1 = "US";
    string public constant COUNTRY_2 = "CA";

    // EIP-712 constants
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant USER_REGISTRATION_TYPEHASH =
        keccak256("UserRegistration(uint256 fid,address userAddress,uint256 deadline)");

    // Events
    event UserRegistered(uint256 indexed fid, string username, string country, address indexed registeredAddress);
    event BackendSignerUpdated(address indexed oldSigner, address indexed newSigner);
    event UserAddressAdded(uint256 indexed fid, address indexed registeredAddress);

    function setUp() public {
        // Use default Foundry account (known private key) as deployer
        uint256 deployerKey = deployerPrivateKey();
        deployer = vm.addr(deployerKey);

        // Derive addresses from private keys for consistent signing
        uint256 user1Key = 0x1111111111111111111111111111111111111111111111111111111111111111;
        uint256 user2Key = 0x2222222222222222222222222222222222222222222222222222222222222222;
        uint256 newBackendSignerKey = 0x3333333333333333333333333333333333333333333333333333333333333333;
        uint256 nonOwnerKey = 0x4444444444444444444444444444444444444444444444444444444444444444;

        user1 = vm.addr(user1Key);
        user2 = vm.addr(user2Key);
        newBackendSigner = vm.addr(newBackendSignerKey);
        nonOwner = vm.addr(nonOwnerKey);

        // Deploy token as deployer
        vm.startPrank(deployer);
        token = new HumanMusicToken();

        // Deploy DAO as deployer
        dao = new HumanMusicDAO(address(token));
        vm.stopPrank();

        // Deposit 1 billion tokens (1e9 * 1e18 = 1e27)
        uint256 depositAmount = 1_000_000_000 * 10 ** 18;
        vm.startPrank(deployer);
        token.approve(address(dao), depositAmount);
        dao.depositRewardTokens(depositAmount);
        vm.stopPrank();

        // Verify deposit
        assertEq(token.balanceOf(address(dao)), depositAmount, "DAO should have 1 billion tokens");
    }

    // ============ EIP-712 SIGNATURE HELPER ============

    /**
     * @notice Generate EIP-712 signature for user registration
     * @param fid The Farcaster FID
     * @param userAddress The user's address
     * @param deadline The signature deadline
     * @param signerPrivateKey The private key of the signer (backend signer)
     * @return signature The EIP-712 signature
     */
    function generateRegistrationSignature(uint256 fid, address userAddress, uint256 deadline, uint256 signerPrivateKey)
        internal
        view
        returns (bytes memory signature)
    {
        // Get domain separator from contract
        (bytes32 domainSeparator,,,,) = dao.getDomainInfo();

        // Create struct hash
        bytes32 structHash = keccak256(abi.encode(USER_REGISTRATION_TYPEHASH, fid, userAddress, deadline));

        // Create digest
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        // Sign with the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    // ============ registerUser TESTS ============

    /**
     * @notice Test that registerUser reverts if _fid is zero
     */
    function test_registerUser_RevertsIfFidZero() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(0, user1, deadline, deployerPrivateKey());

        vm.prank(user1);
        vm.expectRevert("Invalid FID");
        dao.registerUser(0, USERNAME_1, COUNTRY_1, deadline, signature);
    }

    /**
     * @notice Test that registerUser works with a valid signature
     */
    function test_registerUser_ValidSignature() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());

        vm.prank(user1);
        vm.expectEmit(true, true, true, true);
        emit UserRegistered(FID_1, USERNAME_1, COUNTRY_1, user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Verify user is stored correctly
        (uint256 fid, string memory username, string memory country,,,,,,,) = getUserData(FID_1);
        assertEq(fid, FID_1, "FID should match");
        assertEq(username, USERNAME_1, "Username should match");
        assertEq(country, COUNTRY_1, "Country should match");

        // Verify address is added as valid
        assertTrue(dao.userAddressValid(FID_1, user1), "User address should be valid");
    }

    /**
     * @notice Test that registerUser reverts with an invalid signature
     */
    function test_registerUser_RevertsIfInvalidSignature() public {
        uint256 deadline = block.timestamp + 1 hours;

        // Generate signature with wrong private key (nonOwner's key)
        bytes memory badSignature = generateRegistrationSignature(FID_1, user1, deadline, nonOwnerPrivateKey());

        vm.prank(user1);
        vm.expectRevert("Invalid signature");
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, badSignature);
    }

    /**
     * @notice Test that registerUser properly sets up user data
     */
    function test_registerUser_SetsUserDataCorrectly() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());

        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Get user data
        (
            uint256 fid,
            string memory username,
            string memory country,
            uint256 submissionCount,
            uint256 totalUpvotes,
            uint256 lastSubmissionDay,
            uint256 tokensEarned,
            uint256 tokenBalance,
            bool isReviewer,
            uint256 reputationScore
        ) = getUserData(FID_1);

        // Verify all fields
        assertEq(fid, FID_1, "FID should be set");
        assertEq(username, USERNAME_1, "Username should be set");
        assertEq(country, COUNTRY_1, "Country should be set");
        assertEq(submissionCount, 0, "Submission count should be 0");
        assertEq(totalUpvotes, 0, "Total upvotes should be 0");
        assertEq(tokensEarned, 0, "Tokens earned should be 0");
        assertEq(tokenBalance, 0, "Token balance should be 0");
        assertFalse(isReviewer, "Should not be reviewer");
        assertEq(reputationScore, 100, "Reputation score should be 100");
    }

    /**
     * @notice Test that registerUser adds msg.sender as valid address
     */
    function test_registerUser_AddsSenderAsValidAddress() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());

        // Before registration, address should not be valid
        assertFalse(dao.userAddressValid(FID_1, user1), "Address should not be valid before registration");

        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // After registration, address should be valid
        assertTrue(dao.userAddressValid(FID_1, user1), "Address should be valid after registration");
    }

    /**
     * @notice Test that registerUser emits UserRegistered event
     */
    function test_registerUser_EmitsEvent() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());

        vm.prank(user1);
        vm.expectEmit(true, true, true, true);
        emit UserRegistered(FID_1, USERNAME_1, COUNTRY_1, user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);
    }

    /**
     * @notice Test that registerUser reverts if user is already registered
     */
    function test_registerUser_RevertsIfAlreadyRegistered() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());

        // Register user first time
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Try to register again
        uint256 newDeadline = block.timestamp + 1 hours;
        bytes memory newSignature = generateRegistrationSignature(FID_1, user1, newDeadline, deployerPrivateKey());

        vm.prank(user1);
        vm.expectRevert("User already registered");
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, newDeadline, newSignature);
    }

    /**
     * @notice Test that registerUser reverts if signature is expired
     */
    function test_registerUser_RevertsIfSignatureExpired() public {
        uint256 deadline = block.timestamp - 1; // Expired
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());

        vm.prank(user1);
        vm.expectRevert("Signature expired");
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);
    }

    // ============ setBackendSigner TESTS ============

    /**
     * @notice Test that setBackendSigner can only be called by owner
     */
    function test_setBackendSigner_OnlyOwner() public {
        vm.prank(nonOwner);
        vm.expectRevert();
        dao.setBackendSigner(newBackendSigner);
    }

    /**
     * @notice Test that setBackendSigner reverts if new signer is address(0)
     */
    function test_setBackendSigner_RevertsIfZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert("Invalid signer address");
        dao.setBackendSigner(address(0));
    }

    /**
     * @notice Test that setBackendSigner updates the signer correctly
     */
    function test_setBackendSigner_UpdatesSigner() public {
        // Verify initial signer
        assertEq(dao.backendSigner(), deployer, "Initial signer should be deployer");

        // Change signer as owner
        vm.prank(deployer);
        vm.expectEmit(true, true, false, false);
        emit BackendSignerUpdated(deployer, newBackendSigner);
        dao.setBackendSigner(newBackendSigner);

        // Verify new signer
        assertEq(dao.backendSigner(), newBackendSigner, "Signer should be updated");
        assertEq(dao.getBackendSigner(), newBackendSigner, "getBackendSigner should return new signer");
    }

    /**
     * @notice Test that setBackendSigner emits BackendSignerUpdated event
     */
    function test_setBackendSigner_EmitsEvent() public {
        vm.prank(deployer);
        vm.expectEmit(true, true, false, false);
        emit BackendSignerUpdated(deployer, newBackendSigner);
        dao.setBackendSigner(newBackendSigner);
    }

    /**
     * @notice Test that new backend signer can sign user registrations
     */
    function test_setBackendSigner_NewSignerCanSignRegistrations() public {
        // Change backend signer
        vm.prank(deployer);
        dao.setBackendSigner(newBackendSigner);
        assertEq(dao.backendSigner(), newBackendSigner, "Signer should be updated");

        // Register a user with signature from new signer
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_2, user2, deadline, newBackendSignerPrivateKey());

        vm.prank(user2);
        vm.expectEmit(true, true, true, true);
        emit UserRegistered(FID_2, USERNAME_2, COUNTRY_2, user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature);

        // Verify user was registered
        (
            uint256 fid,
            string memory username,
            string memory country,
            uint256 submissionCount,
            uint256 totalUpvotes,
            uint256 lastSubmissionDay,
            uint256 tokensEarned,
            uint256 tokenBalance,
            bool isReviewer,
            uint256 reputationScore
        ) = getUserData(FID_2);
        assertEq(fid, FID_2, "User should be registered");
        assertEq(submissionCount, 0, "Submission count should be 0");
        assertEq(tokenBalance, 0, "Token balance should be 0");
        assertFalse(isReviewer, "Should not be reviewer");
        assertEq(reputationScore, 100, "Reputation score should be 100");
    }

    /**
     * @notice Test that old backend signer can no longer sign after change
     */
    function test_setBackendSigner_OldSignerCannotSignAfterChange() public {
        // Register a user with old signer first
        uint256 deadline1 = block.timestamp + 1 hours;
        bytes memory signature1 = generateRegistrationSignature(FID_1, user1, deadline1, deployerPrivateKey());

        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline1, signature1);

        // Change backend signer
        vm.prank(deployer);
        dao.setBackendSigner(newBackendSigner);

        // Try to register another user with old signer's signature (should fail)
        uint256 deadline2 = block.timestamp + 1 hours;
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline2, deployerPrivateKey());

        vm.prank(user2);
        vm.expectRevert("Invalid signature");
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline2, signature2);
    }

    // ============ addUserAddress TESTS ============

    /**
     * @notice Test that addUserAddress reverts if called by address not registered to the user
     */
    function test_addUserAddress_RevertsIfCallerNotRegisteredToFid() public {
        // First register user1 with FID_1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Try to add address from user2 (not registered to FID_1)
        address newAddress = address(0xAAAA);
        vm.prank(user2);
        vm.expectRevert("Sender addr not registered to FID");
        dao.addUserAddress(FID_1, newAddress);
    }

    /**
     * @notice Test that addUserAddress reverts if _fid has not been registered
     */
    function test_addUserAddress_RevertsIfFidNotRegistered() public {
        // Try to add address for unregistered FID
        address newAddress = address(0xAAAA);
        vm.prank(user1);
        vm.expectRevert("User not registered");
        dao.addUserAddress(FID_1, newAddress);
    }

    /**
     * @notice Test that addUserAddress reverts if address already registered to the fid
     */
    function test_addUserAddress_RevertsIfAddressAlreadyRegistered() public {
        // Register user1 with FID_1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // user1 is already registered to FID_1, try to add it again
        vm.prank(user1);
        vm.expectRevert("Address already registered to FID");
        dao.addUserAddress(FID_1, user1);
    }

    /**
     * @notice Test that addUserAddress reverts if new address is zero
     */
    function test_addUserAddress_RevertsIfZeroAddress() public {
        // Register user1 with FID_1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Try to add zero address
        vm.prank(user1);
        vm.expectRevert("Invalid address");
        dao.addUserAddress(FID_1, address(0));
    }

    /**
     * @notice Test that addUserAddress adds address as valid after function call
     */
    function test_addUserAddress_AddsAddressAsValid() public {
        // Register user1 with FID_1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Add new address
        address newAddress = address(0xAAAA);
        assertFalse(dao.userAddressValid(FID_1, newAddress), "Address should not be valid before adding");

        vm.prank(user1);
        dao.addUserAddress(FID_1, newAddress);

        // Verify address is now valid
        assertTrue(dao.userAddressValid(FID_1, newAddress), "Address should be valid after adding");
    }

    /**
     * @notice Test that addUserAddress emits UserAddressAdded event
     */
    function test_addUserAddress_EmitsEvent() public {
        // Register user1 with FID_1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Add new address
        address newAddress = address(0xAAAA);
        vm.prank(user1);
        vm.expectEmit(true, true, false, false);
        emit UserAddressAdded(FID_1, newAddress);
        dao.addUserAddress(FID_1, newAddress);
    }

    // ============ addUserAddressFromOwner TESTS ============

    /**
     * @notice Test that addUserAddressFromOwner can only be called by owner
     */
    function test_addUserAddressFromOwner_OnlyOwner() public {
        // Register user1 with FID_1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Try to call from non-owner
        address newAddress = address(0xAAAA);
        vm.prank(nonOwner);
        vm.expectRevert();
        dao.addUserAddressFromOwner(FID_1, newAddress);
    }

    /**
     * @notice Test that addUserAddressFromOwner reverts if user not registered
     */
    function test_addUserAddressFromOwner_RevertsIfUserNotRegistered() public {
        // Try to add address for unregistered FID
        address newAddress = address(0xAAAA);
        vm.prank(deployer);
        vm.expectRevert("User not registered");
        dao.addUserAddressFromOwner(FID_1, newAddress);
    }

    /**
     * @notice Test that addUserAddressFromOwner reverts if new address is zero
     */
    function test_addUserAddressFromOwner_RevertsIfZeroAddress() public {
        // Register user1 with FID_1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Try to add zero address
        vm.prank(deployer);
        vm.expectRevert("Invalid address");
        dao.addUserAddressFromOwner(FID_1, address(0));
    }

    /**
     * @notice Test that addUserAddressFromOwner reverts if address already registered
     */
    function test_addUserAddressFromOwner_RevertsIfAddressAlreadyRegistered() public {
        // Register user1 with FID_1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // user1 is already registered to FID_1, try to add it again
        vm.prank(deployer);
        vm.expectRevert("Address already registered to FID");
        dao.addUserAddressFromOwner(FID_1, user1);
    }

    /**
     * @notice Test that addUserAddressFromOwner adds address as valid after function call
     */
    function test_addUserAddressFromOwner_AddsAddressAsValid() public {
        // Register user1 with FID_1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Add new address as owner
        address newAddress = address(0xAAAA);
        assertFalse(dao.userAddressValid(FID_1, newAddress), "Address should not be valid before adding");

        vm.prank(deployer);
        dao.addUserAddressFromOwner(FID_1, newAddress);

        // Verify address is now valid
        assertTrue(dao.userAddressValid(FID_1, newAddress), "Address should be valid after adding");
    }

    /**
     * @notice Test that addUserAddressFromOwner emits UserAddressAdded event
     */
    function test_addUserAddressFromOwner_EmitsEvent() public {
        // Register user1 with FID_1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Add new address as owner
        address newAddress = address(0xAAAA);
        vm.prank(deployer);
        vm.expectEmit(true, true, false, false);
        emit UserAddressAdded(FID_1, newAddress);
        dao.addUserAddressFromOwner(FID_1, newAddress);
    }

    // ============ HELPER FUNCTIONS ============

    /**
     * @notice Get user data from the DAO
     */
    function getUserData(uint256 fid)
        internal
        view
        returns (
            uint256 fid_,
            string memory username,
            string memory country,
            uint256 submissionCount,
            uint256 totalUpvotes,
            uint256 lastSubmissionDay,
            uint256 tokensEarned,
            uint256 tokenBalance,
            bool isReviewer,
            uint256 reputationScore
        )
    {
        return dao.users(fid);
    }

    /**
     * @notice Get deployer's private key for signing
     * @dev Foundry's default private key for address(this) in tests
     */
    function deployerPrivateKey() internal pure returns (uint256) {
        return 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    }

    /**
     * @notice Get newBackendSigner's private key for signing
     */
    function newBackendSignerPrivateKey() internal pure returns (uint256) {
        return 0x3333333333333333333333333333333333333333333333333333333333333333;
    }

    /**
     * @notice Get nonOwner's private key for signing
     */
    function nonOwnerPrivateKey() internal pure returns (uint256) {
        return 0x4444444444444444444444444444444444444444444444444444444444444444;
    }
}
