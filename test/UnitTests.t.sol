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
    string public constant YOUTUBE_VIDEO_ID = "rs6Y4kZ8qtw";
    string public constant CAST_HASH = "0x47636b8ee78c4b05e95e170aca97f76b5d8c9e47";

    // EIP-712 constants
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant USER_REGISTRATION_TYPEHASH =
        keccak256("UserRegistration(uint256 fid,address userAddress,uint256 deadline)");

    // Events
    event UserRegistered(uint256 indexed fid, string username, string country, address indexed registeredAddress);
    event BackendSignerUpdated(address indexed oldSigner, address indexed newSigner);
    event UserAddressAdded(uint256 indexed fid, address indexed registeredAddress);
    event RecommendationSubmitted(
        uint256 indexed id, uint256 indexed submitterFid, string youtubeVideoId, string castHash, string country
    );
    event VoteCast(uint256 indexed recommendationId, uint256 indexed voterFid, bool isUpvote);
    event RecommendationApproved(uint256 indexed id, uint256 approvedBy);
    event RecommendationRejected(uint256 indexed id, uint256 rejectedBy);
    event RecommendationTransitioned(uint256 indexed id, uint256 newState);
    event TokensDeposited(uint256 indexed fid, uint256 amount);
    event TokensWithdrawn(uint256 indexed fid, uint256 amount);
    event DurationSet(uint256 indexed recommendationId, string youtubeVideoId, uint256 duration);

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

        // Deposit 100 million tokens (100 * 1e6 * 1e18 = 1e67)
        uint256 depositAmount = 100_000_000 * 10 ** 18;
        vm.startPrank(deployer);
        token.approve(address(dao), depositAmount);
        dao.depositRewardTokens(depositAmount);
        vm.stopPrank();

        // Verify deposit
        assertEq(token.balanceOf(address(dao)), depositAmount, "DAO should have 100 million tokens");
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

    /**
     * @notice Generate EIP-712 signature for video duration verification
     * @param youtubeVideoId The YouTube video ID
     * @param duration The duration in seconds
     * @param deadline The signature deadline
     * @param signerPrivateKey The private key of the signer (backend signer)
     * @return signature The EIP-712 signature
     */
    function generateDurationSignature(
        string memory youtubeVideoId,
        uint256 duration,
        uint256 deadline,
        uint256 signerPrivateKey
    ) internal view returns (bytes memory signature) {
        // Get domain separator from contract
        (bytes32 domainSeparator,,,,) = dao.getDomainInfo();

        // Create struct hash
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("DurationVerification(string youtubeVideoId,uint256 duration,uint256 deadline)"),
                keccak256(bytes(youtubeVideoId)),
                duration,
                deadline
            )
        );

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

    // ============ submitRecommendation TESTS ============

    /**
     * @notice Test that submitRecommendation can only be called by registered user
     */
    function test_submitRecommendation_OnlyRegisteredUser() public {
        // Try to submit without registering
        vm.prank(user1);
        vm.expectRevert("User not registered");
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);
    }

    /**
     * @notice Test that submitRecommendation reverts if video ID is not exactly 11 characters
     */
    function test_submitRecommendation_RevertsIfVideoIdNot11Characters() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Try with 10 characters
        vm.prank(user1);
        vm.expectRevert("YouTube video ID must be 11 characters");
        dao.submitRecommendation(FID_1, "rs6Y4kZ8qt");

        // Try with 12 characters
        vm.prank(user1);
        vm.expectRevert("YouTube video ID must be 11 characters");
        dao.submitRecommendation(FID_1, "rs6Y4kZ8qtwx");
    }

    /**
     * @notice Test that submitRecommendation reverts if video already submitted
     */
    function test_submitRecommendation_RevertsIfVideoAlreadySubmitted() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Submit first time
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        //advance by 48 hours
        vm.warp(block.timestamp + 48 hours);
        // Try to submit same video again
        vm.prank(user1);
        vm.expectRevert("Video already submitted");
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);
    }

    /**
     * @notice Test that submitRecommendation reverts if user already submitted in last 24 hours
     */
    function test_submitRecommendation_RevertsIfAlreadySubmittedToday() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Submit first video
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Try to submit another video on same day
        vm.prank(user1);
        vm.expectRevert("Can only submit one video per day");
        dao.submitRecommendation(FID_1, "abcdefghijk");
    }

    /**
     * @notice Test that submitRecommendation increments nextRecommendationId
     */
    function test_submitRecommendation_IncrementsNextRecommendationId() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        uint256 initialId = dao.nextRecommendationId();
        assertEq(initialId, 1, "Initial recommendation ID should be 1");

        // Submit recommendation with unique video ID
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Check ID incremented
        assertEq(dao.nextRecommendationId(), initialId + 1, "Recommendation ID should be incremented");
    }

    /**
     * @notice Test that submitRecommendation saves recommendation correctly
     */
    function test_submitRecommendation_SavesRecommendationCorrectly() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Submit recommendation with unique video ID
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Check recommendation data
        (
            uint256 id,
            uint256 submitterFid,
            string memory youtubeVideoId,
            string memory castHash,
            string memory country,
            uint256 duration,
            uint256 submissionTime,
            uint256 scheduledTime,
            HumanMusicDAO.RecommendationState state,
            uint256 upvotes,
            uint256 downvotes,
            uint256 rewardsPaid,
            bool isActive
        ) = dao.recommendations(1);

        assertEq(id, 1, "ID should be 1");
        assertEq(submitterFid, FID_1, "Submitter FID should match");
        assertEq(youtubeVideoId, YOUTUBE_VIDEO_ID, "YouTube video ID should match");
        assertEq(castHash, "", "Cast hash should be empty for direct submission");
        assertEq(country, COUNTRY_1, "Country should match");
        assertEq(duration, 0, "Duration should be 0 initially");
        assertEq(submissionTime, block.timestamp, "Submission time should be current timestamp");
        assertEq(scheduledTime, 0, "Scheduled time should be 0");
        assertEq(uint256(state), 0, "State should be SUBMITTED (0)");
        assertEq(upvotes, 0, "Upvotes should be 0");
        assertEq(downvotes, 0, "Downvotes should be 0");
        assertEq(rewardsPaid, 0, "Rewards paid should be 0");
        assertTrue(isActive, "Recommendation should be active");
    }

    /**
     * @notice Test that submitRecommendation sets submittedVideoIds to true
     */
    function test_submitRecommendation_SetsSubmittedVideoIds() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Check video not submitted
        assertFalse(dao.isVideoSubmitted(YOUTUBE_VIDEO_ID), "Video should not be submitted initially");

        // Submit recommendation
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Check video is now submitted
        assertTrue(dao.isVideoSubmitted(YOUTUBE_VIDEO_ID), "Video should be submitted");
    }

    /**
     * @notice Test that submitRecommendation increments user's submissionCount
     */
    function test_submitRecommendation_IncrementsSubmissionCount() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Check initial submission count
        (,,, uint256 submissionCount,,,,,,) = getUserData(FID_1);
        assertEq(submissionCount, 0, "Initial submission count should be 0");

        // Submit recommendation with unique video ID
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Check submission count incremented
        (,,, submissionCount,,,,,,) = getUserData(FID_1);
        assertEq(submissionCount, 1, "Submission count should be 1");
    }

    /**
     * @notice Test that submitRecommendation updates user's lastSubmissionDay
     */
    function test_submitRecommendation_UpdatesLastSubmissionDay() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        uint256 currentDay = block.timestamp / 1 days;

        // Check initial last submission day
        (,,,,, uint256 lastSubmissionDay,,,,) = getUserData(FID_1);
        assertEq(lastSubmissionDay, 0, "Initial last submission day should be 0");

        // Submit recommendation with unique video ID
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Check last submission day updated
        (,,,,, lastSubmissionDay,,,,) = getUserData(FID_1);
        assertEq(lastSubmissionDay, currentDay, "Last submission day should be current day");
    }

    /**
     * @notice Test that submitRecommendation rewards user with tokens
     */
    function test_submitRecommendation_RewardsUser() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Check initial token balance
        (,,,,,,, uint256 tokenBalance, bool isReviewer, uint256 reputationScore) = getUserData(FID_1);
        assertEq(tokenBalance, 0, "Initial token balance should be 0");

        // Submit recommendation with unique video ID
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Check token balance increased
        (,,,,,,, tokenBalance, isReviewer, reputationScore) = getUserData(FID_1);
        assertEq(tokenBalance, 10 * 10 ** 18, "Token balance should be 10 tokens");
    }

    /**
     * @notice Test that submitRecommendation emits RecommendationSubmitted event
     */
    function test_submitRecommendation_EmitsEvent() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Submit recommendation
        vm.prank(user1);
        vm.expectEmit(true, true, false, true);
        emit RecommendationSubmitted(1, FID_1, YOUTUBE_VIDEO_ID, "", COUNTRY_1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);
    }

    // ============ submitRecommendationFromCast TESTS ============

    /**
     * @notice Test that submitRecommendationFromCast can only be called by owner
     */
    function test_submitRecommendationFromCast_OnlyOwner() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Try to call from non-owner
        vm.prank(nonOwner);
        vm.expectRevert();
        dao.submitRecommendationFromCast(FID_1, YOUTUBE_VIDEO_ID, CAST_HASH);
    }

    /**
     * @notice Test that submitRecommendationFromCast reverts if user not registered
     */
    function test_submitRecommendationFromCast_RevertsIfUserNotRegistered() public {
        vm.prank(deployer);
        vm.expectRevert("User not registered");
        dao.submitRecommendationFromCast(FID_1, YOUTUBE_VIDEO_ID, CAST_HASH);
    }

    /**
     * @notice Test that submitRecommendationFromCast reverts if video ID is not exactly 11 characters
     */
    function test_submitRecommendationFromCast_RevertsIfVideoIdNot11Characters() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Try with 10 characters
        vm.prank(deployer);
        vm.expectRevert("YouTube video ID must be 11 characters");
        dao.submitRecommendationFromCast(FID_1, "rs6Y4kZ8qt", CAST_HASH);
    }

    /**
     * @notice Test that submitRecommendationFromCast reverts if video already submitted
     */
    function test_submitRecommendationFromCast_RevertsIfVideoAlreadySubmitted() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Submit first time via direct submission
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Try to submit same video again via cast
        vm.prank(deployer);
        vm.expectRevert("Video already submitted");
        dao.submitRecommendationFromCast(FID_1, YOUTUBE_VIDEO_ID, CAST_HASH);
    }

    /**
     * @notice Test that submitRecommendationFromCast reverts if user already submitted in last 24 hours
     */
    function test_submitRecommendationFromCast_RevertsIfAlreadySubmittedToday() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Submit first video via direct submission
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Try to submit another video via cast on same day
        vm.prank(deployer);
        vm.expectRevert("Can only submit one video per day");
        dao.submitRecommendationFromCast(FID_1, "abcdefghijk", CAST_HASH);
    }

    /**
     * @notice Test that submitRecommendationFromCast increments nextRecommendationId
     */
    function test_submitRecommendationFromCast_IncrementsNextRecommendationId() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        uint256 initialId = dao.nextRecommendationId();

        // Submit recommendation from cast with unique video ID
        vm.prank(deployer);
        dao.submitRecommendationFromCast(FID_1, YOUTUBE_VIDEO_ID, CAST_HASH);

        // Check ID incremented
        assertEq(dao.nextRecommendationId(), initialId + 1, "Recommendation ID should be incremented");
    }

    /**
     * @notice Test that submitRecommendationFromCast saves recommendation correctly with castHash
     */
    function test_submitRecommendationFromCast_SavesRecommendationCorrectly() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Submit recommendation from cast with unique video ID
        vm.prank(deployer);
        dao.submitRecommendationFromCast(FID_1, YOUTUBE_VIDEO_ID, CAST_HASH);

        // Check recommendation data
        (
            uint256 id,
            uint256 submitterFid,
            string memory youtubeVideoId,
            string memory castHash,
            string memory country,
            uint256 duration,
            uint256 submissionTime,
            uint256 scheduledTime,
            HumanMusicDAO.RecommendationState state,
            uint256 upvotes,
            uint256 downvotes,
            uint256 rewardsPaid,
            bool isActive
        ) = dao.recommendations(1);

        assertEq(id, 1, "ID should be 1");
        assertEq(submitterFid, FID_1, "Submitter FID should match");
        assertEq(youtubeVideoId, YOUTUBE_VIDEO_ID, "YouTube video ID should match");
        assertEq(castHash, CAST_HASH, "Cast hash should match");
        assertEq(country, COUNTRY_1, "Country should match");
        assertEq(duration, 0, "Duration should be 0 initially");
        assertEq(submissionTime, block.timestamp, "Submission time should be current timestamp");
        assertEq(scheduledTime, 0, "Scheduled time should be 0");
        assertEq(uint256(state), 0, "State should be SUBMITTED (0)");
        assertEq(upvotes, 0, "Upvotes should be 0");
        assertEq(downvotes, 0, "Downvotes should be 0");
        assertEq(rewardsPaid, 0, "Rewards paid should be 0");
        assertTrue(isActive, "Recommendation should be active");
    }

    /**
     * @notice Test that submitRecommendationFromCast sets submittedVideoIds to true
     */
    function test_submitRecommendationFromCast_SetsSubmittedVideoIds() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Check video not submitted
        assertFalse(dao.isVideoSubmitted(YOUTUBE_VIDEO_ID), "Video should not be submitted initially");

        // Submit recommendation from cast
        vm.prank(deployer);
        dao.submitRecommendationFromCast(FID_1, YOUTUBE_VIDEO_ID, CAST_HASH);

        // Check video is now submitted
        assertTrue(dao.isVideoSubmitted(YOUTUBE_VIDEO_ID), "Video should be submitted");
    }

    /**
     * @notice Test that submitRecommendationFromCast increments user's submissionCount
     */
    function test_submitRecommendationFromCast_IncrementsSubmissionCount() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Check initial submission count
        (,,, uint256 submissionCount,,,,,,) = getUserData(FID_1);
        assertEq(submissionCount, 0, "Initial submission count should be 0");

        // Submit recommendation from cast with unique video ID
        vm.prank(deployer);
        dao.submitRecommendationFromCast(FID_1, YOUTUBE_VIDEO_ID, CAST_HASH);

        // Check submission count incremented
        (,,, submissionCount,,,,,,) = getUserData(FID_1);
        assertEq(submissionCount, 1, "Submission count should be 1");
    }

    /**
     * @notice Test that submitRecommendationFromCast updates user's lastSubmissionDay
     */
    function test_submitRecommendationFromCast_UpdatesLastSubmissionDay() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        uint256 currentDay = block.timestamp / 1 days;

        // Check initial last submission day
        (,,,,, uint256 lastSubmissionDay,,,,) = getUserData(FID_1);
        assertEq(lastSubmissionDay, 0, "Initial last submission day should be 0");

        // Submit recommendation from cast with unique video ID
        vm.prank(deployer);
        dao.submitRecommendationFromCast(FID_1, YOUTUBE_VIDEO_ID, CAST_HASH);

        // Check last submission day updated
        (,,,,, lastSubmissionDay,,,,) = getUserData(FID_1);
        assertEq(lastSubmissionDay, currentDay, "Last submission day should be current day");
    }

    /**
     * @notice Test that submitRecommendationFromCast rewards user with tokens
     */
    function test_submitRecommendationFromCast_RewardsUser() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Check initial token balance
        (,,,,,,, uint256 tokenBalance, bool isReviewer, uint256 reputationScore) = getUserData(FID_1);
        assertEq(tokenBalance, 0, "Initial token balance should be 0");

        // Submit recommendation from cast with unique video ID
        vm.prank(deployer);
        dao.submitRecommendationFromCast(FID_1, YOUTUBE_VIDEO_ID, CAST_HASH);

        // Check token balance increased
        (,,,,,,, tokenBalance, isReviewer, reputationScore) = getUserData(FID_1);
        assertEq(tokenBalance, 10 * 10 ** 18, "Token balance should be 10 tokens");
    }

    /**
     * @notice Test that submitRecommendationFromCast emits RecommendationSubmitted event
     */
    function test_submitRecommendationFromCast_EmitsEvent() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // advance by 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Submit recommendation from cast with unique video ID
        vm.prank(deployer);
        vm.expectEmit(true, true, false, true);
        emit RecommendationSubmitted(1, FID_1, YOUTUBE_VIDEO_ID, CAST_HASH, COUNTRY_1);
        dao.submitRecommendationFromCast(FID_1, YOUTUBE_VIDEO_ID, CAST_HASH);
    }

    // ============ voteOnRecommendation TESTS ============

    /**
     * @notice Test that voteOnRecommendation can only be called by registered user
     */
    function test_voteOnRecommendation_OnlyRegisteredUser() public {
        // Register user1 and submit a recommendation
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        vm.warp(block.timestamp + 25 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Try to vote without registering user2
        vm.prank(user2);
        vm.expectRevert("User not registered");
        dao.voteOnRecommendation(1, FID_2, true);
    }

    /**
     * @notice Test that voteOnRecommendation reverts for invalid recommendation
     */
    function test_voteOnRecommendation_RevertsIfInvalidRecommendation() public {
        // Register both users
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature1 = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature1);
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        // Try to vote on non-existent recommendation
        vm.prank(user2);
        vm.expectRevert("Invalid recommendation ID");
        dao.voteOnRecommendation(999, FID_2, true);
    }

    /**
     * @notice Test that voteOnRecommendation reverts if voting period expired
     */
    function test_voteOnRecommendation_RevertsIfVotingPeriodExpired() public {
        // Register both users
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature1 = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature1);
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        // Submit recommendation
        vm.warp(block.timestamp + 25 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Get submission time
        (,,,,, uint256 duration, uint256 submissionTime,,,,,,) = dao.recommendations(1);

        // Advance past voting period (24 hours from submission)
        vm.warp(submissionTime + 25 hours);

        // Try to vote
        vm.prank(user2);
        vm.expectRevert("Voting period expired");
        dao.voteOnRecommendation(1, FID_2, true);
    }

    /**
     * @notice Test that voteOnRecommendation reverts if already voted
     */
    function test_voteOnRecommendation_RevertsIfAlreadyVoted() public {
        // Register both users
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature1 = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature1);
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        // Submit recommendation
        vm.warp(block.timestamp + 25 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Vote first time
        vm.prank(user2);
        dao.voteOnRecommendation(1, FID_2, true);

        // Try to vote again
        vm.prank(user2);
        vm.expectRevert("Already voted");
        dao.voteOnRecommendation(1, FID_2, true);
    }

    /**
     * @notice Test that voteOnRecommendation reverts if voting on own submission
     */
    function test_voteOnRecommendation_RevertsIfVotingOnOwnSubmission() public {
        // Register user1
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        // Submit recommendation
        vm.warp(block.timestamp + 25 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Try to vote on own submission
        vm.prank(user1);
        vm.expectRevert("Cannot vote on own submission");
        dao.voteOnRecommendation(1, FID_1, true);
    }

    /**
     * @notice Test that voteOnRecommendation sets hasVoted to true
     */
    function test_voteOnRecommendation_SetsHasVoted() public {
        // Register both users
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature1 = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature1);
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        // Submit recommendation
        vm.warp(block.timestamp + 25 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Check hasVoted is false initially
        assertFalse(dao.hasVoted(FID_2, 1), "Should not have voted initially");

        // Vote
        vm.prank(user2);
        dao.voteOnRecommendation(1, FID_2, true);

        // Check hasVoted is now true
        assertTrue(dao.hasVoted(FID_2, 1), "Should have voted");
    }

    /**
     * @notice Test that voteOnRecommendation handles upvotes correctly
     */
    function test_voteOnRecommendation_UpvoteWorks() public {
        // Register both users
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature1 = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature1);
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        // Submit recommendation
        vm.warp(block.timestamp + 25 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Get initial state
        (,,,,,,,,, uint256 upvotes, uint256 downvotes,,) = dao.recommendations(1);
        assertEq(upvotes, 0, "Initial upvotes should be 0");
        assertEq(downvotes, 0, "Initial downvotes should be 0"); // Get initial reputation
        (,,,,,,,,, uint256 reputationScore) = getUserData(FID_1);
        assertEq(reputationScore, 100, "Initial reputation should be 100");

        // Vote up
        vm.prank(user2);
        dao.voteOnRecommendation(1, FID_2, true);

        // Check upvotes increased
        (,,,,,,,,, upvotes, downvotes,,) = dao.recommendations(1);
        assertEq(upvotes, 1, "Upvotes should be 1");
        assertEq(downvotes, 0, "Downvotes should still be 0");

        // Check submitter reputation increased
        (,,,,,,, uint256 tokenBalance,, uint256 reputationScore2) = getUserData(FID_1);
        assertEq(reputationScore2, 105, "Reputation should increase by 5");

        // Check submitter got reward
        assertEq(tokenBalance, 10 * 10 ** 18 + 5 * 10 ** 18, "Submitter should have submission + upvote reward");

        // Check voter got reward
        (,,,,,,, tokenBalance,,) = getUserData(FID_2);
        assertEq(tokenBalance, 1 * 10 ** 18, "Voter should have voting reward");
    }

    /**
     * @notice Test that voteOnRecommendation handles downvotes correctly
     */
    function test_voteOnRecommendation_DownvoteWorks() public {
        // Register both users
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature1 = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature1);
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        // Submit recommendation
        vm.warp(block.timestamp + 25 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Get initial reputation
        (,,,,,,, uint256 tokenBalance,, uint256 reputationScore) = getUserData(FID_1);
        assertEq(reputationScore, 100, "Initial reputation should be 100");

        // Vote down
        vm.prank(user2);
        dao.voteOnRecommendation(1, FID_2, false);

        // Check downvotes increased
        (,,,,,,,,, uint256 upvotes, uint256 downvotes,,) = dao.recommendations(1);
        assertEq(upvotes, 0, "Upvotes should be 0");
        assertEq(downvotes, 1, "Downvotes should be 1");

        // Check submitter reputation decreased
        (,,,,,,, tokenBalance,, reputationScore) = getUserData(FID_1);
        assertEq(reputationScore, 98, "Reputation should decrease by 2");

        // Check voter got reward
        (,,,,,,, tokenBalance,,) = getUserData(FID_2);
        assertEq(tokenBalance, 1 * 10 ** 18, "Voter should have voting reward");
    }

    /**
     * @notice Test that voteOnRecommendation emits VoteCast event
     */
    function test_voteOnRecommendation_EmitsEvent() public {
        // Register both users
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature1 = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature1);
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        // Submit recommendation
        vm.warp(block.timestamp + 25 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Vote
        vm.prank(user2);
        vm.expectEmit(true, true, false, false);
        emit VoteCast(1, FID_2, true);
        dao.voteOnRecommendation(1, FID_2, true);
    }

    // ============ approveRecommendation TESTS ============

    /**
     * @notice Test that approveRecommendation can only be called by reviewer
     */
    function test_approveRecommendation_OnlyReviewer() public {
        // Register user1 and submit recommendation
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        vm.warp(block.timestamp + 25 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Try to approve without being reviewer
        vm.prank(user2);
        vm.expectRevert("Not authorized reviewer");
        dao.approveRecommendation(1, FID_2);
    }

    /**
     * @notice Test that approveRecommendation updates recommendation state
     */
    function test_approveRecommendation_UpdatesState() public {
        // Register user1 and submit recommendation
        vm.warp(block.timestamp + 25 hours);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Give user2 1000 tokens, then make them reviewer
        vm.startPrank(deployer);
        token.transfer(user2, 1000 * 10 ** 18);
        vm.stopPrank();

        vm.prank(user2);
        token.approve(address(dao), 1000 * 10 ** 18);
        vm.prank(user2);
        dao.userDepositTokens(FID_2, 1000 * 10 ** 18);

        // Check user2 token balance in contract
        (,,,,,,, uint256 tokenBalance,,) = getUserData(FID_2);
        assertEq(tokenBalance, 1000 * 10 ** 18, "User2 should have 1000 tokens in contract");

        // Now grant reviewer role
        vm.prank(deployer);
        dao.grantReviewerRole(FID_2);

        // Check initial state
        (
            uint256 id,
            uint256 submitterFid,
            string memory youtubeVideoId,
            string memory castHash,
            string memory country,
            uint256 duration,
            uint256 submissionTime,
            uint256 scheduledTime,
            HumanMusicDAO.RecommendationState state,
            uint256 upvotes,
            uint256 downvotes,
            uint256 rewardsPaid,
            bool isActive
        ) = dao.recommendations(1);
        assertEq(uint256(state), 0, "Initial state should be SUBMITTED (0)");

        // Approve recommendation
        vm.prank(user2);
        vm.expectEmit(true, false, false, false);
        emit RecommendationApproved(1, FID_2);
        dao.approveRecommendation(1, FID_2);

        // Check state updated
        (
            id,
            submitterFid,
            youtubeVideoId,
            castHash,
            country,
            duration,
            submissionTime,
            scheduledTime,
            state,
            upvotes,
            downvotes,
            rewardsPaid,
            isActive
        ) = dao.recommendations(1);
        assertEq(uint256(state), 1, "State should be APPROVED (1)");

        // Check recommendation added to queue
        uint256[] memory queue = dao.getSongQueue();
        assertEq(queue.length, 1, "Queue should have 1 item");
        assertEq(queue[0], 1, "Queue should contain recommendation 1");
    }

    // ============ rejectRecommendation TESTS ============

    /**
     * @notice Test that rejectRecommendation can only be called by reviewer
     */
    function test_rejectRecommendation_OnlyReviewer() public {
        // Register user1 and submit recommendation
        vm.warp(block.timestamp + 25 hours);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Register user2 but don't make them a reviewer (use current timestamp for deadline)
        uint256 currentTime = block.timestamp;
        uint256 deadline2 = currentTime + 100 hours; // Large deadline to avoid expiration
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline2, deployerPrivateKey());
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline2, signature2);

        // Try to reject without being reviewer
        vm.prank(user2);
        vm.expectRevert("Not authorized reviewer");
        dao.rejectRecommendation(1, FID_2);
    }

    /**
     * @notice Test that rejectRecommendation marks recommendation as inactive
     */
    function test_rejectRecommendation_MarksAsInactive() public {
        // Register user1 and submit recommendation
        vm.warp(block.timestamp + 25 hours);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature1 = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature1);
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());
        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);
        vm.prank(user2);
        dao.submitRecommendation(FID_2, "testvid0014");

        // Give user2 1000 tokens, then make them reviewer
        vm.startPrank(deployer);
        token.transfer(user2, 1000 * 10 ** 18);
        vm.stopPrank();

        vm.prank(user2);
        token.approve(address(dao), 1000 * 10 ** 18);
        vm.prank(user2);
        dao.userDepositTokens(FID_2, 1000 * 10 ** 18);

        vm.prank(deployer);
        dao.grantReviewerRole(FID_2);

        // Check video is submitted
        assertTrue(dao.isVideoSubmitted(YOUTUBE_VIDEO_ID), "Video should be submitted");

        // Check recommendation is active
        (
            uint256 id,
            uint256 submitterFid,
            string memory youtubeVideoId,
            string memory castHash,
            string memory country,
            uint256 duration,
            uint256 submissionTime,
            uint256 scheduledTime,
            HumanMusicDAO.RecommendationState state,
            uint256 upvotes,
            uint256 downvotes,
            uint256 rewardsPaid,
            bool isActive
        ) = dao.recommendations(1);
        assertTrue(isActive, "Recommendation should be active");

        // Reject recommendation
        vm.prank(user2);
        vm.expectEmit(true, true, false, false);
        emit RecommendationRejected(1, FID_2);
        dao.rejectRecommendation(1, FID_2);

        // Check recommendation is inactive
        (
            id,
            submitterFid,
            youtubeVideoId,
            castHash,
            country,
            duration,
            submissionTime,
            scheduledTime,
            state,
            upvotes,
            downvotes,
            rewardsPaid,
            isActive
        ) = dao.recommendations(1);
        assertFalse(isActive, "Recommendation should be inactive");

        // Check video can be resubmitted
        assertFalse(dao.isVideoSubmitted(YOUTUBE_VIDEO_ID), "Video should be available for resubmission");
    }

    // ============ setVideoDuration TESTS ============

    /**
     * @notice Test that setVideoDuration reverts if recommendationId is invalid
     */
    function test_setVideoDuration_RevertsIfInvalidRecommendationId() public {
        setupUsersWithRecommendationAndReviewerTokens();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateDurationSignature(YOUTUBE_VIDEO_ID, 180, deadline, deployerPrivateKey());

        vm.expectRevert("Invalid recommendation ID");
        dao.setVideoDuration(999, 180, deadline, signature);
    }

    /**
     * @notice Test that setVideoDuration reverts if duration is zero
     */
    function test_setVideoDuration_RevertsIfDurationZero() public {
        setupUsersWithRecommendationAndReviewerTokens();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateDurationSignature(YOUTUBE_VIDEO_ID, 0, deadline, deployerPrivateKey());

        vm.expectRevert("Duration must be 1-600 seconds");
        dao.setVideoDuration(1, 0, deadline, signature);
    }

    /**
     * @notice Test that setVideoDuration reverts if duration is greater than 600
     */
    function test_setVideoDuration_RevertsIfDurationGreaterThan600() public {
        setupUsersWithRecommendationAndReviewerTokens();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateDurationSignature(YOUTUBE_VIDEO_ID, 601, deadline, deployerPrivateKey());

        vm.expectRevert("Duration must be 1-600 seconds");
        dao.setVideoDuration(1, 601, deadline, signature);
    }

    /**
     * @notice Test that setVideoDuration reverts if duration is already set
     */
    function test_setVideoDuration_RevertsIfDurationAlreadySet() public {
        setupUsersWithRecommendationAndReviewerTokens();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateDurationSignature(YOUTUBE_VIDEO_ID, 180, deadline, deployerPrivateKey());

        // Set duration first time
        dao.setVideoDuration(1, 180, deadline, signature);

        // Try to set again
        uint256 newDeadline = block.timestamp + 1 hours;
        bytes memory signature2 = generateDurationSignature(YOUTUBE_VIDEO_ID, 200, newDeadline, deployerPrivateKey());
        vm.expectRevert("Duration already set");
        dao.setVideoDuration(1, 200, newDeadline, signature2);
    }

    /**
     * @notice Test that setVideoDuration reverts if recommendation is not active
     */
    function test_setVideoDuration_RevertsIfRecommendationNotActive() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Reject the recommendation to make it inactive
        vm.prank(deployer);
        dao.grantReviewerRole(FID_2);
        vm.prank(user2);
        dao.rejectRecommendation(1, FID_2);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateDurationSignature(YOUTUBE_VIDEO_ID, 180, deadline, deployerPrivateKey());

        vm.expectRevert("Recommendation not active");
        dao.setVideoDuration(1, 180, deadline, signature);
    }

    /**
     * @notice Test that setVideoDuration reverts with invalid signer
     */
    function test_setVideoDuration_RevertsIfInvalidSigner() public {
        setupUsersWithRecommendationAndReviewerTokens();

        uint256 deadline = block.timestamp + 1 hours;
        // Use wrong private key (nonOwner's key instead of deployer's)
        bytes memory signature = generateDurationSignature(YOUTUBE_VIDEO_ID, 180, deadline, nonOwnerPrivateKey());

        vm.expectRevert("Invalid signature");
        dao.setVideoDuration(1, 180, deadline, signature);
    }

    /**
     * @notice Test that setVideoDuration sets duration correctly and emits event
     */
    function test_setVideoDuration_SetsDurationAndEmitsEvent() public {
        setupUsersWithRecommendationAndReviewerTokens();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = generateDurationSignature(YOUTUBE_VIDEO_ID, 180, deadline, deployerPrivateKey());

        // Check initial duration is 0
        (
            uint256 id,
            uint256 submitterFid,
            string memory youtubeVideoId,
            string memory castHash,
            string memory country,
            uint256 duration,
            uint256 submissionTime,
            uint256 scheduledTime,
            HumanMusicDAO.RecommendationState state,
            uint256 upvotes,
            uint256 downvotes,
            uint256 rewardsPaid,
            bool isActive
        ) = dao.recommendations(1);
        assertEq(duration, 0, "Initial duration should be 0");

        // Set duration
        vm.expectEmit(true, false, false, false);
        emit DurationSet(1, YOUTUBE_VIDEO_ID, 180);
        dao.setVideoDuration(1, 180, deadline, signature);

        // Check duration is set
        (
            id,
            submitterFid,
            youtubeVideoId,
            castHash,
            country,
            duration,
            submissionTime,
            scheduledTime,
            state,
            upvotes,
            downvotes,
            rewardsPaid,
            isActive
        ) = dao.recommendations(1);
        assertEq(duration, 180, "Duration should be set to 180");
    }

    // ============ withdrawTokens TESTS ============

    /**
     * @notice Test that withdrawTokens can only be called by addresses associated with the FID
     */
    function test_withdrawTokens_OnlyRegisteredAddress() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // user2 has 1000 tokens deposited, but try to withdraw from user1's FID
        vm.prank(user2);
        vm.expectRevert("Sender addr not registered to FID");
        dao.withdrawTokens(FID_1, 100 * 10 ** 18);
    }

    /**
     * @notice Test that withdrawTokens reverts if user tries to withdraw more than their balance
     */
    function test_withdrawTokens_RevertsIfInsufficientBalance() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // user2 has 1000 tokens, try to withdraw more
        vm.prank(user2);
        vm.expectRevert("Insufficient balance");
        dao.withdrawTokens(FID_2, 2000 * 10 ** 18);
    }

    /**
     * @notice Test that withdrawTokens removes tokens from contract, deposits to user, and emits event
     */
    function test_withdrawTokens_TransfersTokensAndEmitsEvent() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Check initial balances
        (,,,,,,, uint256 tokenBalanceBefore,,) = getUserData(FID_2);
        assertEq(tokenBalanceBefore, 1000 * 10 ** 18, "User2 should have 1000 tokens");

        uint256 contractBalanceBefore = token.balanceOf(address(dao));
        uint256 user2BalanceBefore = token.balanceOf(user2);

        // Withdraw tokens
        uint256 withdrawAmount = 500 * 10 ** 18;
        vm.prank(user2);
        vm.expectEmit(true, false, false, false);
        emit TokensWithdrawn(FID_2, withdrawAmount);
        dao.withdrawTokens(FID_2, withdrawAmount);

        // Check user's token balance in contract decreased
        (,,,,,,, uint256 tokenBalanceAfter,,) = getUserData(FID_2);
        assertEq(tokenBalanceAfter, 500 * 10 ** 18, "User2 should have 500 tokens remaining");

        // Check contract balance decreased
        uint256 contractBalanceAfter = token.balanceOf(address(dao));
        assertEq(contractBalanceAfter, contractBalanceBefore - withdrawAmount, "Contract balance should decrease");

        // Check user's ERC20 balance increased
        uint256 user2BalanceAfter = token.balanceOf(user2);
        assertEq(user2BalanceAfter, user2BalanceBefore + withdrawAmount, "User2 ERC20 balance should increase");
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
     * @notice Setup common test scenario: register users, submit recommendation, and fund user2 as reviewer
     * @dev Warps time forward, registers user1 and user2, has user1 submit a recommendation,
     *      and gives user2 1000 tokens deposited into the contract
     */
    function setupUsersWithRecommendationAndReviewerTokens() internal {
        vm.warp(block.timestamp + 25 hours);

        uint256 deadline = block.timestamp + 1 hours;

        bytes memory signature = generateRegistrationSignature(FID_1, user1, deadline, deployerPrivateKey());
        bytes memory signature2 = generateRegistrationSignature(FID_2, user2, deadline, deployerPrivateKey());

        vm.prank(user1);
        dao.registerUser(FID_1, USERNAME_1, COUNTRY_1, deadline, signature);

        vm.prank(user2);
        dao.registerUser(FID_2, USERNAME_2, COUNTRY_2, deadline, signature2);

        vm.prank(user1);
        dao.submitRecommendation(FID_1, YOUTUBE_VIDEO_ID);

        // Give user2 1000 tokens, then make them reviewer
        vm.startPrank(deployer);
        token.transfer(user2, 1000 * 10 ** 18);
        vm.stopPrank();

        vm.prank(user2);
        token.approve(address(dao), 1000 * 10 ** 18);
        vm.prank(user2);
        dao.userDepositTokens(FID_2, 1000 * 10 ** 18);
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
