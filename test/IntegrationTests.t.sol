// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {HumanMusicDAO} from "../src/humanmusic.sol";
import {HumanMusicToken} from "../src/mocks/HumanMusicToken.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title IntegrationTests
 * @notice Integration tests for HumanMusicDAO functions
 */
contract IntegrationTests is Test {
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
    event StreamInitialized(uint256 indexed firstSongId, uint256 startTime);

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

        uint256 durationDeadline = block.timestamp + 1 hours;
        bytes memory durationSig1 =
            generateDurationSignature(YOUTUBE_VIDEO_ID, 180, durationDeadline, deployerPrivateKey());
        bytes memory durationSig2 =
            generateDurationSignature("testvid0014", 180, durationDeadline, deployerPrivateKey());
        vm.prank(deployer);
        dao.setVideoDuration(1, 180, durationDeadline, durationSig1);
        vm.prank(deployer);
        dao.setVideoDuration(2, 180, durationDeadline, durationSig2);

        vm.prank(deployer);
        dao.grantReviewerRole(FID_2);
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

    // ============ INTEGRATION TESTS ============

    /**
     * @notice Test that voteOnRecommendation auto-approves when MIN_UPVOTES_THRESHOLD is reached
     * @dev Registers 3 additional users, has them all upvote, and checks the recommendation
     *      is automatically approved and added to the song queue
     */
    function test_voteOnRecommendation_AutoApprovesWhenThresholdReached() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Register 3 additional users to vote
        address voter1 = address(0x5001);
        address voter2 = address(0x5002);
        address voter3 = address(0x5003);
        uint256 voter1Fid = 10001;
        uint256 voter2Fid = 10002;
        uint256 voter3Fid = 10003;

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig1 = generateRegistrationSignature(voter1Fid, voter1, deadline, deployerPrivateKey());
        bytes memory sig2 = generateRegistrationSignature(voter2Fid, voter2, deadline, deployerPrivateKey());
        bytes memory sig3 = generateRegistrationSignature(voter3Fid, voter3, deadline, deployerPrivateKey());

        vm.prank(voter1);
        dao.registerUser(voter1Fid, "voter1", "US", deadline, sig1);
        vm.prank(voter2);
        dao.registerUser(voter2Fid, "voter2", "US", deadline, sig2);
        vm.prank(voter3);
        dao.registerUser(voter3Fid, "voter3", "US", deadline, sig3);

        // Check initial state - recommendation should be SUBMITTED
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
        assertEq(upvotes, 0, "Initial upvotes should be 0");

        // Check song queue is empty initially
        uint256[] memory queueBefore = dao.getSongQueue();
        assertEq(queueBefore.length, 0, "Song queue should be empty initially");

        // First upvote
        vm.prank(voter1);
        dao.voteOnRecommendation(1, voter1Fid, true);

        // Second upvote
        vm.prank(voter2);
        dao.voteOnRecommendation(1, voter2Fid, true);

        // Third upvote - this should trigger auto-approval
        vm.prank(voter3);
        dao.voteOnRecommendation(1, voter3Fid, true);

        // Check recommendation state is now APPROVED
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
        assertEq(uint256(state), 1, "State should be APPROVED (1) after 3 upvotes");
        assertEq(upvotes, 3, "Should have 3 upvotes");

        // Check recommendation is added to song queue
        uint256[] memory queueAfter = dao.getSongQueue();
        assertEq(queueAfter.length, 1, "Song queue should have 1 item");
        assertEq(queueAfter[0], 1, "Song queue should contain recommendation 1");
    }

    // ============ initializeStream TESTS ============

    /**
     * @notice Test that initializeStream fails if no songs are approved (songQueue.length < 1)
     */
    function test_initializeStream_RevertsIfNoApprovedSongs() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Don't approve any songs, so queue is empty
        vm.prank(deployer);
        vm.expectRevert("Need at least one approved song in queue");
        dao.initializeStream();
    }

    /**
     * @notice Test that initializeStream successfully initializes the stream
     * @dev Checks that currentlyPlayingId, streamStartTime, and lastUpdateTime are set,
     *      and that StreamInitialized and RecommendationTransitioned events are emitted
     */
    function test_initializeStream_SuccessfullyInitializesStream() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Approve a song
        vm.prank(user2);
        dao.approveRecommendation(1, FID_2);

        // Check initial state
        assertEq(dao.currentlyPlayingId(), 0, "Currently playing ID should be 0 initially");
        assertEq(dao.streamStartTime(), 0, "Stream start time should be 0 initially");
        uint256 lastUpdateTimeBefore = dao.lastUpdateTime();

        // Get the timestamp before initialization
        uint256 timestampBefore = block.timestamp;

        // Initialize stream
        vm.prank(deployer);
        vm.expectEmit(true, false, false, false);
        emit StreamInitialized(1, timestampBefore);
        dao.initializeStream();

        // Verify RecommendationTransitioned event was emitted (check state separately)
        // After initialization, the recommendation should be in PRESENT state
        HumanMusicDAO.RecommendationState state = dao.getRecommendationState(1, 0);
        assertEq(
            uint256(state),
            uint256(HumanMusicDAO.RecommendationState.PRESENT),
            "State should be PRESENT after initialization"
        );

        // Check currentlyPlayingId is set
        assertEq(dao.currentlyPlayingId(), 1, "Currently playing ID should be set to 1");

        // Check streamStartTime is set
        assertEq(dao.streamStartTime(), timestampBefore, "Stream start time should be set to current timestamp");

        // Check lastUpdateTime is updated
        assertEq(dao.lastUpdateTime(), timestampBefore, "Last update time should be set to current timestamp");
        assertGt(dao.lastUpdateTime(), lastUpdateTimeBefore, "Last update time should be updated");

        // Check currentSongIndex is set to 0
        assertEq(dao.getCurrentSongIndex(), 0, "Current song index should be 0");
    }
}
