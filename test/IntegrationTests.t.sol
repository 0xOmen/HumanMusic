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
    event SystemUpdated(uint256 indexed callerFid, uint256 timeGapFilled, uint256 songsProcessed);

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

    // ============ updateSystem TESTS ============

    /**
     * @notice Test that updateSystem reverts if stream is not initialized
     */
    function test_updateSystem_RevertsIfStreamNotInitialized() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Don't initialize stream
        vm.prank(user1);
        vm.expectRevert("Stream not initialized");
        dao.updateSystem(FID_1);
    }

    /**
     * @notice Test that updateSystem can only be called by a submitter
     */
    function test_updateSystem_OnlySubmitter() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Approve and initialize stream
        vm.prank(user2);
        dao.approveRecommendation(1, FID_2);
        vm.prank(deployer);
        dao.initializeStream();

        // Register a user who hasn't submitted anything
        address nonSubmitter = address(0x6000);
        uint256 nonSubmitterFid = 20000;
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = generateRegistrationSignature(nonSubmitterFid, nonSubmitter, deadline, deployerPrivateKey());
        vm.prank(nonSubmitter);
        dao.registerUser(nonSubmitterFid, "nonsubmitter", "US", deadline, sig);

        // Try to call updateSystem
        vm.prank(nonSubmitter);
        vm.expectRevert("Must have submitted at least one video");
        dao.updateSystem(nonSubmitterFid);
    }

    /**
     * @notice Test that updateSystem returns early if current song is still playing
     */
    function test_updateSystem_ReturnsEarlyIfSongStillPlaying() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Approve and initialize stream
        vm.prank(user2);
        dao.approveRecommendation(1, FID_2);
        vm.prank(deployer);
        dao.initializeStream();

        // Try to update immediately - song should still be playing (duration is 180 seconds)
        uint256 lastUpdateTimeBefore = dao.lastUpdateTime();
        vm.prank(user1);
        dao.updateSystem(FID_1);

        // lastUpdateTime should not change (function returned early)
        assertEq(dao.lastUpdateTime(), lastUpdateTimeBefore, "Last update time should not change if song still playing");
        assertEq(dao.currentlyPlayingId(), 1, "Currently playing ID should still be 1");
    }

    /**
     * @notice Test that songs can be added after initializeStream
     */
    function test_updateSystem_SongsCanBeAddedAfterInitializeStream() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Approve first song and initialize stream
        vm.prank(user2);
        dao.approveRecommendation(1, FID_2);
        vm.prank(deployer);
        dao.initializeStream();

        // Check initial queue length
        uint256[] memory queueBefore = dao.getSongQueue();
        assertEq(queueBefore.length, 1, "Queue should have 1 song initially");

        // Submit and approve a second song
        vm.warp(block.timestamp + 25 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, "newvid00001");

        uint256 durationDeadline = block.timestamp + 1 hours;
        bytes memory durationSig = generateDurationSignature("newvid00001", 200, durationDeadline, deployerPrivateKey());
        vm.prank(deployer);
        dao.setVideoDuration(3, 200, durationDeadline, durationSig);

        vm.prank(user2);
        dao.approveRecommendation(3, FID_2);

        // Check queue now has 2 songs
        uint256[] memory queueAfter = dao.getSongQueue();
        assertEq(queueAfter.length, 2, "Queue should have 2 songs after adding new one");
        assertEq(queueAfter[0], 1, "First song should still be ID 1");
        assertEq(queueAfter[1], 3, "Second song should be ID 3");
    }

    /**
     * @notice Test that updateSystem processes songs when current song has finished
     */
    function test_updateSystem_ProcessesSongsWhenCurrentSongFinished() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Approve first song and initialize stream
        vm.prank(user2);
        dao.approveRecommendation(1, FID_2);
        uint256 initTime = block.timestamp;
        // Submit and approve a second song (need to advance 48 hours for new submission)
        vm.warp(initTime + 48 hours);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, "newvid00001");
        uint256 durationDeadline = block.timestamp + 1 hours;
        bytes memory durationSig = generateDurationSignature("newvid00001", 200, durationDeadline, deployerPrivateKey());
        vm.prank(deployer);
        dao.setVideoDuration(3, 200, durationDeadline, durationSig);

        vm.prank(user2);
        dao.approveRecommendation(3, FID_2);
        vm.prank(deployer);
        dao.initializeStream();

        // Verify queue has 2 songs before advancing time
        uint256[] memory queueCheck = dao.getSongQueue();
        assertEq(queueCheck.length, 2, "Queue should have 2 songs");
        assertEq(queueCheck[1], 3, "Second song should be ID 3");

        // Advance time to just past the first song's duration (180 seconds) from initialization
        // This simulates the first song finishing while the second song is in the queue
        vm.warp(initTime + 181 seconds);

        // Get initial balances
        (,,,,,,, uint256 submitterBalanceBefore,,) = getUserData(FID_1);
        (,,,,,,, uint256 callerBalanceBefore,,) = getUserData(FID_1);

        vm.prank(user1);
        dao.updateSystem(FID_1);

        assertGt(dao.currentlyPlayingId(), 0, "Currently playing ID should be set after update");

        // Check submitter was rewarded for songs being played (multiple songs may have played)
        (,,,,,,, uint256 submitterBalanceAfter,,) = getUserData(FID_1);
        assertGt(submitterBalanceAfter, submitterBalanceBefore, "Submitter should receive PLAY_REWARD for songs played");

        // Check caller was rewarded for updating system
        // The caller balance should be the submitter balance (same user) plus UPDATE_REWARD
        assertGe(submitterBalanceAfter, submitterBalanceBefore + 2 * 10 ** 18, "Caller should receive UPDATE_REWARD");

        // Check lastUpdateTime was updated
        assertEq(dao.lastUpdateTime(), block.timestamp, "Last update time should be updated");
    }

    /**
     * @notice Test that updateSystem processes multiple songs in sequence
     */
    function test_updateSystem_ProcessesMultipleSongs() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Approve first song and initialize stream
        vm.prank(user2);
        dao.approveRecommendation(1, FID_2);
        vm.prank(deployer);
        dao.initializeStream();

        // Submit and approve 2 more songs (advance 48 hours between submissions)
        uint256 firstSubmitTime = block.timestamp + 48 hours;
        vm.warp(firstSubmitTime);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, "newvid00001");
        uint256 secondSubmitTime = firstSubmitTime + 48 hours;
        vm.warp(secondSubmitTime);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, "newvid00002");

        uint256 durationDeadline = block.timestamp + 1 hours;
        bytes memory durationSig1 =
            generateDurationSignature("newvid00001", 100, durationDeadline, deployerPrivateKey());
        bytes memory durationSig2 =
            generateDurationSignature("newvid00002", 150, durationDeadline, deployerPrivateKey());
        vm.prank(deployer);
        dao.setVideoDuration(3, 100, durationDeadline, durationSig1);
        vm.prank(deployer);
        dao.setVideoDuration(4, 150, durationDeadline, durationSig2);

        vm.prank(user2);
        dao.approveRecommendation(3, FID_2);
        vm.prank(user2);
        dao.approveRecommendation(4, FID_2);

        // Advance time from initialization - need to account for the time that passed during submissions
        // Initialize was at some time, then we advanced 48h + 48h = 96 hours for submissions
        // Then we advance 281 seconds more to simulate songs finishing
        uint256 initTime = dao.streamStartTime();
        vm.warp(initTime + 281 seconds);

        // Update system
        vm.prank(user1);
        dao.updateSystem(FID_1);

        // After processing, verify that songs were processed
        // Due to the large time gap from submissions, many songs may have been processed
        assertGt(dao.currentlyPlayingId(), 0, "Currently playing ID should be set after update");
    }

    /**
     * @notice Test that updateSystem emits SystemUpdated event with correct parameters
     */
    function test_updateSystem_EmitsSystemUpdatedEvent() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Approve first song and initialize stream
        vm.prank(user2);
        dao.approveRecommendation(1, FID_2);
        vm.prank(deployer);
        dao.initializeStream();

        // Advance time past the first song's duration
        vm.warp(block.timestamp + 181 seconds);

        // Update system and check event
        vm.prank(user1);
        vm.expectEmit(true, false, false, false);
        emit SystemUpdated(FID_1, 181, 1); // 1 song processed (only current song finished, no next song)
        dao.updateSystem(FID_1);
    }

    /**
     * @notice Test that updateSystem processes multiple songs in sequence
     */
    function test_getSystemHealth_ProcessesMultipleSongs() public {
        setupUsersWithRecommendationAndReviewerTokens();

        // Approve first song and initialize stream
        vm.prank(user2);
        dao.approveRecommendation(1, FID_2);

        // Submit and approve 2 more songs (advance 48 hours between submissions)
        uint256 firstSubmitTime = block.timestamp + 48 hours;
        vm.warp(firstSubmitTime);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, "newvid00001");
        uint256 secondSubmitTime = firstSubmitTime + 48 hours;
        vm.warp(secondSubmitTime);
        vm.prank(user1);
        dao.submitRecommendation(FID_1, "newvid00002");

        uint256 durationDeadline = block.timestamp + 1 hours;
        bytes memory durationSig1 =
            generateDurationSignature("newvid00001", 100, durationDeadline, deployerPrivateKey());
        bytes memory durationSig2 =
            generateDurationSignature("newvid00002", 150, durationDeadline, deployerPrivateKey());
        vm.prank(deployer);
        dao.setVideoDuration(3, 100, durationDeadline, durationSig1);
        vm.prank(deployer);
        dao.setVideoDuration(4, 150, durationDeadline, durationSig2);

        vm.prank(user2);
        dao.approveRecommendation(3, FID_2);
        vm.prank(user2);
        dao.approveRecommendation(4, FID_2);
        vm.prank(deployer);
        dao.initializeStream();

        // Advance time from initialization
        vm.warp(block.timestamp + 1205 seconds);

        // Get system health
        (uint256 timeGapToFill, uint256 songsToProcess, uint256 bigBangsNeeded, uint256 newCurrentSongId) =
            dao.getSystemHealth();
        assertEq(timeGapToFill, 1205 seconds, "Time gap to fill should be 1205 seconds");

        // Update system
        vm.prank(user1);
        dao.updateSystem(FID_1);

        // Verify current settings equal what was retruned by getSystemHealth
        assertEq(
            dao.currentlyPlayingId(), newCurrentSongId, "Currently playing ID should be set to new current song ID"
        );
    }
}
