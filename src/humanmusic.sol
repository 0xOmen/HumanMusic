// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title HumanMusicDAO - The Eternal Music Discovery Protocol
 * @author  @0x-omen.eth x @jpfraneto.eth
 * @notice "The Most Diverse Music Recommendation Algorithm in The World" - powered by human nature
 *
 * ============================================================================
 *                                  HUMAN MUSIC
 * ============================================================================
 *
 * This contract implements a decentralized, community-curated music discovery
 * platform that operates as an eternal, continuous radio stream. Unlike
 * algorithmic recommendation systems designed to maximize profit, Human Music
 * harnesses the genuine taste and diverse perspectives of humans worldwide.
 *
 * CORE PHILOSOPHY:
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * • HUMAN CURATION: Community members submit YouTube videos based on personal
 *   taste, not algorithmic manipulation
 * • TEMPORAL MECHANICS: Past/Present/Future system creates continuous flow
 * • ETERNAL CONTINUITY: Stream never stops, auto-cycles through all content
 * • GLOBAL DIVERSITY: Users from any country contribute to musical discovery
 * • ECONOMIC INCENTIVES: $HUMANMUSIC token rewards quality participation
 * • ANTI-GAMING: EIP-712 signatures prevent duration manipulation
 *
 * TEMPORAL MECHANICS SYSTEM:
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The stream operates on three temporal states:
 *
 * 1. FUTURE: Approved songs waiting to play (community-voted queue)
 * 2. PRESENT: Currently playing song (exactly one at any time)
 * 3. PAST: Songs that have finished playing (historical archive)
 *
 * TIME-BASED PROGRESSION:
 * ─────────────────────────
 * Each song has a `duration` (seconds) that determines how long it plays.
 * When a song's duration elapses, the system transitions:
 *
 * • Current song moves: PRESENT → PAST
 * • Next song moves: FUTURE → PRESENT
 * • Stream timing updates: New `streamStartTime` begins
 *
 * ETERNAL STREAM MECHANICS:
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * THE UPDATE SYSTEM:
 * ──────────────────
 * Anyone who has submitted a song can call `updateSystem()` to maintain
 * the eternal stream. This function:
 *
 * 1. Calculates time elapsed since last update
 * 2. Processes all songs that should have played during that gap
 * 3. Moves songs through temporal states to catch up to "present"
 * 4. Rewards the caller for maintaining stream continuity
 *
 * EXAMPLE: 8-HOUR GAP SCENARIO
 * ────────────────────────────
 * • Song A was playing (180 seconds duration)
 * • 8 hours pass with no updateSystem() calls (28,800 seconds)
 * • Someone calls updateSystem():
 *   - Move Song A to PAST (reward submitter)
 *   - Process Song B (200s) → PAST (reward submitter)
 *   - Process Song C (240s) → PAST (reward submitter)
 *   - Continue until gap is filled...
 *   - Final song in gap becomes PRESENT with correct remaining time
 *
 * BIG BANG MECHANICS:
 * ───────────────────
 * When FUTURE queue is empty but time needs filling, the system performs
 * a "Big Bang" - moving all PAST songs back to FUTURE, creating an eternal
 * loop. The music never dies.
 *
 * • `_bigBang()` automatically triggers when needed
 * • `totalCycleCount` tracks how many cycles we've completed
 * • Creates truly infinite music discovery
 *
 * SUBMISSION MECHANICS:
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * DUAL SUBMISSION PATHS:
 * ─────────────────────
 * 1. DIRECT (Miniapp): Users submit YouTube video IDs directly
 * 2. CAST-BASED (Social): Backend detects music in Farcaster casts when the bot is tagged (a la clanker or bankr)
 *
 * DAILY LIMITS:
 * ────────────
 * • One submission per user per day (UTC reset)
 * • Prevents spam while ensuring diverse participation
 * • Tracks via `lastSubmissionDay` per user
 *
 * YOUTUBE ID VALIDATION:
 * ─────────────────────
 * • Must be exactly 11 characters (YouTube standard)
 * • No duplicates allowed across all submissions
 * • Backend sets duration after YouTube API verification
 *
 * COMMUNITY GOVERNANCE:
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * VOTING SYSTEM:
 * ─────────────
 * • Users vote UP/DOWN on submitted songs
 * • Auto-approval when MIN_UPVOTES_THRESHOLD reached
 * • Reputation system tracks user quality over time
 * • Voting period limited to 24 hours per submission
 *
 * REVIEWER SYSTEM:
 * ───────────────
 * • Trusted community members can manually approve/reject
 * • Requires reputation + token holding to become reviewer
 * • Prevents low-quality content while maintaining openness
 *
 * TOKEN ECONOMICS ($HUMANMUSIC):
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * REWARD STRUCTURE:
 * ────────────────
 * • 10 tokens: Song submission
 * • 5 tokens: Receiving an upvote on your submission
 * • 50 tokens: Your song actually plays on the stream
 * • 1 token: Voting on others' submissions
 * • 2 tokens: Calling updateSystem() to maintain stream
 *
 * GOVERNANCE POWER:
 * ────────────────
 * • 1000 tokens required to become a reviewer
 * • Token holders have stake in music quality
 * • Withdrawable tokens create real economic value
 *
 * ANTI-GAMING SECURITY:
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * EIP-712 DURATION VERIFICATION:
 * ──────────────────────────────
 * Backend signs video durations to prevent users from gaming the system
 * by submitting fake durations. Only verified YouTube API data is accepted.
 *
 * DAILY SUBMISSION LIMITS:
 * ───────────────────────
 * Prevents users from overwhelming the system with submissions.
 *
 * REPUTATION SYSTEM:
 * ─────────────────
 * Tracks user behavior over time to identify and limit bad actors.
 *
 * FARCASTER INTEGRATION:
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * • Users identified by Farcaster ID (FID)
 * • Seamless Web3 social integration
 * • Cast hash tracking for social submissions
 * • Country-based diversity tracking
 *
 * MINIAPP DEPLOYMENT:
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This contract serves as the backbone for a Farcaster miniapp deployed on
 * Base chain, creating a new paradigm for music discovery that prioritizes
 * human taste, global diversity, and community ownership over algorithmic
 * manipulation and profit maximization.
 *
 * The result: An eternal, ever-evolving radio stream that never repeats the
 * same sequence twice, powered by the collective musical consciousness of
 * humanity itself.
 *
 * ============================================================================
 */
contract HumanMusicDAO is Ownable, ReentrancyGuard {
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

    // ============ STATE VARIABLES ============

    struct Recommendation {
        uint256 id;
        uint256 submitterFid; // Farcaster FID of submitter
        string youtubeVideoId; // YouTube video ID (11 characters)
        string castHash; // Farcaster cast hash if submitted via cast (null if direct)
        string country; // Submitter's country
        uint256 duration; // Song duration in seconds (set by backend)
        uint256 submissionTime; // When submitted
        uint256 scheduledTime; // When scheduled to play
        RecommendationState state; // Current state in the temporal flow
        uint256 upvotes; // Community approval votes
        uint256 downvotes; // Community disapproval votes
        uint256 rewardsPaid; // $HUMANMUSIC rewards distributed
        bool isActive; // Whether recommendation is active
    }

    enum RecommendationState {
        SUBMITTED, // Just submitted, awaiting review
        APPROVED, // Approved and added to queue
        FUTURE, // Computed: queued for future play (index > currentSongIndex)
        PRESENT, // Computed: currently playing (index == currentSongIndex)
        PAST, // Computed: has finished playing (index < currentSongIndex)
        BANNED // Rejected by reviewer or system

    }

    struct User {
        uint256 fid; // Farcaster FID
        string username; // Farcaster username
        string country; // User's country
        uint256 submissionCount; // Total submissions
        uint256 totalUpvotes; // Total upvotes received
        uint256 lastSubmissionDay; // Last day they submitted (for daily limit)
        uint256 tokensEarned; // Total $HUMANMUSIC earned
        uint256 tokenBalance; // Current $HUMANMUSIC balance
        bool isReviewer; // Can review submissions
        uint256 reputationScore; // Community reputation
    }

    struct Comment {
        uint256 id;
        uint256 recommendationId;
        uint256 commenterFid;
        string content;
        uint256 timestamp;
        bool isActive;
    }

    // ============ STATE STORAGE ============

    /// @dev $HUMANMUSIC token contract for rewards and governance
    IERC20 public humanMusicToken;

    /// @dev Backend signer address that verifies YouTube video durations
    address public backendSigner;

    mapping(uint256 => Recommendation) public recommendations; // Recommendation ID => Recommendation
    mapping(uint256 => User) public users; // FID => User
    mapping(uint256 => Comment) public comments;
    mapping(uint256 => mapping(uint256 => bool)) public hasVoted; // FID => recommendationId => voted
    mapping(string => bool) public submittedVideoIds; // Prevent duplicate video IDs
    mapping(uint256 => mapping(address => bool)) public userAddressValid; // FID => address => valid

    uint256 public nextRecommendationId = 1; // Next recommendation ID to assign, increments by 1
    uint256 public nextCommentId = 1;
    uint256 public currentlyPlayingId = 0; // ID of the currently playing song
    uint256 public streamStartTime; // When the current song started playing
    uint256 public lastUpdateTime; // Last time updateSystem was called
    uint256 public totalCycleCount = 0; // How many times we've cycled through all content

    // Token Economics
    uint256 public SUBMISSION_REWARD = 10 * 10 ** 18; // 10 $HUMANMUSIC for submission
    uint256 public UPVOTE_REWARD = 5 * 10 ** 18; // 5 $HUMANMUSIC for receiving upvote
    uint256 public PLAY_REWARD = 50 * 10 ** 18; // 50 $HUMANMUSIC when song plays
    uint256 public VOTER_REWARD = 1 * 10 ** 18; // 1 $HUMANMUSIC for voting
    uint256 public UPDATE_REWARD = 2 * 10 ** 18; // 2 $HUMANMUSIC for calling updateSystem

    // Governance
    uint256 public VOTING_PERIOD = 24 hours;
    uint256 public MIN_UPVOTES_THRESHOLD = 3;
    uint256 public MIN_REPUTATION_SCORE = 200;
    uint256 public REVIEWER_TOKEN_REQUIREMENT = 1000 * 10 ** 18; // 1000 $HUMANMUSIC to become reviewer

    uint256[] public songQueue; // Queue of all approved recommendations
    uint256 public currentSongIndex = 0; // Index of currently playing song in songQueue

    // ============ EVENTS ============

    event RecommendationSubmitted(
        uint256 indexed id, uint256 indexed submitterFid, string youtubeVideoId, string castHash, string country
    );

    event RecommendationApproved(uint256 indexed id, uint256 approvedBy);
    event RecommendationRejected(uint256 indexed id, uint256 rejectedBy);
    event RecommendationBanned(uint256 indexed id);
    event RecommendationUnbanned(uint256 indexed id);
    event RecommendationTransitioned(uint256 indexed id, RecommendationState newState);
    event VoteCast(uint256 indexed recommendationId, uint256 indexed voterFid, bool isUpvote);
    event CommentAdded(uint256 indexed commentId, uint256 indexed recommendationId, uint256 indexed commenterFid);
    event UserRegistered(uint256 indexed fid, string username, string country, address indexed registeredAddress);
    event UserAddressAdded(uint256 indexed fid, address indexed registeredAddress);
    event StreamTransitioned(uint256 indexed fromId, uint256 indexed toId);
    event TokensRewarded(uint256 indexed fid, uint256 amount, string reason);
    event TokensDeposited(uint256 indexed fid, uint256 amount);
    event TokensWithdrawn(uint256 indexed fid, uint256 amount);
    event SystemUpdated(uint256 indexed callerFid, uint256 timeGapFilled, uint256 songsProcessed);
    event BigBangExecuted(uint256 cycleCount, uint256 songsMovedToFuture);
    event StreamInitialized(uint256 indexed firstSongId, uint256 startTime);
    event DurationSet(uint256 indexed recommendationId, string youtubeVideoId, uint256 duration);
    event BackendSignerUpdated(address indexed oldSigner, address indexed newSigner);

    // ============ MODIFIERS ============

    modifier onlyRegisteredUser(uint256 _fid) {
        require(users[_fid].fid != 0, "User not registered");
        require(userAddressValid[_fid][msg.sender], "Sender addr not registered to FID");
        _;
    }

    modifier onlyReviewer(uint256 _fid) {
        require(users[_fid].isReviewer, "Not authorized reviewer");
        require(userAddressValid[_fid][msg.sender], "Sender addr not registered to FID");
        require(users[_fid].tokenBalance >= REVIEWER_TOKEN_REQUIREMENT, "Insufficient tokens");
        _;
    }

    modifier onlySubmitter(uint256 _fid) {
        require(users[_fid].submissionCount > 0, "Must have submitted at least one video");
        require(userAddressValid[_fid][msg.sender], "Sender addr not registered to FID");
        _;
    }

    modifier validRecommendation(uint256 _id) {
        require(_id > 0 && _id < nextRecommendationId, "Invalid recommendation ID");
        require(recommendations[_id].isActive, "Recommendation not active");
        _;
    }

    // ============ CONSTRUCTOR ============

    /**
     * @dev Initialize the Human Music DAO contract
     * @param _humanMusicToken Address of the $HUMANMUSIC token contract
     */
    constructor(address _humanMusicToken) Ownable(msg.sender) {
        humanMusicToken = IERC20(_humanMusicToken);
        backendSigner = msg.sender; // Owner initially controls duration verification
        lastUpdateTime = block.timestamp;

        // Initialize EIP-712 domain separator
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("HumanMusicDAO"), keccak256("1"), block.chainid, address(this))
        );
    }

    // ============ CORE FUNCTIONS ============

    /**
     * @dev Register a new user (called from Farcaster miniapp)
     * @notice Requires EIP-712 signature from backend signer to prevent FID spoofing
     * @param _fid The Farcaster FID to register
     * @param _username The Farcaster username
     * @param _country The user's country
     * @param _deadline Signature expiration timestamp
     * @param _signature EIP-712 signature from backend signer
     */
    function registerUser(
        uint256 _fid,
        string memory _username,
        string memory _country,
        uint256 _deadline,
        bytes calldata _signature
    ) external {
        require(_fid > 0, "Invalid FID");
        require(users[_fid].fid == 0, "User already registered");
        require(block.timestamp <= _deadline, "Signature expired");

        // Verify EIP-712 signature
        bytes32 structHash = keccak256(abi.encode(USER_REGISTRATION_TYPEHASH, _fid, msg.sender, _deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        address signer = digest.recover(_signature);
        require(signer == backendSigner, "Invalid signature");

        users[_fid] = User({
            fid: _fid,
            username: _username,
            country: _country,
            submissionCount: 0,
            totalUpvotes: 0,
            lastSubmissionDay: 0,
            tokensEarned: 0,
            tokenBalance: 0,
            isReviewer: false,
            reputationScore: 100 // Starting reputation
        });

        // Set the initial address as valid
        userAddressValid[_fid][msg.sender] = true;

        emit UserRegistered(_fid, _username, _country, msg.sender);
    }

    /**
     * @dev Add a new address to a user's registered addresses
     * @param _fid The Farcaster FID of the user
     * @param _newAddress The address to add to the user's addresses
     */
    function addUserAddress(uint256 _fid, address _newAddress) external onlyRegisteredUser(_fid) {
        require(_newAddress != address(0), "Invalid address");
        require(!userAddressValid[_fid][_newAddress], "Address already registered to FID");

        userAddressValid[_fid][_newAddress] = true;
        emit UserAddressAdded(_fid, _newAddress);
    }

    /**
     * @notice Add a new address to a user's FID using an EIP-712 signature from the owner
     * @notice This is for Clients that have different wallets and addresses for the same FID
     * @param _fid Farcaster FID of the user
     * @param _newAddress New address to add to the user's FID
     * @param _deadline Signature expiration timestamp
     * @param _signature EIP-712 signature from the owner approving the address addition
     */
    function addUserAddressWithSignature(
        uint256 _fid,
        address _newAddress,
        uint256 _deadline,
        bytes calldata _signature
    ) external {
        require(users[_fid].fid != 0, "User not registered");
        require(_newAddress != address(0), "Invalid address");
        require(!userAddressValid[_fid][_newAddress], "Address already registered to FID");
        require(block.timestamp <= _deadline, "Signature expired");

        // Verify EIP-712 signature
        bytes32 structHash = keccak256(abi.encode(USER_REGISTRATION_TYPEHASH, _fid, _newAddress, _deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = digest.recover(_signature);
        require(signer == backendSigner, "Invalid signature");

        userAddressValid[_fid][_newAddress] = true;
        emit UserAddressAdded(_fid, _newAddress);
    }

    /**
     * @dev Submit a new music recommendation (direct via miniapp)
     */
    function submitRecommendation(uint256 _submitterFid, string memory _youtubeVideoId)
        external
        onlyRegisteredUser(_submitterFid)
        nonReentrant
    {
        _submitRecommendationInternal(_submitterFid, _youtubeVideoId, "");
    }

    /**
     * @dev Submit a recommendation from a Farcaster cast (backend only)
     */
    function submitRecommendationFromCast(uint256 _submitterFid, string memory _youtubeVideoId, string memory _castHash)
        external
        onlyOwner
    {
        require(users[_submitterFid].fid != 0, "User not registered");
        _submitRecommendationInternal(_submitterFid, _youtubeVideoId, _castHash);
    }

    /**
     * @dev Internal function to handle both direct and cast submissions
     */
    function _submitRecommendationInternal(
        uint256 _submitterFid,
        string memory _youtubeVideoId,
        string memory _castHash
    ) internal {
        require(bytes(_youtubeVideoId).length == 11, "YouTube video ID must be 11 characters");
        require(!submittedVideoIds[_youtubeVideoId], "Video already submitted");

        User storage user = users[_submitterFid];
        uint256 currentDay = block.timestamp / 1 days;
        require(user.lastSubmissionDay < currentDay, "Can only submit one video per day");

        uint256 recommendationId = nextRecommendationId++;

        recommendations[recommendationId] = Recommendation({
            id: recommendationId,
            submitterFid: _submitterFid,
            youtubeVideoId: _youtubeVideoId,
            castHash: _castHash,
            country: user.country,
            duration: 0, // Will be set by backend after YouTube API call
            submissionTime: block.timestamp,
            scheduledTime: 0,
            state: RecommendationState.SUBMITTED,
            upvotes: 0,
            downvotes: 0,
            rewardsPaid: 0,
            isActive: true
        });

        submittedVideoIds[_youtubeVideoId] = true;
        user.submissionCount++;
        user.lastSubmissionDay = currentDay;

        // Reward user for submission
        _rewardUser(_submitterFid, SUBMISSION_REWARD, "submission");

        emit RecommendationSubmitted(recommendationId, _submitterFid, _youtubeVideoId, _castHash, user.country);
    }

    /**
     * @dev Vote on a submitted recommendation
     */
    function voteOnRecommendation(uint256 _recommendationId, uint256 _voterFid, bool _isUpvote)
        external
        onlyRegisteredUser(_voterFid)
        validRecommendation(_recommendationId)
    {
        Recommendation storage rec = recommendations[_recommendationId];
        require(rec.state == RecommendationState.SUBMITTED, "Voting period ended");
        require(block.timestamp <= rec.submissionTime + VOTING_PERIOD, "Voting period expired");
        require(!hasVoted[_voterFid][_recommendationId], "Already voted");
        require(rec.submitterFid != _voterFid, "Cannot vote on own submission");

        hasVoted[_voterFid][_recommendationId] = true;

        if (_isUpvote) {
            rec.upvotes++;
            users[rec.submitterFid].totalUpvotes++;
            users[rec.submitterFid].reputationScore += 5;

            // Reward the submitter for receiving an upvote
            _rewardUser(rec.submitterFid, UPVOTE_REWARD, "upvote_received");
        } else {
            rec.downvotes++;
            if (users[rec.submitterFid].reputationScore > 5) {
                users[rec.submitterFid].reputationScore -= 2;
            }
        }

        // Reward the voter for participating
        _rewardUser(_voterFid, VOTER_REWARD, "voting");

        emit VoteCast(_recommendationId, _voterFid, _isUpvote);

        // Auto-approve if threshold met
        if (rec.upvotes >= MIN_UPVOTES_THRESHOLD && rec.upvotes > rec.downvotes && rec.duration > 0) {
            _approveRecommendation(_recommendationId);
        }
    }

    /**
     * @dev Approve a recommendation for the future queue without requiring vote
     */
    function approveRecommendation(uint256 _recommendationId, uint256 _reviewerFid)
        external
        onlyReviewer(_reviewerFid)
        validRecommendation(_recommendationId)
    {
        _approveRecommendation(_recommendationId);
        emit RecommendationApproved(_recommendationId, _reviewerFid);
    }

    function _approveRecommendation(uint256 _recommendationId) internal {
        Recommendation storage rec = recommendations[_recommendationId];
        require(rec.state == RecommendationState.SUBMITTED, "Already processed");
        require(rec.duration > 0, "Duration not set");

        rec.state = RecommendationState.APPROVED;
        rec.scheduledTime = block.timestamp; // Will be properly scheduled when added to queue
        songQueue.push(_recommendationId);

        emit RecommendationTransitioned(_recommendationId, RecommendationState.APPROVED);
    }

    /**
     * @dev Reject a recommendation
     */
    function rejectRecommendation(uint256 _recommendationId, uint256 _reviewerFid)
        external
        onlyReviewer(_reviewerFid)
        validRecommendation(_recommendationId)
    {
        Recommendation storage rec = recommendations[_recommendationId];
        require(rec.state == RecommendationState.SUBMITTED, "Already processed");

        rec.isActive = false;
        submittedVideoIds[rec.youtubeVideoId] = false; // Allow resubmission

        emit RecommendationRejected(_recommendationId, _reviewerFid);
    }

    /**
     * @dev Internal function to reward users with $HUMANMUSIC tokens
     */
    function _rewardUser(uint256 _fid, uint256 _amount, string memory _reason) internal {
        User storage user = users[_fid];
        user.tokensEarned += _amount;
        user.tokenBalance += _amount;
        emit TokensRewarded(_fid, _amount, _reason);
    }

    /**
     * @dev External function so user can deposit $HUMANMUSIC tokens for rolls
     */
    function userDepositTokens(uint256 _fid, uint256 _amount) external nonReentrant {
        User storage user = users[_fid];
        user.tokenBalance += _amount;
        emit TokensDeposited(_fid, _amount);
        require(humanMusicToken.transferFrom(msg.sender, address(this), _amount), "Token transfer failed");
    }

    /**
     * @dev Set video duration with EIP-712 signature verification
     * @notice Only backend can set duration after YouTube API verification
     * @param _recommendationId The recommendation ID to set duration for
     * @param _duration Duration in seconds (1-600)
     * @param _deadline Signature expiration timestamp
     * @param _signature EIP-712 signature from backend signer
     */
    function setVideoDuration(
        uint256 _recommendationId,
        uint256 _duration,
        uint256 _deadline,
        bytes calldata _signature
    ) external {
        require(_recommendationId > 0 && _recommendationId < nextRecommendationId, "Invalid recommendation ID");
        require(_duration > 0 && _duration <= 600, "Duration must be 1-600 seconds");
        require(block.timestamp <= _deadline, "Signature expired");

        Recommendation storage rec = recommendations[_recommendationId];
        require(rec.duration == 0, "Duration already set");
        require(rec.isActive, "Recommendation not active");

        // Verify EIP-712 signature
        bytes32 structHash =
            keccak256(abi.encode(DURATION_TYPEHASH, keccak256(bytes(rec.youtubeVideoId)), _duration, _deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        address signer = digest.recover(_signature);
        require(signer == backendSigner, "Invalid signature");

        // Set the verified duration
        rec.duration = _duration;

        emit DurationSet(_recommendationId, rec.youtubeVideoId, _duration);

        // Check if has Upvotes to auto approve
        if (rec.upvotes >= MIN_UPVOTES_THRESHOLD && rec.upvotes > rec.downvotes) {
            _approveRecommendation(_recommendationId);
        }
    }

    /**
     * @dev Ban a recommendation
     * @param _recommendationId The recommendation ID to ban
     */
    function banRecommendation(uint256 _recommendationId) external onlyOwner validRecommendation(_recommendationId) {
        Recommendation storage rec = recommendations[_recommendationId];
        require(rec.state == RecommendationState.SUBMITTED, "Already processed");
        rec.state = RecommendationState.BANNED;
        emit RecommendationBanned(_recommendationId);
    }

    /**
     * @dev Unban a recommendation
     * @param _recommendationId The recommendation ID to unban
     */
    function unbanRecommendation(uint256 _recommendationId) external onlyOwner validRecommendation(_recommendationId) {
        Recommendation storage rec = recommendations[_recommendationId];
        require(rec.state == RecommendationState.BANNED, "Not banned");
        rec.state = RecommendationState.SUBMITTED;
        emit RecommendationUnbanned(_recommendationId);
    }

    /**
     * @dev Initialize the eternal stream with the first song
     * @notice Can only be initialized when there are approved songs in the future queue
     */
    function initializeStream() external onlyOwner {
        require(currentlyPlayingId == 0, "Stream already initialized");
        require(songQueue.length >= 1, "Need at least one approved song in queue");

        currentSongIndex = 0;
        uint256 firstSongId = songQueue[0];

        // Set as currently playing
        Recommendation storage firstSong = recommendations[firstSongId];
        require(firstSong.duration > 0, "First song must have duration set");
        currentlyPlayingId = firstSongId;
        streamStartTime = block.timestamp;
        lastUpdateTime = block.timestamp;

        emit StreamInitialized(firstSongId, streamStartTime);
        emit RecommendationTransitioned(firstSongId, getRecommendationState(firstSongId, currentSongIndex));
    }

    /**
     * @dev The eternal thread keeper - anyone who has submitted can call this
     * @param _callerFid The FID of whoever is calling this function
     */
    function updateSystem(uint256 _callerFid) external onlySubmitter(_callerFid) nonReentrant {
        require(currentlyPlayingId != 0, "Stream not initialized");

        uint256 timeElapsed = block.timestamp - streamStartTime;
        uint256 currentSongDuration = recommendations[currentlyPlayingId].duration;
        uint256 songsProcessed = 0;
        uint256 totalTimeToFill = 0;

        // If current song has finished, move it to past and start processing
        if (timeElapsed >= currentSongDuration) {
            _moveCurrentToPast();
            totalTimeToFill = timeElapsed - currentSongDuration;
            songsProcessed++;
            currentSongIndex++;
        } else {
            // Current song is still playing, no processing needed
            return;
        }

        // Iterate through songQueue from currentSongIndex until time gap is filled
        while (totalTimeToFill > 0) {
            // Check if we need to perform Big Bang (reached end of queue)
            if (currentSongIndex >= songQueue.length) {
                _bigBang();
            }

            // Ensure we have songs to process
            if (currentSongIndex >= songQueue.length) {
                break; // No songs available even after Big Bang
            }

            uint256 nextSongId = songQueue[currentSongIndex];
            Recommendation storage nextSong = recommendations[nextSongId];

            if (totalTimeToFill >= nextSong.duration) {
                // This song would have finished in the time gap
                _rewardUser(nextSong.submitterFid, PLAY_REWARD, "song_played");
                nextSong.rewardsPaid += PLAY_REWARD;
                totalTimeToFill -= nextSong.duration;
                songsProcessed++;
                emit RecommendationTransitioned(nextSongId, getRecommendationState(nextSongId, currentSongIndex));
                currentSongIndex++;
            } else {
                // This song is currently playing
                currentlyPlayingId = nextSongId;
                streamStartTime = block.timestamp - totalTimeToFill;
                totalTimeToFill = 0;
                songsProcessed++;
                emit RecommendationTransitioned(nextSongId, getRecommendationState(nextSongId, currentSongIndex));
                break;
            }
        }

        lastUpdateTime = block.timestamp;

        // Reward the caller for maintaining the eternal stream
        _rewardUser(_callerFid, UPDATE_REWARD, "system_update");

        emit SystemUpdated(_callerFid, timeElapsed, songsProcessed);
    }

    /**
     * @dev Big Bang - reset the queue index to restart the cycle
     */
    function _bigBang() internal {
        require(currentSongIndex >= songQueue.length, "Can only big bang when queue is exhausted");
        require(songQueue.length > 0, "No songs in queue");

        // Reset index to start of queue (states are computed dynamically, no need to update)
        currentSongIndex = 0;
        totalCycleCount++;
        uint256 songsMovedCount = songQueue.length;

        emit BigBangExecuted(totalCycleCount, songsMovedCount);
    }

    /**
     * @dev Internal function to move current song to past
     */
    function _moveCurrentToPast() internal {
        if (currentlyPlayingId != 0) {
            Recommendation storage current = recommendations[currentlyPlayingId];

            // Reward submitter for their song being played
            _rewardUser(current.submitterFid, PLAY_REWARD, "song_played");
            current.rewardsPaid += PLAY_REWARD;

            emit RecommendationTransitioned(
                currentlyPlayingId, getRecommendationState(currentlyPlayingId, currentSongIndex)
            );
        }
    }

    /**
     * @dev Add a comment to a recommendation
     */
    function addComment(uint256 _recommendationId, uint256 _commenterFid, string memory _content)
        external
        onlyRegisteredUser(_commenterFid)
        validRecommendation(_recommendationId)
    {
        require(bytes(_content).length > 0, "Comment cannot be empty");
        require(bytes(_content).length <= 500, "Comment too long");

        uint256 commentId = nextCommentId++;

        comments[commentId] = Comment({
            id: commentId,
            recommendationId: _recommendationId,
            commenterFid: _commenterFid,
            content: _content,
            timestamp: block.timestamp,
            isActive: true
        });

        users[_commenterFid].reputationScore += 1; // Small reputation boost for engagement

        emit CommentAdded(commentId, _recommendationId, _commenterFid);
    }

    /**
     * @dev Grant reviewer privileges (requires token holding)
     */
    function grantReviewerRole(uint256 _fid) external onlyOwner {
        require(users[_fid].fid != 0, "User not registered");
        users[_fid].isReviewer = true;
    }

    /**
     * @dev Revoke reviewer privileges
     * @notice resets the user's Reputation Score to 5
     */
    function revokeReviewerRole(uint256 _fid) external onlyOwner {
        require(users[_fid].fid != 0, "User not registered");
        users[_fid].isReviewer = false;
        users[_fid].reputationScore = 5;
    }

    /**
     * @dev Grant reviewer privileges (requires token holding)
     */
    function autoGrantReviewerRole(uint256 _fid) external {
        require(users[_fid].fid != 0, "User not registered");
        require(users[_fid].reputationScore >= MIN_REPUTATION_SCORE, "Insufficient reputation");
        require(users[_fid].tokenBalance >= REVIEWER_TOKEN_REQUIREMENT, "Insufficient tokens");
        users[_fid].isReviewer = true;
    }

    /**
     * @dev Withdraw $HUMANMUSIC tokens
     */
    function withdrawTokens(uint256 _fid, uint256 _amount) external onlyRegisteredUser(_fid) nonReentrant {
        User storage user = users[_fid];
        require(user.tokenBalance >= _amount, "Insufficient balance");
        require(_amount > 0, "Amount must be positive");

        user.tokenBalance -= _amount;
        require(humanMusicToken.transfer(msg.sender, _amount), "Token transfer failed");

        emit TokensWithdrawn(_fid, _amount);
    }

    /**
     * @dev Owner can deposit tokens for rewards (community fund)
     */
    function depositRewardTokens(uint256 _amount) external onlyOwner {
        require(humanMusicToken.transferFrom(msg.sender, address(this), _amount), "Transfer failed");
    }

    // ============ TOKEN ECONOMICS SETTERS ============

    /**
     * @notice Set the reward amount for submitting a recommendation
     * @param _amount New submission reward amount
     */
    function setSubmissionReward(uint256 _amount) external onlyOwner {
        SUBMISSION_REWARD = _amount;
    }

    /**
     * @notice Set the reward amount for receiving an upvote
     * @param _amount New upvote reward amount
     */
    function setUpvoteReward(uint256 _amount) external onlyOwner {
        UPVOTE_REWARD = _amount;
    }

    /**
     * @notice Set the reward amount when a song plays
     * @param _amount New play reward amount
     */
    function setPlayReward(uint256 _amount) external onlyOwner {
        PLAY_REWARD = _amount;
    }

    /**
     * @notice Set the reward amount for voting on a recommendation
     * @param _amount New voter reward amount
     */
    function setVoterReward(uint256 _amount) external onlyOwner {
        VOTER_REWARD = _amount;
    }

    /**
     * @notice Set the reward amount for calling updateSystem
     * @param _amount New update reward amount
     */
    function setUpdateReward(uint256 _amount) external onlyOwner {
        UPDATE_REWARD = _amount;
    }

    // ============ GOVERNANCE SETTER ============

    /**
     * @notice Set all governance parameters
     * @param _votingPeriod New voting period in seconds
     * @param _minUpvotesThreshold New minimum upvotes threshold for auto-approval
     * @param _reviewerTokenRequirement New token requirement to become a reviewer
     */
    function setGovernanceParameters(
        uint256 _votingPeriod,
        uint256 _minUpvotesThreshold,
        uint256 _minReputationScore,
        uint256 _reviewerTokenRequirement
    ) external onlyOwner {
        VOTING_PERIOD = _votingPeriod;
        MIN_UPVOTES_THRESHOLD = _minUpvotesThreshold;
        MIN_REPUTATION_SCORE = _minReputationScore;
        REVIEWER_TOKEN_REQUIREMENT = _reviewerTokenRequirement;
    }

    // ============ ADMIN FUNCTIONS ============

    function setBackendSigner(address _newSigner) external onlyOwner {
        require(_newSigner != address(0), "Invalid signer address");
        address oldSigner = backendSigner;
        backendSigner = _newSigner;
        emit BackendSignerUpdated(oldSigner, _newSigner);
    }

    // ============ VIEW FUNCTIONS ============

    /**
     * @dev Get currently playing recommendation
     */
    function getCurrentlyPlaying() external view returns (Recommendation memory) {
        require(currentlyPlayingId != 0, "Nothing currently playing");
        return recommendations[currentlyPlayingId];
    }

    /**
     * @dev Get the song queue
     */
    function getSongQueue() external view returns (uint256[] memory) {
        return songQueue;
    }

    /**
     * @dev Get the current song index
     */
    function getCurrentSongIndex() external view returns (uint256) {
        return currentSongIndex;
    }

    /**
     * @dev Get the computed state of a recommendation based on its position in the queue
     * @param _recommendationId The recommendation ID
     * @param _queueIndex The index of the recommendation in the songQueue
     * @return The computed RecommendationState (SUBMITTED if stored, PAST/PRESENT/FUTURE if computed from queue position)
     */
    function getRecommendationState(uint256 _recommendationId, uint256 _queueIndex)
        public
        view
        validRecommendation(_recommendationId)
        returns (RecommendationState)
    {
        Recommendation storage rec = recommendations[_recommendationId];

        // Return SUBMITTED state directly (not in queue yet)
        if (rec.state == RecommendationState.SUBMITTED) {
            return RecommendationState.SUBMITTED;
        }

        // Compute state based on position relative to currentSongIndex
        if (_queueIndex < currentSongIndex) {
            return RecommendationState.PAST;
        } else if (_queueIndex == currentSongIndex) {
            return RecommendationState.PRESENT;
        } else {
            return RecommendationState.FUTURE;
        }
    }

    /**
     * @dev Get user stats
     */
    function getUserStats(uint256 _fid)
        external
        view
        returns (
            uint256 submissionCount,
            uint256 totalUpvotes,
            uint256 reputationScore,
            uint256 tokensEarned,
            uint256 tokenBalance,
            bool isReviewer,
            bool canSubmitToday
        )
    {
        User memory user = users[_fid];
        uint256 currentDay = block.timestamp / 1 days;
        bool canSubmit = user.lastSubmissionDay < currentDay;

        return (
            user.submissionCount,
            user.totalUpvotes,
            user.reputationScore,
            user.tokensEarned,
            user.tokenBalance,
            user.isReviewer,
            canSubmit
        );
    }

    /**
     * @dev Get recommendation with comments count
     */
    function getRecommendationDetails(uint256 _id)
        external
        view
        returns (Recommendation memory recommendation, uint256 commentsCount)
    {
        recommendation = recommendations[_id];

        // Count comments for this recommendation
        commentsCount = 0;
        for (uint256 i = 1; i < nextCommentId; i++) {
            if (comments[i].recommendationId == _id && comments[i].isActive) {
                commentsCount++;
            }
        }
    }

    /**
     * @dev Get global stats
     */
    function getGlobalStats()
        external
        view
        returns (uint256 totalRecommendations, uint256 currentQueueLength, uint256 cycleCount)
    {
        totalRecommendations = nextRecommendationId - 1;
        currentQueueLength = songQueue.length;
        cycleCount = totalCycleCount;
    }

    /**
     * @dev Check if video ID has been submitted
     */
    function isVideoSubmitted(string memory _videoId) external view returns (bool) {
        return submittedVideoIds[_videoId];
    }

    /**
     * @dev Check if user can submit today
     */
    function canUserSubmitToday(uint256 _fid) external view returns (bool) {
        if (users[_fid].fid == 0) return false; // User not registered
        uint256 currentDay = block.timestamp / 1 days;
        return users[_fid].lastSubmissionDay < currentDay;
    }

    /**
     * @dev Get recommendation source info
     */
    function getRecommendationSource(uint256 _id)
        external
        view
        returns (string memory videoId, string memory castHash, bool isFromCast)
    {
        Recommendation memory rec = recommendations[_id];
        return (rec.youtubeVideoId, rec.castHash, bytes(rec.castHash).length > 0);
    }

    /**
     * @dev Get today's submissions count
     */
    function getTodaySubmissionsCount() external view returns (uint256) {
        uint256 count = 0;
        uint256 endTime = block.timestamp - 1 days;
        uint256 submissionIndex = nextRecommendationId - 1;

        while (recommendations[submissionIndex].submissionTime >= endTime) {
            count++;
            submissionIndex--;
        }
        return count;
    }

    /**
     * @dev Get contract token balance
     */
    function getContractTokenBalance() external view returns (uint256) {
        return humanMusicToken.balanceOf(address(this));
    }

    /**
     * @dev Get EIP-712 domain info for frontend signature generation
     * @return domain The domain separator
     * @return name The contract name
     * @return version The contract version
     * @return chainId The chain ID
     * @return verifyingContract This contract's address
     */
    function getDomainInfo()
        external
        view
        returns (bytes32 domain, string memory name, string memory version, uint256 chainId, address verifyingContract)
    {
        return (DOMAIN_SEPARATOR, "HumanMusicDAO", "1", block.chainid, address(this));
    }

    /**
     * @dev Get the current backend signer address
     */
    function getBackendSigner() external view returns (address) {
        return backendSigner;
    }

    /**
     * @dev Check if system is ready for initialization
     */
    function canInitializeStream()
        external
        view
        returns (bool canInitialize, uint256 approvedSongsCount, string memory reason)
    {
        if (currentlyPlayingId != 0) {
            return (false, songQueue.length, "Stream already initialized");
        }

        if (songQueue.length == 0) {
            return (false, 0, "No approved songs in queue");
        }

        // Check if at least the first song has duration set
        uint256 firstSongId = songQueue[0];
        if (recommendations[firstSongId].duration == 0) {
            return (false, songQueue.length, "First song duration not set");
        }

        return (true, songQueue.length, "Ready to initialize");
    }

    /**
     * @dev Get current stream status and timing information
     */
    function getStreamStatus()
        external
        view
        returns (
            uint256 currentSongId,
            uint256 timeElapsedInCurrentSong,
            uint256 remainingTimeInCurrentSong,
            uint256 totalTimeElapsedSinceLastUpdate,
            bool needsUpdate,
            uint256 cycleCount
        )
    {
        currentSongId = currentlyPlayingId;
        cycleCount = totalCycleCount;

        if (currentlyPlayingId == 0) {
            return (0, 0, 0, 0, false, cycleCount);
        }

        Recommendation memory current = recommendations[currentlyPlayingId];
        uint256 totalElapsed = block.timestamp - streamStartTime;
        totalTimeElapsedSinceLastUpdate = block.timestamp - lastUpdateTime;

        if (totalElapsed >= current.duration) {
            // Current song has finished
            timeElapsedInCurrentSong = current.duration;
            remainingTimeInCurrentSong = 0;
            needsUpdate = true;
        } else {
            timeElapsedInCurrentSong = totalElapsed;
            remainingTimeInCurrentSong = current.duration - totalElapsed;
            needsUpdate = false;
        }
    }

    /**
     * @dev Get system health - how much time gap needs to be filled
     */
    function _getSystemHealth()
        external
        view
        returns (uint256 timeGapToFill, uint256 songsToProcess, uint256 bigBangsNeeded, uint256 newCurrentSongId)
    {
        uint256 timeProcessed = 0;
        uint256 _currentSongIndex = currentSongIndex;
        songsToProcess = 0;
        bigBangsNeeded = 0;

        if (currentlyPlayingId == 0) {
            return (0, songsToProcess, bigBangsNeeded, 0); // Not initialized
        }

        Recommendation memory current = recommendations[currentlyPlayingId];
        uint256 timeElapsed = block.timestamp - streamStartTime;

        if (timeElapsed > current.duration) {
            timeGapToFill = timeElapsed - current.duration;
        } else {
            timeGapToFill = 0;
            return (timeGapToFill, songsToProcess, bigBangsNeeded, currentlyPlayingId); // No time gap to fill
        }

        while (timeProcessed < timeGapToFill) {
            uint256 nextSongId = songQueue[_currentSongIndex];
            uint256 nextDuration = recommendations[nextSongId].duration;
            if (timeProcessed + nextDuration > timeGapToFill) {
                newCurrentSongId = nextSongId;
                break;
            }
            timeProcessed += nextDuration;
            songsToProcess++;
            _currentSongIndex++;
            if (_currentSongIndex >= songQueue.length) {
                bigBangsNeeded++;
                _currentSongIndex = 0;
            }
        }
        return (timeGapToFill, songsToProcess, bigBangsNeeded, newCurrentSongId);
    }

    function getSystemHealth()
        public
        view
        returns (uint256 timeGapToFill, uint256 songsProcessed, uint256 bigBangsNeeded, uint256 newCurrentSongId)
    {
        uint256 timeElapsed = block.timestamp - streamStartTime;
        uint256 currentSongDuration = recommendations[currentlyPlayingId].duration;
        newCurrentSongId = currentlyPlayingId;
        songsProcessed = 0;
        bigBangsNeeded = 0;
        uint256 totalTimeToFill = 0;
        uint256 _currentSongIndex = currentSongIndex;

        // If current song has finished, move it to past and start processing
        if (timeElapsed >= currentSongDuration) {
            totalTimeToFill = timeElapsed - currentSongDuration;
            songsProcessed++;
            _currentSongIndex++;
        } else {
            // Current song is still playing, no processing needed
            return (0, songsProcessed, bigBangsNeeded, currentlyPlayingId);
        }

        // Iterate through songQueue from currentSongIndex until time gap is filled
        while (totalTimeToFill > 0) {
            // Check if we need to perform Big Bang (reached end of queue)
            if (_currentSongIndex >= songQueue.length) {
                bigBangsNeeded++;
                _currentSongIndex = 0;
            }

            // Ensure we have songs to process
            if (_currentSongIndex >= songQueue.length) {
                break; // No songs available even after Big Bang
            }

            uint256 nextSongId = songQueue[_currentSongIndex];
            uint256 nextSongDuration = recommendations[nextSongId].duration;

            if (totalTimeToFill >= nextSongDuration) {
                // This song would have finished in the time gap
                totalTimeToFill -= nextSongDuration;
                songsProcessed++;
                _currentSongIndex++;
            } else {
                // This song is currently playing
                newCurrentSongId = nextSongId;
                totalTimeToFill = 0;
                songsProcessed++;
                break;
            }
        }
        return (timeElapsed, songsProcessed, bigBangsNeeded, newCurrentSongId);
    }
}
