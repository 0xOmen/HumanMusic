// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {HumanMusicDAO} from "./humanmusic.sol";

/**
 * @title HumanMusicManager - The Manager of the HumanMusicDAO contract
 * version 1.0.0
 * @author  @0x-omen.eth x @jpfraneto.eth
 * @notice "The Most Diverse Music Recommendation Algorithm in The World" - powered by human nature
 *
 * This contract manages the HumanMusicDAO contract and provides a way to interact with it.
 *
 * ============================================================================
 *                                  HUMAN MUSIC MANAGER
 * ============================================================================
 *
 */

// ============ EVENTS ============

contract HumanMusicManager is Ownable, ReentrancyGuard {
    using ECDSA for bytes32;

    HumanMusicDAO public humanMusicDAO;

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
    event DurationSet(uint256 indexed recommendationId, string youtubeVideoId, uint256 duration);
    event BackendSignerUpdated(address indexed oldSigner, address indexed newSigner);
    event SongsRemovedFromQueue(uint256 indexed songsRemoved);

    // ============ MODIFIERS ============

    modifier onlyRegisteredUser(uint256 _fid) {
        (uint256 fid,,,,,,,,,) = HumanMusicDAO(humanMusicDAO).users(_fid);
        require(fid != 0, "User not registered");
        require(HumanMusicDAO(humanMusicDAO).userAddressValid(_fid, msg.sender), "Sender addr not registered to FID");
        _;
    }

    modifier onlyReviewer(uint256 _fid) {
        (uint256 fid,,,,,,, uint256 tokenBalance, bool isReviewer,) = HumanMusicDAO(humanMusicDAO).users(_fid);
        require(isReviewer, "Not authorized reviewer");
        require(HumanMusicDAO(humanMusicDAO).userAddressValid(_fid, msg.sender), "Sender addr not registered to FID");
        require(tokenBalance >= HumanMusicDAO(humanMusicDAO).REVIEWER_TOKEN_REQUIREMENT(), "Insufficient tokens");
        _;
    }

    modifier onlySubmitter(uint256 _fid) {
        (,,, uint256 submissionCount,,,,,,) = HumanMusicDAO(humanMusicDAO).users(_fid);
        require(submissionCount > 0, "Must have submitted at least one video");
        require(HumanMusicDAO(humanMusicDAO).userAddressValid(_fid, msg.sender), "Sender addr not registered to FID");
        _;
    }

    modifier validRecommendation(uint256 _id) {
        (uint256 id,,,,,,,,,,,, bool isActive) = HumanMusicDAO(humanMusicDAO).recommendations(_id);
        require(id > 0 && id < HumanMusicDAO(humanMusicDAO).nextRecommendationId(), "Invalid recommendation ID");
        require(isActive, "Recommendation not active");
        _;
    }

    // ============ CONSTRUCTOR ============

    constructor(address _humanMusicDAO) Ownable(msg.sender) {
        humanMusicDAO = HumanMusicDAO(_humanMusicDAO);
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
        (uint256 fid,,,,,,,,,) = HumanMusicDAO(humanMusicDAO).users(_fid);
        require(fid == 0, "User already registered");
        require(block.timestamp <= _deadline, "Signature expired");

        // Verify EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(HumanMusicDAO(humanMusicDAO).getUserRegistrationTypehash(), _fid, msg.sender, _deadline)
        );

        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", HumanMusicDAO(humanMusicDAO).getDomainSeparator(), structHash));

        address signer = digest.recover(_signature);
        require(signer == HumanMusicDAO(humanMusicDAO).getBackendSigner(), "Invalid signature");

        HumanMusicDAO(humanMusicDAO).addUser(_fid, _username, _country, msg.sender, 100);

        HumanMusicDAO(humanMusicDAO).setUserAddressValid(_fid, msg.sender, true);

        emit UserRegistered(_fid, _username, _country, msg.sender);
    }

    /**
     * @dev Add a new address to a user's registered addresses
     * @param _fid The Farcaster FID of the user
     * @param _newAddress The address to add to the user's addresses
     */
    function addUserAddress(uint256 _fid, address _newAddress) external onlyRegisteredUser(_fid) {
        require(_newAddress != address(0), "Invalid address");
        require(!HumanMusicDAO(humanMusicDAO).userAddressValid(_fid, _newAddress), "Address already registered to FID");

        HumanMusicDAO(humanMusicDAO).setUserAddressValid(_fid, _newAddress, true);
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
        (uint256 fid,,,,,,,,,) = HumanMusicDAO(humanMusicDAO).users(_fid);
        require(fid != 0, "User not registered");
        require(_newAddress != address(0), "Invalid address");
        require(!HumanMusicDAO(humanMusicDAO).userAddressValid(_fid, _newAddress), "Address already registered to FID");
        require(block.timestamp <= _deadline, "Signature expired");

        // Verify EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(HumanMusicDAO(humanMusicDAO).getUserRegistrationTypehash(), _fid, _newAddress, _deadline)
        );
        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", HumanMusicDAO(humanMusicDAO).getDomainSeparator(), structHash));
        address signer = digest.recover(_signature);
        require(signer == HumanMusicDAO(humanMusicDAO).getBackendSigner(), "Invalid signature");

        HumanMusicDAO(humanMusicDAO).setUserAddressValid(_fid, _newAddress, true);
        emit UserAddressAdded(_fid, _newAddress);
    }
}
