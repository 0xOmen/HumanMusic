# HumanMusicDAO

## Overview

HumanMusicDAO is a decentralized, community-curated music discovery platform that operates as an eternal, continuous radio stream. Unlike algorithmic recommendation systems, Human Music harnesses the genuine taste and diverse perspectives of humans worldwide.

**How it works:**

- Users submit YouTube videos they love
- The community votes on submissions
- Approved songs enter a queue and play in an eternal stream
- Participants earn $HUMANMUSIC tokens for quality contributions
- The stream never stops - when the queue empties, it cycles back through all past songs

**Key Features:**

- **Human Curation**: Community members submit based on personal taste, not algorithms
- **Eternal Continuity**: Stream never stops, auto-cycles through all content
- **Global Diversity**: Users from any country contribute to musical discovery
- **Economic Incentives**: $HUMANMUSIC token rewards quality participation
- **Anti-Gaming**: EIP-712 signatures prevent manipulation

---

## Front-End Integration Guide

This section provides detailed specifications for front-end developers integrating with the HumanMusicDAO smart contracts.

### Contract Architecture

HumanMusicDAO consists of **two main contracts** that work together:

1. **HumanMusicDAO** (`humanmusic.sol`) - Core DAO contract handling token deposits, withdrawals, and stream initialization
2. **HumanMusicManager** (`HumanMusicManager.sol`) - Manager contract handling user registration, submissions, voting, and recommendations

### Quick Reference: Functions by Contract

**HumanMusicDAO (`humanmusic.sol`):**

- `userDepositTokens()` - Deposit tokens
- `withdrawTokens()` - Withdraw tokens
- `initializeStream()` - Initialize the stream (call once when ready)

**HumanMusicManager (`HumanMusicManager.sol`):**

- `registerUser()` - Register a new user
- `addUserAddress()` - Add address to existing FID
- `addUserAddressWithSignature()` - Add address with signature (for different Farcaster clients)
- `submitRecommendation()` - Submit a recommendation
- `submitRecommendationWithDuration()` - **Recommended:** Submit with duration (reduces transactions)
- `voteOnRecommendation()` - Vote on a recommendation
- `approveRecommendation()` - Approve as reviewer
- `rejectRecommendation()` - Reject as reviewer
- `updateSystem()` - Update the stream
- `addComment()` - Add a comment to a recommendation

### Contract Addresses

**Deployed Contract Addresses:**

- **Fake Token Address**: `0x3E853062407A32c5F5E06Be8d36DBCe6b7c4DA03`
- **DAO Address**: `0xBdc4E325629B2cF58F6c77912f81b73FE900C94d`
- **Manager Address**: `0x1364C85679b5459146dE57523CB1CF1ABAB917A8`

### Prerequisites

- Users must have a Farcaster FID (Farcaster ID)
- Users need a Web3 wallet (MetaMask, WalletConnect, etc.)
- The front-end must interact with the backend to obtain EIP-712 signatures for certain operations

---

## HumanMusicDAO Contract Functions

The `humanmusic.sol` contract handles token management and stream initialization.

### `userDepositTokens`

**Contract:** `humanmusic.sol`  
**Purpose:** Allows users to deposit $HUMANMUSIC tokens into the contract. These tokens count toward the reviewer requirement and can be withdrawn at any time.

**Function Signature:**

```solidity
function userDepositTokens(uint256 _fid, uint256 _amount) external
```

**Front-End Requirements:**

1. **Token Approval**: Before depositing, users must approve the contract to spend their tokens. **For better UX, bundle the approval and deposit calls together:**
   ```javascript
   // Example flow:
   // 1. Check current allowance
   // 2. If insufficient, request approval transaction
   // 3. After approval, immediately call deposit
   // 4. Show both transactions as a single user action
   ```
2. **Balance Display**: Show:
   - User's wallet token balance
   - User's deposited token balance in the contract
   - Required tokens to become a reviewer (1000 tokens by default)
   - Progress toward reviewer status
3. **Withdrawal Option**: Provide easy access to `withdrawTokens` function
4. **Transaction Flow**:
   - User enters amount to deposit
   - Check if approval is needed
   - If needed, request approval transaction first
   - After approval, automatically trigger deposit transaction
   - Handle `TokensDeposited` event

**Important Notes:**

- Tokens must be approved before deposit (standard ERC20 pattern)
- Tokens can be withdrawn at any time via `withdrawTokens`
- Deposited tokens count toward the reviewer requirement (1000 tokens)
- Tokens are held in the contract and can be withdrawn by the user

---

### `withdrawTokens`

**Contract:** `humanmusic.sol`  
**Purpose:** Allows users to withdraw their deposited $HUMANMUSIC tokens from the contract.

**Function Signature:**

```solidity
function withdrawTokens(uint256 _fid, uint256 _amount) external
```

**Front-End Requirements:**

1. **Balance Check**: Verify user has sufficient deposited balance before allowing withdrawal
2. **User Experience**:
   - Show current deposited balance
   - Allow partial or full withdrawal
   - Handle `TokensWithdrawn` event for UI updates

**Important Notes:**

- Users can only withdraw tokens they have deposited
- Withdrawal does not affect reviewer status (tokens are still counted while deposited)

---

### `initializeStream`

**Contract:** `humanmusic.sol`  
**Purpose:** Starts the eternal stream. **This function must be called once when the stream is ready to start.**

**Function Signature:**

```solidity
function initializeStream() external
```

**Important Notes:**

- Can only be called by contract owner, not intended to be called by users
- Can only be called once
- Requires at least one approved song in the queue
- Sets the first song as currently playing
- After initialization, the stream begins its eternal cycle

---

## HumanMusicManager Contract Functions

The `HumanMusicManager.sol` contract handles user registration, submissions, voting, comments, and recommendation management.

### `registerUser`

**Contract:** `HumanMusicManager.sol`  
**Purpose:** Activates a FID and registers the `msg.sender` address to a Farcaster FID.

**Function Signature:**

```solidity
function registerUser(
    uint256 _fid,
    string memory _username,
    string memory _country,
    uint256 _deadline,
    bytes calldata _signature
) external
```

**Front-End Requirements:**

1. **FID Ownership Verification**: The front-end MUST verify that the user owns the FID before requesting a signature from the backend. This prevents FID spoofing attacks.
2. **Signature Generation**: Request an EIP-712 signature from the backend signer with:
   - `_fid`: The user's Farcaster FID
   - `userAddress`: The wallet address that will be calling the function (`msg.sender`)
   - `_deadline`: A reasonable expiration time (e.g., 1 hour from now)
3. **Transaction Flow**:
   - Verify FID ownership (via Farcaster API or client verification)
   - Request signature from backend with user's FID and wallet address
   - Call `registerUser` with the signature
   - Handle `UserRegistered` event for UI updates

**Important Notes:**

- Each FID can only be registered once
- The `msg.sender` address is automatically added as a valid address for the FID
- Registration requires a valid EIP-712 signature from the backend signer

---

### `addUserAddress`

**Contract:** `HumanMusicManager.sol`  
**Purpose:** Allows a FID owner address to associate additional addresses with their FID, enabling multiple addresses to sign transactions as the same FID.

**Function Signature:**

```solidity
function addUserAddress(uint256 _fid, address _newAddress) external
```

**Front-End Requirements:**

1. **Prerequisite Check**: The `msg.sender` MUST already be associated with the FID. Verify this before allowing the user to call this function.
2. **Address Validation**: Ensure the new address is not zero and not already registered to the FID.
3. **User Experience**:
   - Show which addresses are currently associated with the FID
   - Allow users to add new addresses (e.g., for different devices or wallets)
   - Display a warning that addresses cannot be removed once added (unless a removal function is added in the future)

**Important Notes:**

- There is currently **no way to remove an address** once it's been added to a FID
- Only addresses already associated with a FID can add new addresses
- This is useful for users who want to use multiple wallets with the same FID

---

### `addUserAddressWithSignature`

**Contract:** `HumanMusicManager.sol`  
**Purpose:** Associates a new address with a FID using an EIP-712 signature. **This is used for registering addresses to FIDs on a different Farcaster client.**

**Function Signature:**

```solidity
function addUserAddressWithSignature(
    uint256 _fid,
    address _newAddress,
    uint256 _deadline,
    bytes calldata _signature
) external
```

**Front-End Requirements:**

1. **FID Ownership Verification**: Like `registerUser`, the front-end MUST verify that the user owns the FID before requesting a signature. This prevents unauthorized address associations.
2. **Use Case**: This function is specifically for users who want to use Human Music on multiple Farcaster clients (e.g., Warpcast and another client) that use different wallet addresses.
3. **Signature Request**: Request an EIP-712 signature from the backend with:
   - `_fid`: The user's Farcaster FID
   - `_newAddress`: The new address to associate
   - `_deadline`: Signature expiration time
4. **Transaction Flow**:
   - Verify FID ownership
   - Request signature from backend
   - Call `addUserAddressWithSignature` with the signature
   - Handle `UserAddressAdded` event

**Important Notes:**

- The signature must come from the backend signer (not the user)
- This allows users to seamlessly switch between different Farcaster clients
- The new address will have full permissions for the FID once added

---

### `submitRecommendation`

**Contract:** `HumanMusicManager.sol`  
**Purpose:** Submits a YouTube video recommendation. Users submit YouTube video IDs (must be exactly 11 characters).

**Function Signature:**

```solidity
function submitRecommendation(
    string memory _youtubeVideoId,
    string memory _castHash
) external
```

**Front-End Requirements:**

1. **Validation**: Ensure YouTube video ID is exactly 11 characters
2. **Daily Limit**: Check that user hasn't already submitted today (UTC reset)
3. **User Registration**: Verify user is registered with valid FID and address
4. **Transaction Flow**:
   - Validate YouTube video ID format
   - Check daily submission limit
   - Call `submitRecommendation`
   - Handle `RecommendationSubmitted` event

**Important Notes:**

- One submission per user per day (UTC reset)
- Requires user to be registered with valid FID and address
- `_castHash` can be empty string if not submitted via cast

---

### `submitRecommendationWithDuration`

**Contract:** `HumanMusicManager.sol`  
**Purpose:** **This is the best option for submitting recommendations** as it reduces the number of transactions needed. Submits a recommendation with duration included in a single transaction.

**Function Signature:**

```solidity
function submitRecommendationWithDuration(
    string memory _youtubeVideoId,
    string memory _castHash,
    uint256 _duration,
    uint256 _deadline,
    bytes calldata _signature
) external
```

**Front-End Requirements:**

1. **Video Verification**: **Before the miniapp provides a signature, it should verify:**
   - Playback is enabled on YouTube (critical for the stream to actually play)
   - The video exists and is accessible
   - The video duration fits within requirements (1-600 seconds typically)
   - Any other parameters are met
2. **Backend Integration**: The backend should:
   - Query YouTube API to get actual video duration
   - Verify embed permissions and playback availability
   - Generate EIP-712 signature with verified duration
3. **User Experience**:
   - Show verification status before submission
   - Display video information (title, duration, thumbnail)
   - Handle `RecommendationSubmitted` event
   - Show that duration is already set (no need for separate duration call)

**Important Notes:**

- **This is the recommended submission method** as it combines submission and duration setting in one transaction
- Duration must be verified by backend before signature generation
- Signature must come from backend signer
- Reduces gas costs and improves UX compared to separate `submitRecommendation` + `setVideoDuration` calls

---

### `voteOnRecommendation`

**Contract:** `HumanMusicManager.sol`  
**Purpose:** Allows users to upvote or downvote submissions.

**Function Signature:**

```solidity
function voteOnRecommendation(
    uint256 _recommendationId,
    bool _isUpvote
) external
```

**Front-End Requirements:**

1. **Voting Rules**: Enforce:
   - Users cannot vote on their own submissions
   - One vote per user per recommendation
   - Voting period restrictions (if applicable)
2. **User Experience**:
   - Show current vote counts (upvotes/downvotes)
   - Display user's current vote (if any)
   - Allow vote change (upvote to downvote or vice versa)
   - Handle `VoteCast` event
   - Show auto-approval status when threshold is reached

**Important Notes:**

- Users can upvote or downvote submissions
- Voting period is 24 hours (configurable)
- Auto-approval when threshold is reached (3 upvotes by default)
- Users cannot vote on their own submissions

---

### `approveRecommendation`

**Contract:** `HumanMusicManager.sol`  
**Purpose:** Allows reviewers to bypass the voting process and automatically approve a song.

**Function Signature:**

```solidity
function approveRecommendation(uint256 _recommendationId, uint256 _reviewerFid) external
```

**Front-End Requirements:**

1. **Reviewer Status Check**: Verify the user is a reviewer before showing this option
2. **Duration Check**: Ensure the recommendation has a duration set (it cannot be approved without one)
3. **UI Considerations**:
   - Show reviewer-only interface for pending recommendations
   - Display recommendation details (submitter, video ID, votes, etc.)
   - Allow reviewers to approve or reject submissions
   - Show which recommendations are eligible for approval (have duration set)

**Important Notes:**

- Only users with reviewer status can call this function
- Reviewers must have sufficient tokens and reputation (see `userDepositTokens` and `autoGrantReviewerRole`)
- Approval immediately adds the song to the queue (if duration is set)
- This bypasses the normal voting threshold

---

### `rejectRecommendation`

**Contract:** `HumanMusicManager.sol`  
**Purpose:** Allows reviewers to reject submissions that don't meet quality standards.

**Function Signature:**

```solidity
function rejectRecommendation(uint256 _recommendationId, uint256 _reviewerFid) external
```

**Front-End Requirements:**

1. **Reviewer Status Check**: Verify the user is a reviewer before showing this option
2. **User Experience**:
   - Show reviewer-only interface
   - Allow reviewers to reject submissions
   - Handle `RecommendationRejected` event
   - Show rejected recommendations separately

**Important Notes:**

- Only reviewers can reject recommendations
- Rejection allows immediate resubmission (unlike bans)
- Use rejection for quality issues, not policy violations

---

### `updateSystem`

**Contract:** `HumanMusicManager.sol`  
**Purpose:** Maintains the eternal stream by processing time gaps. Anyone who has submitted a song can call this.

**Function Signature:**

```solidity
function updateSystem() external
```

**Front-End Requirements:**

1. **Caller Verification**: Verify caller has submitted at least one song
2. **User Experience**:
   - Show when last update occurred
   - Display time since last update
   - Allow users to trigger update
   - Handle `SystemUpdated` event
   - Show rewards distributed to caller

**Important Notes:**

- Maintains the eternal stream by processing time gaps
- Anyone who has submitted a song can call this
- Rewards the caller for maintaining stream continuity
- Processes songs that should have played during time gaps

---

### `addComment`

**Contract:** `HumanMusicManager.sol`  
**Purpose:** Allows users to add comments to recommendations.

**Function Signature:**

```solidity
function addComment(
    uint256 _recommendationId,
    string memory _content
) external
```

**Front-End Requirements:**

1. **User Registration**: Verify user is registered
2. **Content Validation**: Ensure comment content is not empty and meets length requirements
3. **User Experience**:
   - Show comment input field for each recommendation
   - Display existing comments with timestamps
   - Handle comment submission
   - Show commenter's username/FID

**Important Notes:**

- Users must be registered to comment
- Comments are associated with recommendations
- Comments can be used for community discussion and feedback

---

### EIP-712 Signature Requirements

The contracts use EIP-712 for secure off-chain message signing. Front-ends need to:

1. **Get Domain Info**: Call `getDomainInfo()` on the Manager contract to get the domain separator and chain information
2. **Request Signatures**: For functions requiring signatures, request them from the backend:
   - `registerUser`: Backend signs FID + user address
   - `addUserAddressWithSignature`: Backend signs FID + new address
   - `submitRecommendationWithDuration`: Backend signs YouTube video ID + duration (after YouTube API verification and playback verification)
3. **Signature Expiration**: All signatures have deadlines - ensure they're used before expiration

---

### Events to Monitor

Front-ends should listen for these events for real-time updates:

**From HumanMusicDAO (`humanmusic.sol`):**

- `StreamInitialized`: Eternal stream started
- `TokensDeposited`: User deposited tokens
- `TokensWithdrawn`: User withdrew tokens
- `RecommendationTransitioned`: Song moved between states (PAST/PRESENT/FUTURE)
- `SystemUpdated`: Stream updated (time gap processed)

**From HumanMusicManager (`HumanMusicManager.sol`):**

- `UserRegistered`: New user registration
- `UserAddressAdded`: New address associated with FID
- `RecommendationSubmitted`: New song submission
- `VoteCast`: User voted on a recommendation
- `RecommendationApproved`: Song approved (via vote or reviewer)
- `RecommendationRejected`: Song rejected by reviewer
- `RecommendationBanned`: Song banned by owner
- `CommentAdded`: User added a comment to a recommendation

---

### Security Considerations

1. **FID Verification**: Always verify FID ownership before requesting signatures
2. **Signature Expiration**: Check signature deadlines before submitting transactions
3. **Address Validation**: Verify addresses are not zero before submission
4. **Token Approvals**: Use proper approval patterns (check allowance, request approval if needed)
5. **Video Verification**: Before requesting signatures for `submitRecommendationWithDuration`, verify YouTube playback is enabled and video is accessible
6. **Contract Addresses**: Always verify you're interacting with the correct contract addresses
7. **Reentrancy**: Both contracts use ReentrancyGuard, but front-ends should still follow best practices
8. **Manager Contract**: The Manager contract delegates to the DAO contract - ensure you're calling functions on the correct contract

---

### Testing

The contract includes comprehensive test suites:

- `Deployment.t.sol`: Constructor and deployment tests
- `UnitTests.t.sol`: Individual function tests
- `IntegrationTests.t.sol`: End-to-end flow tests

Run tests with:

```bash
forge test
```

---

## Development

### Build

```bash
forge build
```

### Test

```bash
forge test
```

### Deploy

See `script/README.md` for deployment instructions across multiple chains.

### Verify

```bash
source .env && forge verify-contract --chain-id 8453 --num-of-optimiza
tions 200 --watch --constructor-args 0000000000000000000000003e853062407a32c5f5e06be8d36dbce6b7c4da03 --verifier etherscan --etherscan-api-key ${ETHERSCAN_API_KEY} --rpc-url ${BASE_MAINNET_RPC} <contract address > src/humanmusic.sol:HumanMusicDAO
```

---

## License

MIT
