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

This section provides detailed specifications for front-end developers integrating with the HumanMusicDAO smart contract.

### Prerequisites

- Users must have a Farcaster FID (Farcaster ID)
- Users need a Web3 wallet (MetaMask, WalletConnect, etc.)
- The front-end must interact with the backend to obtain EIP-712 signatures for certain operations

### Core User Functions

#### `registerUser`

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

#### `addUserAddress`

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

#### `addUserAddressWithSignature`

**Purpose:** Associates a new address with a FID using an EIP-712 signature. This is designed for different Farcaster clients that use different wallet addresses for the same FID.

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

#### `setVideoDuration`

**Purpose:** Critical gatekeeper function that sets the duration of a submitted video. **A video cannot be approved to enter the song queue until its duration is set.**

**Function Signature:**

```solidity
function setVideoDuration(
    uint256 _recommendationId,
    uint256 _duration,
    uint256 _deadline,
    bytes calldata _signature
) external
```

**Front-End Requirements:**

1. **Video Verification**: Before requesting a signature, the front-end should verify:
   - The video exists on YouTube
   - The video duration fits within requirements (1-600 seconds)
   - The video has **embed playback enabled** (critical for the stream to actually play)
   - The video is accessible and playable
2. **Backend Integration**: The backend should:
   - Query YouTube API to get actual video duration
   - Verify embed permissions
   - Generate EIP-712 signature with verified duration
3. **User Experience**:
   - Show pending recommendations waiting for duration verification
   - Display status: "Waiting for duration verification" vs "Duration set"
   - Allow users to see which of their submissions are pending duration

**Important Notes:**

- Duration can only be set once per recommendation
- Duration must be between 1 and 600 seconds
- Only the backend signer can create valid signatures
- Without duration, a recommendation cannot be approved (even by reviewers)

---

#### `approveRecommendation`

**Purpose:** Allows reviewers to bypass the voting process and automatically approve a song, provided the duration has been set.

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

#### `userDepositTokens`

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

#### `banRecommendation`

**Purpose:** Allows the contract owner to ban certain submissions if they are spam, unplayable, or have other issues.

**Function Signature:**

```solidity
function banRecommendation(uint256 _recommendationId) external onlyOwner
```

**Front-End Requirements:**

1. **Owner-Only Interface**: This should only be accessible to the contract owner
2. **Ban vs Reject Distinction**:
   - **Ban**: Permanent removal, can only be reversed by owner via `unbanRecommendation`
   - **Reject**: Temporary removal via `rejectRecommendation`, allows immediate resubmission
3. **UI Considerations**:
   - Show banned recommendations separately
   - Allow owner to unban if needed
   - Display reason for ban (if stored off-chain)
   - Show which recommendations have been banned vs rejected

**Important Notes:**

- Only the contract owner can ban recommendations
- Bans can only be reversed by the owner (via `unbanRecommendation`)
- Unlike `rejectRecommendation`, bans prevent immediate resubmission
- Use bans for serious issues (spam, unplayable content, policy violations)

---

### Additional Important Functions

#### `submitRecommendation`

- Users submit YouTube video IDs (must be exactly 11 characters)
- One submission per user per day (UTC reset)
- Requires user to be registered with valid FID and address

#### `voteOnRecommendation`

- Users can upvote or downvote submissions
- Voting period is 24 hours (configurable)
- Auto-approval when threshold is reached (3 upvotes by default)
- Users cannot vote on their own submissions

#### `updateSystem`

- Maintains the eternal stream by processing time gaps
- Anyone who has submitted a song can call this
- Rewards the caller for maintaining stream continuity
- Processes songs that should have played during time gaps

#### `initializeStream`

- Starts the eternal stream
- Requires at least one approved song in the queue
- Sets the first song as currently playing
- Can only be called once

---

### EIP-712 Signature Requirements

The contract uses EIP-712 for secure off-chain message signing. Front-ends need to:

1. **Get Domain Info**: Call `getDomainInfo()` to get the domain separator and chain information
2. **Request Signatures**: For functions requiring signatures, request them from the backend:
   - `registerUser`: Backend signs FID + user address
   - `addUserAddressWithSignature`: Backend signs FID + new address
   - `setVideoDuration`: Backend signs recommendation ID + duration (after YouTube API verification)
3. **Signature Expiration**: All signatures have deadlines - ensure they're used before expiration

---

### Events to Monitor

Front-ends should listen for these events for real-time updates:

- `UserRegistered`: New user registration
- `UserAddressAdded`: New address associated with FID
- `RecommendationSubmitted`: New song submission
- `VoteCast`: User voted on a recommendation
- `RecommendationApproved`: Song approved (via vote or reviewer)
- `RecommendationRejected`: Song rejected by reviewer
- `RecommendationBanned`: Song banned by owner
- `StreamInitialized`: Eternal stream started
- `RecommendationTransitioned`: Song moved between states (PAST/PRESENT/FUTURE)
- `SystemUpdated`: Stream updated (time gap processed)
- `TokensDeposited`: User deposited tokens
- `TokensWithdrawn`: User withdrew tokens
- `DurationSet`: Video duration was set

---

### Security Considerations

1. **FID Verification**: Always verify FID ownership before requesting signatures
2. **Signature Expiration**: Check signature deadlines before submitting transactions
3. **Address Validation**: Verify addresses are not zero before submission
4. **Token Approvals**: Use proper approval patterns (check allowance, request approval if needed)
5. **Reentrancy**: The contract uses ReentrancyGuard, but front-ends should still follow best practices

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
