# Deployment Scripts

This directory contains deployment scripts for the HumanMusicDAO contract.

## Files

- `Deploy.s.sol` - Main deployment script that supports multiple chains
- `DeployHelper.sol` - Helper library for deployment operations (optional)
- `DeploySignatureHelper.s.sol` - Deployment script for SignatureHelper contract (for local signature generation)

## Supported Chains

1. **Anvil (Local Testing)** - Chain ID: 31337
   - Automatically deploys a mock ERC20 token before deploying the DAO
2. **Base Mainnet** - Chain ID: 8453

   - Requires token address to be set in script

3. **Base Sepolia (Testnet)** - Chain ID: 84532

   - Requires token address to be set in script

4. **Ethereum Mainnet** - Chain ID: 1
   - Requires token address to be set in script

## Setup

### 1. Configure Token Addresses

Before deploying to mainnet/testnet chains, update the token addresses in `Deploy.s.sol`:

```solidity
address private constant BASE_MAINNET_TOKEN = address(0x...); // Your token address
address private constant BASE_SEPOLIA_TOKEN = address(0x...); // Your token address
address private constant ETHEREUM_MAINNET_TOKEN = address(0x...); // Your token address
```

### 2. Set Up Environment Variables

Create a `.env` file in the project root (optional, for private keys):

```bash
PRIVATE_KEY=your_private_key_here
RPC_URL_ANVIL=http://localhost:8545
RPC_URL_BASE=https://mainnet.base.org
RPC_URL_BASE_SEPOLIA=https://sepolia.base.org
RPC_URL_ETHEREUM=https://eth.llamarpc.com
```

**⚠️ Security Note:** Never commit your `.env` file to version control. Add it to `.gitignore`.

## Usage

### Deploy to Anvil (Local)

1. Start Anvil in a separate terminal:

   ```bash
   anvil
   ```

2. Deploy using Foundry:

   ```bash
   forge script script/Deploy.s.sol:Deploy --rpc-url http://localhost:8545 --broadcast --verify -vvvv
   ```

   The script will automatically:

   - Detect Anvil (chain ID 31337)
   - Deploy a mock HumanMusicToken
   - Deploy HumanMusicDAO with the token address

### Deploy to Base Sepolia (Testnet)

```bash
forge script script/Deploy.s.sol:Deploy \
  --rpc-url $RPC_URL_BASE_SEPOLIA \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  -vvvv
```

### Deploy to Base Mainnet

```bash
  forge script script/Deploy.s.sol:Deploy --rpc-url ${BASE_MAINNET_RPC} --broadcast --verify --etherscan-api-key ${ETHERSCAN_API_KEY} --account deployer -vvvv
```

### Deploy to Ethereum Mainnet

```bash
forge script script/Deploy.s.sol:Deploy \
  --rpc-url $RPC_URL_ETHEREUM \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --slow \
  -vvvv
```

## Deployment Output

After deployment, the script will:

1. Log deployment addresses to the console
2. Save deployment information to `deployments/{chain-name}.json`

Example output file (`deployments/anvil.json`):

```json
{
  "tokenAddress": "0x...",
  "daoAddress": "0x...",
  "chainId": 31337,
  "chainName": "anvil",
  "deployedAt": "1234567890"
}
```

## Verification

After deployment, you can verify the contracts on block explorers:

- Base: https://basescan.org
- Base Sepolia: https://sepolia.basescan.org
- Ethereum: https://etherscan.io

Add the `--verify` flag to automatically verify contracts on block explorers (requires `ETHERSCAN_API_KEY` in your `.env`).

## SignatureHelper Deployment

The `SignatureHelper` contract is used to generate EIP-712 registration signatures locally for testing purposes.

### Deploy SignatureHelper to Anvil

1. Start Anvil in a separate terminal:

   ```bash
   anvil
   ```

2. Deploy the SignatureHelper contract:

   ```bash
   forge script script/DeploySignatureHelper.s.sol:DeploySignatureHelper \
     --rpc-url http://localhost:8545 \
     --broadcast \
     -vvvv
   ```

   The script will:

   - Deploy the SignatureHelper contract
   - Display the domain separator and contract info
   - Generate an example registration signature

### Generate Registration Signatures

After deployment, you can generate signatures using the script. The script uses Foundry's `vm.sign()` to create EIP-712 signatures.

**Example: Generate a signature with custom parameters**

You can modify the script's `run()` function or create a custom script that calls `generateSignature()`:

```solidity
// In your script
bytes memory signature = deploySignatureHelper.generateSignature(
    fid,           // uint256 - Farcaster ID
    userAddress,   // address - User's Ethereum address
    deadline       // uint256 - Signature deadline (unix timestamp)
);
```

**Using environment variables:**

You can set a custom private key via environment variable:

```bash
PRIVATE_KEY=0x... forge script script/DeploySignatureHelper.s.sol:DeploySignatureHelper \
  --rpc-url http://localhost:8545 \
  --broadcast \
  -vvvv
```

**Default signer:** The script uses Anvil's first account by default (`0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`).

### Signature Format

The generated signature is returned as a hex string in the format: `r || s || v` (65 bytes total), which can be directly used in your application.

Example output:

```
==========================================
SIGNATURE GENERATED:
==========================================
Hex: 0x1234567890abcdef...
==========================================
```

## Notes

- For Anvil deployments, a mock token is automatically created
- For mainnet/testnet deployments, you must have the token contract already deployed
- The script uses `vm.broadcast()` which requires the `--broadcast` flag
- Make sure you have enough native tokens (ETH) for gas fees on the target chain
- **Note:** The `SignatureHelper` contract's `generateRegistrationSignature()` function has an issue - it uses `ECDSA.tryRecover()` incorrectly. The deployment script uses `vm.sign()` which is the correct way to generate signatures in Foundry.
