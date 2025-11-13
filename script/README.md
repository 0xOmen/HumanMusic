# Deployment Scripts

This directory contains deployment scripts for the HumanMusicDAO contract.

## Files

- `Deploy.s.sol` - Main deployment script that supports multiple chains
- `DeployHelper.sol` - Helper library for deployment operations (optional)

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

## Notes

- For Anvil deployments, a mock token is automatically created
- For mainnet/testnet deployments, you must have the token contract already deployed
- The script uses `vm.broadcast()` which requires the `--broadcast` flag
- Make sure you have enough native tokens (ETH) for gas fees on the target chain
