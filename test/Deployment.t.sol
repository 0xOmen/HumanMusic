// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {HumanMusicDAO} from "../src/humanmusic.sol";
import {HumanMusicToken} from "../src/mocks/HumanMusicToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title DeploymentTest
 * @notice Tests for HumanMusicDAO contract deployment and constructor initialization
 */
contract DeploymentTest is Test {
    HumanMusicDAO public dao;
    HumanMusicToken public token;
    address public deployer;
    address public owner;

    // EIP-712 constants
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    event UserRegistered(uint256 indexed fid, string username, string country, address indexed registeredAddress);

    function setUp() public {
        // Set up deployer/owner
        deployer = address(this);
        owner = deployer;

        // Deploy mock token
        token = new HumanMusicToken();

        // Deploy DAO
        dao = new HumanMusicDAO(address(token));
    }

    /**
     * @notice Test that the contract owner is correctly set
     */
    function test_Constructor_SetsOwner() public view {
        assertEq(dao.owner(), owner, "Owner should be set to deployer");
    }

    /**
     * @notice Test that the humanMusicToken address is correctly set
     */
    function test_Constructor_SetsHumanMusicToken() public view {
        assertEq(address(dao.humanMusicToken()), address(token), "Token address should match deployed token");

        // Verify it's actually an IERC20 interface by checking the token contract
        assertEq(token.name(), "HumanMusic", "Token name should be HumanMusic");
        assertEq(token.symbol(), "HUMANMUSIC", "Token symbol should be HUMANMUSIC");
    }

    /**
     * @notice Test that the backendSigner is correctly set to the owner
     */
    function test_Constructor_SetsBackendSigner() public view {
        assertEq(dao.backendSigner(), owner, "Backend signer should be set to owner/deployer");
        assertEq(dao.getBackendSigner(), owner, "getBackendSigner() should return owner");
    }

    /**
     * @notice Test that the DOMAIN_SEPARATOR is correctly computed
     */
    function test_Constructor_SetsDomainSeparator() public view {
        // Get domain info from the contract
        (bytes32 domain, string memory name, string memory version, uint256 chainId, address verifyingContract) =
            dao.getDomainInfo();

        // Verify domain name
        assertEq(name, "HumanMusicDAO", "Domain name should be HumanMusicDAO");
        assertEq(version, "1", "Domain version should be 1");
        assertEq(chainId, block.chainid, "Chain ID should match current chain");
        assertEq(verifyingContract, address(dao), "Verifying contract should be DAO address");

        // Compute expected domain separator
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256("HumanMusicDAO"), // name
                keccak256("1"), // version
                block.chainid, // chainId
                address(dao) // verifyingContract
            )
        );

        // Verify the domain separator matches
        assertEq(domain, expectedDomainSeparator, "Domain separator should match computed value");
    }

    /**
     * @notice Test that all constructor parameters are set correctly together
     */
    function test_Constructor_SetsAllParameters() public view {
        // Test owner
        assertEq(dao.owner(), owner, "Owner should be set");

        // Test token
        assertEq(address(dao.humanMusicToken()), address(token), "Token should be set");

        // Test backend signer
        assertEq(dao.backendSigner(), owner, "Backend signer should be set to owner");

        // Test domain separator
        (bytes32 domain,,, uint256 chainId, address verifyingContract) = dao.getDomainInfo();
        assertEq(verifyingContract, address(dao), "Domain verifying contract should be DAO");
        assertEq(chainId, block.chainid, "Domain chain ID should match current chain");
        assertNotEq(domain, bytes32(0), "Domain separator should not be zero");
    }

    /**
     * @notice Test that the contract can be deployed with zero token address
     * @dev Note: The contract doesn't check for zero address in constructor
     * This test verifies the current behavior (allows zero address)
     */
    function test_Constructor_AllowsZeroTokenAddress() public {
        // The contract doesn't revert on zero address, so we verify it deploys
        HumanMusicDAO daoZero = new HumanMusicDAO(address(0));
        assertEq(address(daoZero.humanMusicToken()), address(0), "Token address should be zero");
        assertNotEq(address(daoZero), address(0), "DAO should still be deployed");
    }

    /**
     * @notice Test that the contract can be deployed with a valid token address
     */
    function test_Constructor_DeploysWithValidToken() public {
        // Create a new token for this test
        HumanMusicToken newToken = new HumanMusicToken();

        // Deploy DAO with the new token
        HumanMusicDAO newDao = new HumanMusicDAO(address(newToken));

        // Verify it was deployed successfully
        assertEq(address(newDao.humanMusicToken()), address(newToken), "DAO should use the new token");
        assertNotEq(address(newDao), address(0), "DAO address should not be zero");
    }

    /**
     * @notice Test that the contract initializes correctly with different deployers
     */
    function test_Constructor_DifferentDeployer() public {
        // Create a new deployer
        address newDeployer = address(0x1234);
        vm.prank(newDeployer);

        // Deploy new token
        HumanMusicToken newToken = new HumanMusicToken();

        // Deploy DAO from new deployer
        vm.prank(newDeployer);
        HumanMusicDAO newDao = new HumanMusicDAO(address(newToken));

        // Verify owner and backend signer are set to new deployer
        assertEq(newDao.owner(), newDeployer, "Owner should be new deployer");
        assertEq(newDao.backendSigner(), newDeployer, "Backend signer should be new deployer");
        assertEq(address(newDao.humanMusicToken()), address(newToken), "Token should be set correctly");
    }

    /**
     * @notice Test that lastUpdateTime is set to block.timestamp
     */
    function test_Constructor_SetsLastUpdateTime() public view {
        // Get current timestamp
        uint256 currentTimestamp = block.timestamp;
        assertEq(dao.lastUpdateTime(), currentTimestamp, "Last update time should be set to current timestamp");
    }

    /**
     * @notice Test that the domain separator is unique per contract address
     */
    function test_DomainSeparator_UniquePerContract() public {
        // Deploy two DAOs on the same chain
        HumanMusicToken token2 = new HumanMusicToken();
        HumanMusicDAO dao2 = new HumanMusicDAO(address(token2));

        (bytes32 domain1,,, uint256 chainId1, address contract1) = dao.getDomainInfo();
        (bytes32 domain2,,, uint256 chainId2, address contract2) = dao2.getDomainInfo();

        // Domain separators should be different due to different contract addresses
        assertNotEq(domain1, domain2, "Domain separators should differ for different contracts");
        assertEq(chainId1, chainId2, "Chain IDs should be the same");
        assertNotEq(contract1, contract2, "Contract addresses should differ");
    }
}
