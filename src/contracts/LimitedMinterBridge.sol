// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title LimitedMinterBridge
 * @notice Enforces daily minting limits for multiple LatamStable tokens, but allows
 *         minting directly to arbitrary destinations (no fixed mintDestination).
 * @dev
 *  - Token admins (DEFAULT_ADMIN_ROLE on the token) can register/unregister tokens
 *    and set daily limits.
 *  - Only addresses with MINTER_ROLE in this contract can request mints.
 *  - The contract itself must have MINTER_ROLE on each LatamStable token it mints.
 *  - Days are measured in UTC using Unix time (00:00 UTC boundaries).
 *  - Includes ReentrancyGuard and Pausable for extra safety.
 */

import "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

interface ILatamStableToken {
    function hasRole(bytes32 role, address account) external view returns (bool);
    function DEFAULT_ADMIN_ROLE() external pure returns (bytes32);
    function mint(address to, uint256 amount) external;
}

contract LimitedMinterBridge is AccessControlEnumerable, ReentrancyGuard, Pausable {
    /// @notice Role that allows minting through this contract
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /**
     * @notice Configuration for each registered token
     * @param dailyMaxMint Maximum amount that can be minted per day (in token's smallest unit)
     * @param exists Whether the token is registered
     */
    struct TokenConfig {
        uint256 dailyMaxMint;
        bool exists;
    }

    /// @notice Maps token address to its configuration
    mapping(address => TokenConfig) public tokenConfigs;

    /// @notice Maps (token, day) to amount minted on that day
    /// @dev This mapping persists even if a token is unregistered and re-registered
    mapping(address => mapping(uint256 => uint256)) public mintedPerDay;

    /// @notice Emitted when a token is registered
    event TokenRegistered(address indexed token, uint256 dailyMaxMint);
    /// @notice Emitted when a token is unregistered
    event TokenUnregistered(address indexed token);
    /// @notice Emitted when a token's daily mint limit is updated
    event DailyMintLimitUpdated(address indexed token, uint256 newLimit);
    /// @notice Emitted when tokens are minted
    event Minted(address indexed token, address indexed minter, address indexed to, uint256 amount);

    /// @notice Custom errors
    error NotExternalAdmin();
    error TokenNotRegistered();
    error InvalidTokenAddress();
    error TokenAlreadyRegistered();
    error MintAmountZero();
    error ExceedsDailyMintLimit();
    error InvalidRecipient();

    /**
     * @notice Constructor that sets up roles
     * @param defaultAdmin Address to receive the DEFAULT_ADMIN_ROLE
     * @param minter Address to receive the MINTER_ROLE (e.g. your bridge/orchestrator)
     */
    constructor(address defaultAdmin, address minter) {
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(MINTER_ROLE, minter);
    }

    /**
     * @notice Ensures caller is an admin of the external token
     * @param token Address of the token to check admin rights for
     */
    modifier onlyExternalAdmin(address token) {
        if (!ILatamStableToken(token).hasRole(ILatamStableToken(token).DEFAULT_ADMIN_ROLE(), msg.sender)) {
            revert NotExternalAdmin();
        }
        _;
    }

    /**
     * @notice Ensures the token is registered
     * @param token Address of the token to check
     */
    modifier tokenExists(address token) {
        if (!tokenConfigs[token].exists) {
            revert TokenNotRegistered();
        }
        _;
    }

    // -------------------------------------------------------------------------
    // Admin: token registration / configuration
    // -------------------------------------------------------------------------

    /**
     * @notice Registers a token with a daily mint limit
     * @dev Only callable by an admin (DEFAULT_ADMIN_ROLE) of the token
     * @param token Address of the token to register
     * @param dailyMaxMint Maximum amount that can be minted per day for this token
     */
    function registerToken(
        address token,
        uint256 dailyMaxMint
    ) external onlyExternalAdmin(token) {
        if (token == address(0)) revert InvalidTokenAddress();
        if (tokenConfigs[token].exists) revert TokenAlreadyRegistered();

        tokenConfigs[token] = TokenConfig({
            dailyMaxMint: dailyMaxMint,
            exists: true
        });

        emit TokenRegistered(token, dailyMaxMint);
    }

    /**
     * @notice Unregisters a token
     * @dev Only callable by an admin of the token being unregistered
     * @param token Address of the token to unregister
     */
    function unregisterToken(address token)
        external
        onlyExternalAdmin(token)
        tokenExists(token)
    {
        delete tokenConfigs[token];
        emit TokenUnregistered(token);
    }

    /**
     * @notice Updates the daily mint limit for a token
     * @dev Only callable by an admin of the token
     * @param token Address of the token
     * @param newLimit New daily mint limit
     */
    function updateDailyMintLimit(address token, uint256 newLimit)
        external
        onlyExternalAdmin(token)
        tokenExists(token)
    {
        tokenConfigs[token].dailyMaxMint = newLimit;
        emit DailyMintLimitUpdated(token, newLimit);
    }

    // -------------------------------------------------------------------------
    // Admin: pause / unpause
    // -------------------------------------------------------------------------

    /**
     * @notice Pauses all minting operations
     * @dev Only callable by addresses with DEFAULT_ADMIN_ROLE
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpauses all minting operations
     * @dev Only callable by addresses with DEFAULT_ADMIN_ROLE
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // -------------------------------------------------------------------------
    // Minting
    // -------------------------------------------------------------------------

    /**
     * @notice Mints tokens to an arbitrary recipient, enforcing the daily mint cap
     * @dev
     *  - Caller must have MINTER_ROLE in this contract.
     *  - This contract must have MINTER_ROLE on the token.
     *  - Reverts if the daily limit would be exceeded.
     * @param token Address of the token to mint
     * @param to Recipient address
     * @param mintAmount Amount to mint (in token's smallest unit)
     */
    function mintTo(address token, address to, uint256 mintAmount)
        external
        onlyRole(MINTER_ROLE)
        tokenExists(token)
        nonReentrant
        whenNotPaused
    {
        if (mintAmount == 0) revert MintAmountZero();
        if (to == address(0)) revert InvalidRecipient();

        TokenConfig storage config = tokenConfigs[token];
        uint256 currentDay = block.timestamp / 1 days;
        uint256 alreadyMinted = mintedPerDay[token][currentDay];

        if (alreadyMinted + mintAmount > config.dailyMaxMint) {
            revert ExceedsDailyMintLimit();
        }

        mintedPerDay[token][currentDay] = alreadyMinted + mintAmount;

        // Mint directly to the final recipient (no hot wallet / extra transfer)
        ILatamStableToken(token).mint(to, mintAmount);

        emit Minted(token, msg.sender, to, mintAmount);
    }

    /**
     * @notice Returns the amount minted today for a token
     * @dev Reverts if the token is not registered
     * @param token Address of the token
     * @return Amount minted today
     */
    function mintedToday(address token)
        external
        view
        tokenExists(token)
        returns (uint256)
    {
        uint256 currentDay = block.timestamp / 1 days;
        return mintedPerDay[token][currentDay];
    }
}


