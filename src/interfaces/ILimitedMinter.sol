// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ILimitedMinter {
    // Minting
    function mint(address account, uint256 amount) external;

    // Token registration
    function registerToken(address token, address mintDestination, uint256 dailyMintLimit) external;
    function unregisterToken(address token) external;
    function updateDailyMintLimit(address token, uint256 newLimit) external;
    function updateMintDestination(address token, address newDestination) external;

    // View functions
    function tokenConfigs(address token) external view returns (address mintDestination, uint256 dailyLimit, bool isActive);
    function mintedToday(address token) external view returns (uint256);
    function mintedPerDay(address token, uint256 day) external view returns (uint256);

    // Roles
    function DEFAULT_ADMIN_ROLE() external pure returns (bytes32);
    function MINTER_ROLE() external pure returns (bytes32);
    function hasRole(bytes32 role, address account) external view returns (bool);

    // Lifecycle
    function pause() external;
    function unpause() external;
    function paused() external view returns (bool);
}
