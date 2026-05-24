// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBridgeDeposit {
    // Core bridge functions
    function depositForBridge(address token, uint256 amount, uint256 routeId, address to, bytes32 depositId) external;
    function fulfillBridgeMint(address token, address to, uint256 amount, uint256 routeId, bytes32 depositId, uint256 timestamp) external;

    // Configuration
    function setBridgeRoutes(address token, uint256[] calldata routeIds, bool enabled, uint256 fee) external;
    function updateRouteFee(address token, uint256 routeId, uint256 fee) external;
    function updateLimitedMinter(address newMinter) external;
    function setFeeCollector(address newCollector) external;

    // View functions
    function bridgeFulfilled(bytes32 depositId) external view returns (uint256);
    function nextDepositId() external view returns (uint256);
    function routeConfigs(address token, uint256 routeId) external view returns (bool enabled, uint256 fee);
    function totalBurnedTo(address token, uint256 routeId) external view returns (uint256);
    function totalMintedFrom(address token, uint256 routeId) external view returns (uint256);
    function remainingMintCapacity(address token) external view returns (uint256);
    function limitedMinter() external view returns (address);
    function feeCollector() external view returns (address);

    // Rescue
    function rescueTokens(address token, address to, uint256 amount) external;

    // Roles
    function DEFAULT_ADMIN_ROLE() external pure returns (bytes32);
    function BRIDGE_OPERATOR_ROLE() external pure returns (bytes32);
    function FEE_MANAGER_ROLE() external pure returns (bytes32);
    function hasRole(bytes32 role, address account) external view returns (bool);

    // Lifecycle
    function pause() external;
    function unpause() external;
    function paused() external view returns (bool);
}
