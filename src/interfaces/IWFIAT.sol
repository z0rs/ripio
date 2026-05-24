// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IWFIAT {
    // ERC-20
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function totalSupply() external view returns (uint256);
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);

    // EIP-2612 Permit
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    function nonces(address owner) external view returns (uint256);
    function eip712Domain() external view returns (bytes1 fields, string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] memory extensions);

    // Burn
    function burnFrom(address account, uint256 value) external;

    // AccessControl
    function hasRole(bytes32 role, address account) external view returns (bool);
    function getRoleAdmin(bytes32 role) external view returns (bytes32);
    function grantRole(bytes32 role, address account) external;
    function revokeRole(bytes32 role, address account) external;
    function renounceRole(bytes32 role, address callerConfirmation) external;
    function getRoleMemberCount(bytes32 role) external view returns (uint256);
    function getRoleMember(bytes32 role, uint256 index) external view returns (address);
    function getRoleMembers(bytes32 role) external view returns (address[] memory);

    // Roles
    function DEFAULT_ADMIN_ROLE() external pure returns (bytes32);
    function MINTER_ROLE() external pure returns (bytes32);
    function PAUSER_ROLE() external pure returns (bytes32);
    function UPGRADER_ROLE() external pure returns (bytes32);

    // UUPS
    function UPGRADE_INTERFACE_VERSION() external pure returns (string memory);

    // Initialization
    function initialize(address defaultAdmin, address pauser, address minter, address upgrader, string memory name_, string memory symbol_) external;
}
