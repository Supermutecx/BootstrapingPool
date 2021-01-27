// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.0;

// Imports

import "./BootstrapingPool.sol";

// Contracts

contract CRPFactory {
    // State variables

    // Keep a list of all Configurable Rights Pools
    mapping(address=>bool) private _isCrp;

    // Event declarations

    // Log the address of each new smart pool, and its creator
    event LogNewCrp(
        address indexed caller,
        address indexed pool
    );

    // Function declarations

    function newCrp(
        address factoryAddress,
        BootstrapingPool.PoolParams calldata poolParams,
        RightsManager.Rights calldata rights
    )
        external
        returns (BootstrapingPool)
    {
        require(poolParams.constituentTokens.length >= BalancerConstants.MIN_ASSET_LIMIT, "ERR_TOO_FEW_TOKENS");

        // Arrays must be parallel
        require(poolParams.tokenBalances.length == poolParams.constituentTokens.length, "ERR_START_BALANCES_MISMATCH");
        require(poolParams.tokenWeights.length == poolParams.constituentTokens.length, "ERR_START_WEIGHTS_MISMATCH");

        BootstrapingPool crp = new BootstrapingPool(
            factoryAddress,
            poolParams,
            rights
        );

        emit LogNewCrp(msg.sender, address(crp));

        _isCrp[address(crp)] = true;
        // The caller is the controller of the CRP
        // The CRP will be the controller of the underlying Core BPool
        crp.transferOwnership(msg.sender);

        return crp;
    }

    function isCrp(address addr) external view returns (bool) {
        return _isCrp[addr];
    }
}
