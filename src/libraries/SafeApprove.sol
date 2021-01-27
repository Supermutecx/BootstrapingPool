// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.0;

// Imports

import "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

// Libraries
library SafeApprove {

    function safeApprove(IERC20 token, address spender, uint amount) internal returns (bool) {
        uint currentAllowance = token.allowance(address(this), spender);

        // Do nothing if allowance is already set to this value
        if(currentAllowance == amount) {
            return true;
        }

        // If approval is not zero reset it to zero first
        if(currentAllowance != 0) {
            return token.approve(spender, 0);
        }

        // do the actual approval
        return token.approve(spender, amount);
    }
}
