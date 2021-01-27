// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.0;

contract ReentrancyGuard {
    uint private constant _NOT_ENTERED = 1;
    uint private constant _ENTERED = 2;

    uint private _status;

    constructor () {
        _status = _NOT_ENTERED;
    }

    modifier lock() {
        require(_status != _ENTERED, "ERR_REENTRY");

        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

     modifier checkLock() {
        require(_status != _ENTERED, "ERR_REENTRY_VIEW");
        _;
     }
}
