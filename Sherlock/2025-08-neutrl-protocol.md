# [M-1] **`FULL_RESTRICTED` users can stake**

## **Vulnerability Details**

The contest ReadMe states

> Role Consistency
> 
> - Property: FULL_RESTRICTED users cannot transfer and stake/unstake, SOFT_RESTRICTED cannot stake/unstake
> - Description: Blacklist roles must be properly enforced across all operations
> - Location: sNUSD.sol and NUSD.sol

It is observed within the sNUSD vault that `FULL_RESTRICTED` can still stake in the vault by using a receiver address that is not restricted. When users that are fully restricted deposits NUSD in exchange for sNUSD shares via `sNUSD.deposit` or `sNUSD.mint`, he can specify a receiver address that is not restricted and still stake his NUSD for sNUSD.

```
    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override {
@>        if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) { //@audit only soft restricted users are checked
            revert OperationNotAllowed();
        }
        if (assets == 0 || shares == 0) revert ZeroInput();
@>super._deposit(caller, receiver, assets, shares);
        _checkMinShares();
    }
```

This breaks invariant (7) stated in the READMe

## **Impact**

`FULL_RESTRICTED` users can still stake `NUSD` in exchange for `sNUSD` shares which breaks invariant stated in READMe

## **Mitigation**

Add checks to ensure `FULL_RESTRICTED` users cannot stake in `sNUSD._deposit`

## **LOC**

https://github.com/sherlock-audit/2025-08-neutrl-protocol/blob/main/contracts/src/sNUSD.sol#L338