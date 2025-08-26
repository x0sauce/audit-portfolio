# Inflation attack is possible via direct donations and deposit rewards call

## Vulnerability Details

In the current design of the protocol, users can deposit the underlying token (USDT) in exchange for Portfolio tokens, which are divided into 4 sub-tokens. The normal process when invoking `PortfolioToken.deposit` is as follows:

1. Users send a certain amount of the underlying token (USDT).
2. The deposit action triggers the minting of pool shares to the `PortfolioToken`.
3. The user receives minted portfolio tokens at the specified index.

However, an issue arises when the protocol provides users with the ability to directly call `PortfolioToken.subDepositRewards`. This functionality permits users to make a direct USDT donation to the `PortfolioToken`, which then allows that amount to be deposited into the pool, resulting in the minting of pool shares to the `PortfolioToken` without any portfolio tokens minted.

```
    function subDepositRewards(uint index) public {
        require(index < NUM_TOKENS, "Index out of range");
        IPool pool = pools[index];
        if (address(pool) == address(0)) {
            return;
        }

        _subDepositRewardsPoolCheck(pool, index);
    }

    function _subDepositRewardsPoolCheck(IPool pool, uint index) private {

        IERC20 token = tokens[index];

        pool.claimRewards();
        // deposit all contract token balance
@>        uint balance = token.balanceOf(address(this)); //@audit direct donation

        // This scales it back to system precision in the pool
        if ((balance / tokensPerSystem[index]) > 0) {
@>            pool.deposit(balance); //@audit deposit balance for pool shares
            emit DepositedRewards(balance, address(token));
        }
    }
```

This creates a vulnerability commonly referred to as the first depositor attack. The attack scenario can be outlined as follows:

1. The attacker deposits a small amount of tokens to acquire some pool shares.
2. The attacker then makes a substantial donation directly to the `PortfolioToken`, allowing them to mint pool shares through reward deposits without receiving any portfolio tokens.
3. As a result, subsequent depositors receive zero shares due to rounding issues.

Consequently, later users will not have any portfolio tokens minted, and the rounding occurs during the `_mintAfterTotalChanged` -> `_fromVirtualAfterTotalChangedForMint` -> `MultiToken.mint` call.

```
    function _fromVirtualAfterTotalChangedForMint(uint virtualAmount, uint index) private view returns (uint out) {
        uint realTotal = MultiToken.subTotalSupply(index);
        if (realTotal == 0) {
@>            return virtualAmount; //@audit on first deposit, attacker gets minted portfolio tokens equivalent to pool shares minted to PortfolioToken
        }
@>        uint totalVirtualAmount = _totalVirtualAmount(index); //@audit direct donation of underlying token + subDepositReward calls inflated total pool shares held by PortFolioToken
        require(totalVirtualAmount >= virtualAmount, "Virtual amount exceeds total");
@>        uint totalVirtual = totalVirtualAmount - virtualAmount; //@audit On subsequent user's deposits, inflated pool shares - pool shares minted to user is still a large amount
        if (totalVirtual == 0) {
            return 0;
        }

        // amount * realTotal / totalVirtual
        // amount could be grater than totalVirtual
        assembly {
@>            out := div(mul(virtualAmount, realTotal), totalVirtual) //@audit underflows here since totalVirtual > virtualAmount * realTotal
        }
    }
```

**Note** that Celo has successfully transitioned from a standalone L1 chain to an L2 chain, which means it no longer has a public mempool. The latest pending transactions occurred around the time of this transition to an L2 chain.

However, in the case of Sherlock's rule, the described vulnerability need not depend on a public mempool. An informed attacker only needs to examine the on-chain contract to confirm that an empty pool has been established through the `IPool[NUM_TOKENS] public pools` mapping and can invoke `Pool.balanceOf` to verify that the pool currently holds no shares, enabling them to execute the attack and causing losses to the first depositor.

https://celoscan.io/txsPending

## POC

Consider the following scenario

1. Alice notices a new pool set up by the admin through `PortfolioToken.setPool`.
2. She acts as the first depositor, contributing `3e3` USDT to the pool via `PortfolioToken.deposit` for the sub token with `index = 0`.
3. Assuming the pool is newly configured in PortfolioToken and does not accumulate any rewards via `PortfolioToken._subDepositRewardsPoolCheck`.
4. A transfer of `3e3` USDT occurs from Alice to `PortfolioToken`.
5. The `3e3` USDT is then transferred from `PortfolioToken` to the `Pool`.
6. Alice's `3e3` deposit would mint her `2 wei` worth of pool shares to the `PortfolioToken` (calculated manually based on on chain values, can provide POC if neccessary).
    - Depositing `3e3` USDT here will increment
    - tokenBalance in Pool by 1 wei - 37053833 -> 37053834
    - vUsdBalance in Pool by 1 wei - 33983457 -> 33983458
    - A change of 2 wei (d - oldD), which mints 2 wei worth of shares to the `PortfolioToken`
7. Given that she is the first depositor and there is no existing supply of sub token `index = 0`, `PortfolioToken._mintAfterTotalChanged` will mint her `2 wei` worth of the `index = 0` subtoken.
8. In the same transaction, she also makes a direct donation of `200e6` USDT ($200 USDT) to the `PortfolioToken` contract and invokes `PortfolioToken.subDepositRewards`.
9. This initiates the following call sequence: `PortfolioToken.subDepositRewards` -> `token.balanceOf` -> `pool.deposit`.
10. This flow will mint `199e3` worth of pool shares, but no portfolio tokens are minted to support those pool shares.
    - Depositing `200e6` USDT via donation and direct deposit call will increment
    - tokenBalance: 37053834 -> 37158156
    - vUsdBalance: 33983458 -> 34079135
    - A change of 199e3 (d - oldD), which mints 199e3 worth of shares to the `PortfolioToken`
11. Consequently, there will be `199e3 + 2` pool shares linked to `PortfolioToken`, with Alice holding `2 wei` worth of portfolio tokens in the form of subtoken `index = 0`.
12. Another user, Bob, deposits `200e6` USDT, and it is assumed that his deposit also mints another `199e3` worth of pool shares to `PortfolioToken`.
    - Note that over here, there is no front running happening, the sequence of events is that both Alice and Bob submitted deposit transactions and Alice first successfully became the first depositor while Bob also has a pending deposit transaction and suffered from the attack when Alice's (malicious) manages to successfully become the first depositor
    - Front running cannot happen on Celo chain since it has transitioned into a OP-based chain with a private mempool
13. The amount of portfolio tokens to be minted for him would be calculated in `VirtualMultiToken._fromVirtualAfterTotalChangedForMint`as:
    - virtualAmount * realTotal / totalVirtual
    - 199e3 * 2 / (199e3 + 2 + 199e3 - 199e3) = 1 wei of portfolio sub token
    - Now there are 3 wei worth of portfolio sub token index = 0 minted (2 for Alice, 1 for Bob) and 199e3 + 199e3 + 2 = 398,002 worth of pool shares in `PortfolioToken`
14. Bob receives 1 wei of portfolio tokens despite depositing 200e6 worth of USDT.
15. Alice can then withdraw all the underlying tokens (USDT) using all her portfolio token representing 66.67% of the pool shares (66.67% * 398002 = 265347) minted to `PortfolioToken` backed against her `PortfolioToken`.
    - Alice calls `PortfolioToken.subWithdraw`
    - She will burn 2 wei worth of portfolio token and withdraw by burning 265347 worth of pool shares from `PortfolioToken` which will return her ~$265 USDT for a ~30% gain
    - If Bob withdraws using 1 wei worth of portfolio toke nand burns the remaining pool shares (~132655) he will only get ~$132 USDT which is roughly a ~30% loss for him

## Root Cause

Direct use of `balanceOf` with exposed rewards deposit functionality to mint pool shares to `PortfolioToken` without minting portfolio token.

## Impact

Loss of funds for user.

Loss of funds for protocol.

## Mitigation

Consider introducing a virtual shares mechanism when minting portfolio tokens to render the attack economically impractical.

## LOC

https://github.com/sherlock-audit/2025-07-allbridge-core-yield/blob/main/core-auto-evm-contracts/contracts/PortfolioToken.sol#L142


# Insufficient slippage protection and the ability for users to increment pool shares via rewared deposits in `PortfolioToken` may result in users receiving fewer portfolio tokens than anticipated.

## Vulnerability Details

In the current design of the protocol, users can deposit the underlying token (USDT) in exchange for Portfolio tokens, which are divided into 4 sub-tokens at specified indexes. The normal process when invoking `PortfolioToken.deposit` is as follows:

1. Users send a certain amount of the underlying token (USDT).
2. The deposit action triggers the minting of pool shares to the `PortfolioToken`.
3. The user receives minted portfolio tokens at the specified index.

The problem arises when there is a lack of slippage for user deposits. In the current protocol design a deposit flow is as follows

`PortfolioToken.deposit` -> `PortfolioToken._subDepositRewardsPoolCheck` (takes redeemed rewards and mints pool shares to PortfolioToken in return) -> `Pool.deposit` -> `VirtualMultiToken._mintAfterTotalChanged` -> `VirtualMultiToken._fromVirtualAfterTotalChangedForMint` -> `MultiToken.mint`

The calculation for amount of portfolio token at specific index to be minted to user is calculated below

```
    function _fromVirtualAfterTotalChangedForMint(uint virtualAmount, uint index) private view returns (uint out) {
        uint realTotal = MultiToken.subTotalSupply(index);
        if (realTotal == 0) {
            return virtualAmount;
        }
        uint totalVirtualAmount = _totalVirtualAmount(index);
        require(totalVirtualAmount >= virtualAmount, "Virtual amount exceeds total");
        uint totalVirtual = totalVirtualAmount - virtualAmount;
        if (totalVirtual == 0) {
            return 0;
        }

        // amount * realTotal / totalVirtual
        // amount could be grater than totalVirtual
        assembly {
@>            out := div(mul(virtualAmount, realTotal), totalVirtual)
        }
    }

```

On observation, it is evident that all the variables involved can fluctuate. Specifically:

- `virtualAmount` - The quantity of pool shares minted to the `PortfolioToken`, as determined by the `Pool` base on how much `d` increments.
- `realTotal` - The overall supply of portfolio tokens, which can be influenced by pending withdrawals that burn portfolio tokens and decrease the supply.
- `totalVirtual` - The total pool shares in the `PortfolioToken`, excluding the pool shares minted from the current deposit. This can also be impacted by rewards claimed and deposited into the pool that increases pool shares held by `PortfolioToken`

In the absence of adequate slippage protection (`minPortfolioTokensReceived`), users may end up receiving fewer portfolio tokens than anticipated, which would subsequently limit the amount of underlying tokens they can withdraw later on.

More specifcally, exposing a public reward deposit function like `PortfolioToken.depositRewards` also allows anyone to increase the current pool shares (`totalVirtual`) of the PortfolioToken, which can result in less portfolio token minted to the depositor

```
@>    function depositRewards() public { //@audit anyone can call
        subDepositRewards(0);
        subDepositRewards(1);
        subDepositRewards(2);
        subDepositRewards(3);
    }

    /**
     * @dev Claim and deposit rewards of a specified pool
     * @param index The index of the pool for which rewards are to be deposited.
     */
    function subDepositRewards(uint index) public {
        require(index < NUM_TOKENS, "Index out of range");
        IPool pool = pools[index];
        if (address(pool) == address(0)) {
            return;
        }

        _subDepositRewardsPoolCheck(pool, index);
    }

    function _subDepositRewardsPoolCheck(IPool pool, uint index) private {

        IERC20 token = tokens[index];

        pool.claimRewards();
        // deposit all contract token balance
        uint balance = token.balanceOf(address(this));

        // This scales it back to system precision in the pool
        if ((balance / tokensPerSystem[index]) > 0) {
@>            pool.deposit(balance); //@audit mints pool shares to portfolio token
            emit DepositedRewards(balance, address(token));
        }
    }
```

```
    function _fromVirtualAfterTotalChangedForMint(uint virtualAmount, uint index) private view returns (uint out) {
        uint realTotal = MultiToken.subTotalSupply(index);
        if (realTotal == 0) {
            return virtualAmount;
        }
        uint totalVirtualAmount = _totalVirtualAmount(index);
        require(totalVirtualAmount >= virtualAmount, "Virtual amount exceeds total");
        uint totalVirtual = totalVirtualAmount - virtualAmount;
        if (totalVirtual == 0) {
            return 0;
        }

        // amount * realTotal / totalVirtual
        // amount could be grater than totalVirtual
        assembly {
@>            out := div(mul(virtualAmount, realTotal), totalVirtual) //@audit rewards claims increases totalVirtual without increasing total supply of sub tokens
        }
    }
```

## POC

Consider the following simplistic scenario:

1. Alice wants to deposit `1000e6 USDT` into the protocol and expects to receive ~666.67e3 portfolio tokens at index 0 based on current rates
    - virtualAmount = 800e3 (pool shares minted for her 1000 USDT)
    - realTotal = 1000e3
    - totalVirtual = 1200e3
2. Before her transaction is executed:
    - Reward is claimed and deposited into `Pool` via `PortfolioToken.depositRewards`
    - Suppose this mints 10e3 worth of pool shares to `PortfolioToken`
    - totalVirtual = 1200e3 + 10e3 = 1210e3
3. The deposit transaction executes with
    - virtualAmount = 800e3 (pool shares minted for depositor for 3000 USDT)
    - realTotal = 1000e3
    - totalVirtual = 1210e3
4. Alice's transaction executes. Calculation for amount minted to her becomes:
    
    ```
    out = (800e3 * 1000e3) / 1210e3 = 661.15e3
    ```
    
5. This would result in a slight loss (>0.01%) in the amount of portfolio tokens minted to her
6. Due to the lack of slippage protection, Alice has no guarantee on the minimum portfolio tokens she'll receive. The amount could be significantly lower due to execution of reward claims and state changes that occur between when she submits the transaction and when it executes.

## Root Cause

Lack of user defined slippage for amount of portfolio tokens minted on deposits which is calculated via fluctuating variables.

Public reward deposit functionality which allows anyone to increment pool shares held by `PortfolioToken` and cause less portfolio tokens minted to user

## Impact

Loss of yield for user.

Less than expected porfolio tokens received by user.

## LOC

https://github.com/sherlock-audit/2025-07-allbridge-core-yield/blob/main/core-auto-evm-contracts/contracts/PortfolioToken.sol#L33