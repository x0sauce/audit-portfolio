# `Pool.transferReserveToAuction` does not correctly reduce `currentPeriod` to transfer `reserveTokens` to Auction

## Summary

`Pool.transferReserveToAuction` cannot transfer reserveToken to the Auction of the previous period once auction ends

## Vulnerability Details

Whenever an auction is started in `Pool.startAuction`, the `currentPeriod` of bondToken will be incremented by 1.

```solidity
  function startAuction() external whenNotPaused() {
    ...
    (uint256 currentPeriod,) = bondToken.globalPool(); // @audit starts auction with currentPeriod
    require(auctions[currentPeriod] == address(0), AuctionAlreadyStarted());

    uint8 bondDecimals = bondToken.decimals();
    uint8 sharesDecimals = bondToken.SHARES_DECIMALS();
    uint8 maxDecimals = bondDecimals > sharesDecimals ? bondDecimals : sharesDecimals;

    uint256 normalizedTotalSupply = bondToken.totalSupply().normalizeAmount(bondDecimals, maxDecimals);
    uint256 normalizedShares = sharesPerToken.normalizeAmount(sharesDecimals, maxDecimals);

    // Calculate the coupon amount to distribute
    uint256 couponAmountToDistribute = (normalizedTotalSupply * normalizedShares)
        .toBaseUnit(maxDecimals * 2 - IERC20(couponToken).safeDecimals());

    auctions[currentPeriod] = Utils.deploy(
      address(new Auction()),
      abi.encodeWithSelector(
        Auction.initialize.selector,
        address(couponToken),
        address(reserveToken),
        couponAmountToDistribute,
        block.timestamp + auctionPeriod,
        1000,
        address(this),
        poolSaleLimit
      )
    );

    // Increase the bond token period
    bondToken.increaseIndexedAssetPeriod(sharesPerToken); // @audit currentPeriod is incremented by 1

    // Update last distribution time
    lastDistribution = block.timestamp;
  }
```

Once the auction succeeds and `Auction.endAuction` is called, the Pool is suppose to transfer the total `reserveAmount` sold to the Auction for bidders to claim. However, this will not happen since the Pool does not decrement the currentPeriod to retrieve the latest Auction that ended in order to send the reserveToken.

```solidity
  function transferReserveToAuction(uint256 amount) external virtual {
    (uint256 currentPeriod, ) = bondToken.globalPool(); // @audit currentPeriod retrieved is already incremented
    address auctionAddress = auctions[currentPeriod]; // @audit auctionAddress will not return latest Auction that ended
    require(msg.sender == auctionAddress, CallerIsNotAuction()); // @audit this reverts

    IERC20(reserveToken).safeTransfer(msg.sender, amount);
  }
```

## LOC

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L578

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Auction.sol#L345

## POC

Consider the following scenario

1. At currentPeriod = 0, an auction is started via `Pool.startAuction`. `currentPeriod` is incremented to `1`
2. After some time (10 days per docs), the auction ends and `Auction.endAuction` is called
3. This will trigger `Pool.transferReserveToAuction`. Since `currentPeriod = 1`, auctionAddress will be 0x0 assuming no auction has started. Even if an auction has started, the wrong Auction address wil be retrieved.
4. `Auction.endAuction` reverts and no reserves can be transferred from `Pool` to `Auction` since the Auction callling `Pool.transferReserveToAuction` is not the same as `auctionAddress` retrieved
5. `reserveTokens` in the `Pool` to be send to the `Auction` are stuck in the `Pool` since `currentPeriod` can never be decremented

## Impact

Reserve tokens cannot be claimed by bidders since they cannot be transferred from the `Pool` to the `Auction` contract.

## Mitigation

Decrement the `currentPeriod` to retrieve the `previousPeriod` (similar to `Pool.distribute`) such that `reserveToken` can be transferred to the latest `Auction` that has ended

# Precision difference in `getRedeemAmount` results in inaccurate marketRate and redeemRate compairison

## Summary

Precision difference in `getRedeemAmount` results in inaccurate `marketRate` and `redeemRate` comparison

## Vulnerability Details

When redeeming `reserveToken` using bondETH or levETH derivative tokens, protocol would take the lower rate between `marketRate` (from oracle) and `redeemRate` (from internal caclulations). The problem here is that precisions are not properly considered for `marketRate`. This will result in redeemers receiving more reserveTokens than intended by the protocol.

In `Pool.simulateRedeem`

```solidity
    function simulateRedeem(TokenType tokenType, uint256 depositAmount) public view returns(uint256) {
    ...
    uint256 marketRate;
    address feed = OracleFeeds(oracleFeeds).priceFeeds(address(bondToken), USD);
    if (feed != address(0)) {
      marketRate = getOraclePrice(address(bondToken), USD)
        .normalizeAmount(
          getOracleDecimals(address(bondToken), USD),  // <@ audit 8 decimal places
          oracleDecimals // <@ audit 8 decimal places
        );
    }
  ...
  }
```

In `Pool.getRedeemAmount`

```solidity
    function getRedeemAmount(
        TokenType tokenType,
        uint256 depositAmount,
        uint256 bondSupply,
        uint256 levSupply,
        uint256 poolReserves,
        uint256 ethPrice,
        uint8 oracleDecimals,
        uint256 marketRate
    ) public pure returns(uint256) {
    ...
    uint256 redeemRate;
    if (collateralLevel <= COLLATERAL_THRESHOLD) {
      redeemRate = ((tvl * multiplier) / assetSupply);
    } else if (tokenType == TokenType.LEVERAGE) {
      redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) / assetSupply) * PRECISION;
    } else {
      redeemRate = BOND_TARGET_PRICE * PRECISION; // <@ audit redeemRate is set to precision of 1e6
    }

    if (marketRate != 0 && marketRate < redeemRate) {
      redeemRate = marketRate; // <@ audit redeemRate is not set to lower marketRate as it has a higher precision of 1e8
    }
  ...
  }
```

## LOC

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L441

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L516

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L519

## POC

Suppose a user attempts to redeem 1 bondETH for WETH (reserveToken). Both oracles for bondETH <> USD and WETH <> USD comes from chainlink. Chainlink oracle feeds returns 8 decimal places unless its an ETH pair.

- oracle decimals for bondToken, USD price feed is 8
- oracle decimals for reserveToken, USD price feed is 8
1. Suppose the price of one bondETH in USD is 1 USDC/bondETH (i.e. `1e8`).
2. Entering `simulateRedeem` - `marketRate` will return `marketRate = 1e8` since since the below line is called
    
    ```solidity
       ...
       uint8 oracleDecimals = getOracleDecimals(reserveToken, USD); //@audit 8 decimal places
    
       uint256 marketRate;
       address feed = OracleFeeds(oracleFeeds).priceFeeds(address(bondToken), USD);
       if (feed != address(0)) {
       marketRate = getOraclePrice(address(bondToken), USD)
           .normalizeAmount(
           getOracleDecimals(address(bondToken), USD), // @audit 8 decimal places
           oracleDecimals // @audit 8 decimal places
           );
       ...
    ```
    
3. Entering `getRedeemAmount`. In the event when `collateralLevel > COLLATERAL_THRESHOLD`, `redeemRate` = 100 * 1e6 = 100e6 (i.e. 100 USDC)
4. `redeemRate` (100e6 which represents 100 USDC/bondETH) will always be taken even if `marketRate` (1e8 which represents 1 USDC/bondETH) is in fact lower with a higher precision.
5. Redeemer will receive more `reserveToken` than intended by protocol.

## Impact

Redeemer receives more reserveToken than intended even when marketRate of `bondtoken` is lower. Lower `marketRate` is not used which breaks protocol core functionality.

## Mitigation

Consider normalizing `marketRate` to the correct precision before comparing with `redeemRate`

# Precision loss in `getCreateAmount` and `getRedeemAmount` functions

## Summary

Division before multiplcation when calculating tvl may result in redemption and creation failing.

## Vulnerability Details

In `Pool.getCreateAmount`, value of ethPrice includes oracle decimal places and needs to be divided by a base unit. Conversion is done when calculating tvl, which may lead to loss of precision in subsequent calculation. One example is `creationRate` can be 0. This will cause creation of derivative tokens to revert due to a division by 0 error

```solidity
  function getCreateAmount(
    TokenType tokenType,
    uint256 depositAmount,
    uint256 bondSupply,
    uint256 levSupply,
    uint256 poolReserves,
    uint256 ethPrice,
    uint8 oracleDecimals) public pure returns(uint256) {
    if (bondSupply == 0) {
      revert ZeroDebtSupply();
    }

    uint256 assetSupply = bondSupply;
    uint256 multiplier = POINT_EIGHT;
    if (tokenType == TokenType.LEVERAGE) {
      multiplier = POINT_TWO;
      assetSupply = levSupply;
    }

    uint256 tvl = (ethPrice * poolReserves).toBaseUnit(oracleDecimals); // @audit division happens
    uint256 collateralLevel = (tvl * PRECISION) / (bondSupply * BOND_TARGET_PRICE);
    uint256 creationRate = BOND_TARGET_PRICE * PRECISION;

    if (collateralLevel <= COLLATERAL_THRESHOLD) {
      if (tokenType == TokenType.LEVERAGE && assetSupply == 0) {
        revert ZeroLeverageSupply();
      }
      creationRate = (tvl * multiplier) / assetSupply;
    } else if (tokenType == TokenType.LEVERAGE) {
      if (assetSupply == 0) {
        revert ZeroLeverageSupply();
      }

      uint256 adjustedValue = tvl - (BOND_TARGET_PRICE * bondSupply);
      creationRate = (adjustedValue * PRECISION) / assetSupply; // @audit  division happens before multiplication
    }

    return ((depositAmount * ethPrice * PRECISION) / creationRate).toBaseUnit(oracleDecimals); // @audit division by zero error
  }
```

In `Pool.getRedeemAmount`, similar precision loss can happen when calculating redeemRate which can be returned as 0. This causes redemption to revert as reserveAmount returned will be 0

```solidity
  function getRedeemAmount(
    TokenType tokenType,
    uint256 depositAmount,
    uint256 bondSupply,
    uint256 levSupply,
    uint256 poolReserves,
    uint256 ethPrice,
    uint8 oracleDecimals,
    uint256 marketRate
  ) public pure returns(uint256) {
    if (bondSupply == 0) {
      revert ZeroDebtSupply();
    }

    uint256 tvl = (ethPrice * poolReserves).toBaseUnit(oracleDecimals); //@audit division happens
    uint256 assetSupply = bondSupply;
    uint256 multiplier = POINT_EIGHT;

    // Calculate the collateral level based on the token type
    uint256 collateralLevel;
    if (tokenType == TokenType.BOND) {
      collateralLevel = ((tvl - (depositAmount * BOND_TARGET_PRICE)) * PRECISION) / ((bondSupply - depositAmount) * BOND_TARGET_PRICE);
    } else {
      multiplier = POINT_TWO;
      assetSupply = levSupply;
      collateralLevel = (tvl * PRECISION) / (bondSupply * BOND_TARGET_PRICE);

      if (assetSupply == 0) {
        revert ZeroLeverageSupply();
      }
    }

    // Calculate the redeem rate based on the collateral level and token type
    uint256 redeemRate;
    if (collateralLevel <= COLLATERAL_THRESHOLD) {
      redeemRate = ((tvl * multiplier) / assetSupply);
    } else if (tokenType == TokenType.LEVERAGE) {
      redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) / assetSupply) * PRECISION; // @audit division happens before multiplication
    } else {
      redeemRate = BOND_TARGET_PRICE * PRECISION;
    }

    if (marketRate != 0 && marketRate < redeemRate) {
      redeemRate = marketRate;
    }

    // Calculate and return the final redeem amount
    return ((depositAmount * redeemRate).fromBaseUnit(oracleDecimals) / ethPrice) / PRECISION; //@audit zero value returned
  }
```

## LOC

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L325

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L339

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L491

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L514

## POC

Consider the following scenario

1. Current bondToken price is such that tvl = 100e18
2. Suppose `adjustedValue = 90e18` After subtracting `BOND_TARGET_PRICE * bondSupply`
3. if levToken `assetSupply > adjustedValue * PRECISION`, creationRate = 0
4. Division by zero error occurs in `((depositAmount * ethPrice * PRECISION) / creationRate).toBaseUnit(oracleDecimals)`

## Impact

Creation and redemption transactions will revert for users. Temporary DOS of protocol core functionalities.

## Mitigation

Perform multiplication before division.

# Inconsistency in `sharesPerToken` values recorded

## Summary

Less than intended shares will be claimed by bondETH holders due to inconsistent `sharesPerToken` values cached.

## Vulnerability Details

In `Pool.startAuction`, whenever an auction is started, the `sharesPerToken` global variable will be used to calculate the total coupon amount that can be be bid by bidders in `Auction` .

At the same time, in `BondToken`, currentPeriod also increments by 1 and the previous `sharesPerToken` is cached in the `globalPool.previousPoolAmounts` array. The problem is that the `sharesPerToken` value used can be different if governance changes the sharesPerToken in `Pool.setSharesPerToken`.

This can result in bondETH holders to receive less than the shares they deserve when they subsequently call `Distributor.claim` to claim their coupon tokens.

In `Pool.setSharesPerToken`

```
  function setSharesPerToken(uint256 _sharesPerToken) external NotInAuction onlyRole(poolFactory.GOV_ROLE()) {
    sharesPerToken = _sharesPerToken; // @audit 1. Example - sharesPerToken set from 1 USDC/bondETH to 2 USDC/bondETH at currentPeriod = 1

    emit SharesPerTokenChanged(sharesPerToken);
  }
```

In `Pool.startAuction`

```solidity
    function startAuction() external whenNotPaused() {
    ...
    (uint256 currentPeriod,) = bondToken.globalPool(); // @audit Exmaple 2. currentPeriod is 1
    require(auctions[currentPeriod] == address(0), AuctionAlreadyStarted());

    uint8 bondDecimals = bondToken.decimals();
    uint8 sharesDecimals = bondToken.SHARES_DECIMALS();
    uint8 maxDecimals = bondDecimals > sharesDecimals ? bondDecimals : sharesDecimals;

    uint256 normalizedTotalSupply = bondToken.totalSupply().normalizeAmount(bondDecimals, maxDecimals);
    uint256 normalizedShares = sharesPerToken.normalizeAmount(sharesDecimals, maxDecimals); // @audit 3. sharesPerToken will be 2 USDC/bondETH

    // Calculate the coupon amount to distribute
    uint256 couponAmountToDistribute = (normalizedTotalSupply * normalizedShares)
        .toBaseUnit(maxDecimals * 2 - IERC20(couponToken).safeDecimals());

    auctions[currentPeriod] = Utils.deploy(
      address(new Auction()),
      abi.encodeWithSelector(
        Auction.initialize.selector,
        address(couponToken),
        address(reserveToken),
        couponAmountToDistribute,
        block.timestamp + auctionPeriod,
        1000,
        address(this),
        poolSaleLimit
      )
    );

    // Increase the bond token period
    bondToken.increaseIndexedAssetPeriod(sharesPerToken); // @audit 4. Enter increaseIndexedAssetPeriod
    ...
    }

```

```solidity
  function increaseIndexedAssetPeriod(uint256 sharesPerToken) public onlyRole(DISTRIBUTOR_ROLE) whenNotPaused() {
    globalPool.previousPoolAmounts.push(
      PoolAmount({
        period: globalPool.currentPeriod,
        amount: totalSupply(),
        sharesPerToken: globalPool.sharesPerToken //@audit 5. sharesPerToken will be 1 USDC/bondETH here instead of 2 USDC/bondETH as it takes previous cahced sharesPerToken
      })
    );
    globalPool.currentPeriod++;
    globalPool.sharesPerToken = sharesPerToken;

    emit IncreasedAssetPeriod(globalPool.currentPeriod, sharesPerToken);
  }
```

## LOC

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L546

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L549

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L558

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L567

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BondToken.sol#L222

## POC

Consider the below scenario

1. There was an `Auction` that has started and ended in `currentPeriod` = 0. Suppose `sharesPerToken` = 1 USDC/bondETH was used. `currentPeriod` was incremented to 1 and `globalPool.sharesPerToken` was cached with 1 USDC/bondETH when `bondToken.increaseIndexedAssetPeriod` was triggered.
2. Governance now sets `sharesPerToken = 2 USDC/bondETH` via `Pool.setSharesPerToken` at `currentPeriod` = 1
3. A new auction is now started at `currentPeriod = 1`. `sharesPerToken` = 2 USDC will be used to calculate `couponAmountToDistribute`.
4. However in `bondToken.increaseIndexedAssetPeriod`, `sharesPerToken` = 1 USDC will be used and `currentPeriod` is incremented to 2.
5. Subsequently, the `Auction` ends and coupon token is transferred to the `Pool` and then to the `Distributor`.
6. When bondETH holder calls `Distribute.claim`, he wouldve used `sharesPerToken` = 1 USDC when calculating his shares at period 1 instead of `sharesPerToken` = 2 USDC, which was the `sharesPerToken` used to determine the total coupon amount that can be bid by users at `currentPeriod = 1`

## Impact

bondETH holder receives less than expected shares.

## Mitigation

When setting a new `sharesPerToken` in `Pool`, consider updating the `globalPool.sharesPerToken` of the `currentPeriod`

# Excess bids cannot be removed in `Auction.removeExcessBids` if address is USDC blacklisted

# Summary

Excess bids cannot be removed from lowest bids if address is blacklisted by USDC in `Auction.removeExcessBids`.

## Vulnerability Details

In `Auction.bid`, whenever a new bidder bids, Auction contract will attempt to remove any excess bids starting from the lowest bids if the `currentCouponAmount` used by bidders exceeds the maximum `totalBuyCouponAmount` allowed.

The problem is that if a user has been blacklisted by USDC, the protocol will not be able to remove excess bids as `Auction.removeExcessBids` will revert.

```solidity
  function removeExcessBids() internal {
      ...
      else {
        // Calculate the proportion of sellAmount being removed
        uint256 proportion = (amountToRemove * 1e18) / sellCouponAmount;

        // Reduce the current bid's amounts
        currentBid.sellCouponAmount = sellCouponAmount - amountToRemove;
        currentCouponAmount -= amountToRemove;

        uint256 reserveReduction = ((currentBid.buyReserveAmount * proportion) / 1e18);
        currentBid.buyReserveAmount = currentBid.buyReserveAmount - reserveReduction;
        totalSellReserveAmount -= reserveReduction;

        // Refund the proportional sellAmount
        IERC20(buyCouponToken).safeTransfer(currentBid.bidder, amountToRemove); // @audit reverts is bidder is USDC blacklisted

        amountToRemove = 0;
        emit BidReduced(currentIndex, currentBid.bidder, currentBid.buyReserveAmount, currentBid.sellCouponAmount);
      }
     ...
  }
```

## LOC

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Auction.sol#L286

## Impact

Bidders will not be able to place a higher bid since removal of excess bids cannot go through as long as one of the bidders in the lowest bids is blacklisted by USDC

## Mitigation

Consider using internal accounting to store the amount of coupon token that should be refunded to the lowest bidders in a mapping, together with a separate function to allow lowest bidders to claim the amount of coupon token that was pushed out by a higher bidder.

# Unspent deposit amount is stuck in `BalancerRouter` and not returned to depositor

## Summary

Unspend BalancerPoolToken reserve token is not refunded to user and can be stuck in `BalancerRouter`

## Vulnerability Details

In the event that a user pre deposits a BalancerPoolToken (BPT) `reserveToken` via `BalancerRouter.joinBalancerAndPredeposit`, the unspend BPT tokens will not be returned to the user and will be stuck in the `BalancerRouter`

In `BalancerRouter.joinBalancerAndPredeposit`, a user will supply an array of asset token and BPT tokens will be received by the `BalancerRouter`.

```solidity
    function joinBalancerAndPredeposit(
        bytes32 balancerPoolId,
        address _predeposit,
        IAsset[] memory assets,
        uint256[] memory maxAmountsIn,
        bytes memory userData
    ) external nonReentrant returns (uint256) {
        // Step 1: Join Balancer Pool
        uint256 balancerPoolTokenReceived = joinBalancerPool(balancerPoolId, assets, maxAmountsIn, userData);

        // Step 2: Approve balancerPoolToken for PreDeposit
        balancerPoolToken.safeIncreaseAllowance(_predeposit, balancerPoolTokenReceived);

        // Step 3: Deposit to PreDeposit
        PreDeposit(_predeposit).deposit(balancerPoolTokenReceived, msg.sender); // @audit full BPT token received might not be spend

        return balancerPoolTokenReceived;
    }
```

Subsequently the function calls the `PreDeposit.deposit` function. If the amount of BPT tokens supplied hits the cap, PreDeposit will take the difference of the `reserveAmount` and the amount of BPT token deposited by the user to fill up to the `reserveCap`. The difference will then be transferred to the PreDeposit contract.

However, the remanining amount of BPT tokens aill be stuck in `BalancerRouter` and remain unused.

```solidity
  function _deposit(uint256 amount, address onBehalfOf) private checkDepositStarted checkDepositNotEnded {
    if (reserveAmount >= reserveCap) revert DepositCapReached();

    address recipient = onBehalfOf == address(0) ? msg.sender : onBehalfOf;

    // if user would like to put more than available in cap, fill the rest up to cap and add that to reserves
    if (reserveAmount + amount >= reserveCap) {
      amount = reserveCap - reserveAmount; // @audit difference in amount is taken
    }

    balances[recipient] += amount;
    reserveAmount += amount;

    IERC20(params.reserveToken).safeTransferFrom(msg.sender, address(this), amount); // @audit full BPT tokens received is not transferred to PreDeposit contract

    emit Deposited(recipient, amount);
  }
```

## LOC

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L23

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/PreDeposit.sol#L124

## POC

Consider the following scenario

1. Alice sends WETH and WBTC to receive 100 BPT tokens in return via `BalancerRouter.joinBalancerAndPredeposit`
2. Suppose in `PreDeposit`, `reserveAmount` = 100 BPT and `reserveCap` = 101 BPT.
3. Entering `PreDeposit.deposit -> PreDeposit._deposit` - the amount of BPT tokens that will be deposited by Alice will be 1 BPT
4. `BalancerRouter` will send 1 BPT to the `PreDeposit` contract.
5. The remaining 99 BPT tokens will remain in `BalancerRouter`.
6. Alice has no way to retrieve that unspend 99 BPT tokens.

## Impact

BPT reserve tokens will be stuck in the router. Loss of tokens for users.

## Mitigation

Refund the unspend BPT tokens to the user who predeposits via the `BalancerRouter`