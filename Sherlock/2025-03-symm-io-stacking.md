# Reward distribution can be indefinitely extended by supplying small amounts of reward token

## Summary

The `SymmStaking` contract allows anyone to extend the reward distribution period by supplying minimal amounts of reward tokens, griefing existing stakers.

## Vulnerability Details

Currently in `SymmStaking`, any one can supply tiny amounts of reward token to extend reward distribution duration for existing stakers.

In `SymmStaking._addRewardsForToken`

```solidity
	function _addRewardsForToken(address token, uint256 amount) internal {
		TokenRewardState storage state = rewardState[token];

		if (block.timestamp >= state.periodFinish) {
			state.rate = amount / state.duration;
		} else {
			uint256 remaining = state.periodFinish - block.timestamp;
			uint256 leftover = remaining * state.rate;
			state.rate = (amount + leftover) / state.duration;
		}

@>		state.lastUpdated = block.timestamp; // @audit can be stretched by calling notifyRewardAmount with small reward tokens
		state.periodFinish = block.timestamp + state.duration;
	}
```

## Root Cause

Anyone can supply small amount of reward token to stretch out distribution period

## POC

Let's consider a straightforward example:

1. The `SymmStaking` contract holds 100 USDC in reward tokens. This amount was deposited before any stakers joined and was updated through the `_addRewardsForToken` function.
    - state.rate = 100e6 / 1 week = 165;
    - state.lastUpdated = 10
    - state.periodFinish = 604810 (10 + 1 week)
2. At `block.timestamp = 20`, Alice deposits 100 SYMM worth of tokens into `SymmStaking`.
    - state.perTokenStored = 0;
    - state.lastUpdated = 20
    - 10e18 SYMM from Alice -> `SymmStaking`
    - totalSupply = 10e18
    - balanceOf[Alice] = 10e18
3. In this simple scenario, Alice is entitled to the 100 USDC in reward tokens (as she constitutes the totalSupply), which should be distributed to her in one week when she claims at `block.timestamp = 604810`.
4. However, if Bob, an attacker, contributes 10 wei worth of USDC at `block.timestamp = 30`, he can effectively prolong the reward distribution period for Alice, making it take longer than one week for her to receive her share of the rewards by modifying the following variables:
    - remaining = 604810 - 30 = 604780
    - leftover = 604780 * 165 = 99,788,700
    - state.rate = (10 + 99,788,700) / 604800 = 164.9945601852
    - state.lastUpdated = 30
    - state.periodFinish = 604830 (30 + 1 week)
5. Consequently, when Alice claims at `block.timestamp = 604810`, she will only receive (604810 - 30) * 164.9945601852 = 99.7854101088 e6 worth of USDC. She will require a significantly longer time to claim the 100e6 USDC that she rightfully earned.

The amount of USDC that Alice was unable to claim is minimal, but this figure can be greater for a larger number of users.

## Impact

Staker rewards can be griefed by notifying the contract of minimal rewards, which can continuously extend the duration for reward distribution to stakers.

## Mitigation

Consider restricting the notification of rewards to the Staking contract authorized notifiers, similar to the approach implemented by Unistaker.

```solidity
  function notifyRewardAmount(uint256 _amount) external {
    if (!isRewardNotifier[msg.sender]) revert UniStaker__Unauthorized("not notifier", msg.sender);

    // We checkpoint the accumulator without updating the timestamp at which it was updated, because
    // that second operation will be done after updating the reward rate.
    rewardPerTokenAccumulatedCheckpoint = rewardPerTokenAccumulated();

    if (block.timestamp >= rewardEndTime) {
      scaledRewardRate = (_amount * SCALE_FACTOR) / REWARD_DURATION;
    } else {
      uint256 _remainingReward = scaledRewardRate * (rewardEndTime - block.timestamp);
      scaledRewardRate = (_remainingReward + _amount * SCALE_FACTOR) / REWARD_DURATION;
    }

    rewardEndTime = block.timestamp + REWARD_DURATION;
    lastCheckpointTime = block.timestamp;

    if ((scaledRewardRate / SCALE_FACTOR) == 0) revert UniStaker__InvalidRewardRate();

    // This check cannot _guarantee_ sufficient rewards have been transferred to the contract,
    // because it cannot isolate the unclaimed rewards owed to stakers left in the balance. While
    // this check is useful for preventing degenerate cases, it is not sufficient. Therefore, it is
    // critical that only safe reward notifier contracts are approved to call this method by the
    // admin.
    if (
      (scaledRewardRate * REWARD_DURATION) > (REWARD_TOKEN.balanceOf(address(this)) * SCALE_FACTOR)
    ) revert UniStaker__InsufficientRewardBalance();

    emit RewardNotified(_amount, msg.sender);
  }
```

## LOC

https://github.com/sherlock-audit/2025-03-symm-io-stacking/blob/main/token/contracts/staking/SymmStaking.sol#L377

# Vesting plans cannot be resetted upon new addition of SYMM LP tokens

## Summary

If staker is adding liquidity for the 2nd or subsequent time, an unnecessary requirement check in _resetVestingPlans() can cause the function to fail, not allowing staker to add liquidity again.

## Vulnerability Details

Assume this scenario whereby Alice is adding liquidity for a second time. Hence, Alice has an existing vesting plan for SYMM LP token.

## POC

1. Alice invokes the `addLiquidity()` function in SYMMVesting.sol, specifying an amount of 40e18 SYMM tokens.
2. The `_addLiquidityProcess`() function is executed.
3. Unlocked SYMM tokens are obtained through claimUnlockedToken().
4. The `_addLiquidity()` function is called, which in turn calls `addLiquidityProportional()`, engaging with the Balancer pool.
5. For the sake of this scenario, let's assume that the function has transferred 20e18 worth of SYMM LP tokens to SymmVesting.sol.
6. As this is Alice's second instance of adding liquidity, let's assume her current unlocked tokens for her SYMM LP vesting plan total `30e18`, with locked tokens amounting to `5e18`.
7. The `_claimUnlockedToken()` function is invoked again to claim Alice's unlocked SYMM LP tokens, which total `30e18`.
8. amounts[0] is calculated as `lpVestingPlan.lockedAmount() + lpAmount = 5e18 + 20e18 = 25e18`.
9. The `_resetVestingPlans()` function is called, passing `25e18` as the amounts parameter.
10. Within `_resetVestingPlans()`, since the amount of `25e18` is less than the unlocked amount of 30e18, the function will revert.

## Root Cause

Inaccurate validation for the amount being less than the unlocked tokens for SYMMLP tokens.

## LOC

https://github.com/sherlock-audit/2025-03-symm-io-stacking-0xgremlincat5555/blob/304fb24fcd3935d47791d1782407cb490be64dbb/token/contracts/vesting/Vesting.sol#L231

## Impact

Stakers who wish to add liquidity for the 2nd and subsequent times will revert, due to this unnecessary check. Even when stakers have enough locked SYMM LP tokens to be vested, they cannot proceed with liquidity addition as attempts to reset their SYMMLP vesting will revert.

## Mitigation

Consider not reverting for SYMMLP vesting plans as the check is only applicable for SYMM tokens.