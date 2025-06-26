# Distribution created with very small amount results in lost in fees for fee recipient and distribution assets for hypervisors

## Summary
In `GammaRewarder.createDistribution`, if incentivizer creates a distribution with a very small `_amount`, it can result in a loss in fees due to precision loss and no assets being distributed to hypervizors and being stuck in the protocol.

## Vulnerability Detail
fee is calculated as
```javascript
uint256 fee = _amount * protocolFee / BASE_9;
```
and subsequently, realAmountToDistribute is calculated as
```javascript
uint256 realAmountToDistribute = _amount - fee;
```
Lastly, amountPerEpoch is calculated as
```javascript
uint256 amountPerEpoch = realAmountToDistribute / ((_endBlockNum - _startBlockNum) / blocksPerEpoch);
```
Consider the scenario
1. Incetivizer creates a distribution with a very small `_amount` i.e 10.
2. Assuming protocolFee is set to `10e7`. fee is calculated as fee = 10 \* 10e7 / 1e9 = 0
3. realAmountToDistribute = 10 - 0 = 10
4. If realAmountToDistribute < ((\_endBlockNum - \_startBlockNum) / blocksPerEpoch), `amountPerEpoch` = 0
5. protocolFeeRecipient receives no fees
6. GammaRewarder receives full `realAmountToDistribute`
7. When hypervisor claims rewards, no rewards will be diistributed to them, since `amountPerEpoch = 0`

## Impact
Loss of tokens for fee recipients and hypervisors.

## Code Snippet
https://github.com/sherlock-audit/2024-10-gamma-rewarder/blob/main/GammaRewarder/contracts/GammaRewarder.sol#L125

## Tools Used
Manual Review

## Recommendation
Consider enforcing a check that fee is greater than zero after calculation.