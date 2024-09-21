# [H-01] Using a liquidity pool for price functionality allows Liquidity Providers (LPs) to reduce fees paid

## Vulnerability Details

The `getCalculatedFee` function uses `OracleUpgradeable:getPriceInWeth()` to obtain the price of the underlying token in WETH.

Consider the following scenario:

Setup

- A simple TokenA-WETH AMM liquidity pool
  - Initialized with 50 tokenA and 100 WETH

1. The LP observes that the current spot price of 1 tokenA is 2 WETH (100 WETH / 50 tokenA).
2. The LP swaps 50 tokenA for WETH. The new spot price of 1 tokenA becomes 0.5 WETH (50 WETH / 100 tokenA).
3. The LP deposits tokenA to receive AssetTokens in return.
   - The calculated fee will be lower
   - The exchange rate will be lower
   - The user will receive more AssetTokens than expected

## Impact

A user can manipulate the spot price of the underlying token to receive more AssetTokens in return.

## Proof-Of-Concept

```javascript
function test_feeDrops() public {
    /*
    Calculating fee using value of token in WETH coming from a price oracle from a liquidity pool results inlesser fees being paid
    User can easily manipulate the price of a token in the AMM Pool by depositing and withdrawing token pairs.
    This will cause LP to pay less fees and profit more off the protocol

    Scenario:
        1. Swap 50 tokenA for WETH in the AMM Pool (TokenA - WETH Pair)
            - Suppose the pool now has 50 tokenA and 100 WETH -> 1 tokenA = 2 WETH
            - After the swap, the pool will have 100 tokenA and 50 WETH -> 1 tokenA =  0.5 WETH
        2. The fee will now drop as the price of tokenA in WETH has dropped
    */
    // Initialize tokens
    vm.startPrank(user);
    tokenA = new ERC20Mock();
    weth = new ERC20Mock();
    poolFactory = new MockPoolFactory();
    // Simulate price of 1 token A in Weth. assuming the pool has 50 tokenA and 100 Weth. Which means the priceof 1 tokenA is 2 Weth
    // Before user made the swap
    poolFactory.createPool(address(tokenA), 2e18);
    // Initialize ThunderLoan
    thunderloan = new ThunderLoan();
    proxy = new ERC1967Proxy(address(thunderloan), "");
    thunderloan = ThunderLoan(address(proxy));
    thunderloan.initialize(address(poolFactory));
    // Allow tokenA as underlying token
    thunderloan.setAllowedToken(tokenA, true);
    // Allow weth as underlying token
    thunderloan.setAllowedToken(weth, true);

    console.log("Price of fee: ", thunderloan.getCalculatedFee(tokenA, 10e18));
    // User swaps 50 tokenA for WETH in the AMM Pool (TokenA - WETH Pair)
    // After the swap, the pool will have 100 tokenA and 50 WETH -> 1 tokenA =  0.5 WETH
    MockTSwapPool(poolFactory.getPool(address(tokenA))).updatePriceofOnePoolTokenInWeth(5e16);
    console.log("Price of fee: ", thunderloan.getCalculatedFee(tokenA, 10e18));
    vm.stopPrank();
}
```

While we are manually adjusting the price of the underlying token in this POC, it effectively demonstrates how an attacker could manipulate the spot price by swapping tokens within the AMM liquidity pool.

## Tools Used

Manual Analysis, Foundry

## Recommended Mitigation

To prevent this, avoid relying on a single liquidity pool for price determination. Instead, use a decentralized price oracle to obtain the true price of the underlying token. Manipulating the price across multiple pools would require significantly more resources.

# [H-02] Differing storage layout between ThunderLoan and ThunderLoanUpgraded leads to storage collision

## Vulnerability Details

Variable `ThunderLoan:s_feePrecision` has been newly defined as a constant`ThunderLoanUpgraded:FEE_PRECISION`, which results in a storage slot not being reserved. Additionally, `s_flashLoanFee` is now positioned above `FEE_PRECISION` in ThunderLoanUpgraded.

Discrepancy causes the below storage collisions

- ThunderLoan:fee_precision and ThunderLoanUpgraded:s_flashLoanFee
- ThunderLoan:s_flashLoanFee and ThunderLoanUpgraded:s_currentlyFlashLoaning

## Impact

Vulnerability allows users to deposit underlying tokens at significantly lower fees than intended by the protocol. Furthermore, users may also execute repayments into the protocol when they shouldnt be able to do so.

## Proof-Of-Concept

```javascript
function test_storageCollision() public {

    // Initialize contracts with dummy user

    vm.startPrank(user);

    // Initialize tokens
    tokenA = new ERC20Mock();
    weth = new ERC20Mock();
    poolFactory = new MockPoolFactory();
    // Simulate price of 1 token A in Weth. assuming the pool has 50 tokenA and 100 Weth. Which means the price of 1 tokenA is 2 Weth
    poolFactory.createPool(address(tokenA), 2e18);

    thunderloan = new ThunderLoan();
    proxy = new ERC1967Proxy(address(thunderloan), "");
    thunderloan = ThunderLoan(address(proxy));
    thunderloan.initialize(address(poolFactory));

    console.log("Thunderloan fee precision: ", thunderloan.getFeePrecision());
    console.log("Thunderloan fee: ", thunderloan.getFee());
    console.log("Thunderloan is currently flashloaning: ", thunderloan.isCurrentlyFlashLoaning(tokenA));

    thunderloanUpgraded = new ThunderLoanUpgraded();
    ThunderLoan(address(proxy)).upgradeTo(address(thunderloanUpgraded));

    // console.log("Thunderloan fee precision: ", thunderloan.getFeePrecision());
    console.log("Thunderloan fee: ", thunderloan.getFee());
    console.log("Thunderloan is currently flashloaning: ", thunderloan.isCurrentlyFlashLoaning(tokenA));
}
```

## Tools Used

Foundry, Manual Analysis

## Recommended Mitigation

Declare variables in the same storage layout and variable keywords to avoid storage collisions.

# [M-03] User can call repay function when another user is flashloaning, depositing underlying tokens without paying fee

## Vulnerability Details

`ThunderLoan:repay` is a function allows users who created flash loan to repay the underlying token borrowed. However there are no additional checks to ensure that another user cannot call the function when another user is flashloaning.

## Impact

User can deposit underlying tokens without paying fee.

## Tools Used

Manual Analysis

## Recommended Mitigation

Add an additional check to ensure that the repay function can only be called by a user that created a flash loan.

```diff

+ error ThunderLoan__OnlyFlashLoanCreator();
+ mapping(address => bool) s_flashLoanCreator;

function flashloan(address receiverAddress, IERC20 token, uint256 amount, bytes calldata params) external {
    AssetToken assetToken = s_tokenToAssetToken[token];
    uint256 startingBalance = IERC20(token).balanceOf(address(assetToken));

    if (amount > startingBalance) {
        revert ThunderLoan__NotEnoughTokenBalance(startingBalance, amount);
    }

    if (!receiverAddress.isContract()) {
        revert ThunderLoan__CallerIsNotContract();
    }

    uint256 fee = getCalculatedFee(token, amount);
    // slither-disable-next-line reentrancy-vulnerabilities-2 reentrancy-vulnerabilities-3
    assetToken.updateExchangeRate(fee);

    emit FlashLoan(receiverAddress, token, amount, fee, params);

    s_currentlyFlashLoaning[token] = true;
+   s_flashLoanCreator[msg.sender] = true;
    assetToken.transferUnderlyingTo(receiverAddress, amount);
    // slither-disable-next-line unused-return reentrancy-vulnerabilities-2
    receiverAddress.functionCall(
        abi.encodeWithSignature(
            "executeOperation(address,uint256,uint256,address,bytes)",
            address(token),
            amount,
            fee,
            msg.sender,
            params
        )
    );

    uint256 endingBalance = token.balanceOf(address(assetToken));
    if (endingBalance < startingBalance + fee) {
        revert ThunderLoan__NotPaidBack(startingBalance + fee, endingBalance);
    }
    s_currentlyFlashLoaning[token] = false;
+   s_flashLoanCreator[msg.sender] = false;
}

function repay(IERC20 token, uint256 amount) public {
    if (!s_currentlyFlashLoaning[token]) {
        revert ThunderLoan__NotCurrentlyFlashLoaning();
    }

+    if (!s_flashLoanCreator[tx.origin]) {
+        revert ThunderLoan__OnlyFlashLoanCreator();
+    }

    AssetToken assetToken = s_tokenToAssetToken[IERC20(token)];
    token.safeTransferFrom(msg.sender, address(assetToken), amount);
}
```

# [M-04] Deletion of AssetToken in mapping can lead to funds being locked permanently

## Vulnerability Details

In `ThunderLoan:setAllowedToken`, No checks are perform on whether the AssetToken has any funds before its mapping is deleted in `s_tokenToAssetToken`. Once deleted, underlying tokens mapped to the AssetToken can never be withdrawn and will be locked permanently in the contract.

## Impact

Funds can be locked in the contract, leading to a loss of funds for the user.

## Tools Used

Manual Analysis, Foundry

## Recommended Mitigation

Add a check in `setAllowedToken` to ensure that the AssetToken has no funds before deleting the mapping.

```diff
+ error ThunderLoan__AssetTokenHasFunds();
function setAllowedToken(IERC20 token, bool allowed) external onlyOwner returns (AssetToken) {
    if (allowed) {
        if (address(s_tokenToAssetToken[token]) != address(0)) {
            revert ThunderLoan__AlreadyAllowed();
        }
        string memory name = string.concat("ThunderLoan ", IERC20Metadata(address(token)).name());
        string memory symbol = string.concat("tl", IERC20Metadata(address(token)).symbol());
        AssetToken assetToken = new AssetToken(address(this), token, name, symbol);
        s_tokenToAssetToken[token] = assetToken;
        emit AllowedTokenSet(token, assetToken, allowed);
        return assetToken;
    } else {
        AssetToken assetToken = s_tokenToAssetToken[token];
+        if (token.balanceOf(address(assetToken)) > 0) {
+            revert ThunderLoan__AssetTokenHasFunds();
+        }
        delete s_tokenToAssetToken[token];
        emit AllowedTokenSet(token, assetToken, allowed);
        return assetToken;
    }
}
```
