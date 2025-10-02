# [H-1] **In `Dinero` withdraw request manager, uint16 `s_batchNonce` can overflow**

## **Vulnerability Details**

In `DineroWithdrawRequestManager`, currently there is a state variable `s_batchNonce` that keeps track of the nonces during withdrawal initiations for `pirexETH` redemption initiations that can come in batches. The problem arises due to the use of a small `uint16` nonce variable, which means once the batch nonce increments to greater than `2**16 -1 = 65,535`, `s_batchNonce` will overflow and revert in the `_initiateWithdrawImpl` call.

This would mean that after ~65k withdrawal initiations (which is highly possible), the call to `_initiateWithdrawImpl` will always cause `s_batchNonce` to overflow and revert.

```
    function _initiateWithdrawImpl(
        address /* account */,
        uint256 amountToWithdraw,
        bytes calldata /* data */
    ) override internal returns (uint256 requestId) {
        if (YIELD_TOKEN == address(apxETH)) {
            // First redeem the apxETH to pxETH before we initiate the redemption3
            amountToWithdraw = apxETH.redeem(amountToWithdraw, address(this), address(this));
        }

        uint256 initialBatchId = PirexETH.batchId();
        pxETH.approve(address(PirexETH), amountToWithdraw);
        // TODO: what do we put for should trigger validator exit?
        PirexETH.initiateRedemption(amountToWithdraw, address(this), false);
        uint256 finalBatchId = PirexETH.batchId();
@>        uint256 nonce = ++s_batchNonce; //@audit this overflows and reverts after s_batchNonce > 65535

        // May require multiple batches to complete the redemption
        require(initialBatchId < MAX_BATCH_ID);
        require(finalBatchId < MAX_BATCH_ID);
        // Initial and final batch ids may overlap between requests so the nonce is used to ensure uniqueness
        return nonce << 240 | initialBatchId << 120 | finalBatchId;
    }
```

## **Root Cause**

Variable size is too small for nonce

## **Mitigation**

Consider using a larger variable (uint256) to store the batch nonces. Consequently, consider modifying the methodology when generating `requestId` to use a hash and store the relevant information required (`initialBatchId`, `finalBatchId`) in a separate mapping

## **POC**

Consider the following scenario:

1. The DineroWithdrawRequestManager has been operating for some time and has processed 65,535 withdrawal batches, bringing s_batchNonce to its maximum uint16 value
2. A user initiates a new withdrawal request by calling _initiateWithdrawImpl()
3. The function executes normally:
    - Redeems apxETH if needed
    - Gets initialBatchId from PirexETH
    - Approves and initiates redemption
    - Gets finalBatchId
4. When trying to increment s_batchNonce (currently at 65,535):
    
    ```
    uint256 nonce = ++s_batchNonce; // Attempts to increment 65,535 to 65,536
    ```
    
5. Since s_batchNonce is uint16, this increment causes an overflow:
    - 65,535 + 1 = 65,536
    - 65,536 exceeds maximum uint16 value (65,535)
    - The operation reverts due to overflow protection
6. The withdrawal request fails completely, blocking all future withdrawals since the nonce can no longer be incremented

This demonstrates how the uint16 size limitation creates a hard cap on the number of withdrawal batches that can be processed before the system becomes unusable.

## **Impact**

Initiating withdrawals will be permanently DOSed

## **LOC**

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/withdraws/Dinero.sol#L32


# [H-2] **Dinero `_finalizeWithdrawImpl` incorrectly includes final `batchId`**

## **Vulnerability Details**

Users can finalize withdrawals in two ways:

1. Through `MorphoLendingRouter.exitPosition`
2. Directly via `AbstractYieldStrategy.redeemNative` for liquidators with vault shares

Both paths eventually call `_redeemShares` on the strategy contract, which follows this call flow:

`AbstractStakingStrategy._redeemShares` -> `AbstractWithdrawRequestManager.finalizeAndRedeemWithdrawRequest` -> `AbstractWithdrawRequestManager._finalizeWithdraw` -> `Dinero._finalizeWithdrawImpl`

The vulnerability lies in `Dinero._finalizeWithdrawImpl`, which processes all `batchIds` from the `PirexETH` redemption, including the final batch. This becomes problematic because of how `PirexETHValidators._initiateRedemption` handles batch IDs and minting.

In `PirexETHValidators._initiateRedemption`, the `batchId` is post-incremented after each validator allocation, but `upxETH` tokens are only minted for the final batch if there is a remaining amount. This creates a mismatch where:

1. The final `batchId` is incremented but may not have any `upxETH` minted
2. When `Dinero._finalizeWithdrawImpl` processes this empty final batch, it can accidentally claim `upxETH` that was minted for subsequent withdrawal requests by other users

```
    function _initiateRedemption(
        uint256 _pxEthAmount,
        address _receiver,
        bool _shouldTriggerValidatorExit
    ) internal {
        pendingWithdrawal += _pxEthAmount;

        while (pendingWithdrawal / DEPOSIT_SIZE != 0) {
            uint256 _allocationPossible = DEPOSIT_SIZE +
                _pxEthAmount -
                pendingWithdrawal;

            upxEth.mint(_receiver, batchId, _allocationPossible, "");

            (bytes memory _pubKey, , , , ) = _stakingValidators.getNext(
                withdrawalCredentials
            );

            pendingWithdrawal -= DEPOSIT_SIZE;
            _pxEthAmount -= _allocationPossible;

            oracleAdapter.requestVoluntaryExit(_pubKey);

@>            batchIdToValidator[batchId++] = _pubKey; //@audit  batchId post incremented
            status[_pubKey] = DataTypes.ValidatorStatus.Withdrawable;
        }

        if (_shouldTriggerValidatorExit && _pxEthAmount > 0)
            revert Errors.NoPartialInitiateRedemption();

        if (_pxEthAmount > 0) {
@>            upxEth.mint(_receiver, batchId, _pxEthAmount, ""); //@audit minting only happens if _pxEthAmount > 0
        }
    }
```

However in `Dinero._initiateWithdrawImpl` which is called during withrawal intiations, the `finalBatchId` is always the final one retrieved from `PirexETH` contract

```
    function _initiateWithdrawImpl(
        address /* account */,
        uint256 amountToWithdraw,
        bytes calldata /* data */
    ) override internal returns (uint256 requestId) {
        if (YIELD_TOKEN == address(apxETH)) {
            // First redeem the apxETH to pxETH before we initiate the redemption
            amountToWithdraw = apxETH.redeem(amountToWithdraw, address(this), address(this));
        }

        uint256 initialBatchId = PirexETH.batchId();
        pxETH.approve(address(PirexETH), amountToWithdraw);
        // TODO: what do we put for should trigger validator exit?
        PirexETH.initiateRedemption(amountToWithdraw, address(this), false);
@>        uint256 finalBatchId = PirexETH.batchId();
        uint256 nonce = ++s_batchNonce;

        // May require multiple batches to complete the redemption
        require(initialBatchId < MAX_BATCH_ID);
        require(finalBatchId < MAX_BATCH_ID);
        // Initial and final batch ids may overlap between requests so the nonce is used to ensure uniqueness
@>        return nonce << 240 | initialBatchId << 120 | finalBatchId; // @audit encoded
    }
```

In `Dinero._finalizeWithdrawImpl`, which handles redeeming shares for assets during position exits, the loop iterates up to and including `finalBatchId`, regardless of whether `upxETH` tokens were actually minted to the Dinero withdraw request manager during that user's withdrawal initiation

```
    function _finalizeWithdrawImpl(
        address /* account */,
        uint256 requestId
    ) internal override returns (uint256 tokensClaimed, bool finalized) {
        finalized = canFinalizeWithdrawRequest(requestId);

        if (finalized) {
            (uint256 initialBatchId, uint256 finalBatchId) = _decodeBatchIds(requestId);

@>            for (uint256 i = initialBatchId; i <= finalBatchId; i++) { //@audit finalBatchId included
                uint256 assets = upxETH.balanceOf(address(this), i);
                if (assets == 0) continue;
                PirexETH.redeemWithUpxEth(i, assets, address(this));
                tokensClaimed += assets;
            }
        }

        WETH.deposit{value: tokensClaimed}();
    }

```

Ultimately, this may cause finalization of withdrawals to incur loss of assets for users whose withdraw finalization is tied to the same `finalBatchId` of the `upxETH` required to withdraw their underlying `ETH` and subsequently `WETH`

## **Root Cause**

Wrong logic in determining `finalBatchId` of upxETH minted to withdraw request manager associated with the withdrawal initiation of the user.

## **POC**

1. Alice initiates a withdrawal of 100 pxETH
    - Current batchId = 5
    - PirexETH._initiateRedemption processes withdrawal:
        - Mints upxETH for batchId 5 = 32 ETH
        - Increments to batchId 6
        - Suppose no upxETH minted for batchId 6
    - Dinero._initiateWithdrawImpl records:
        - initialBatchId = 5
        - finalBatchId = 6
        - Returns encoded requestId with both batch IDs
2. Bob initiates a withdrawal of 100 pxETH
    - Current batchId = 6
    - PirexETH._initiateRedemption processes withdrawal:
        - Mints upxETH for batchId 6 = 32 ETH
        - Increments to batchId 7
        - Suppose no upxETH minted for batchId 7
    - Dinero._initiateWithdrawImpl records:
        - initialBatchId = 6
        - finalBatchId = 7
        - Returns encoded requestId with both batch IDs
3. Alice attempts to finalize withdrawal
    - Dinero._finalizeWithdrawImpl loops from batchId 5 to 6
    - For batchId 5: Claims her 32 ETH upxETH
    - For batchId 6: Claims Bob's 32 ETH upxETH (since finalBatchId included)
    - Alice receives 64 ETH -> WETH total instead of 32 WETH
4. Bob attempts to finalize withdrawal
    - Dinero._finalizeWithdrawImpl loops from batchId 6 to 7
    - For batchId 6: No upxETH left (claimed by Alice)
    - For batchId 7: No upxETH minted
    - Bob receives 0 ETH -> WETH despite having valid claim to 32 ETH -> WETH or at the very least his call to swap the WETH for other underlying asset will fail (due to slippage) and cause his yield tokens to be stuck in the withdraw request manager until rescued by owner

## **Impact**

Loss of assets for users whose withdraw finalization is tied to the same `finalBatchId` of the `upxETH` required to withdraw their underlying `ETH` and subsequently `WETH`.

Funds stuck in withdraw request manager if trade for WETH -> underlying vault asset happens as user is protected by slippage

## **Mitigation**

Directly query the `batchId` minted to the user via `UpxETH.balanceOf` before and after the initiate redemption process via `PirexETH` instead of through `PirexETH.batchId`

```
// UpxETH.ERC1155 contract

mapping(address => mapping(uint256 => uint256)) public balanceOf;
```

## **LOC**

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/withdraws/Dinero.sol#L60

# [M-1] **Malicious users can prevent initialization of Morpho Market**

## **Vulnerability Details**

In `MorphoLendingRouter.initializeMarket`, a user can currently block the initialization of a vault in the `s_morphoParams[vault]` state mapping by directly invoking `Morpho.createMarket` and front-running any transactions to `MorphoLendingRouter.initializeMarket`. This occurs because the state variable is set during the process of creating a new market through `Morpho.createMarket`.

Given that the creation of new markets can be time-sensitive due to the volatility of underlying asset prices, this situation could lead to potential losses for the protocol if there are insufficient additional markets available for users to create positions with.

In `MorphoLendingRouter.initializeMarket`

```
    function initializeMarket(address vault, address irm, uint256 lltv) external {
        require(ADDRESS_REGISTRY.upgradeAdmin() == msg.sender);
        // Cannot override parameters once they are set
        require(s_morphoParams[vault].irm == address(0));
        require(s_morphoParams[vault].lltv == 0);

        s_morphoParams[vault] = MorphoParams({
            irm: irm,
            lltv: lltv
        });

@>        MORPHO.createMarket(marketParams(vault)); //@audit this reverts if market is directly created via Morpho.createMarket
    }
```

In `Morpho.createMarket`

```
    function createMarket(MarketParams memory marketParams) external {
        Id id = marketParams.id();
        require(isIrmEnabled[marketParams.irm], ErrorsLib.IRM_NOT_ENABLED);
        require(isLltvEnabled[marketParams.lltv], ErrorsLib.LLTV_NOT_ENABLED);
@>        require(market[id].lastUpdate == 0, ErrorsLib.MARKET_ALREADY_CREATED); //@audit malicious actor can create market directly via this function call which subsequently DOS-es calls form MorphoLendingRouter to initialize vault and create market

        // Safe "unchecked" cast.
        market[id].lastUpdate = uint128(block.timestamp);
        idToMarketParams[id] = marketParams;

        emit EventsLib.CreateMarket(id, marketParams);

        // Call to initialize the IRM in case it is stateful.
        if (marketParams.irm != address(0)) IIrm(marketParams.irm).borrowRate(marketParams, market[id]);
    }
```

## **Root Cause**

Lack of mechanisms to initialize vault in `MorphoLendingRouter` in the event a market is already creeated directly via `Morpho`

## **POC**

Consider the following simplistic scenario

1. Alice initiates anew market via `MorphoLendingRouter.initializeMarket` with the below `marketParams`
    - loanToken: USDC
    - collateralToken: 0xVault
    - oracle: 0xVault
    - irm: 0xirm
    - lltv: 0.95
2. In Morpho, the `id` of the the created market would be the `keccak256` hash of the market params
3. Bob observes Alice's transaction and directly calls `Morpho.createMarket` with the same `marketParams`
    - This populates `the Morpho.market[id].lastUpdate` variable
4. Alice's transaction fails, and the vault fails to initialize in `MorphoLendingRouter.s_morphoParams[vault]` which prevents any positions from being created on the router
5. In the end, Alice is DOS-ed and protocol loses yield as positions cannot be entered via the `MorphoLendingRouter` without the intialization of the `s_morphoParams[vault]` mapping since most user actions require the vault information to be retrieved from `MorphoLendingRouter.marketParams` call.

## **Impact**

- Broken core functionality due to DOS
- Loss of yield for protocol due to prevention of positions being created from lending router

## **Mitigation**

Consider implementing a check to determine if the market has already been created; if so, proceed to initialize the vault in the mapping.

## **LOC**

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/MorphoLendingRouter.sol#L40

# [M-2] **Lack of USDT support when migrating positions**

## **Vulnerability Details**

Currently in the README, it is indicated that USDT is supported.

However, in the `AbstractLendingRouter._enterOrMigrate` call, a regular `approve` call is used instead of a `forceApprove`.

This means it is unable to support USDT due to the use of `approve` functions in the `_enterOrmigrate` method, as approve does not return a boolean value.

This means calls to `_enterOrMigrate` will consistently fail for USDT

```
    function _enterOrMigrate(
        address onBehalf,
        address vault,
        address asset,
        uint256 assetAmount,
        bytes memory depositData,
        address migrateFrom
    ) internal returns (uint256 sharesReceived) {
        if (migrateFrom != address(0)) {
            // Allow the previous lending router to repay the debt from assets held here.
            ERC20(asset).checkApprove(migrateFrom, assetAmount);
            sharesReceived = ILendingRouter(migrateFrom).balanceOfCollateral(onBehalf, vault);

            // Must migrate the entire position
            ILendingRouter(migrateFrom).exitPosition(
                onBehalf, vault, address(this), sharesReceived, type(uint256).max, bytes("")
            );
        } else {
@>            ERC20(asset).approve(vault, assetAmount); //@audit fails for USDT
            sharesReceived = IYieldStrategy(vault).mintShares(assetAmount, onBehalf, depositData);
        }

        _supplyCollateral(onBehalf, vault, asset, sharesReceived);
    }
```

## **Root Cause**

Use of `approve` will prevent USDT usage in `AbstractLendingRouter`

## **Impact**

Broken core functionality due to lack of support for USDT specifcally mentioned in README

## **Mitigation**

Use `checkApprove / safeApprove` instead of regular approve

## **LOC**

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L240

# [M-3] **Migrating positions from router A -> B can fail**

## **Vulnerability Details**

When migrating a position from Router A to Router B, the execution follows this specific call flow:

`RouterB.allocateAndMigratePosition` -> `RouterB.migratePosition` -> `RouterB._enterPosition` -> `RouterB._enterOrMigrate` -> `RouterA.exitPosition` -> `RouterA._exitWithRepay` -> `RouterA.Morpho.repay` -> `RouterA.onMorphoRepay` -> (return from call) `RouterB._supplyCollateral`

The issue stems from always passing `type(uint256).max` as the `assetsToRepay` parameter in the `RouterB.exitPosition` call, regardless of the actual borrowed amount. When a user has no outstanding borrowed amount, this causes the `RouterB.Morpho.repay` call to revert due to the `UtilsLib.exactlyOneZero(assets, shares)` check failing since both assets and shares would be 0 in this case.

Lets go through the call flow

In `RouterB.MorphoLendingPosition.allocateAndMigratePosition`

```
    function allocateAndMigratePosition(
        address onBehalf,
        address vault,
        address migrateFrom,
        MorphoAllocation[] calldata allocationData
    ) external payable isAuthorized(onBehalf, vault) {
        _allocate(vault, allocationData);
@>        migratePosition(onBehalf, vault, migrateFrom);
    }

```

In `RouterB.MorphoLendingPosition.migratePosition`

```
    function migratePosition(
        address onBehalf,
        address vault,
        address migrateFrom
    ) public override isAuthorized(onBehalf, vault) {
        if (!ADDRESS_REGISTRY.isLendingRouter(migrateFrom)) revert InvalidLendingRouter();
        // Borrow amount is set to the amount of debt owed to the previous lending router
@>        (uint256 borrowAmount, /* */, /* */) = ILendingRouter(migrateFrom).healthFactor(onBehalf, vault);

@>        _enterPosition(onBehalf, vault, 0, borrowAmount, bytes(""), migrateFrom); //@audit borrowAmount can be 0 here
    }
```

In `RouterB.AbstractLendingRouter._enterPostiion`

```
    function _enterPosition(
        address onBehalf,
        address vault,
        uint256 depositAssetAmount,
        uint256 borrowAmount,
        bytes memory depositData,
        address migrateFrom
    ) internal {
        address asset = IYieldStrategy(vault).asset();
        // Cannot enter a position if the account already has a native share balance
        if (IYieldStrategy(vault).balanceOf(onBehalf) > 0) revert CannotEnterPosition();

        // During migratePosition call flow, this is not called
        if (depositAssetAmount > 0) {
            // Take any margin deposit from the sender initially
            ERC20(asset).safeTransferFrom(msg.sender, address(this), depositAssetAmount);
        }

        if (borrowAmount > 0) {
            // For migratePosition call flow, flash loan the amount you owe on the previous router to repay past debt
            _flashBorrowAndEnter(
                onBehalf, vault, asset, depositAssetAmount, borrowAmount, depositData, migrateFrom
            );
        } else {
@>            _enterOrMigrate(onBehalf, vault, asset, depositAssetAmount, depositData, migrateFrom); //@audit borrowAmount = 0, go through _enterOrMigrate
        }

        ADDRESS_REGISTRY.setPosition(onBehalf, vault);
    }
```

In `RouterB.AbstractLendingRouter._enterOrMigrate`

```
    function _enterOrMigrate(
        address onBehalf,
        address vault,
        address asset,
        uint256 assetAmount,
        bytes memory depositData,
        address migrateFrom
    ) internal returns (uint256 sharesReceived) {
        if (migrateFrom != address(0)) {
            // Allow the previous lending router to repay the debt from assets held here.
            ERC20(asset).checkApprove(migrateFrom, assetAmount);
            sharesReceived = ILendingRouter(migrateFrom).balanceOfCollateral(onBehalf, vault);

            // Must migrate the entire position
            ILendingRouter(migrateFrom).exitPosition(
@>                onBehalf, vault, address(this), sharesReceived, type(uint256).max, bytes("") //@audit exit position via Router B with max uint256 assetToRepay
            );
        } else {
            // In the allocateAndEnterPosition flow, else block is always triggered since we don't migrate position
            ERC20(asset).approve(vault, assetAmount);
            sharesReceived = IYieldStrategy(vault).mintShares(assetAmount, onBehalf, depositData);
        }

        _supplyCollateral(onBehalf, vault, asset, sharesReceived);
    }
```

In `RouterB.AbstractLendingRouter.exitPosition`

```
    function exitPosition(
        address onBehalf,
        address vault,
        address receiver,
        uint256 sharesToRedeem,
        uint256 assetToRepay,
        bytes calldata redeemData
    ) external override isAuthorized(onBehalf, vault) {
        _checkExit(onBehalf, vault);

        address asset = IYieldStrategy(vault).asset();

        // Either exit position by repaying borrowed assets
        if (0 < assetToRepay) {
@>            _exitWithRepay(onBehalf, vault, asset, receiver, sharesToRedeem, assetToRepay, redeemData); //@audit assetToRepay == max uint256
        } else { // Or exit without paying anything
            address migrateTo = _isMigrate(receiver) ? receiver : address(0);
            uint256 assetsWithdrawn = _redeemShares(onBehalf, vault, asset, migrateTo, sharesToRedeem, redeemData);
            if (0 < assetsWithdrawn) ERC20(asset).safeTransfer(receiver, assetsWithdrawn);
        }

        if (balanceOfCollateral(onBehalf, vault) == 0) {
            ADDRESS_REGISTRY.clearPosition(onBehalf, vault);
        }
    }
```

In `RouterB.MorphoLendingRouter._exitWithRepay`

```
    function _exitWithRepay(
        address onBehalf,
        address vault,
        address asset,
        address receiver,
        uint256 sharesToRedeem,
        uint256 assetToRepay,
        bytes calldata redeemData
    ) internal override {
        MarketParams memory m = marketParams(vault, asset);

        uint256 sharesToRepay;
        if (assetToRepay == type(uint256).max) {
            // If assetToRepay is uint256.max then get the morpho borrow shares amount to
            // get a full exit.
@>            sharesToRepay = MORPHO.position(morphoId(m), onBehalf).borrowShares; //@audit brrowShares == 0
            assetToRepay = 0;
        }

        bytes memory repayData = abi.encode(
            onBehalf, vault, asset, receiver, sharesToRedeem, redeemData, _isMigrate(receiver)
        );

        // Will trigger a callback to onMorphoRepay
@>        MORPHO.repay(m, assetToRepay, sharesToRepay, onBehalf, repayData); //@audit both assetToRepay and sharesToRepay == 0, call reverts
    }
```

In `Morpho.repay`

```
    function repay(
        MarketParams memory marketParams,
        uint256 assets,
        uint256 shares,
        address onBehalf,
        bytes calldata data
    ) external returns (uint256, uint256) {
        Id id = marketParams.id();
        require(market[id].lastUpdate != 0, ErrorsLib.MARKET_NOT_CREATED);
@>        require(UtilsLib.exactlyOneZero(assets, shares), ErrorsLib.INCONSISTENT_INPUT); //@audit reverts as both shares and assets == 0
        require(onBehalf != address(0), ErrorsLib.ZERO_ADDRESS);

        _accrueInterest(marketParams, id);

        if (assets > 0) shares = assets.toSharesDown(market[id].totalBorrowAssets, market[id].totalBorrowShares);
        else assets = shares.toAssetsUp(market[id].totalBorrowAssets, market[id].totalBorrowShares);

        position[id][onBehalf].borrowShares -= shares.toUint128();
        market[id].totalBorrowShares -= shares.toUint128();
        market[id].totalBorrowAssets = UtilsLib.zeroFloorSub(market[id].totalBorrowAssets, assets).toUint128();

        // `assets` may be greater than `totalBorrowAssets` by 1.
        emit EventsLib.Repay(id, msg.sender, onBehalf, assets, shares);

        if (data.length > 0) IMorphoRepayCallback(msg.sender).onMorphoRepay(assets, data);

        IERC20(marketParams.loanToken).safeTransferFrom(msg.sender, address(this), assets);

        return (assets, shares);
    }
```

## **Root Cause**

Lack of mechanisms to skip repay when user actually has no borrowed amount on his position

## **POC**

Consider the following simplistic scenario:

1. User A has a position on Router A with:
    - 100 collateral shares
    - 0 borrow shares (no borrowed amount)
2. User A attempts to migrate their position from Router A to Router B by calling:
    
    ```
    RouterB.allocateAndMigratePosition(
        userA, // onBehalf
        vault,
        routerA, // migrateFrom
        [] // allocationData
    )
    ```
    
3. This triggers `RouterB.migratePosition()` which:
    - Calls `RouterA.healthFactor()` to get borrowAmount
    - borrowAmount = 0 since user has no borrows
    - Calls `_enterPosition()` with borrowAmount = 0
4. Inside `_enterPosition()`:
    - Since borrowAmount = 0, calls `_enterOrMigrate()`
    - Retrieves user's collateral shares (100)
    - Calls `RouterA.exitPosition()` with:
        - sharesToRedeem = 100
        - assetToRepay = type(uint256).max
5. `RouterA.exitPosition()` then:
    - Calls `_exitWithRepay()` since assetToRepay > 0
    - Gets user's borrowShares from Morpho = 0
    - Sets assetToRepay = 0 and sharesToRepay = 0
6. Finally calls `Morpho.repay()` with:
    - assets = 0
    - shares = 0
    - This reverts on `UtilsLib.exactlyOneZero()` check since both are 0
7. The entire migration transaction reverts, leaving User A unable to migrate their position from Router A to Router B.

## **Impact**

Permanenet DOS of migrations for users with no borrow positions.

## **Mitigation**

Consider skipping the `Morpho.repay` call entirely user does not have a borrow amount.

## **LOC**

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L237

# [M-4] **In `Ethena` withdraw request manager, tokens claimed can be 0 when cool down duration is set to 0**

## **Vulnerability Details**

The Ethena withdraw request manager allows users to finalize withdrawals in two ways: through the Router or by directly calling `redeemNative`.

When initializing a withdrawal, the following transfers occur:

1. The `sUSDe` yield token moves from the Strategy to the Ethena withdraw request manager
2. The withdraw request manager then transfers it to a newly cloned Holder contract
3. The Holder contract initiates Ethena's cooldown mechanism by burning `sUSDe` from holder and transferring `Usde` to the silo address to later claim the underlying `USDe` when finalizing withdraw request

A issue arises when the cooldown duration is set to 0. In this case, instead of entering the cooldown period, the Holder contract immediately redeems the `sUSDe` for `USDE` via the `sUSDe.redeem` function. This results in the underlying `USDE` being transferred directly to the Holder contract right after initialization.

An example call flow would be

1. Initate withdraw request - `MorphoLendingRouter.initiateWithdraw` -> `Ethena._initiateWithdrawImpl` -> `ClonedCooldownHolder.startCooldown` -> `EthenaCoolDownHolder._startCoolDown`
2. Initiate finalization of request - `MorphoLendingRouter.exitPosition` -> `AbstractLendingRouter._redeemShares` -> `AbstractYieldStrategy.burnShares` -> `AbstractYieldStrategy._burnShares` -> `AbstractStakingStrategy._redeemShares` -> back to `AbstractLendingRouter.exitPosition`

In `EthenaWithdrawRequestManager._initiateWithdrawImpl`

```
    function _initiateWithdrawImpl(
        address /* account */,
        uint256 balanceToTransfer,
        bytes calldata /* data */
    ) internal override returns (uint256 requestId) {
        EthenaCooldownHolder holder = EthenaCooldownHolder(Clones.clone(HOLDER_IMPLEMENTATION));
        sUSDe.transfer(address(holder), balanceToTransfer);
@>        holder.startCooldown(balanceToTransfer);

        return uint256(uint160(address(holder)));
    }
```

In `ClonedCoolDownHolder.startCooldown -> EthenaCoolDownHolder._startCoolDown`

```
    function _startCooldown(uint256 cooldownBalance) internal override {
        uint24 duration = sUSDe.cooldownDuration();
@>        if (duration == 0) {
            // If the cooldown duration is set to zero, can redeem immediately
@>            sUSDe.redeem(cooldownBalance, address(this), address(this)); //@audit instantly redeemed to holder
        } else {
            // If we execute a second cooldown while one exists, the cooldown end
            // will be pushed further out. This holder should only ever have one
            // cooldown ever.
            require(sUSDe.cooldowns(address(this)).cooldownEnd == 0);
            sUSDe.cooldownShares(cooldownBalance);
        }
    }
```

Subsequently when users attempt to exit positions through either the MorphoLendingRouter or by directly redeeming underlying assets via vault share burning, they follow a withdrawal process that involves several contract calls:

1. `AbstractStakingStrategy._redeemShares`
2. `AbstractWithdrawRequestManager.finalizeAndRedeemWithdrawRequest`
3. `AbstractWithdrawRequestManager._finalizeWithdraw`
4. `Ethena._finalizeWithdrawImpl`

When `Ethena._finalizeWithdrawImpl` calls `finalizeCooldown`, the `tokensClaimed` value will be 0 since the cooldown duration is zero and the USDe tokens were already redeemed to the holder contract earlier during initialization. As a result, the holder contract's USDe balance remains unchanged during finalization. This will result in the `balanceAfter - balanceBefore` calculation for `tokensClaimed` to return 0

In `EthenaWithdrawRequestManager._finalizeWithdrawImpl`

```
    function _finalizeWithdrawImpl(
        address /* account */,
        uint256 requestId
    ) internal override returns (uint256 tokensClaimed, bool finalized) {
        EthenaCooldownHolder holder = EthenaCooldownHolder(address(uint160(requestId)));
@>        (tokensClaimed, finalized) = holder.finalizeCooldown();
    }
```

```
    function _finalizeCooldown() internal override returns (uint256 tokensClaimed, bool finalized) {
        uint24 duration = sUSDe.cooldownDuration();
        IsUSDe.UserCooldown memory userCooldown = sUSDe.cooldowns(address(this));

        if (block.timestamp < userCooldown.cooldownEnd && 0 < duration) {
            // Cooldown has not completed, return a false for finalized
            return (0, false);
        }

@>        uint256 balanceBefore = USDe.balanceOf(address(this));
        // If a cooldown has been initiated, need to call unstake to complete it. If
        // duration was set to zero then the USDe will be on this contract already.
@>        if (0 < userCooldown.cooldownEnd) sUSDe.unstake(address(this)); //@audit skipped when cooldown duration is 0
@>        uint256 balanceAfter = USDe.balanceOf(address(this));

        // USDe is immutable. It cannot have a transfer tax and it is ERC20 compliant
        // so we do not need to use the additional protections here.
@>        tokensClaimed = balanceAfter - balanceBefore; //@audit calculated as 0 since balanceAfter == balanceBefore on holder contract as USDe was previously already redeemed to the holder contract
        USDe.transfer(manager, tokensClaimed);
        finalized = true;
    }
```

Subsequently when trying to finalize the withdrawal, the `tokensWithdrawn` will be returned as 0 and user would burn their vault shares without ever receiving any asset.

In `AbstractLendingRouter.exitPosition`

```
    function exitPosition(
        address onBehalf,
        address vault,
        address receiver,
        uint256 sharesToRedeem,
        uint256 assetToRepay,
        bytes calldata redeemData
    ) external override isAuthorized(onBehalf, vault) {
        _checkExit(onBehalf, vault);

        address asset = IYieldStrategy(vault).asset();

        // Either exit position by repaying borrowed assets
        if (0 < assetToRepay) {
            _exitWithRepay(onBehalf, vault, asset, receiver, sharesToRedeem, assetToRepay, redeemData);
        } else { // Or exit without paying anything
            address migrateTo = _isMigrate(receiver) ? receiver : address(0);
@>            uint256 assetsWithdrawn = _redeemShares(onBehalf, vault, asset, migrateTo, sharesToRedeem, redeemData); //@audit enteres AbstractStakingStrategy._redeemShares
@>            if (0 < assetsWithdrawn) ERC20(asset).safeTransfer(receiver, assetsWithdrawn); //@audit no asset transferred to receiver
        }

        if (balanceOfCollateral(onBehalf, vault) == 0) {
            ADDRESS_REGISTRY.clearPosition(onBehalf, vault);
        }
    }
```

In `AbstractLendingRouter.burnShares`

```
    function _redeemShares(
        address sharesOwner,
        address vault,
        address asset,
        address migrateTo,
        uint256 sharesToRedeem,
        bytes memory redeemData
    ) internal returns (uint256 assetsWithdrawn) {
        address receiver = migrateTo == address(0) ? sharesOwner : migrateTo;
        uint256 sharesHeld = balanceOfCollateral(sharesOwner, vault);

        // Allows the transfer from the lending market to the sharesOwner
        IYieldStrategy(vault).allowTransfer(receiver, sharesToRedeem, sharesOwner);
        _withdrawCollateral(vault, asset, sharesToRedeem, sharesOwner, receiver);

        // If we are not migrating then burn the shares
        if (migrateTo == address(0)) {
@>            assetsWithdrawn = IYieldStrategy(vault).burnShares(
                sharesOwner, sharesToRedeem, sharesHeld, redeemData
            );
        }
    }
```

In `AbstractYieldStrategy.burnShares` -> `AbstractYieldStrategy._burnShares`

```
    function burnShares(
        address sharesOwner,
        uint256 sharesToBurn,
        uint256 sharesHeld,
        bytes calldata redeemData
    ) external override onlyLendingRouter setCurrentAccount(sharesOwner) nonReentrant returns (uint256 assetsWithdrawn) {
@>        assetsWithdrawn = _burnShares(sharesToBurn, sharesHeld, redeemData, sharesOwner); // @audit assets is zero

        // Send all the assets back to the lending router
@>        ERC20(asset).safeTransfer(t_CurrentLendingRouter, assetsWithdrawn); //@audit no asset send back to lending router
    }
```

```
    function _burnShares(
        uint256 sharesToBurn,
        uint256 /* sharesHeld */,
        bytes memory redeemData,
        address sharesOwner
    ) internal virtual returns (uint256 assetsWithdrawn) {
        if (sharesToBurn == 0) return 0;
        bool isEscrowed = _isWithdrawRequestPending(sharesOwner);

        uint256 initialAssetBalance = TokenUtils.tokenBalance(asset);

        // First accrue fees on the yield token
        _accrueFees();
@>        _redeemShares(sharesToBurn, sharesOwner, isEscrowed, redeemData);
        if (isEscrowed) s_escrowedShares -= sharesToBurn;

        uint256 finalAssetBalance = TokenUtils.tokenBalance(asset);
        assetsWithdrawn = finalAssetBalance - initialAssetBalance;

        // This burns the shares from the sharesOwner's balance
        _burn(sharesOwner, sharesToBurn);
    }
```

In `AbstractStakingStrategy._redeemShares`

```
    function _redeemShares(
        uint256 sharesToRedeem,
        address sharesOwner,
        bool isEscrowed,
        bytes memory redeemData
    ) internal override {
        if (isEscrowed) {
            (WithdrawRequest memory w, /* */) = withdrawRequestManager.getWithdrawRequest(address(this), sharesOwner);
            uint256 yieldTokensBurned = uint256(w.yieldTokenAmount) * sharesToRedeem / w.sharesAmount;

@>            (uint256 tokensClaimed, bool finalized) = withdrawRequestManager.finalizeAndRedeemWithdrawRequest({ //@audit tokensClaimed is 0
                account: sharesOwner, withdrawYieldTokenAmount: yieldTokensBurned, sharesToBurn: sharesToRedeem
            });
            if (!finalized) revert WithdrawRequestNotFinalized(w.requestId);

            // Trades may be required here if the borrowed token is not the same as what is
            // received when redeeming.
            if (asset != withdrawToken) {
                RedeemParams memory params = abi.decode(redeemData, (RedeemParams));
                Trade memory trade = Trade({
                    tradeType: TradeType.EXACT_IN_SINGLE,
                    sellToken: address(withdrawToken),
                    buyToken: address(asset),
                    amount: tokensClaimed,
                    limit: params.minPurchaseAmount,
                    deadline: block.timestamp,
                    exchangeData: params.exchangeData
                });

                _executeTrade(trade, params.dexId);
            }
        } else {
            uint256 yieldTokensBurned = convertSharesToYieldToken(sharesToRedeem);
            _executeInstantRedemption(yieldTokensBurned, redeemData);
        }
    }
```

## **Root Cause**

Lack of mechanisms to allow user to finalize withdraw requests when cooldown duration is zero on sUSDe vault as underlying USDe has already been redeemed directly to the holder contract

## **POC**

Here's the step-by-step scenario showing how users can lose their vault shares when cooldown duration is zero:

1. User initiates a withdrawal request through `MorphoLendingRouter.initiateWithdraw`:
    - `sUSDe` yield tokens are transferred from Strategy to Ethena withdraw request manager
    - Manager deploys new Holder contract and transfers tokens to it
    - Since cooldown duration is 0, Holder immediately redeems `sUSDe` for `USDe` via `sUSDe.redeem()`
    - `USDe` tokens are transferred directly to Holder contract
2. User attempts to finalize withdrawal through `MorphoLendingRouter.exitPosition`:
    - Calls `AbstractLendingRouter._redeemShares`
    - Which calls `AbstractYieldStrategy.burnShares`
    - Then `AbstractStakingStrategy._redeemShares`
    - Finally reaches `EthenaWithdrawRequestManager._finalizeWithdrawImpl`
3. In `EthenaWithdrawRequestManager._finalizeWithdrawImpl`:
    - Calls `holder.finalizeCooldown()`
    - Since cooldown duration is 0, skips `sUSDe.unstake()` call
    - Checks `balanceAfter - balanceBefore` which equals 0 since:
        - `balanceBefore` = Current USDe balance in Holder (from step 1)
        - `balanceAfter` = Same balance since no new tokens received
    - Returns `tokensClaimed = 0`
4. Back in `AbstractLendingRouter.exitPosition`:
    - User's vault shares are burned
    - But `assetsWithdrawn = 0` so no assets are transferred to receiver
    - User loses their vault shares without receiving any underlying assets

The core issue is that when cooldown duration is 0, the USDe redemption happens immediately during withdrawal request initialization, but the finalization logic still expects tokens to be claimed during the finalization step. This mismatch causes the finalization to report 0 tokens claimed even though the Holder contract holds the redeemed USDe.

## **Impact**

Loss of vault shares for user

Loss of funds (assets) for user

## **Mitigation**

In Ethena withdraw request manager, if the cooldown duration on sUSDe vault is zero, consider taking the full balance of USDe held by the holder contract stored in an internal accounting variable.

## **LOC**

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/withdraws/Ethena.sol#L47