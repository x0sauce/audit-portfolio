# **Any user can `claimRefund` for another user's reverted transaction in `GatewayTransferNative`**

## **Vulnerability Details**

In `GatewayTransferNative.claimRefund`, any individual can claim refunds belonging to other users as long as the wallet address is not a 20-byte address. As previously noted, the `GatewayTransferNative.withdrawAndCall` function incorrectly specifies the receiver address of the user on the Solana/Ethereum chain instead of their corresponding address on Zetachain. This oversight allows anyone to claim refunds associated with addresses that are not 20 bytes in length. For instance, since Solana addresses are 32 bytes, this means that any user can claim the refund of another user whose `refundInfo.walletAddress` is a Solana address.

In `GatewayTransferNative.withdrawAndCall`

```solidity
    function withdrawAndCall(
        bytes32 externalId,
        bytes memory contractAddress,
        address targetZRC20,
        uint256 outputAmount,
        bytes memory receiver,
        bytes memory message
    ) internal {
        gateway.withdrawAndCall(
            contractAddress,
            outputAmount,
            targetZRC20,
            message,
            CallOptions({
                isArbitraryCall: false,
                gasLimit: gasLimit
            }),
            RevertOptions({
                revertAddress: address(this),
                callOnRevert: true,
                abortAddress: address(0),
@>                revertMessage: bytes.concat(externalId, receiver), //@audit revert message incorrectly concats address of receiver at destination chain (can be solana 32 bytes address)
                onRevertGasLimit: gasLimit
            })
        );
    }

```

In `GatewayTransferNative.claimRefund`

```solidity
    function claimRefund(bytes32 externalId) external {
        RefundInfo storage refundInfo = refundInfos[externalId];

@>        address receiver = msg.sender;
        if(refundInfo.walletAddress.length == 20) {
            receiver = address(uint160(bytes20(refundInfo.walletAddress)));
        }
@>        require(bots[msg.sender] || msg.sender == receiver, "INVALID_CALLER"); // @audit check will pass as long as it is not referring to 20 bytes address
        require(refundInfo.externalId != "", "REFUND_NOT_EXIST");

        TransferHelper.safeTransfer(refundInfo.token, receiver, refundInfo.amount);
        delete refundInfos[externalId];

        emit EddyCrossChainRefundClaimed(
            externalId,
            refundInfo.token,
            refundInfo.amount,
            abi.encodePacked(msg.sender)
        );
    }

```

## **POC**

Consider the following scenario

1. Alice initiates a call to `GatewayTransferNative.withdrawToNativeChain`
    - During this process, she calls `GatewayTransferNative.withdrawAndCall`
    - She provides her receiver address (`0xSolanaAlice32Bytes`) on the Solana chain (32 bytes) for the call
2. Alice's call fails, and her refundInfo[externalId].RefundInfo.walletAddress holds her wallet address of `0xSolanaAlice32Bytes`.
3. Bob notices this and utilizes Alice's `externalId` to invoke `GatewayTransferNative.claimRefund`
4. Bob's call is successful, as `receiver = msg.sender` is cahced on the Zetachain call, allowing the tokens to be sent to him
5. Ultimately, Alice loses her funds

## **Root Cause**

Wrong logic to check authorized addresses that can claim refunds

## **Impact**

Loss of funds for user

## **LOC**

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewayTransferNative.sol#L661

# **Users can exploit `GatewayTransferNative` during `withdrawToNativeChain` calls to drain funds or cause the protocol to incur losses in fees through direct transfers, as there are insufficient checks to ensure that the provided ZRC20 token address corresponds with the token address used for swapping the output token before initiating the withdrawal process to the destination chain.**

## **Vulnerability Details**

In `GatewayTransferNative`, any user can invoke `GatewayTransferNative.withdrawToNativeChain` using a token of lesser value to cover fees while utilizing the actual token they wish to swap. For instance, if a user intends to convert `params.fromToken` to a target output token through `DODORouteProxy`, they can opt to use a token with a lower value for the fee payment.

In `GatewayTransferNative.withdrawToNativeChain`

```solidity
    function withdrawToNativeChain(
@>        address zrc20, //@audit  ZRC20 token is not checked against actual token used for swap
        uint256 amount,
        bytes calldata message
    ) external payable {
        if(zrc20 != _ETH_ADDRESS_) {
            require(IZRC20(zrc20).transferFrom(msg.sender, address(this), amount), "INSUFFICIENT ALLOWANCE: TRANSFER FROM FAILED");
        }

        globalNonce++;
        bytes32 externalId = _calcExternalId(msg.sender);

        // Decode message and decompress swap params
        (DecodedMessage memory decoded, MixSwapParams memory params) = SwapDataHelperLib.decodeMessage(message);

        // Check if the message is from Bitcoin to Solana
        // address evmWalletAddress = (decoded.dstChainId == BITCOIN_EDDY || decoded.dstChainId == SOLANA_EDDY)
        //     ? msg.sender
        //     : address(uint160(bytes20(decoded.receiver)));

        // Transfer platform fees
@>        uint256 platformFeesForTx = _handleFeeTransfer(zrc20, amount); // platformFee = 5 <> 0.5% //@audit payment of fees uses user supplied ZRC20 which can be a low valued token e.g. SHIB.ETH ZRC20 token
        amount -= platformFeesForTx;

        // Swap on DODO Router
@>        uint256 outputAmount = _doMixSwap(decoded.swapDataZ, amount, params); //@audit user can do direct transfer to GatewayTransferNative contract for actual token they wish to use to swap

        // Withdraw
        if (decoded.dstChainId == BITCOIN_EDDY) {
            (, uint256 gasFee) = IZRC20(decoded.targetZRC20).withdrawGasFee();
            _handleBitcoinWithdraw(
                externalId,
                decoded,
                outputAmount,
                gasFee
            );

            emit EddyCrossChainSwap(
                externalId,
                ZETACHAIN,
                decoded.dstChainId,
                zrc20,
                decoded.targetZRC20,
                amount,
                outputAmount - gasFee,
                decoded.sender,
                decoded.receiver,
                platformFeesForTx
            );
        } else {
            uint256 amountsOutTarget = _handleEvmOrSolanaWithdraw(
                externalId,
                decoded,
                outputAmount,
                decoded.receiver
            );

            emit EddyCrossChainSwap(
                externalId,
                ZETACHAIN,
                decoded.dstChainId,
                zrc20,
                decoded.targetZRC20,
                amount,
                amountsOutTarget,
                decoded.sender,
                decoded.receiver,
                platformFeesForTx
            );
        }
    }

```

In `GatewayTransferNative._doMixSwap`

```solidity
    function _doMixSwap(
        bytes memory swapData,
        uint256 amount,
        MixSwapParams memory params
    ) internal returns (uint256 outputAmount) {
        if (swapData.length == 0) {
            return amount;
        }

@>        IZRC20(params.fromToken).approve(DODOApprove, amount); //@audit amount approved
@>        return IDODORouteProxy(DODORouteProxy).mixSwap{value: msg.value}( //@audit this call will pass since user did a direct transfer of tokens in a batch call to this withdrawToNativeChain
            params.fromToken,
            params.toToken,
            params.fromTokenAmount,
            params.expReturnAmount,
            params.minReturnAmount,
            params.mixAdapters,
            params.mixPairs,
            params.assetTo,
            params.directions,
            params.moreInfo,
            params.feeData,
            params.deadline
        );
    }

```

## **POC**

Consider the following scenario

1. Alice initiates a withdrawal using `GatewayTransferNative.withdrawToNativeChain` to extract 1800e6 USDC.ETH ZRC20 tokens, utilizing 1990e6 USDC.ETH worth of tokens to account for fees directed to her receiver address on Ethereum.
2. During this process, she intends to first exchange 1990 `USDC.ETH` for 0.9 `ETH.ETH`.
    - While calling `GatewayTransferNative.withdrawToNativeChain`, she has the option to instead provide `2000e6` worth of `zrc20 = SHIB.ETH` to cover the protocol fees.
    - If the protocol imposes a fee of 0.5%, she will incur a platform fee of `10e6` worth of `SHIB.ETH` (which holds minimal value).
    - Consequently, she forfeits her remaining `1990e6` worth of SHIB.ETH, which she deems acceptable to lose since it is worth only a few cents.
3. In the same transaction, she also batches a direct transfer of `1990e6` worth of `USDC`.ETH.
4. Upon entering `GatewayTransferNative._doMixSwap`, the amount to be approved continues to reference the `params.fromToken` she indicated in her `message` parameter.
5. Ultimately, she successfully engages in `DODORouteProxy.mixSwap`, exchanging her `1990e6` worth of `USDC.ETH` for 0.9 (0.9e18) `ETH.ETH`, which will be sent to her receiver address on Ethereum.
    - Sufficient funds are available due to the direct transfer of `1990e6` worth of USDC.ETH she executed.
    - Alternatively, she does not need to do a direct transfer but just use funds held by the `GatewayTransferNative` contract due to calls being reverted
6. In the end, she only loses `2000e6` (10e6 + 1990e6) worth of `SHIB.ETH` (which is valued at a few cents in USD) instead of `10e6` worth of USDC.ETH (valued at $10 USD) as protocol fees, resulting in a significant loss of fees for the protocol.

## **Root Cause**

Lack of checks that the provided ZRC20 token address matches the address used for swapping the output token prior to starting the withdrawal process to the destination chain

## **Impact**

Loss of fees for protocol

Loss of funds for users

## **Mitigation**

When users invoke `GatewayTransferNative.withdrawToNativeChain`, verify that the `zrc20` token they provide matches the `MixSwapParams.paramsFromToken` that the user intends to utilize for swapping to the output token, which will be sent to the receiver address on the destination chain.

## **LOC**

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewayTransferNative.sol#L531

# **Users can exploit `GatewayTransferNative` during `withdrawToNativeChain` calls due to inadequate checks ensuring that the `decoded.targetZRC20` matches the `params.toToken` received after swapping to drain funds**

## **Vulnerability Details**

In `GatewayTransferNative`, any user has the ability to call `GatewayTransferNative.withdrawToNativeChain` using a token of lesser value to pay for fees while still utilizing the actual token they intend to swap. For example, if a user plans to exchange `params.fromToken` for a target output token via `DODORouteProxy`, they can choose to use a token with a lower value for the fee payment.

Additionally, they can specify a higher value token (`params.toToken != decoded.targetZRC20`) to be sent to their receiver address on the destination chain, rather than the token they received from the swap through the `DODORouteProxy` contract.

This vulnerability allows users to potentially drain funds from the `GatewayTransferNative` contract.

In `GatewayTransferNative.withdrawToNativeChain`

```solidity
    function withdrawToNativeChain(
@>        address zrc20, //@audit  ZRC20 token is not checked against actual token used for swap
        uint256 amount,
        bytes calldata message
    ) external payable {
        if(zrc20 != _ETH_ADDRESS_) {
            require(IZRC20(zrc20).transferFrom(msg.sender, address(this), amount), "INSUFFICIENT ALLOWANCE: TRANSFER FROM FAILED");
        }

        globalNonce++;
        bytes32 externalId = _calcExternalId(msg.sender);

        // Decode message and decompress swap params
        (DecodedMessage memory decoded, MixSwapParams memory params) = SwapDataHelperLib.decodeMessage(message);

        // Check if the message is from Bitcoin to Solana
        // address evmWalletAddress = (decoded.dstChainId == BITCOIN_EDDY || decoded.dstChainId == SOLANA_EDDY)
        //     ? msg.sender
        //     : address(uint160(bytes20(decoded.receiver)));

        // Transfer platform fees
@>        uint256 platformFeesForTx = _handleFeeTransfer(zrc20, amount); // platformFee = 5 <> 0.5% //@audit payment of fees uses user supplied ZRC20 which can be a low valued token e.g. SHIB.ETH ZRC20 token
        amount -= platformFeesForTx;

        // Swap on DODO Router
@>        uint256 outputAmount = _doMixSwap(decoded.swapDataZ, amount, params); //@audit In _doMixSwap, user can swap from params.fromToken -> params.toToken. params.toToken will be the token received by the GatewayTransferNative contract after the swap

        // Withdraw
        if (decoded.dstChainId == BITCOIN_EDDY) {
            (, uint256 gasFee) = IZRC20(decoded.targetZRC20).withdrawGasFee();
            _handleBitcoinWithdraw(
                externalId,
@>                decoded,  // @audit decoded.targetZRC20 token address is used to call gateway.withdraw to initate withdrawal process to destination chain. This CAN be different from parms.toToken but it shouldnt be the case
                outputAmount,
                gasFee
            );

            emit EddyCrossChainSwap(
                externalId,
                ZETACHAIN,
                decoded.dstChainId,
                zrc20,
                decoded.targetZRC20,
                amount,
                outputAmount - gasFee,
                decoded.sender,
                decoded.receiver,
                platformFeesForTx
            );
        } else {
            uint256 amountsOutTarget = _handleEvmOrSolanaWithdraw(
                externalId,
@>                decoded,  //@audit decoded.targetZRC20 token address is used to call gateway.withdrawAndCall to initate withdrawal process to destination chain. This CAN be different from parms.toToken but it shouldnt be the case
                outputAmount,
                decoded.receiver
            );

            emit EddyCrossChainSwap(
                externalId,
                ZETACHAIN,
                decoded.dstChainId,
                zrc20,
                decoded.targetZRC20,
                amount,
                amountsOutTarget,
                decoded.sender,
                decoded.receiver,
                platformFeesForTx
            );
        }
    }

```

In `GatewayTransferNative._doMixSwap`

```solidity
    function _doMixSwap(
        bytes memory swapData,
        uint256 amount,
        MixSwapParams memory params
    ) internal returns (uint256 outputAmount) {
        if (swapData.length == 0) {
            return amount;
        }

@>        IZRC20(params.fromToken).approve(DODOApprove, amount); //@audit amount approved
@>        return IDODORouteProxy(DODORouteProxy).mixSwap{value: msg.value}( //@audit this call will pass since user will use existing funds in GatewayTransferNative contract to swap
            params.fromToken,
@>            params.toToken, //@audit here the params.toToken may not be the same as the decoded.targetZRC20 token specified by the user
            params.fromTokenAmount,
            params.expReturnAmount,
            params.minReturnAmount,
            params.mixAdapters,
            params.mixPairs,
            params.assetTo,
            params.directions,
            params.moreInfo,
            params.feeData,
            params.deadline
        );
    }

```

In `GatewayTransferNative._handleBitCoinWithdraw`

```solidity
function _handleBitcoinWithdraw(
    bytes32 externalId,
    DecodedMessage memory decoded,
    uint256 outputAmount,
    uint256 gasFee
) internal {
    if(gasFee >= outputAmount) revert NotEnoughToPayGasFee();
    IZRC20(decoded.targetZRC20).approve(address(gateway), outputAmount + gasFee);
    withdraw(
        externalId,
        decoded.receiver,
@>        decoded.targetZRC20,  //@audit user can specify a higher value token here instead of the params.toToken they indicated which should actually be the token is supposed to be use here
        outputAmount - gasFee
    );
}

```

```solidity
    function _handleEvmOrSolanaWithdraw(
        bytes32 externalId,
        DecodedMessage memory decoded,
        uint256 outputAmount,
        bytes memory receiver
    ) internal returns (uint256 amountsOutTarget) {
        (address gasZRC20, uint256 gasFee) = IZRC20(decoded.targetZRC20).withdrawGasFeeWithGasLimit(gasLimit);

        if (decoded.targetZRC20 == gasZRC20) {
            if (gasFee >= outputAmount) revert NotEnoughToPayGasFee();
            IZRC20(decoded.targetZRC20).approve(address(gateway), outputAmount + gasFee);

            bytes memory data = SwapDataHelperLib.buildOutputMessage(
                externalId,
                outputAmount - gasFee,
                decoded.receiver,
                decoded.swapDataB
            );

            bytes memory encoded = (decoded.dstChainId == SOLANA_EDDY)
                ? AccountEncoder.encodeInput(AccountEncoder.decompressAccounts(decoded.accounts), data)
                : data;

            withdrawAndCall(
                externalId,
                decoded.contractAddress,
@>                decoded.targetZRC20,  //@audit user can specify a higher value token here instead of the params.toToken they indicated which should actually be the token is supposed to be use here
                outputAmount - gasFee,
                receiver,
                encoded
            );

            amountsOutTarget = outputAmount - gasFee;
        } else {
            amountsOutTarget = _swapAndSendERC20Tokens(
                decoded.targetZRC20,
                gasZRC20,
                gasFee,
                outputAmount
            );

            bytes memory data = SwapDataHelperLib.buildOutputMessage(
                externalId,
                amountsOutTarget,
                decoded.receiver,
                decoded.swapDataB
            );

            bytes memory encoded = (decoded.dstChainId == SOLANA_EDDY)
                ? AccountEncoder.encodeInput(AccountEncoder.decompressAccounts(decoded.accounts), data)
                : data;

            withdrawAndCall(
                externalId,
                decoded.contractAddress,
@>                decoded.targetZRC20, //@audit user can specify a higher value token here instead of the params.toToken they indicated which should actually be the token is supposed to be use here
                amountsOutTarget,
                receiver,
                encoded
            );
        }
    }

```

## **POC**

Consider the following scenario

1. Alice begins a withdrawal process using `GatewayTransferNative.withdrawToNativeChain` to exploit the protocol by utilizing 1990e6 USDC.ETH.
    - She sets `params.fromToken = USDC.ETH` and `params.toToken = ETH.ETH` via `message` parameter.
2. In this process, she plans to first convert `100e6` `USDC.ETH` into `0.9e6` `ETH.ETH`.
    - While invoking `GatewayTransferNative.withdrawToNativeChain`, she has the option to provide `100e6` worth of `zrc20 = SHIB.ETH` to cover the protocol fees.
    - If the protocol charges a fee of 0.5%, she will incur a platform fee of `0.5e6` worth of `SHIB.ETH` (which has minimal value).
    - As a result, she forfeits her remaining `99.5e6` worth of SHIB.ETH, which she considers an acceptable loss since it is valued at only a few cents.
3. When she enters `GatewayTransferNative._doMixSwap`, the amount to be approved continues to refer to the `params.fromToken` specified in her `message` parameter.
4. Ultimately, she successfully executes `DODORouteProxy.mixSwap`, converting `100e6` worth of `USDC.ETH` held by `GatewayTransferNative` via reverted transactions into `0.9e6` `ETH.ETH`, which will be sent to her Ethereum receiver address.
    - Sufficient funds are available as she can utilize funds held by the `GatewayTransferNative` contract due to reverted calls.
    - Alternatively she can just batch a direct transfer of `100e6` USDC.ETH to the `GatewayTransferNative` contract
5. However, she observes that there are `0.9e6` worth of `WBTC.ETH` tokens in the `GatewayTransferNative` contract, accumulated from reverted calls. She then specifies `decoded.targetZRC20` as `address(WBTC.ETH)`.
6. This leads to `0.9e6` worth of WBTC.ETH being transferred from `GatewayTransferNative` to `GatewayZEVM`, and subsequently to Alice's Ethereum receiver address.
7. In conclusion:
    - Alice incurs a loss of `100e6` (0.5e6 + 99.5e6) worth of `SHIB.ETH` (valued at a few cents in USD < 0.5 USD) instead of `0.5e6` worth of USDC.ETH (valued at $0.5 USD) as protocol fees.
    - The protocol loses `100e6` worth of `USDC.ETH` (as Alice uses available funds in `GatewayTransferNative`) or Alice loses `100e6` worth of USDC.ETH if she supplies them.
    - `0.9e6` worth of `ETH.ETH` remains stuck in `GatewayTransferNative` (when the swap is executed using protocol funds).
    - Alice utilizes `0.9e6` worth of `WBTC.ETH` (which exceeds the combined loss of `100e6` USDC.ETH and `100e6` SHIB.ETH incurred by the protocol) held by `GatewayTransferNative` from reverted transactions to initiate the withdrawal to her Ethereum receiver address.
8. Alice makes at minimum a profit of `0.9e6 WBTC.ETH - 100e6 SHIB.ETH - 100e6 USDC.ETH` and at maximum `0.9e6 WBTC.ETH - 100e6 SHIB.ETH`

## **Root Cause**

Insufficient checks to ensure that the `decoded.targetZRC20` address corresponds with the token address `params.toToken` received after swapping before initiating the withdrawal process to the destination chain.

## **Impact**

Protocol insolvency. Loss of funds for the protocol as attacker can extract value from `GatewayTransferNative` contract

## **Mitigation**

When users invoke `GatewayTransferNative.withdrawToNativeChain`, verify that the `decoded.targetZRC20` token they provide matches the `params.toToken` that the `GatewayTransferNative` contract receives after the initial swap via `_doMixSwap`

## **LOC**

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewayTransferNative.sol#L531

# **User can bypass fees for native zeta withdrawals to destination chain**

## **Vulnerability Details**

In the `GatewayTransferNative.withdrawToNativeChain` function, the protocol imposes fees for any tokens being withdrawn to the destination chain. However, an issue arises with native transfers of the `zeta` token, as users can circumvent these fees.

This occurs because, in the call flow from `GatewayTransferNative.withdrawToNativeChain` to `GatewayTransferNative._handleFeeTransfer`, the amount provided is not verified against the amount specified by the user. Consequently, users can bypass fees entirely and exchange the full amount of native zeta for other ZRC20 tokens without incurring any charges.

In `GatewayTransferNative.withdrwaToNativeChain`

```solidity
    function withdrawToNativeChain(
        address zrc20,
        uint256 amount,
        bytes calldata message
    ) external payable {
        if(zrc20 != _ETH_ADDRESS_) {
            require(IZRC20(zrc20).transferFrom(msg.sender, address(this), amount), "INSUFFICIENT ALLOWANCE: TRANSFER FROM FAILED");
        }

        globalNonce++;
        bytes32 externalId = _calcExternalId(msg.sender);

        // Decode message and decompress swap params
        (DecodedMessage memory decoded, MixSwapParams memory params) = SwapDataHelperLib.decodeMessage(message);

        // Check if the message is from Bitcoin to Solana
        // address evmWalletAddress = (decoded.dstChainId == BITCOIN_EDDY || decoded.dstChainId == SOLANA_EDDY)
        //     ? msg.sender
        //     : address(uint160(bytes20(decoded.receiver)));

        // Transfer platform fees
@>        uint256 platformFeesForTx = _handleFeeTransfer(zrc20, amount); // platformFee = 5 <> 0.5% // @audit msg.value is not use for native zeta swaps to ZRC20 tokens
        amount -= platformFeesForTx;
        ...

```

## **POC**

Consider the following scenario

1. Alice plans to withdraw the USDC.ETH token from Zetachain to her Ethereum address by initially converting native zeta to USDC.ETH.
2. She calls `GatewayTransferNative.withdrawToNativeChain`
    - she inputs `zrc20 = _ETH_ADDRESS` and `amount = 0`
    - she successfully avoids the `_handleTransferFee` function since the fees are set to 0
3. Ultimately, she exchanges her native zeta for the USDC.ETH ZRC20 token through `DODORouteProxy.mixSwap` without incurring any fees

## **Root Cause**

Protocol does not deduct platform fees for native zeta withdrawals to detination chain

## **Impact**

Loss of yield for protocol

## **Mitigation**

Consider checking if the withdrawal involves a native zeta transfer to the recipient address on the destination chain, and to manage the fee deduction by reducing it from `msg.value`.

## **LOC**

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewayTransferNative.sol#L253


# **User can siphon funds from `GatewayTransferNative` via USDC/USDT transfers from BNB -> `GatewayTransferNative` -> Destination chain due to flawed precision handling and checks**

## **Vulnerability Details**

The READMe clearly states that the protocol is designed to work with all assets listed as supported by Zetachain, including USDT and USDC on the Binance Smart Chain. A problem arises due to the fact that USDT and USDC have 18 decimal places on the BNB chain, while USDC on Zetachain and subsequently on the destination chain has only 6 decimal places.

When transferring USDC from BNB to ZetaChain and then to other EVM-compatible chains, the user will follow the flow of `GatewaySend.depositAndCall` to `GatewaySendNative.onCall`.

By providing 1e12 USDT.BNB (which is equivalent to 1e12 / 1e18, or 0.000001 USD on the BNB chain) through `GatewaySend`, a user could potentially siphon 1e12 USDT.ETH, which translates to 1e6 (1 million USDT.ETH worth of ZRC20) from the `GatewayTransferNative` contract. This is possible because the user can submit `swapData` with empty data and set `decoded.targetZRC20` to USDT.ETH, allowing them to extract all funds from the contract. The only requirement is that the `GatewayTransferNative` holds 1 million USDT.ETH from reverted transactions.

In `GatewaySend.depositAndCall`

```solidity
    function depositAndCall(
        address fromToken,
        uint256 amount,
        bytes calldata swapData,
        address targetContract,
        address asset,
        uint32 dstChainId,
        bytes calldata payload
    ) public payable {
        globalNonce++;
        bytes32 externalId = _calcExternalId(msg.sender);
        bool fromIsETH = (fromToken == _ETH_ADDRESS_);

        // Handle input token
        if(fromIsETH) {
            require(
                msg.value >= amount,
                "INSUFFICIENT AMOUNT: ETH NOT ENOUGH"
            );
        } else {
            require(
                IERC20(fromToken).transferFrom(msg.sender, address(this), amount),
                "INSUFFICIENT AMOUNT: ERC20 TRANSFER FROM FAILED"
            );
        }

        // Swap on DODO Router
        uint256 outputAmount = _doMixSwap(swapData);

        // Construct message and revert options
        bytes memory message = concatBytes(externalId, payload);
        RevertOptions memory revertOptions = RevertOptions({
            revertAddress: address(this),
            callOnRevert: true,
            abortAddress: targetContract,
            revertMessage: bytes.concat(externalId, bytes20(msg.sender)),
            onRevertGasLimit: gasLimit
        });

        bool toIsETH = (asset == _ETH_ADDRESS_);
        if (toIsETH) {
            _handleETHDeposit(
                targetContract,
                outputAmount,
                message,
                revertOptions
            );
        } else {
            _handleERC20Deposit(
@>                targetContract, //@audit this is GatewaySend contract for A->ZetaChain->B calls
@>                outputAmount, //@audit amount is in 18 precision for USDC/USDT.BNB ERC20 tokens which will subsequently be transferred to receiver address on other EVM compatible chain
                asset,
                message,
                revertOptions
            );
        }

        emit EddyCrossChainSend(
            externalId,
            dstChainId,
            fromToken,
            asset,
            amount,
            outputAmount,
            msg.sender,
            message
        );
    }

```

In `GatewaySendNative.onCall`

```solidity
    function onCall(
        MessageContext calldata context,
        address zrc20,
        uint256 amount,
        bytes calldata message
    ) external override onlyGateway {
        // Decode the message
        // 32 bytes(externalId) + bytes message
        (bytes32 externalId) = abi.decode(message[0:32], (bytes32));
        bytes calldata _message = message[32:];
        (DecodedNativeMessage memory decoded, MixSwapParams memory params) = SwapDataHelperLib.decodeNativeMessage(_message);

        // Fee for platform
        uint256 platformFeesForTx = _handleFeeTransfer(zrc20, amount); // platformFee = 5 <> 0.5%
        address receiver = address(uint160(bytes20(decoded.receiver)));

        if (decoded.targetZRC20 == zrc20) {
            // same token
            TransferHelper.safeTransfer(
                decoded.targetZRC20,
                receiver,
                amount - platformFeesForTx
            );

            emit EddyCrossChainSwap(
                externalId,
                uint32(context.chainID),
                ZETACHAIN,
                zrc20,
                decoded.targetZRC20,
                amount,
                amount - platformFeesForTx,
                decoded.sender,
                decoded.receiver,
                platformFeesForTx
            );
@>        } else { //@audit here decoded.targetZRC20 = USDT.ETH, zrc20 = USDT.BNB
            // Swap on DODO Router
@>            uint256 outputAmount = _doMixSwap(decoded.swapData, amount, params); //@audit user can supply empty decoded.swapData which will return to this call flow with the amount of USDT.BNB (1e12) token he supplied

            if (decoded.targetZRC20 == WZETA) {
                // withdraw WZETA to get Zeta in 1:1 ratio
                IWETH9(WZETA).withdraw(outputAmount);
                // transfer wzeta
                TransferHelper.safeTransferETH(receiver, outputAmount);
            } else {
                TransferHelper.safeTransfer(
                    decoded.targetZRC20,
                    receiver,
@>                    outputAmount //@audit At this step, the 1e12 worth of USDT.ETH (which was suppose to be referring to USDT.BNB) is transferred to the user from GatewayTransferNative (this funds comes from reverted transactions that are suppose to be claimed by legitimate users)
                );
            }

            emit EddyCrossChainSwap(
                externalId,
                uint32(context.chainID),
                ZETACHAIN,
                zrc20,
                decoded.targetZRC20,
                amount,
                outputAmount,
                decoded.sender,
                decoded.receiver,
                platformFeesForTx
            );
        }
    }

```

In `GatewayTransferNative._doMixSwap`

```solidity
   function _doMixSwap(
        bytes memory swapData,
        uint256 amount,
        MixSwapParams memory params
    ) internal returns (uint256 outputAmount) {
@>        if (swapData.length == 0) { //@audit as long as swapData is empty
@>            return amount; // @audit return 1e12 USDT.BNB worth of amount
        }

        IZRC20(params.fromToken).approve(DODOApprove, amount);
        return IDODORouteProxy(DODORouteProxy).mixSwap{value: msg.value}(
            params.fromToken,
            params.toToken,
            params.fromTokenAmount,
            params.expReturnAmount,
            params.minReturnAmount,
            params.mixAdapters,
            params.mixPairs,
            params.assetTo,
            params.directions,
            params.moreInfo,
            params.feeData,
            params.deadline
        );
    }

```

## **POC**

Consider the following scenario

1. Alice initiates a transfer of 1e12 (equivalent to 0.000001 USD on the BNB chain) in USDT.BNB to her Ethereum address using `GatewaySend.depositAndCall`, designating `GatewayTransferNative` as the `targetContract`.
2. This action triggers the `GatewayTransferNative.onCall`, where the 1e12 USDT.BNB is sent to the `GatewayTransferNative` contract through the gateway.
3. Alice configures
    - an empty `swapData` - meaning she opts not to exchange the `USDT.BNB` for any output token through `GatewayTransferNative._doMixSwap`, allowing the 1e12 amount to be return back into the `GatewayTransferNative.onCall` call, and
    - she assigns `decoded.targetZRC20 = USDC.ETH`
    - As a result, `1e12` USDC.ETH is sent to her EVM address using `TransferHelper.safeTransfer`.
4. Ultimately, Alice ends up with `1e12 USDC.ETH`, which originates from funds intended for refunds to users affected by reverted transactions.

## **Root Cause**

Failure to convert the USDC/USDT.BNB amount to align with the necessary decimal precision for the target USDC (for instance, converting from 18 decimals to 6 for transfers from USDC.BNB to USDC.ETH).

Permitting high-precision amounts and tokens not matching the swap token to be outputted (decoded.targetZRC20 != params.toToken) to be returned when `swapData` is empty

## **Impact**

Loss of funds for protocol.

## **LOC**

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewayTransferNative.sol#L395

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewayTransferNative.sol#L403

# **User can specify arbitary `externalId` via `GatewayTransferNative` to overwrite existing refunds of other users**

## **Vulnerability Details**

In the `GatewayTransferNative.withdraw` function, any user has the ability to invoke this method using an already existing `externalId`, which can overwrite the refunds of users whose transactions have been reverted or aborted. This poses a risk of financial loss for those users affected by the aborted or reverted calls.

Additionally, since the caller can specify the `sender` as themselves, they can potentially reclaim their own funds, causing a loss of funds for other users.

In `GatewayTransferNative.withdraw`

```solidity
function withdraw(
@>    bytes32 externalId, //@audit this can be arbitrarily decided by the caller
    bytes memory sender,
    address outputToken,
    uint256 amount
) public {
    gateway.withdraw(
        sender,
        amount,
        outputToken,
        RevertOptions({
            revertAddress: address(this),
            callOnRevert: true,
            abortAddress: address(0),
@>            revertMessage: bytes.concat(externalId, bytes20(sender)), //@audit arbitary exernalId given by caller
            onRevertGasLimit: gasLimit
        })
    );
}

```

In `GatewayTransferNative.claimRefund`

```solidity
function claimRefund(bytes32 externalId) external {
@>    RefundInfo storage refundInfo = refundInfos[externalId]; // @audit transaction that reverts due to caller specifiying an already existing externalId will overwrite an existing users refundInfo

    address receiver = msg.sender;
    if(refundInfo.walletAddress.length == 20) {
        receiver = address(uint160(bytes20(refundInfo.walletAddress)));
    }
    require(bots[msg.sender] || msg.sender == receiver, "INVALID_CALLER");
    require(refundInfo.externalId != "", "REFUND_NOT_EXIST");

    TransferHelper.safeTransfer(refundInfo.token, receiver, refundInfo.amount);
    delete refundInfos[externalId];

    emit EddyCrossChainRefundClaimed(
        externalId,
        refundInfo.token,
        refundInfo.amount,
        abi.encodePacked(msg.sender)
    );
}

```

## **POC**

Consider the following scenario

1. Alice has an ongoing `GatewayTransferNative.withdrawToNativeChain` transaction with `externalId = 0x1` (this is merely an example value) that has reverted.
    - In this transaction, she transfers 10000 USDC.SOL to her designated `receiver` address on Solana.
    - Her transaction fails, triggering the `GatewayTransferNative.onRevert` function.
    - She is eligible for a refund of 9980 USDC.SOL (after deducting fees).
    - Given that Solana utilizes 32-byte addresses, her refund information is stored in `refundInfos[0x1]` and is not returned to her immediately.
2. Bob observes this situation and decides to execute a `GatewayTransferNative.withdraw` transaction using the same `externalId = 0x1`, identifying himself as the sender.
    - He utilizes 100 USDC.SOL.
    - His transaction also fails, invoking the `GatewayTransferNative.onRevert` function.
    - He is entitled to a refund of 98 USDC.SOL (after deducting fees).
    - Since Solana employs 32-byte addresses, his refund information is stored in `refundInfos[0x1]` and is not returned to him immediately.
    - Bob successfully overwrites Alice's refund information.
3. Bob proceeds to claim his refund through `GatewayTransferNative.claimRefund`.
4. Ultimately, Alice's record is overwritten (resulting in her losing 9980 USDC.SOL), while Bob successfully retrieves his refund, minus any applicable fees.

## **Root Cause**

Arbitary `externalId` can be supplied by user during withdrawal calls to overwrite existing refundInfo with same `externalId`

## **Impact**

Loss of funds for users

## **Mitigation**

Consider calculating the `externalId` via `_calcExternalId` and do not allow any user to pass in a arbitray `externalId` as a parameter when initiating withdrawals

## **LOC**

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewayTransferNative.sol#L286

# **`GatewaySend` contract lacks support for USDT tokens, resulting in broken core functionality and wasted gas fees.**

## **Vulnerability Details**

The `GatewaySend` contract is unable to support `USDT` due to the repeated use of `transferFrom` and `transfer` functions in the `depositAndCall` and `onCall` methods, as these functions do not return a boolean value.

This limitation exists even though the README explicitly states that the protocol will support all tokens listed in ZetaChain's supported token list, which includes `USDT`

> Q: If you are integrating tokens, are you allowing only whitelisted tokens to work with the codebase or any complying with the standard? Are they assumed to have certain properties, e.g. be non-reentrant? Are there any types of weird tokens you want to integrate?
> 

> The project only integrate tokens inside ZetaChain supported asset list.
> 

> For token supported, please refer to: https://www.zetachain.com/docs/developers/tokens/zrc20/#supported-assets
> 

calls `GatewaySend.depositAndCall` from the EVM chain to Zetachain will consistently fail for USDT.

Similarly, calls from Zetachain to the EVM chain through `GatewaySend.onCall` will also fail, resulting in users incurring gas fees and only being able to recover the remaining amount after gas fees are deducted.

## **Root Cause**

Use of `transferFrom` / `transfer` functions will prevent `USDT` usage in `GatewaySend`

## **Impact**

Broken core functionality due to lack of support for `USDT` specifcally mentioned in `README`

Loss of funds (in gas fees) for user due to calls always reverting

## **Mitigation**

Use `safeTransferFrom` and `safeTransfer` from SafeERC20 library.

## **LOC**

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewaySend.sol#L239

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewaySend.sol#L317

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewaySend.sol#L359

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewaySend.sol#L370

# **Aborted native token `depositAndCall` that aborts via `onAbort` calls are not handled properly on `GatewayTransferNative` as they are considered no-asset calls (asset address is zero)**

## **Vulnerability Details**

In the `GatewayTransferNative` on Zetachain, it is possible to abort calls originating from `GatewaySend` on EVM chains if the `onRevert` calls via `GatewaySend.onRevert` fail (which can occur for various reasons). This failure will invoke the `GatewayTransferNative.onAbort` function on Zetachain.

The specific call flow is detailed [here](https://www.zetachain.com/docs/developers/chains/zetachain/#call-options).

The problem occurs when a user initiates a native token transfer (e.g. ETH) from `GatewaySend.depositAndCall` to `GatewayTransferNative`, and then to the receiver address on Zetachain. If the call falls back to `GatewayTransferNative.onAbort` due to a failure in `GatewayTransferNative.onRevert`, the asset address is stored as the zero address.

In `GatewayEVM.depositAndCall`

```solidity
    /// @notice Deposits ETH to the TSS address and calls an omnichain smart contract.
    /// @param receiver Address of the receiver.
    /// @param payload Calldata to pass to the call.
    /// @param revertOptions Revert options.
    function depositAndCall(
        address receiver,
        bytes calldata payload,
        RevertOptions calldata revertOptions
    )
        external
        payable
        whenNotPaused
    {
        if (msg.value == 0) revert InsufficientETHAmount();
        if (receiver == address(0)) revert ZeroAddress();
        if (payload.length + revertOptions.revertMessage.length > MAX_PAYLOAD_SIZE) revert PayloadSizeExceeded();

        (bool deposited,) = tssAddress.call{ value: msg.value }("");

        if (!deposited) revert DepositFailed();

@>        emit DepositedAndCalled(msg.sender, receiver, msg.value, address(0), payload, revertOptions); //@audit address(0) here refers to native ETH deposits and call
    }

```

In `GatewaySend._handleETHDeposit` which is called during payable `depositAndCall` function

```solidity
    function _handleETHDeposit(
        address targetContract,
        uint256 amount,
        bytes memory message,
        RevertOptions memory revertOptions
    ) internal {
@>        gateway.depositAndCall{value: amount}( //@audit this call will use address(0) since it is for native ETH deposits and Call to target universal contract on Zetachain
            targetContract,
            message,
            revertOptions
        );
    }

```

In `GatewayTransferNative.onAbort`

```solidity
    function onAbort(AbortContext calldata abortContext) external onlyGateway {
        // 52 bytes = 32 bytes externalId + 20 bytes evmWalletAddress
        bytes32 externalId = bytes32(abortContext.revertMessage[0:32]);
        bytes memory walletAddress = abortContext.revertMessage[32:];

        RefundInfo memory refundInfo = RefundInfo({
            externalId: externalId,
@>            token: abortContext.asset, // @audit This will be zero address for native ETH transfers which needs to be mapped to the equivalent ZRC20 token depending on source chain
            amount: abortContext.amount,
            walletAddress: walletAddress
        });
        refundInfos[externalId] = refundInfo;

        emit EddyCrossChainRefund(
            externalId,
            abortContext.asset,
            abortContext.amount,
            walletAddress
        );
    }

```

## **POC**

Consider the following scenario

1. Alice calls `GatewaySend.depositAndCall` to deposit 1 native ETH and call the `GatewayTransferNative` as the universal contract on Zetachain
2. Her call subsequently aborts which triggers `GatewayTransferNative.onAbort` since `abortAddress` is specified as `targetContract` which is address of `GatewayTransferNative`
3. Entering `GatewayTransferNative.onAbort` the `RefundInfo.token` is stored as the `abortContext.asset` which is the zero address that refers to native ETH deposit and calls
4. In the end the funds will be stuck in `GatewayTransferNative` and Alice can never claim back her ETH because the `TransferHelper.safeTransfer` call will revert for a 0 address token

```solidity
    function claimRefund(bytes32 externalId) external {
        RefundInfo storage refundInfo = refundInfos[externalId];

        address receiver = msg.sender;
        if(refundInfo.walletAddress.length == 20) {
            receiver = address(uint160(bytes20(refundInfo.walletAddress)));
        }
        require(bots[msg.sender] || msg.sender == receiver, "INVALID_CALLER");
        require(refundInfo.externalId != "", "REFUND_NOT_EXIST");

@>        TransferHelper.safeTransfer(refundInfo.token, receiver, refundInfo.amount); //@audit call will revert for address(0)
        delete refundInfos[externalId];

        emit EddyCrossChainRefundClaimed(
            externalId,
            refundInfo.token,
            refundInfo.amount,
            abi.encodePacked(msg.sender)
        );
    }

```

## **Root Cause**

Lack of mechanisms on universal contract on Zetachain to handle `GatewaySend.depositAndCall` that aborts from EVM chains using native tokens

## **Impact**

Loss of funds for user.

## **Mitigation**

Based on the source chain, map native token transfers to their corresponding ZRC20 token for refunding to the caller.

## **LOC**

https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex/blob/main/omni-chain-contracts/contracts/GatewayTransferNative.sol#L647