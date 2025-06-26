# VirtualToken will not be minted to user if underlying asset is not ETH

## **Vulnerability Details**

When a buy initiates to buy a quoteToken via a router, `VirtualToken.cashIn` will be called. Although currently only vETH will be supported, subsequent versions of `VirtualToken` utilizing either USDC or USDT as the underlying token will not be able to get the equivalent virtual token minted to them. This is because in `VirtualToken.cashIn`, the function uses `msg.value` which only applies to native ETH. In the future, when a new router is set up for vUSDC, there is still no way no for buyer to get equivalent vUSDC minted to the router without transferring native ETH to the VirtualToken contract before it is transferred to the uniswap pool.

*This is due to the use of `msg.value` in VirtualToken.cashIn, which only supports minting of virtual tokens if native ETH is send to the contract.

```solidity
    function cashIn(uint256 amount) external payable onlyWhiteListed {
        if (underlyingToken == LaunchPadUtils.NATIVE_TOKEN) {
            require(msg.value == amount, "Invalid ETH amount");
        } else {
            _transferAssetFromUser(amount);
        }
@>         _mint(msg.sender, msg.value); // @audit use of msg.value means minting is only supported for native ETH transfers
        emit CashIn(msg.sender, msg.value);
    }

```

## **Code Snippet**

[**https://github.com/code-423n4/2024-12-lambowin/blob/b8b8b0b1d7c9733a7bd9536e027886adb78ff83a/src/VirtualToken.sol#L72**](https://github.com/code-423n4/2024-12-lambowin/blob/b8b8b0b1d7c9733a7bd9536e027886adb78ff83a/src/VirtualToken.sol#L72)

## **Impact**

`VirtualToken` is suppose to be intended to support multiple underlying tokens which can result in no `VirtualToken` being minted to the router and subsequently transferred to the pool.

## **Recommendation**

Pass in the `amount` parameter to `cashIn` when minting virtual tokens

```diff

    function cashIn(uint256 amount) external payable onlyWhiteListed {
        if (underlyingToken == LaunchPadUtils.NATIVE_TOKEN) {
            require(msg.value == amount, "Invalid ETH amount");
        } else {
            _transferAssetFromUser(amount);
        }
-       _mint(msg.sender, msg.value);
+       _mint(msg.sender, amount);
        emit CashIn(msg.sender, msg.value);
    }

```

### **Links to affected code**

- [VirtualToken.sol#L72](https://github.com/code-423n4/2024-12-lambowin/blob/b8b8b0b1d7c9733a7bd9536e027886adb78ff83a/src/VirtualToken.sol#L72)
