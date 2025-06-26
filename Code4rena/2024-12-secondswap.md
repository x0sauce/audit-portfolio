# Seller can mistakenly create a listing with `discountPct > BASE`, which can prevent purchases to happen for the listing

## **Vulnerability Details**

In `SecondSwap_Marketplace.listVesting`, if a seller by accident provides a `discountPct` with the wrong precision (a precision greater than BASE), no purchases can be made for that listing

```solidity
    function listVesting(
        address _vestingPlan,
        uint256 _amount,
        uint256 _price,
        uint256 _discountPct,
        ListingType _listingType,
        DiscountType _discountType,
        uint256 _maxWhitelist,
        address _currency,
        uint256 _minPurchaseAmt,
        bool _isPrivate
    ) external isFreeze {
        require(
            _listingType != ListingType.SINGLE || (_minPurchaseAmt > 0 && _minPurchaseAmt <= _amount),
            "SS_Marketplace: Minimum Purchase Amount cannot be more than listing amount"
        );
        require(_price > 0, "SS_Marketplace: Price must be greater than 0");
        require(
@>            (_discountType != DiscountType.NO && _discountPct > 0) || (_discountType == DiscountType.NO), // @audit only checks if _discountPct is > 0 but not within the precision of BASE
            "SS_Marketplace: Invalid discount amount"
        );
        require(_amount > 0, "SS_Marketplace: Invalid listing amount"); // 3.10. Inefficient _listingType check
        require(isTokenSupport[_currency], "SS_Marketplace: Payment token is not supported");

        require(
            doesFunctionExist(
                address(
                    IVestingManager(IMarketplaceSetting(marketplaceSetting).vestingManager()).getVestingTokenAddress(
                        _vestingPlan
                    )
                ),
                "decimals()"
            ),
            "SS_Marketplace: No decimals function"
        ); // 3.1. Rounding issue leads to total drain of vesting entries

        uint256 baseAmount = (_amount * _price) /
            uint256(
                10 **
                    (
                        IERC20Extended(
                            address(
                                IVestingManager(IMarketplaceSetting(marketplaceSetting).vestingManager())
                                    .getVestingTokenAddress(_vestingPlan)
                            )
                        ).decimals()
                    )
            ); // 3.1. Rounding issue leads to total drain of vesting entries
        require(baseAmount > 0, "SS_Marketplace: Cannot list amount it is too little"); // 3.1. Rounding issue leads to total drain of vesting entries

        IVestingManager(IMarketplaceSetting(marketplaceSetting).vestingManager()).listVesting(
            msg.sender,
            _vestingPlan,
            _amount
        );

        uint256 listingId = nextListingId[_vestingPlan]++;
        address whitelistAddress;

        if (_isPrivate) {
            require(_maxWhitelist > 0, "SS_Marketplace: Minimum whitelist user cannot be 0");
            whitelistAddress = SecondSwap_WhitelistDeployer(IMarketplaceSetting(marketplaceSetting).whitelistDeployer())
                .deployWhitelist(_maxWhitelist, msg.sender);
            emit WhitelistCreated(_vestingPlan, listingId, whitelistAddress, msg.sender, _maxWhitelist);
        }

        listings[_vestingPlan][listingId] = Listing({
            seller: msg.sender,
            total: _amount,
            balance: _amount,
            pricePerUnit: _price,
            listingType: _listingType,
            discountType: _discountType,
            discountPct: _discountPct,
            listTime: block.timestamp,
            whitelist: whitelistAddress,
            currency: _currency,
            minPurchaseAmt: _minPurchaseAmt,
            status: Status.LIST,
            vestingPlan: _vestingPlan
        });
        emit Listed(_vestingPlan, listingId);
    }

```

Subsequently when a buyer attempts to purchase vested tokens from the listing via `SecondSwap_Marketplace.spotPurchase`, `SecondSwap_Marketplace._getDiscountedPrice` will be called and the purchase transaction will always revert due to an underflow.

```solidity
    function spotPurchase(
        address _vestingPlan,
        uint256 _listingId,
        uint256 _amount,
        address _referral
    ) external isFreeze {
        // Get listing and validate purchase parameters
        Listing storage listing = listings[_vestingPlan][_listingId];
        _validatePurchase(listing, _amount, _referral);

        // Calculate fees and final price
        (uint256 bfee, uint256 sfee) = _getFees(_vestingPlan);
@>        uint256 discountedPrice = _getDiscountedPrice(listing, _amount); // @audit attempts to retrieve discountedPrice

        // Process all transfers
        (uint256 buyerFeeTotal, uint256 sellerFeeTotal, uint256 referralFeeCost) = _handleTransfers(
            listing,
            _amount,
            discountedPrice,
            bfee,
            sfee,
            _referral
        );

        // Update listing status
        listing.balance -= _amount;
        listing.status = listing.balance == 0 ? Status.SOLDOUT : Status.LIST;

        // Complete the purchase through vesting manager
        IVestingManager(IMarketplaceSetting(marketplaceSetting).vestingManager()).completePurchase(
            msg.sender,
            _vestingPlan,
            _amount
        );

        // Emit purchase event
        emit Purchased(
            _vestingPlan,
            _listingId,
            msg.sender,
            _amount,
            _referral,
            buyerFeeTotal,
            sellerFeeTotal,
            referralFeeCost
        );
    }

```

```solidity
    function _getDiscountedPrice(Listing storage listing, uint256 _amount) private view returns (uint256) {
        uint256 discountedPrice = listing.pricePerUnit;

        if (listing.discountType == DiscountType.LINEAR) {
            discountedPrice = (discountedPrice * (BASE - ((_amount * listing.discountPct) / listing.total))) / BASE;
        } else if (listing.discountType == DiscountType.FIX) {
@>            discountedPrice = (discountedPrice * (BASE - listing.discountPct)) / BASE; // @audit line will always revert due to a underflow when listing.discountPrice > BASE
        }
        return discountedPrice;
    }

```

## **Impact**

No purchases can be made on listings with wrong `discountPct` set. Seller would have to delist and relist a listing with the correct precision set for the `discountPct`.

## **Recommendation**

Add a check to ensure that discountPct is not more than BASE amount

```diff
    function listVesting(
        address _vestingPlan,
        uint256 _amount,
        uint256 _price,
        uint256 _discountPct,
        ListingType _listingType,
        DiscountType _discountType,
        uint256 _maxWhitelist,
        address _currency,
        uint256 _minPurchaseAmt,
        bool _isPrivate
    ) external isFreeze {
        require(
            _listingType != ListingType.SINGLE || (_minPurchaseAmt > 0 && _minPurchaseAmt <= _amount),
            "SS_Marketplace: Minimum Purchase Amount cannot be more than listing amount"
        );
        require(_price > 0, "SS_Marketplace: Price must be greater than 0");
        require(
        -    (_discountType != DiscountType.NO && _discountPct > 0) || (_discountType == DiscountType.NO),
        +    (_discountType != DiscountType.NO && _discountPct > 0 && _discountPct <= BASE) || (_discountType == DiscountType.NO),
            "SS_Marketplace: Invalid discount amount"
        );
        require(_amount > 0, "SS_Marketplace: Invalid listing amount"); // 3.10. Inefficient _listingType check
        require(isTokenSupport[_currency], "SS_Marketplace: Payment token is not supported");

        require(
            doesFunctionExist(
                address(
                    IVestingManager(IMarketplaceSetting(marketplaceSetting).vestingManager()).getVestingTokenAddress(
                        _vestingPlan
                    )
                ),
                "decimals()"
            ),
            "SS_Marketplace: No decimals function"
        ); // 3.1. Rounding issue leads to total drain of vesting entries

        uint256 baseAmount = (_amount * _price) /
            uint256(
                10 **
                    (
                        IERC20Extended(
                            address(
                                IVestingManager(IMarketplaceSetting(marketplaceSetting).vestingManager())
                                    .getVestingTokenAddress(_vestingPlan)
                            )
                        ).decimals()
                    )
            ); // 3.1. Rounding issue leads to total drain of vesting entries
        require(baseAmount > 0, "SS_Marketplace: Cannot list amount it is too little"); // 3.1. Rounding issue leads to total drain of vesting entries

        IVestingManager(IMarketplaceSetting(marketplaceSetting).vestingManager()).listVesting(
            msg.sender,
            _vestingPlan,
            _amount
        );

        uint256 listingId = nextListingId[_vestingPlan]++;
        address whitelistAddress;

        if (_isPrivate) {
            require(_maxWhitelist > 0, "SS_Marketplace: Minimum whitelist user cannot be 0");
            whitelistAddress = SecondSwap_WhitelistDeployer(IMarketplaceSetting(marketplaceSetting).whitelistDeployer())
                .deployWhitelist(_maxWhitelist, msg.sender);
            emit WhitelistCreated(_vestingPlan, listingId, whitelistAddress, msg.sender, _maxWhitelist);
        }

        listings[_vestingPlan][listingId] = Listing({
            seller: msg.sender,
            total: _amount,
            balance: _amount,
            pricePerUnit: _price,
            listingType: _listingType,
            discountType: _discountType,
            discountPct: _discountPct,
            listTime: block.timestamp,
            whitelist: whitelistAddress,
            currency: _currency,
            minPurchaseAmt: _minPurchaseAmt,
            status: Status.LIST,
            vestingPlan: _vestingPlan
        });
        emit Listed(_vestingPlan, listingId);
    }

```

### **Links to affected code**

- [SecondSwap_Marketplace.sol#L240](https://github.com/code-423n4/2024-12-secondswap/blob/214849c3517eb26b31fe194bceae65cb0f52d2c0/contracts/SecondSwap_Marketplace.sol#L240)
- [SecondSwap_Marketplace.sol#L517](https://github.com/code-423n4/2024-12-secondswap/blob/214849c3517eb26b31fe194bceae65cb0f52d2c0/contracts/SecondSwap_Marketplace.sol#L517)
- [SecondSwap_Marketplace.sol#L413](https://github.com/code-423n4/2024-12-secondswap/blob/214849c3517eb26b31fe194bceae65cb0f52d2c0/contracts/SecondSwap_Marketplace.sol#L413)