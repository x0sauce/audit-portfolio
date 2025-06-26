# `VVVVCTokenDistributor.claim` can be front-run to steal rewards

# Description
`VVVVCTokenDistributor.claim` is vulnerable to front-running attacks, allowing an attacker to claim funds intended for a user. Even though all claim transactions require approval from the centralized system, an approved claim transaction can be front-run, resulting in the funds being transferred to the attacker.
The vulnerability exists because the rewards are sent directly to the caller using `msg.sender`.
```solidity
    /**
        @notice Allows any address which is an alias of a KYC address to claim tokens across multiple rounds which provide that token
        @param _params A ClaimParams struct describing the desired claim(s)
     */
    function claim(ClaimParams memory _params) public {
        if (claimIsPaused) {
            revert ClaimIsPaused();
        }

        if (_params.projectTokenProxyWallets.length != _params.tokenAmountsToClaim.length) {
            revert ArrayLengthMismatch();
        }

        if (_params.nonce <= nonces[_params.kycAddress]) {
            revert InvalidNonce();
        }

        if (!_isSignatureValid(_params)) {
            revert InvalidSignature();
        }

        // update nonce
        nonces[_params.kycAddress] = _params.nonce;

        // define token to transfer
        IERC20 projectToken = IERC20(_params.projectTokenAddress);

        // transfer tokens from each wallet to the caller
        for (uint256 i = 0; i < _params.projectTokenProxyWallets.length; i++) {
            projectToken.safeTransferFrom(
                _params.projectTokenProxyWallets[i],
                msg.sender, // <@ tokens are transferred directly to attacker who front runs the claim transaction
                _params.tokenAmountsToClaim[i]
            );
        }

        emit VCClaim(
            _params.kycAddress,
            _params.projectTokenAddress,
            _params.projectTokenProxyWallets,
            _params.tokenAmountsToClaim,
            _params.nonce
        );
    }
```

# POC
Below POC shows that attacker can pre-construct the `VVVVCTokenDistributor.ClaimParams` struct and data parameters to front-run the claim transaction and claim user rewards for themselves.
Add it to `VVVVCTokenDistributor.unit.t` and run `forge test --mt testFrontRunClaim`
```solidity
    function testFrontRunClaim() public {
        address alice = makeAddr("address");
        address[] memory thisProjectTokenProxyWallets = new address[](1);
        uint256[] memory thisTokenAmountsToClaim = new uint256[](1);

        thisProjectTokenProxyWallets[0] = projectTokenProxyWallets[0];

        uint256 claimAmount = sampleTokenAmountsToClaim[0];
        thisTokenAmountsToClaim[0] = claimAmount;

        VVVVCTokenDistributor.ClaimParams memory claimParams = generateClaimParamsWithSignature(
            sampleKycAddress,
            thisProjectTokenProxyWallets,
            thisTokenAmountsToClaim
        );

        claimAsUser(alice, claimParams);
        assertTrue(ProjectTokenInstance.balanceOf(alice) == claimAmount);
    }

```

# Code Snippet
https://github.com/sherlock-audit/2024-11-vvv-exchange-update/blob/main/vvv-platform-smart-contracts/contracts/vc/VVVVCTokenDistributor.sol#
L133

# Impact
Attacker can front run claim function and steal user funds

# Recommendation
Send the rewards directly to the kyc address which has been approved by the protocol or consider adding a `ClaimParams.receiverAddress` param which will be hashed and signed
```diff
    /**
        @notice Allows any address which is an alias of a KYC address to claim tokens across multiple rounds which provide that token
        @param _params A ClaimParams struct describing the desired claim(s)
     */
    function claim(ClaimParams memory _params) public {
        if (claimIsPaused) {
            revert ClaimIsPaused();
        }

        if (_params.projectTokenProxyWallets.length != _params.tokenAmountsToClaim.length) {
            revert ArrayLengthMismatch();
        }

        if (_params.nonce <= nonces[_params.kycAddress]) {
            revert InvalidNonce();
        }

        if (!_isSignatureValid(_params)) {
            revert InvalidSignature();
        }

        // update nonce
        nonces[_params.kycAddress] = _params.nonce;

        // define token to transfer
        IERC20 projectToken = IERC20(_params.projectTokenAddress);

        // transfer tokens from each wallet to the caller
        for (uint256 i = 0; i < _params.projectTokenProxyWallets.length; i++) {
            projectToken.safeTransferFrom(
                _params.projectTokenProxyWallets[i],
-                msg.sender, // <@ tokens are transferred directly to attacker who front runs the claim
+                _params.kycAddress, // Send the rewards directly to the kyc address which has been approved by the protocol
                transaction
                _params.tokenAmountsToClaim[i]
            );
        }

        emit VCClaim(
            _params.kycAddress,
            _params.projectTokenAddress,
            _params.projectTokenProxyWallets,
            _params.tokenAmountsToClaim,
            _params.nonce
        );
    }
```
