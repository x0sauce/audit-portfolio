# Non bridged TITN tokens on BASE cannot be transferred at any time until the owner unlocks `isBridgedTokensTransferLocked`

## **Summary**

The current implementation restricts non-bridged TITN token transfers until the admin disables the locking mechanism, which contradicts the protocol's intent for unrestricted transfers for non bridged `BASE.TITN` tokens.

## **Vulnerability Details**

The protocol indicates that non-bridged BASE.TITN tokens should be transferable without restrictions to any address.

Base on protocol `README`

> Non-bridged TITN Tokens: Holders can transfer their TITN tokens freely to any address as long as the tokens have not been bridged from ARBITRUM.
> 

The current implementation of the transfer function first verifies the `_validateTransfer` conditions before executing any transfer. The presence of `isBridgedTokensTransferLocked` indicates that non-bridged TITN tokens can only be transferred if the admin disables this locking mechanism by setting `isBridgedTokensTransferLocked` to false. Consequently, non-bridged TITN tokens cannot be transferred unless the transfer of bridged TITN tokens is permitted.

```solidity
    function _validateTransfer(address from, address to) internal view {
        // Arbitrum chain ID
        uint256 arbitrumChainId = 42161;

        // Check if the transfer is restricted
        if (
            from != owner() && // Exclude owner from restrictions
            from != transferAllowedContract && // Allow transfers to the transferAllowedContract
            to != transferAllowedContract && // Allow transfers to the transferAllowedContract
            // @audit Non-Bridged TITN tokens cannot be transferred unless isBridgedTokensTransferLocked is set to false
            isBridgedTokensTransferLocked && // Check if bridged transfers are locked
            // Restrict bridged token holders OR apply Arbitrum-specific restriction
            (isBridgedTokenHolder[from] || block.chainid == arbitrumChainId) &&
            to != lzEndpoint // Allow transfers to LayerZero endpoint
        ) {
            revert BridgedTokensTransferLocked();
        }
    }

```

### **Root Cause**

Bridge token mechanism also applies to non bridge tokens

### **Impact**

Non-bridged TITN token transfers cannot happen.

### **Mitigation**

Consider adding separate logic to allow transfers of Non Briged TITN token to happen on BASE.

### **Links to affected code**

- [Titn.sol#L80](https://github.com/code-423n4/2025-02-thorwallet/blob/98d7e936518ebd80e2029d782ffe763a3732a792/contracts/Titn.sol#L80)