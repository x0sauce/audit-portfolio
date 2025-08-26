# `getVotingPowers` can run OOG and will always revert as number of historical operators grow

## Vulnerability Details

In the SDK, it is crucial for all public view functions to operate correctly to facilitate offchain mechanisms or on chain functionality that depend on fetching on-chain data from these function. A prime example of this is the `VotingPowerProvider.getVotingPowers` function.

This function returns an array of `IVotingPowerProvider.OperatorVotingPower[]` structs, which include operator addresses along with their corresponding voting powers. The execution flow follows this path:

`VotingPowerProvider.getVotingPowers` -> `VotingPowerProviderLogic.getVotingPowers` -> `VotingPowerProvider.getOperators`, which retrieves the current set of operators and their voting powers.

Internally, the `VotingPowerProvider.getOperators` function accesses the `PersistentSet.AddressSet _operators` data type and invokes the `PersistentSet.values` function.

The historical operators are maintained within a struct of type `AddressSet`, which comprises the following elements defined in `PersistentAddress.sol`

```
    struct AddressSet {
        Set _inner;
    }

    struct Set {
        bytes32[] _elements;
        mapping(bytes32 => Status) _statuses;
        uint256 _length;
    }
```

When operators are registered, the `PersistentSet.AddressSet _operators` variable internally invokes the `PersistentSet._add` function, which continuously appends the operator addresses, cast to bytes32, into the `bytes32[] _elements` array. This array does not decrease in size even when operators are removed.

The problem occurs during the execution flow from `VotingPowerProvider.getVotingPowers` to `VotingPowerProviderLogic.getVotingPowers`, then to `VotingPowerProvider.getOperators`, followed by `_getVotingPowerProviderStorage()._operators.values()`, and finally reaching the `PersistentSet._values` function.

```
    function _values(
        Set storage set
    ) private view returns (bytes32[] memory values_) {
        unchecked {
@>            uint256 totalLength = set._elements.length; //@audit full historical length of operators retrieved, which can cause OOG in subsequent for loop
            values_ = new bytes32[](totalLength);
            uint256 actualLength;
            for (uint256 i; i < totalLength; ++i) {
                if (_contains(set, set._elements[i])) {
                    values_[actualLength++] = set._elements[i];
                }
            }
            assembly ("memory-safe") {
                mstore(values_, actualLength)
            }
        }
    }
```

It is important to note that since the full length of `_elements` is consistently retrieved (and never decreases), if the number of operators grows to a large amount, potentially reaching hundreds of thousands, this will inevitably lead to out-of-gas (OOG) errors and cause the retrieval of operator voting powers through `VotingPowerProvider.getVotingPowers` to fail. This situation poses a significant issue for the SDK and off-chain mechanisms that depend on on-chain data (such as committing a new validator header set). Additionally, critical features that rely on the `getVotingPowers` view function may also experience failures, resulting in those functionalities consistently reverting.

The growth of operators in the `_elements` array can happen in different scenarios depending on the SDK use case. Some examples are

1. In the event the use case allows any operators to register themselves with no blocklists, a malicious user can flood the array with random addresses which triggers OOG
2. In the event where blocklists do happen, a legitimate use case that wants to support tens to hundreds of thousands of operators will not be able to retrieve important voting power information

## POC

Consider the following scenario

1. Bob wants to retrieve the current voting power of the operators.
2. However, the number of historical operator addresses has increased to hundreds of thousands.
3. When he attempts to call `VotingPowerProvider.getVotingPowers`, the function consistently reverts due to exceeding the block gas limit on Ethereum.
4. As a result, he is unable to carry out critical off-chain operations that depend on the on-chain voting power information or his call to crucial on chain functionality consistently reverts.

## Root Cause

Unbounded array in `PersistentSet.AddressSet` data types, specifically in the `Set.bytes32[] _elements` variable

## Impact

Unable to retrieve important information from view function which can cause DOS of offchain operations or crucial on chain functionalities

## LOC

https://github.com/sherlock-audit/2025-06-symbiotic-relay/blob/main/middleware-sdk/src/contracts/libraries/structs/PersistentSet.sol#L38