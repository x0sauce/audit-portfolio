# Signature can be replayed in `Forwarder.execute`

## **Summary**

The `Forwarder.execute` function is vulnerable to replay attacks due to its reliance on the relayer to create a valid `domainSeparator`, which can be exploited by malicious actors to replay transactions.

## **Vulnerability Details**

The `Forwarder.execute` function relies on the relayer to accurately create a `domainSeparator` to prevent cross-chain replay attacks. If a relayer constructs a same digest using a different `domainSeparator`, they could replay a valid signature.

This issue can be avoided by adopting a method similar to that used in `ERC2771Forwarder`, where the domain separator is obtained in an EIP712 compliant manner through `EIP712._domainSeparatorV4()`.

## **LOC**

[**https://github.com/code-423n4/2025-01-next-generation/blob/499cfa50a56126c0c3c6caa30808d79f82d31e34/contracts/Forwarder.sol#L101**](https://github.com/code-423n4/2025-01-next-generation/blob/499cfa50a56126c0c3c6caa30808d79f82d31e34/contracts/Forwarder.sol#L101)

https://github.com/code-423n4/2025-01-next-generation/blob/499cfa50a56126c0c3c6caa30808d79f82d31e34/contracts/Forwarder.sol#L144

## **Impact**

Malicious relayer can carefully construct same digest and replay the same transaction.

## **Mitigation**

Consider adopting method used in ERC2771Forwarder for obtaining the domainSeparator, which employs `EIP712._domainSeparatorV4()` to ensure a secure domainSeparator.

### **Links to affected code**

- [Forwarder.sol#L101](https://github.com/code-423n4/2025-01-next-generation/blob/499cfa50a56126c0c3c6caa30808d79f82d31e34/contracts/Forwarder.sol#L101)
- [Forwarder.sol#L144](https://github.com/code-423n4/2025-01-next-generation/blob/499cfa50a56126c0c3c6caa30808d79f82d31e34/contracts/Forwarder.sol#L144)