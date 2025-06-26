# Market funds cannot be withdrawn for a profile as fees are not subtracted from fundsPaid when they are already applied

## Vulnerability Details
When users buy votes in the ReputationMarket contract, they pay fees that go to two places:

1. Protocol fees that go to the treasury
2. Donation fees that go to the market owner

```solidity  
  /**
   * @notice Processes protocol fees and donations for a market transaction
   * @dev Handles both protocol fee transfer and donation escrow updates.
   *      Protocol fees go to protocol fee address immediately.
   *      Donations are held in escrow until withdrawn by recipient.
   * @param protocolFee Amount of protocol fee to collect
   * @param donation Amount to add to donation escrow
   * @param marketOwnerProfileId Profile ID of market owner receiving donation
   * @return fees Total fees processed
   */
  function applyFees(
    uint256 protocolFee,
    uint256 donation,
    uint256 marketOwnerProfileId
  ) private returns (uint256 fees) {
@>    donationEscrow[donationRecipient[marketOwnerProfileId]] += donation; // donation fees are updated for market owner
    if (protocolFee > 0) {
@>      (bool success, ) = protocolFeeAddress.call{ value: protocolFee }(""); // protocolFees paid to treasury
      if (!success) revert FeeTransferFailed("Protocol fee deposit failed");
    }
    fees = protocolFee + donation;
  }
```
The fundsPaid variable tracks the total amount a user pays when buying votes, which includes:

1. The actual cost of votes
2. Protocol fees
3. Donation fees

The issue arises in the execution flow:

1. First, `applyFees()` processes the fees by:  
    - Sending protocol fees to the treasury
    - Adding donations to the market owner's escrow. marketOwner can withdraw their donations through withdrawDonations() at anytime
2. Then, marketFunds[profileId] is updated by adding the full fundsPaid amount

Double counting happens where fees are both:

- Distributed to their destinations (treasury and/or market owner address)
- Still included in the market's recorded funds via marketFunds[profileId]

```solidity
  /**
   * @dev Buys votes for a given market.
   * @param profileId The profileId of the market to buy votes for.
   * @param isPositive Whether the votes are trust or distrust.
   * @param expectedVotes The expected number of votes to buy. This is used as the basis for the slippage check.
   * @param slippageBasisPoints The slippage tolerance in basis points (1 basis point = 0.01%).
   */
  function buyVotes(
    uint256 profileId,
    bool isPositive,
    uint256 expectedVotes,
    uint256 slippageBasisPoints
  ) public payable whenNotPaused activeMarket(profileId) nonReentrant {
    _checkMarketExists(profileId);

    // Determine how many votes can be bought with the funds provided
    (
      uint256 votesBought,
@>      uint256 fundsPaid, // @audit funds paid include amount paid for votes + protocolFee + donation
      ,
      uint256 protocolFee,
      uint256 donation,
      uint256 minVotePrice,
      uint256 maxVotePrice
    ) = _calculateBuy(markets[profileId], isPositive, msg.value);

    _checkSlippageLimit(votesBought, expectedVotes, slippageBasisPoints);

    // Apply fees first
@>    applyFees(protocolFee, donation, profileId); // @audit fees are applied first

    // Update market state
    markets[profileId].votes[isPositive ? TRUST : DISTRUST] += votesBought;
    votesOwned[msg.sender][profileId].votes[isPositive ? TRUST : DISTRUST] += votesBought;

    // Add buyer to participants if not already a participant
    if (!isParticipant[profileId][msg.sender]) {
      participants[profileId].push(msg.sender);
      isParticipant[profileId][msg.sender] = true;
    }

    // Calculate and refund remaining funds
    uint256 refund = msg.value - fundsPaid;
    if (refund > 0) _sendEth(refund);

    // tally market funds
@>    marketFunds[profileId] += fundsPaid; // @audit fundsPaid still includes protocolFee + donation
    emit VotesBought(
      profileId,
      msg.sender,
      isPositive,
      votesBought,
      fundsPaid,
      block.timestamp,
      minVotePrice,
      maxVotePrice
    );
    _emitMarketUpdate(profileId);
  }
```

Subsequently, when a market graduates, funds from other markets might be required or the transaction might revert when authorize address calls ReputationMarket.withdrawGraduatedMarketFunds

```solidity
  /**
   * @notice Withdraws funds from a graduated market
   * @dev Only callable by the authorized graduation withdrawal address
   * @param profileId The ID of the graduated market to withdraw from
   */
  function withdrawGraduatedMarketFunds(uint256 profileId) public whenNotPaused {
    address authorizedAddress = contractAddressManager.getContractAddressForName(
      "GRADUATION_WITHDRAWAL"
    );
    if (msg.sender != authorizedAddress) {
      revert UnauthorizedWithdrawal();
    }
    _checkMarketExists(profileId);
    if (!graduatedMarkets[profileId]) {
      revert MarketNotGraduated();
    }
    if (marketFunds[profileId] == 0) {
      revert InsufficientFunds();
    }

@>    _sendEth(marketFunds[profileId]); // @audit will revert or tap into ETH from other markets / initialLiquidity
    emit MarketFundsWithdrawn(profileId, msg.sender, marketFunds[profileId]);
    marketFunds[profileId] = 0;
  }
```

## POC

Consider a simplistic scenario:

Setup:

A market exists for profile Colossal Chiffon Urchin - authorProfileId can avoid being slashed #1 with 1 trust and 1 distrust vote
Protocol fee and donation fee are both set to 5%
Each vote costs 0.005 ETH
Vulnerability Scenario:
1. Alice sends 0.01 ETH to buy 1 trust vote
2. The contract calculates:
    - 0.0005 ETH for protocol fee
    - 0.0005 ETH for donation
    - 0.009 ETH left for buying votes
3. For her one vote purchase:
    - Vote cost = 0.005 ETH
    - Total charged = 0.006 ETH (0.005 ETH + 0.0005 ETH protocol fee + 0.0005 ETH donation)
4. The contract:
    - Sends 0.0005 ETH to treasury
    - Records 0.0005 ETH for donation.
    - Keeps 0.005 ETH for the vote
    - Refunds her remaining 0.004 ETH
5. Market owner withdraw the donation and 0.005 ETH is send to his address.
6. However, the contract incorrectly records the market funds as 0.006 ETH (including fees and donations that were already paid out )
7. Later when trying to withdraw funds after market graduation:
    - Contract only has 0.005 ETH for this market
    - But tries to withdraw 0.006 ETH
    - Transaction fails and funds get stuck or funds from other markets / `initialLiqudity` are withdrawn

## Impact
Market funds can get stuck in the contract with no way to withdraw them. If withdrawal succeeds, it may incorrectly take ETH that belongs to other markets / initialLiqiduity, causing other users to lose funds. Furthermore, if market owner hasn't withdraw their donations, they may not be able to receive donations or may incorrectly take ETH that belongs to other market owners or from the initialLiquidity.

## Code Snippet
https://github.com/sherlock-audit/2024-11-ethos-network-ii/blob/main/ethos/packages/contracts/contracts/ReputationMarket.sol#L442

https://github.com/sherlock-audit/2024-11-ethos-network-ii/blob/main/ethos/packages/contracts/contracts/ReputationMarket.sol#L1116

https://github.com/sherlock-audit/2024-11-ethos-network-ii/blob/main/ethos/packages/contracts/contracts/ReputationMarket.sol#L920

https://github.com/sherlock-audit/2024-11-ethos-network-ii/blob/main/ethos/packages/contracts/contracts/ReputationMarket.sol#L660

## Recommendations
When recording market funds, subtract out the fees and donations before updating the market funds in the profileId.
```solidity
  /**
   * @dev Buys votes for a given market.
   * @param profileId The profileId of the market to buy votes for.
   * @param isPositive Whether the votes are trust or distrust.
   * @param expectedVotes The expected number of votes to buy. This is used as the basis for the slippage check.
   * @param slippageBasisPoints The slippage tolerance in basis points (1 basis point = 0.01%).
   */
  function buyVotes(
    uint256 profileId,
    bool isPositive,
    uint256 expectedVotes,
    uint256 slippageBasisPoints
  ) public payable whenNotPaused activeMarket(profileId) nonReentrant {
    _checkMarketExists(profileId);

    // Determine how many votes can be bought with the funds provided
    (
      uint256 votesBought,
      uint256 fundsPaid,
      ,
      uint256 protocolFee,
      uint256 donation,
      uint256 minVotePrice,
      uint256 maxVotePrice
    ) = _calculateBuy(markets[profileId], isPositive, msg.value);

    _checkSlippageLimit(votesBought, expectedVotes, slippageBasisPoints);

    // Apply fees first
    applyFees(protocolFee, donation, profileId);

    // Update market state
    markets[profileId].votes[isPositive ? TRUST : DISTRUST] += votesBought;
    votesOwned[msg.sender][profileId].votes[isPositive ? TRUST : DISTRUST] += votesBought;

    // Add buyer to participants if not already a participant
    if (!isParticipant[profileId][msg.sender]) {
      participants[profileId].push(msg.sender);
      isParticipant[profileId][msg.sender] = true;
    }

    // Calculate and refund remaining funds
    uint256 refund = msg.value - fundsPaid;
    if (refund > 0) _sendEth(refund);

    // tally market funds
+    marketFunds[profileId] += (fundsPaid - protocolFee - donation)
-    marketFunds[profileId] += fundsPaid;
    emit VotesBought(
      profileId,
      msg.sender,
      isPositive,
      votesBought,
      fundsPaid,
      block.timestamp,
      minVotePrice,
      maxVotePrice
    );
    _emitMarketUpdate(profileId);
  }
```