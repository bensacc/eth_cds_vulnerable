// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ETH Credit Default Swap
 * @notice Simulates a CDS that pays out if ETH price drops below $1,500.
 *
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * !! INTENTIONALLY VULNERABLE CONTRACT - FOR SECURITY TESTING ONLY  !!
 * !! DO NOT DEPLOY TO MAINNET OR ANY LIVE NETWORK                   !!
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 * EMBEDDED VULNERABILITY: Classic reentrancy attack in claimPayout().
 * The contract sends ETH *before* updating the caller's balance/state,
 * allowing a malicious contract to recursively re-enter claimPayout()
 * and drain the protection pool.
 */

interface IOracle {
    function getEthUsdPrice() external view returns (uint256); // price in USD * 1e8
}

contract EthCreditDefaultSwap {

    // -------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------

    address public owner;
    IOracle public oracle;

    uint256 public constant STRIKE_PRICE  = 1_500 * 1e8; // $1,500.00 in 1e8 format
    uint256 public constant PREMIUM_RATE  = 0.01 ether;  // flat premium per period
    uint256 public constant PERIOD        = 30 days;

    struct Position {
        uint256 protectionAmount; // ETH amount covered
        uint256 premiumPaid;
        uint256 expiry;
        bool    active;
    }

    mapping(address => Position) public positions;
    mapping(address => uint256)  public pendingPayouts;

    uint256 public totalProtectionPool; // ETH held as collateral by sellers

    event ProtectionBought(address indexed buyer, uint256 amount, uint256 expiry);
    event PayoutClaimed(address indexed buyer, uint256 amount);
    event PoolFunded(address indexed seller, uint256 amount);

    // -------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------

    constructor(address _oracle) {
        owner  = msg.sender;
        oracle = IOracle(_oracle);
    }

    // -------------------------------------------------------------------
    // Seller side: fund the protection pool
    // -------------------------------------------------------------------

    function fundPool() external payable {
        require(msg.value > 0, "Must send ETH");
        totalProtectionPool += msg.value;
        emit PoolFunded(msg.sender, msg.value);
    }

    // -------------------------------------------------------------------
    // Buyer side: purchase protection
    // -------------------------------------------------------------------

    function buyProtection(uint256 protectionAmount) external payable {
        require(msg.value >= PREMIUM_RATE, "Insufficient premium");
        require(protectionAmount > 0, "Invalid protection amount");
        require(protectionAmount <= totalProtectionPool, "Pool insufficient");
        require(!positions[msg.sender].active, "Position already active");

        positions[msg.sender] = Position({
            protectionAmount: protectionAmount,
            premiumPaid:      msg.value,
            expiry:           block.timestamp + PERIOD,
            active:           true
        });

        emit ProtectionBought(msg.sender, protectionAmount, block.timestamp + PERIOD);
    }

    // -------------------------------------------------------------------
    // Trigger: check if payout condition is met
    // -------------------------------------------------------------------

    function triggerCDS() external {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No active position");
        require(block.timestamp <= pos.expiry, "Position expired");

        uint256 currentPrice = oracle.getEthUsdPrice();
        require(currentPrice < STRIKE_PRICE, "ETH price above strike");

        pendingPayouts[msg.sender] += pos.protectionAmount;
        pos.active = false;
        totalProtectionPool -= pos.protectionAmount;
    }

    // -------------------------------------------------------------------
    // !! VULNERABLE FUNCTION !!
    //
    // REENTRANCY BUG: ETH is transferred via call() BEFORE
    // pendingPayouts[msg.sender] is zeroed out. A malicious contract's
    // receive() function can re-enter claimPayout() repeatedly,
    // draining the contract's entire balance.
    //
    // Fix would be: zero out pendingPayouts[msg.sender] BEFORE the call,
    // or use a ReentrancyGuard modifier (checks-effects-interactions).
    // -------------------------------------------------------------------

    function claimPayout() external {
        uint256 amount = pendingPayouts[msg.sender];
        require(amount > 0, "Nothing to claim");

        // !! BUG: state is NOT updated before the external call !!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens AFTER the external call — too late!
        pendingPayouts[msg.sender] = 0;

        emit PayoutClaimed(msg.sender, amount);
    }

    // -------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------

    function setOracle(address _oracle) external {
        require(msg.sender == owner, "Not owner");
        oracle = IOracle(_oracle);
    }

    receive() external payable {
        totalProtectionPool += msg.value;
    }
}
