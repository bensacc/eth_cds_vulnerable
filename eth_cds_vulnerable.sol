// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


// --------------------------------------------------------------------
// Main CDS Contract
// --------------------------------------------------------------------

contract EthCreditDefaultSwap {

    address public owner;
    UniswapV3TWAPOracle public oracle;

    // Uniswap V3 USDC/WETH 0.05% pool on Ethereum mainnet
    address public constant USDC_WETH_POOL = 0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640;

    uint256 public constant STRIKE_PRICE = 1_500 * 1e8; // $1,500 in 1e8 format
    uint256 public constant PREMIUM_RATE = 0.01 ether;
    uint256 public constant PERIOD       = 30 days;

    struct Position {
        uint256 protectionAmount;
        uint256 premiumPaid;
        uint256 expiry;
        bool    active;
    }

    mapping(address => Position) public positions;
    mapping(address => uint256)  public pendingPayouts;
    uint256 public totalProtectionPool;

    event ProtectionBought(address indexed buyer, uint256 amount, uint256 expiry);
    event PayoutClaimed(address indexed buyer, uint256 amount);
    event PoolFunded(address indexed seller, uint256 amount);

    constructor() {
        owner  = msg.sender;
        // Deploy the oracle pointed at the canonical Uniswap V3 USDC/WETH pool
        oracle = new UniswapV3TWAPOracle(USDC_WETH_POOL);
    }

    function fundPool() external payable {
        require(msg.value > 0, "Must send ETH");
        totalProtectionPool += msg.value;
        emit PoolFunded(msg.sender, msg.value);
    }

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

    function triggerCDS() external {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No active position");
        require(block.timestamp <= pos.expiry, "Position expired");

        uint256 currentPrice = oracle.getEthUsdPrice();
        require(currentPrice < STRIKE_PRICE, "ETH price above strike: currently $" );

        pendingPayouts[msg.sender] += pos.protectionAmount;
        pos.active = false;
        totalProtectionPool -= pos.protectionAmount;
    }

    // !! VULNERABLE FUNCTION — reentrancy bug intentionally present !!
    // State (pendingPayouts) is updated AFTER the external .call{}
    // allowing recursive re-entry before the balance is zeroed.
    function claimPayout() external {
        uint256 amount = pendingPayouts[msg.sender];
        require(amount > 0, "Nothing to claim");

        // BUG: send ETH before updating state
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // Too late — attacker has already re-entered multiple times by here
        pendingPayouts[msg.sender] = 0;

        emit PayoutClaimed(msg.sender, amount);
    }

    function setOracle(address _newOracle) external {
        require(msg.sender == owner, "Not owner");
        oracle = UniswapV3TWAPOracle(_newOracle);
    }

    receive() external payable {
        totalProtectionPool += msg.value;
    }
}
