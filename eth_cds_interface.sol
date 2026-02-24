// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ETH Credit Default Swap
 * @notice Pays out if ETH/USDC TWAP drops below $1,500.
 *         Price is sourced from the Uniswap V3 USDC/WETH 0.05% pool on-chain.
 *
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * !! INTENTIONALLY VULNERABLE CONTRACT - FOR SECURITY TESTING ONLY  !!
 * !! DO NOT DEPLOY TO MAINNET OR ANY LIVE NETWORK                   !!
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 * EMBEDDED VULNERABILITY: Classic reentrancy in claimPayout().
 * ETH is sent BEFORE pendingPayouts state is zeroed, allowing a
 * malicious contract to recursively drain the pool.
 */

// --------------------------------------------------------------------
// Uniswap V3 Pool Interface (only what we need)
// --------------------------------------------------------------------

interface IUniswapV3Pool {
    /// @notice Returns cumulative tick and liquidity data for given secondsAgos
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (
            int56[]  memory tickCumulatives,
            uint160[] memory secondsPerLiquidityCumulativeX128s
        );

    /// @notice Token0 of the pool (USDC in USDC/WETH pool)
    function token0() external view returns (address);
}

// --------------------------------------------------------------------
// Uniswap V3 TWAP Oracle — reads from USDC/WETH 0.05% pool
//
// Mainnet pool:  0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640
//   token0 = USDC  (6 decimals)
//   token1 = WETH  (18 decimals)
//
// The pool's "tick" encodes the price as:
//   price = 1.0001^tick  (in token0/token1 units)
//
// We take a 5-minute TWAP to reduce spot-price manipulation risk.
// --------------------------------------------------------------------
