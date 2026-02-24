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

contract UniswapV3TWAPOracle {

    IUniswapV3Pool public immutable pool;
    uint32  public constant TWAP_PERIOD = 5 minutes;

    // Decimal adjustment: USDC has 6 decimals, WETH has 18.
    // Raw tick price is in USDC-per-WETH * 1e(6-18) = * 1e-12
    // We scale up to match the CDS contract's 1e8 USD format.
    int256  private constant DECIMAL_ADJUSTMENT = 1e20; // 1e8 * 1e12

    constructor(address _pool) {
        pool = IUniswapV3Pool(_pool);
    }

    /// @notice Returns ETH price in USD scaled by 1e8 (e.g. $2000 => 200000000000)
    function getEthUsdPrice() external view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD; // oldest observation
        secondsAgos[1] = 0;           // most recent

        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);

        // Average tick over the TWAP window
        int56 tickDelta    = tickCumulatives[1] - tickCumulatives[0];
        int24 averageTick  = int24(tickDelta / int56(uint56(TWAP_PERIOD)));

        // price = 1.0001^tick  (approximated via TickMath library logic)
        // For simplicity we use the tick directly; in production use
        // TickMath.getSqrtRatioAtTick + FullMath for precise pricing.
        //
        // price_usdc_per_weth (raw) = 1.0001^averageTick
        // We use a log-linear approximation: e^(tick * ln(1.0001))
        // ln(1.0001) ≈ 0.00009999500033
        //
        // For a testing contract this integer approximation is sufficient:
        //   priceRaw ≈ 1e8 * 1.0001^tick
        //
        // Positive tick  => WETH more expensive than 1 USDC (normal)
        // Negative tick  => would mean 1 WETH < 1 USDC (not realistic)

        // Simple integer power approximation using the identity:
        //   1.0001^n ≈ e^(0.00009999500033 * n)
        // We implement this as a fixed-point multiply loop for small ranges,
        // but for a CDS test contract we use a direct scaling shortcut:
        uint256 price = _tickToUsdPrice(averageTick);
        return price;
    }

    /// @dev Converts a Uniswap V3 tick to a USD price scaled by 1e8.
    ///      Uses the relationship: sqrtPriceX96 = sqrt(1.0001^tick) * 2^96
    ///      and works backward to a human-readable price.
    ///
    ///      For the USDC/WETH pool:
    ///        raw_price = 1.0001^tick           (USDC units per WETH, unscaled)
    ///        eth_usd   = raw_price * 1e12       (correct for 6 vs 18 decimals)
    ///        result    = eth_usd * 1e8          (scale to 1e8 format)
    ///
    ///      We approximate 1.0001^tick with a Babylonian sqrt + bit-shift trick
    ///      on the sqrtPriceX96 value derived from the tick.
    function _tickToUsdPrice(int24 tick) internal pure returns (uint256) {
        // Get sqrtPriceX96 from tick using condensed TickMath logic.
        // This is a simplified version for illustrative / test purposes.
        uint256 sqrtPrice = _getSqrtPriceFromTick(tick);

        // price_raw = (sqrtPrice / 2^96)^2
        // price_usdc_per_weth = price_raw * 10^12   (decimal correction)
        // price_1e8 = price_usdc_per_weth * 1e8

        // Combined: price_1e8 = sqrtPrice^2 * 1e20 / 2^192
        uint256 Q192 = 2**96;
        // Compute price = sqrtPrice^2 / Q192^2, scaled by DECIMAL_ADJUSTMENT
        uint256 price = (sqrtPrice * sqrtPrice) / (Q192 * Q192 / uint256(DECIMAL_ADJUSTMENT > 0 ? uint256(DECIMAL_ADJUSTMENT) : 1));
        return price;
    }

    /// @dev Minimal tick-to-sqrtPriceX96 implementation.
    ///      Full production version: use Uniswap's TickMath.sol
    function _getSqrtPriceFromTick(int24 tick) internal pure returns (uint256 sqrtPriceX96) {
        // Encode tick as ratio: ratio = 1.0001^|tick| as Q128.128 fixed point
        uint256 absTick = tick < 0 ? uint256(int256(-tick)) : uint256(int256(tick));

        uint256 ratio = absTick & 0x1 != 0
            ? 0xfffcb933bd6fad37aa2d162d1a594001
            : 0x100000000000000000000000000000000;

        // Apply each bit of the tick as a precomputed multiplier
        if (absTick & 0x2  != 0) ratio = (ratio * 0xfff97272373d413259a46990580e213a) >> 128;
        if (absTick & 0x4  != 0) ratio = (ratio * 0xfff2e50f5f656932ef12357cf3c7fdcc) >> 128;
        if (absTick & 0x8  != 0) ratio = (ratio * 0xffe5caca7e10e4e61c3624eaa0941cd0) >> 128;
        if (absTick & 0x10 != 0) ratio = (ratio * 0xffcb9843d60f6159c9db58835c926644) >> 128;
        if (absTick & 0x20 != 0) ratio = (ratio * 0xff973b41fa98c081472e6896dfb254c0) >> 128;
        if (absTick & 0x40 != 0) ratio = (ratio * 0xff2ea16466c96a3843ec78b326b52861) >> 128;
        if (absTick & 0x80 != 0) ratio = (ratio * 0xfe5dee046a99a2a811c461f1969c3053) >> 128;

        // Invert for negative ticks (price of token1 in token0 terms)
        if (tick > 0) ratio = type(uint256).max / ratio;

        // Convert Q128.128 → Q64.96 (sqrtPriceX96 format)
        sqrtPriceX96 = (ratio >> 32) + (ratio % (1 << 32) == 0 ? 0 : 1);
    }
}
