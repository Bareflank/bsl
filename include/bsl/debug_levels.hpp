/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///
/// @file debug_levels.hpp
///

#ifndef BSL_DEBUG_LEVELS_HPP
#define BSL_DEBUG_LEVELS_HPP

#include "bsl/cstdint.hpp"

namespace bsl
{
    /// @brief defines the default verbose mode
    constexpr bsl::uintmx CRITICAL_ONLY{static_cast<bsl::uintmx>(0)};
    /// @brief defines "-v" verbose mode
    constexpr bsl::uintmx V{static_cast<bsl::uintmx>(1)};
    /// @brief defines "-vv" verbose mode
    constexpr bsl::uintmx VV{static_cast<bsl::uintmx>(2)};
    /// @brief defines "-vvv" verbose mode
    constexpr bsl::uintmx VVV{static_cast<bsl::uintmx>(3)};

    /// <!-- description -->
    ///   @brief Returns true if the debug level was set to critical only
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the debug level was set to critical only
    ///
    [[nodiscard]] constexpr auto
    debug_level_is_critical_only() noexcept -> bool
    {
        // NOLINTNEXTLINE(misc-redundant-expression)
        return BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY;
    }

    /// <!-- description -->
    ///   @brief Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    [[nodiscard]] constexpr auto
    debug_level_is_at_least_v() noexcept -> bool
    {
        // NOLINTNEXTLINE(misc-redundant-expression)
        return BSL_DEBUG_LEVEL >= bsl::V;
    }

    /// <!-- description -->
    ///   @brief Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    [[nodiscard]] constexpr auto
    debug_level_is_at_least_vv() noexcept -> bool
    {
        // NOLINTNEXTLINE(misc-redundant-expression)
        return BSL_DEBUG_LEVEL >= bsl::VV;
    }

    /// <!-- description -->
    ///   @brief Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    [[nodiscard]] constexpr auto
    debug_level_is_at_least_vvv() noexcept -> bool
    {
        // NOLINTNEXTLINE(misc-redundant-expression)
        return BSL_DEBUG_LEVEL >= bsl::VVV;
    }
}

#endif
