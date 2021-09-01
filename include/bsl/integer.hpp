/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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

#ifndef BSL_INTEGER_HPP
#define BSL_INTEGER_HPP

#include "cstdint.hpp"
#include "is_signed.hpp"
#include "numeric_limits.hpp"
#include "touch.hpp"
#include "unlikely.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to tell the user during compile-time that an
    ///     error has occurred during an add, sub or mul operation
    ///     from a bsl::safe_integral.
    ///
    inline void
    integral_overflow_underflow_wrap_error() noexcept
    {}

    /// <!-- description -->
    ///   @brief Returns __builtin_add_overflow(x, y, res)
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of values to add
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @param pmut_cst_res the result of the operation
    ///   @return Returns __builtin_add_overflow(x, y, res)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    builtin_add_overflow(T const lhs, T const rhs, T *const pmut_cst_res) noexcept -> bool
    {
        // This is how Clang presents the builtins, which we are required
        // top use.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
        if (unlikely(__builtin_add_overflow(lhs, rhs, pmut_cst_res))) {
            integral_overflow_underflow_wrap_error();
            return true;
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief Returns __builtin_sub_overflow(x, y, res)
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of values to subtract
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @param pmut_cst_res the result of the operation
    ///   @return Returns __builtin_sub_overflow(x, y, res)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    builtin_sub_overflow(T const lhs, T const rhs, T *const pmut_cst_res) noexcept -> bool
    {
        // This is how Clang presents the builtins, which we are required
        // top use.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
        if (unlikely(__builtin_sub_overflow(lhs, rhs, pmut_cst_res))) {
            integral_overflow_underflow_wrap_error();
            return true;
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief Returns __builtin_mul_overflow(x, y, res)
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of values to multiply
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @param pmut_cst_res the result of the operation
    ///   @return Returns __builtin_mul_overflow(x, y, res)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    builtin_mul_overflow(T const lhs, T const rhs, T *const pmut_cst_res) noexcept -> bool
    {
        // This is how Clang presents the builtins, which we are required
        // top use.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
        if (unlikely(__builtin_mul_overflow(lhs, rhs, pmut_cst_res))) {
            integral_overflow_underflow_wrap_error();
            return true;
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief If no overflow, underflow, wrap occurs, sets *res to
    ///     lhs / rhs and returns false. Otherwise returns true.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of values to divide
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @param pmut_cst_res the result of the operation
    ///   @return If no overflow, underflow, wrap occurs, sets *res to
    ///     lhs / rhs and returns false. Otherwise returns true
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    builtin_div_overflow(T const lhs, T const rhs, T *const pmut_cst_res) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
        if (unlikely(T{} == rhs)) {
            integral_overflow_underflow_wrap_error();
            return true;
        }

        if constexpr (is_signed<T>::value) {
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            if (numeric_limits<T>::min_value() == lhs) {
                // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
                constexpr T neg_one{static_cast<T>(-1)};
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                if (unlikely(neg_one == rhs)) {
                    integral_overflow_underflow_wrap_error();
                    return true;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }
        }

        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        *pmut_cst_res = lhs / rhs;
        return false;
    }

    /// <!-- description -->
    ///   @brief If no overflow, underflow, wrap occurs, sets *res to
    ///     lhs % rhs and returns false. Otherwise returns true.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of values to mod
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @param pmut_cst_res the result of the operation
    ///   @return If no overflow, underflow, wrap occurs, sets *res to
    ///     lhs % rhs and returns false. Otherwise returns true
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    builtin_mod_overflow(T const lhs, T const rhs, T *const pmut_cst_res) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
        if (unlikely(T{} == rhs)) {
            integral_overflow_underflow_wrap_error();
            return true;
        }

        if constexpr (is_signed<T>::value) {
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            if (numeric_limits<T>::min_value() == lhs) {
                // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
                constexpr T neg_one{static_cast<T>(-1)};
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                if (unlikely(neg_one == rhs)) {
                    integral_overflow_underflow_wrap_error();
                    return true;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }
        }

        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        *pmut_cst_res = lhs % rhs;
        return false;
    }
}

#endif
