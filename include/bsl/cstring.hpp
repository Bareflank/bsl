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
/// @file cstring.hpp
///

#ifndef BSL_CSTRING_HPP
#define BSL_CSTRING_HPP

#include "char_type.hpp"
#include "convert.hpp"
#include "cstr_type.hpp"
#include "safe_integral.hpp"

// Notes: --
// - In general, you should not use these functions as they are not
//   Core Guideline or AUTOSAR compliant. We leverage them internally
//   within the BSL as this is the only way to ensure some of the BSL's
//   APIs have the proper optimizations.
// - We only implement the functions that we need here. Once again, do
//   not rely on this header.
// - The APIs of these functions have been modified to remove the need
//   for conversions as well as ensure sizes are provided (where possible).
//   This means that some of the APIs are our own to ensure there are not
//   issues with name collisions.
// - Instead of calling the builtin functions manually, we rely on the
//   build system to provide the implementation of each of these functions.
//   This allows you to replace these with your compiler's version, or
//   with a static answer to analysis if needed (for example, PRQA does
//   not support these builtins)
// - Each of these functions has safety added to them to ensure crashing is
//   not possible.
// - All function arguments are sent to bsl::discard to ensure you can replace
//   the builtins with static values without getting unused argument errors.
//

namespace bsl
{
    /// <!-- description -->
    ///   @brief Same as std::strncmp with parameter checks. If lhs, rhs are a
    ///     nullptr, or count is 0, this function returns 0.
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the comparison
    ///   @param rhs the right hand side of the comparison
    ///   @param count the total number of bytes to compare
    ///   @return Returns the same result as std::strncmp.
    ///
    [[nodiscard]] inline constexpr safe_int32
    builtin_strncmp(cstr_type const lhs, cstr_type const rhs, safe_uintmax const count) noexcept
    {
        if ((nullptr == lhs) || (nullptr == rhs) || (count.is_zero())) {
            return to_i32(0);
        }

        if constexpr (BSL_PERFORCE) {
            return to_i32(0);
        }
        else {
            return to_i32(__builtin_strncmp(lhs, rhs, count.get()));
        }
    }

    /// <!-- description -->
    ///   @brief Same as std::strlen with parameter checks. If str is a
    ///     nullptr, this returns 0.
    ///
    /// <!-- inputs/outputs -->
    ///   @param str a pointer to a string to get the length of
    ///   @return Returns the same result as std::strlen.
    ///
    [[nodiscard]] inline constexpr safe_uintmax
    builtin_strlen(cstr_type const str) noexcept
    {
        if (nullptr == str) {
            return to_umax(0);
        }

        if constexpr (BSL_PERFORCE) {
            return to_umax(0);
        }
        else {
            return to_umax(__builtin_strlen(str));
        }
    }

    /// <!-- description -->
    ///   @brief Same as std::strnchr with parameter checks. If str is a
    ///     nullptr, or count is 0, this function returns a nullptr.
    ///
    /// <!-- inputs/outputs -->
    ///   @param str the string to search
    ///   @param ch the character to look for.
    ///   @param count the total number of character in str to search through
    ///   @return Returns the same result as std::strnchr.
    ///
    [[nodiscard]] inline constexpr cstr_type
    builtin_strnchr(cstr_type const str, char_type const ch, safe_uintmax const count) noexcept
    {
        if ((nullptr == str) || (count.is_zero())) {
            return nullptr;
        }

        if constexpr (BSL_PERFORCE) {
            return nullptr;
        }
        else {
            safe_uintmax len{__builtin_strlen(str)};
            return __builtin_char_memchr(str, ch, count.min(len + to_umax(1)).get());
        }
    }
}

#endif
