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

#include "cstdint.hpp"
#include "char_type.hpp"
#include "cstr_type.hpp"
#include "discard.hpp"
#include "is_constant_evaluated.hpp"
#include "is_void.hpp"
#include "min_of.hpp"

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
    ///   @brief Same as std::memset with parameter checks. If dst is a
    ///     nullptr, or count is 0, this function returns a nullptr without
    ///     doing anything.
    ///
    /// <!-- notes -->
    ///   @note Clang currently does not have support for this function in
    ///     constexpr logic.
    ///
    /// <!-- inputs/outputs -->
    ///   @param dst the buffer to set to all 'ch'
    ///   @param ch the value to set the provided buffer to
    ///   @param count the total number of bytes to set
    ///   @return Returns the same result as std::memset.
    ///
    [[maybe_unused]] inline void *
    builtin_memset(void *const dst, bsl::int8 const ch, bsl::uintmax const count) noexcept
    {
        bsl::discard(dst);
        bsl::discard(ch);
        bsl::discard(count);

        if ((nullptr == dst) || (count == 0U)) {
            return nullptr;
        }

        return BSL_BUILTIN_MEMSET;
    }

    /// <!-- description -->
    ///   @brief Same as std::memcmp with parameter checks. If lhs, rhs are a
    ///     nullptr, or count is 0, this function returns 0.
    ///
    /// <!-- notes -->
    ///   @note For now, this function is marked as a non-constexpr as there
    ///     seems to be a bug in how this function is implemented by Clang
    ///     with constexpr functions.
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the comparison
    ///   @param rhs the right hand side of the comparison
    ///   @param count the total number of bytes to compare
    ///   @return Returns the same result as std::memcmp.
    ///
    [[nodiscard]] inline bsl::int32
    builtin_memcmp(void const *const lhs, void const *const rhs, bsl::uintmax const count) noexcept
    {
        bsl::discard(lhs);
        bsl::discard(rhs);
        bsl::discard(count);

        if ((nullptr == lhs) || (nullptr == rhs) || (0U == count)) {
            return 0;
        }

        return BSL_BUILTIN_MEMCMP;
    }

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
    [[nodiscard]] inline constexpr bsl::int32
    builtin_strncmp(cstr_type const lhs, cstr_type const rhs, bsl::uintmax const count) noexcept
    {
        bsl::discard(lhs);
        bsl::discard(rhs);
        bsl::discard(count);

        if ((nullptr == lhs) || (nullptr == rhs) || (0U == count)) {
            return 0;
        }

        return BSL_BUILTIN_STRNCMP;
    }

    /// <!-- description -->
    ///   @brief Same as std::strlen with parameter checks. If str is a
    ///     nullptr, this returns 0.
    ///
    /// <!-- inputs/outputs -->
    ///   @param str a pointer to a string to get the length of
    ///   @return Returns the same result as std::strlen.
    ///
    [[nodiscard]] inline constexpr bsl::uintmax
    builtin_strlen(cstr_type const str) noexcept
    {
        bsl::discard(str);

        if (nullptr == str) {
            return 0U;
        }

        return BSL_BUILTIN_STRLEN;
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
    builtin_strnchr(cstr_type const str, char_type const ch, bsl::uintmax const count) noexcept
    {
        bsl::discard(str);
        bsl::discard(ch);
        bsl::discard(count);

        if ((nullptr == str) || (0U == count)) {
            return nullptr;
        }

        return BSL_BUILTIN_CHAR_MEMCHR;
    }
}

#endif
