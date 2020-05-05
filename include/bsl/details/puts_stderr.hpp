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

#ifndef BSL_DETAILS_PUTS_STDERR_HPP
#define BSL_DETAILS_PUTS_STDERR_HPP

#include "../discard.hpp"
#include "../cstr_type.hpp"
#include "../is_constant_evaluated.hpp"

#ifndef __bareflank__

#include <stdio.h>    // PRQA S 1-10000 // NOLINT

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Outputs a string to stderr. If this function is
        ///     executed from a constexpr, or is given a nullptr, this
        ///     function does nothing. The provided string must also end
        ///     in a '\0'. By default this function will call
        ///     fputs(str, stderr).
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defaults to void. Provides the ability to specialize
        ///     this function to provide your own custom implementation.
        ///   @param str the string to output to stderr
        ///
        template<typename T = void>
        constexpr void
        puts_stderr(cstr_type const str) noexcept
        {
            if constexpr (BSL_PERFORCE) {
                bsl::discard(str);
            }
            else {
                if ((!is_constant_evaluated()) && (nullptr != str)) {
                    bsl::discard(fputs(str, stderr));    // PRQA S 1-10000 // NOLINT
                }
                else {
                    bsl::discard(str);
                }
            }
        }
    }
}

#else

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Outputs a string to stderr. If this function is
        ///     executed from a constexpr, or is given a nullptr, this
        ///     function does nothing. The provided string must also end
        ///     in a '\0'. By default this function will call
        ///     fputs(str, stderr).
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defaults to void. Provides the ability to specialize
        ///     this function to provide your own custom implementation.
        ///   @param str the string to output to stderr
        ///
        template<typename T = void>
        constexpr void puts_stderr(cstr_type const str) noexcept;
    }
}

#endif

#endif
