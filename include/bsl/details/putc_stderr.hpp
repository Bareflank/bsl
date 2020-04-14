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

#ifndef BSL_DETAILS_PUTC_STDERR_HPP
#define BSL_DETAILS_PUTC_STDERR_HPP

#include "../discard.hpp"
#include "../char_type.hpp"
#include "../is_constant_evaluated.hpp"

#include <stdio.h>    // PRQA S 1-10000 // NOLINT

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Outputs a character to stderr. If this function is
        ///     executed from a constexpr this function does nothing. By
        ///     default this function will call fputc(c, stderr).
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defaults to void. Provides the ability to specialize
        ///     this function to provide your own custom implementation.
        ///   @param c the character to output to stderr
        ///
        template<typename T = void>
        constexpr void
        putc_stderr(char_type const c) noexcept
        {
            if (!is_constant_evaluated()) {
                bsl::discard(fputc(c, stderr));    // PRQA S 1-10000 // NOLINT
            }
            else {
                bsl::discard(c);
            }
        }
    }
}

#endif
