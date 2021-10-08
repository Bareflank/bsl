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
/// @file cstdio.hpp
///

#ifndef BSL_CSTDIO_HPP
#define BSL_CSTDIO_HPP

#include "bsl/char_type.hpp"

// NOLINTNEXTLINE(hicpp-deprecated-headers, modernize-deprecated-headers)
#include <stdio.h>

#include <bsl/cstr_type.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Output a character to stdout
    ///
    /// <!-- inputs/outputs -->
    ///   @param c the character to output
    ///
    constexpr void
    stdio_out_char(bsl::char_type const c) noexcept
    {
        return ::putchar(c);
    }

    /// <!-- description -->
    ///   @brief Output a string to stdout
    ///
    /// <!-- inputs/outputs -->
    ///   @param str the string to output
    ///   @param len the total number of bytes to output
    ///
    constexpr void
    stdio_out_cstr(bsl::cstr_type const str, bsl::uintmx const len) noexcept
    {
        if (bsl::is_constant_evaluated()) {
            return;
        }

        syscall::bf_debug_op_write_str_impl(str, len);
    }
}

#endif
