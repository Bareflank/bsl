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

#ifndef BSL_ASSERT_HPP
#define BSL_ASSERT_HPP

#include "cstr_type.hpp"
#include "debug_levels.hpp"
#include "details/put_char.hpp"
#include "details/put_cstr.hpp"
#include "details/put_line.hpp"
#include "source_location.hpp"

#include <bsl/cstdlib.hpp>

#pragma clang diagnostic ignored "-Wmissing-noreturn"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Outputs a raw error string to stderr if debugging is
    ///     turned on, along with the location of the assert. If
    ///     BSL_ASSERT_FAST_FAILS is enabled, the assert will fast fail.
    ///     In release mode, this function does nothing.
    ///   @include example_assert_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param str a string to output to stderr
    ///   @param sloc the location of the assert
    ///
    constexpr void
    assert(cstr_type const str, source_location const &sloc) noexcept
    {
        if constexpr (BSL_RELEASE_MODE) {
            return;
        }

        if constexpr (ENABLE_COLOR) {
            details::put_cstr("\033[1;91m");
        }

        details::put_cstr("ASSERT: ");

        if constexpr (ENABLE_COLOR) {
            details::put_cstr("\033[0m");
        }

        details::put_cstr(str);
        details::put_cstr("\n  --> ");

        if constexpr (ENABLE_COLOR) {
            details::put_cstr("\033[0;93m");
        }

        details::put_cstr(sloc.file_name());

        if constexpr (ENABLE_COLOR) {
            details::put_cstr("\033[0;96m");
        }

        details::put_cstr(" [");
        details::put_line(sloc.line());
        details::put_char(']');

        if constexpr (ENABLE_COLOR) {
            details::put_cstr("\033[0m");
        }

        details::put_cstr(": ");
        details::put_cstr(sloc.function_name());
        details::put_cstr("\n\n");

        if constexpr (BSL_ASSERT_FAST_FAILS) {
            exit(1);    // GRCOV_EXCLUDE
        }
    }
}

#endif
