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

#ifndef TESTS_FMT_TEST_HPP
#define TESTS_FMT_TEST_HPP

#define REDIRECT_STDOUT

// NOLINTNEXTLINE(hicpp-deprecated-headers, modernize-deprecated-headers)
#include <stdio.h>
// NOLINTNEXTLINE(hicpp-deprecated-headers, modernize-deprecated-headers)
#include <stdlib.h>
// NOLINTNEXTLINE(hicpp-deprecated-headers, modernize-deprecated-headers)
#include <string.h>

#include <bsl/carray.hpp>
#include <bsl/char_type.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/details/out_char.hpp>
#include <bsl/details/out_cstr.hpp>
#include <bsl/discard.hpp>

namespace fmt_test
{
    /// @brief stores the total number of chars that can be outputted
    constexpr inline bsl::uintmx FMT_TEST_BUF_SIZE{static_cast<bsl::uintmx>(10000)};    // NOLINT

    /// @brief stores the total number of chars that have been outputted
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline bsl::uintmx g_mut_fmt_test_num{};    // NOLINT
    /// @brief stores the chars that have been outputted
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline bsl::carray<bsl::char_type, FMT_TEST_BUF_SIZE> g_mut_fmt_test_buf{};

    /// <!-- description -->
    ///   @brief Resets the test. Normally, this is frowned upon in a unit test
    ///     as it can lead to issues, but the output logic requires the use
    ///     of a global resource, which means global state cannot be avoided
    ///     here. As a result, we need a way to reset before each test.
    ///
    inline void
    reset() noexcept
    {
        for (bsl::uintmx mut_i{}; mut_i < g_mut_fmt_test_buf.size(); ++mut_i) {    // NOLINT
            *g_mut_fmt_test_buf.at_if(mut_i) = {};
        }

        g_mut_fmt_test_num = {};
    }

    /// <!-- description -->
    ///   @brief Returns true if what was outputted matches the provided
    ///     string, false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param str the string to compare with
    ///   @return Returns true if what was outputted matches the provided
    ///     string, false otherwise.
    ///
    [[nodiscard]] inline auto
    was_this_outputted(bsl::cstr_type const str) noexcept -> bool
    {
        if (strlen(str) != g_mut_fmt_test_num) {
            return false;
        }

        return 0 == __builtin_memcmp(g_mut_fmt_test_buf.data(), str, g_mut_fmt_test_num);
    }
}

namespace bsl::details
{
    /// <!-- description -->
    ///   @brief Outputs a character to stdout.
    ///
    /// <!-- inputs/outputs -->
    ///   @param c the character to output to stdout
    ///
    inline void
    redirected_out_char(bsl::char_type const c) noexcept
    {
        bsl::uintmx const i{fmt_test::g_mut_fmt_test_num};                    // NOLINT
        if (auto *const pmut_ptr{fmt_test::g_mut_fmt_test_buf.at_if(i)}) {    // GRCOV_EXCLUDE_BR
            *pmut_ptr = c;
        }
        else {
            // This is required by stdio
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            bsl::discard(fputs("res.data too small\n", stderr));    // GRCOV_EXCLUDE
            exit(1);                                                // GRCOV_EXCLUDE
        }

        ++fmt_test::g_mut_fmt_test_num;
    }

    /// <!-- description -->
    ///   @brief Outputs a string to stdout.
    ///
    /// <!-- inputs/outputs -->
    ///   @param str the string to output to stdout
    ///
    inline void
    redirected_out_cstr(bsl::cstr_type const str) noexcept
    {
        for (bsl::uintmx mut_i{}; mut_i < strlen(str); ++mut_i) {    // NOLINT
            redirected_out_char(str[mut_i]);
        }
    }
}

#include <bsl/debug.hpp>

namespace fmt_test
{
    /// <!-- description -->
    ///   @brief Outputs to all of the out<T> types. This is needed to ensure
    ///     complete coverage of all functions.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of thing to output
    ///   @param mut_val the thing to output
    ///
    template<typename T>
    constexpr void
    output_to_all(T &&mut_val) noexcept    // NOLINT
    {
        bsl::print() << mut_val;
        bsl::debug() << mut_val;
        bsl::alert() << mut_val;
        bsl::error() << mut_val;
    }

    /// <!-- description -->
    ///   @brief Outputs to all of the out<T> types. This is needed to ensure
    ///     complete coverage of all functions.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of thing to output
    ///   @param mut_val the thing to output
    ///
    template<typename T>
    constexpr void
    output_to_all(bsl::fmt_options const &ops, T &&mut_val) noexcept    // NOLINT
    {
        bsl::print() << bsl::fmt{ops, mut_val};
        bsl::debug() << bsl::fmt{ops, mut_val};
        bsl::alert() << bsl::fmt{ops, mut_val};
        bsl::error() << bsl::fmt{ops, mut_val};
    }
}

#endif
