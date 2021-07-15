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

#define BSL_DETAILS_PUTC_STDOUT_HPP
#define BSL_DETAILS_PUTS_STDOUT_HPP

#include <bsl/array.hpp>
#include <bsl/char_type.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/cstdio.hpp>
#include <bsl/cstdlib.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/cstring.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>

namespace fmt_test
{
    namespace details
    {
        /// @brief stores the total number of chars that can be outputted
        constexpr inline bsl::safe_uintmax FMT_TEST_BUF_SIZE{static_cast<bsl::uintmax>(10000)};

        /// @brief stores the total number of chars that have been outputted
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
        constinit inline bsl::safe_uintmax g_mut_fmt_test_num{};
        /// @brief stores the chars that have been outputted
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
        constinit inline bsl::array<bsl::char_type, FMT_TEST_BUF_SIZE.get()> g_mut_fmt_test_buf{};
    }

    /// <!-- description -->
    ///   @brief Resets the test. Normally, this is frowned upon in a unit test
    ///     as it can lead to issues, but the output logic requires the use
    ///     of a global resource, which means global state cannot be avoided
    ///     here. As a result, we need a way to reset before each test.
    ///
    inline void
    reset() noexcept
    {
        for (bsl::safe_uintmax mut_i{}; mut_i < details::g_mut_fmt_test_buf.size(); ++mut_i) {
            *details::g_mut_fmt_test_buf.at_if(mut_i) = static_cast<bsl::char_type>(0);
        }

        details::g_mut_fmt_test_num = static_cast<bsl::uintmax>(0);
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
        if (bsl::builtin_strlen(str) != details::g_mut_fmt_test_num) {
            return false;
        }

        return 0 == __builtin_memcmp(
                        details::g_mut_fmt_test_buf.data(), str, details::g_mut_fmt_test_num.get());
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
    putc_stdout(bsl::char_type const c) noexcept
    {
        auto const i{fmt_test::details::g_mut_fmt_test_num};
        if (auto *const pmut_ptr{
                fmt_test::details::g_mut_fmt_test_buf.at_if(i)}) {    // GRCOV_EXCLUDE_BR
            *pmut_ptr = c;
        }
        else {
            // This is required by stdio
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            bsl::discard(fputs("res.data too small\n", stderr));    // GRCOV_EXCLUDE
            exit(1);                                                // GRCOV_EXCLUDE
        }

        ++fmt_test::details::g_mut_fmt_test_num;
    }

    /// <!-- description -->
    ///   @brief Outputs a string to stdout.
    ///
    /// <!-- inputs/outputs -->
    ///   @param str the string to output to stdout
    ///
    inline void
    puts_stdout(bsl::cstr_type const str) noexcept
    {
        for (bsl::safe_uintmax mut_i{}; mut_i < bsl::builtin_strlen(str); ++mut_i) {
            putc_stdout(str[mut_i.get()]);
        }
    }
}

#endif
