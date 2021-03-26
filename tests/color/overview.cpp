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

#include <bsl/color.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// <!-- description -->
    ///   @brief String comparison function
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the comparison
    ///   @param rhs the right hand side of the comparison
    ///   @return Returns true if the strings are equal, false otherwise
    ///
    [[nodiscard]] constexpr auto
    check(bsl::cstr_type const lhs, bsl::cstr_type const rhs) noexcept -> bool
    {
        bsl::safe_uintmax i{};
        for (; (lhs[i.get()] != '\0') && (rhs[i.get()] != '\0'); ++i) {
            if (lhs[i.get()] != rhs[i.get()]) {
                return false;
            }
        }

        return lhs[i.get()] == rhs[i.get()];
    }
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::reset_color, "\033[0m"));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::black, "\033[0;90m"));
    static_assert(check(bsl::blk, bsl::black));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::red, "\033[0;91m"));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::green, "\033[0;92m"));
    static_assert(check(bsl::grn, bsl::green));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::yellow, "\033[0;93m"));
    static_assert(check(bsl::ylw, bsl::yellow));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::blue, "\033[0;94m"));
    static_assert(check(bsl::blu, bsl::blue));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::magenta, "\033[0;95m"));
    static_assert(check(bsl::mag, bsl::magenta));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::cyan, "\033[0;96m"));
    static_assert(check(bsl::cyn, bsl::cyan));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::white, "\033[0;97m"));
    static_assert(check(bsl::wht, bsl::white));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::bold_black, "\033[1;90m"));
    static_assert(check(bsl::bold_blk, bsl::bold_black));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::bold_red, "\033[1;91m"));
    static_assert(check(bsl::bold_red, bsl::bold_red));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::bold_green, "\033[1;92m"));
    static_assert(check(bsl::bold_grn, bsl::bold_green));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::bold_yellow, "\033[1;93m"));
    static_assert(check(bsl::bold_ylw, bsl::bold_yellow));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::bold_blue, "\033[1;94m"));
    static_assert(check(bsl::bold_blu, bsl::bold_blue));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::bold_magenta, "\033[1;95m"));
    static_assert(check(bsl::bold_mag, bsl::bold_magenta));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::bold_cyan, "\033[1;96m"));
    static_assert(check(bsl::bold_cyn, bsl::bold_cyan));

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(check(bsl::bold_white, "\033[1;97m"));
    static_assert(check(bsl::bold_wht, bsl::bold_white));

    return bsl::ut_success();
}
