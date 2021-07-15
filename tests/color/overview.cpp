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
    static_assert(bsl::reset_color == "\033[0m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::black == "\033[0;90m");
    static_assert(bsl::blk == bsl::black);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::red == "\033[0;91m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::green == "\033[0;92m");
    static_assert(bsl::grn == bsl::green);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::yellow == "\033[0;93m");
    static_assert(bsl::ylw == bsl::yellow);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::blue == "\033[0;94m");
    static_assert(bsl::blu == bsl::blue);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::magenta == "\033[0;95m");
    static_assert(bsl::mag == bsl::magenta);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::cyan == "\033[0;96m");
    static_assert(bsl::cyn == bsl::cyan);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::white == "\033[0;97m");
    static_assert(bsl::wht == bsl::white);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_black == "\033[1;90m");
    static_assert(bsl::bold_blk == bsl::bold_black);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_red == "\033[1;91m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_green == "\033[1;92m");
    static_assert(bsl::bold_grn == bsl::bold_green);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_yellow == "\033[1;93m");
    static_assert(bsl::bold_ylw == bsl::bold_yellow);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_blue == "\033[1;94m");
    static_assert(bsl::bold_blu == bsl::bold_blue);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_magenta == "\033[1;95m");
    static_assert(bsl::bold_mag == bsl::bold_magenta);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_cyan == "\033[1;96m");
    static_assert(bsl::bold_cyn == bsl::bold_cyan);

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_white == "\033[1;97m");
    static_assert(bsl::bold_wht == bsl::bold_white);

    return bsl::ut_success();
}
