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
    static_assert(bsl::rst == "\033[0m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::blk == "\033[0;90m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::red == "\033[0;91m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::grn == "\033[0;92m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::ylw == "\033[0;93m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::blu == "\033[0;94m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::mag == "\033[0;95m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::cyn == "\033[0;96m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::wht == "\033[0;97m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_blk == "\033[1;90m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_red == "\033[1;91m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_grn == "\033[1;92m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_ylw == "\033[1;93m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_blu == "\033[1;94m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_mag == "\033[1;95m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_cyn == "\033[1;96m");

    // Defining colors using octals is the standard way of doing this.
    // NOLINTNEXTLINE(bsl-literals-no-octal)
    static_assert(bsl::bold_wht == "\033[1;97m");

    return bsl::ut_success();
}
