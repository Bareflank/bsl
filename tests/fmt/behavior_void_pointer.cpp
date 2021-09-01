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

#include "../fmt_test.hpp"

#include <bsl/debug.hpp>
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
    bsl::ut_scenario{"void pointer"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            void *const pmut_val{};
            bsl::print() << pmut_val;
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("nullptr"));
            };

            bsl::debug() << pmut_val;
            bsl::alert() << pmut_val;
            bsl::error() << pmut_val;
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            void const *const val{};
            bsl::print() << val;
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("nullptr"));
            };

            bsl::debug() << val;
            bsl::alert() << val;
            bsl::error() << val;
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            // Needed to validate the output of the fmt logic for a pointer
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            void *const pmut_val{reinterpret_cast<void *>(0x0000000000000042)};
            bsl::print() << pmut_val;
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x0000000000000042"));
            };

            bsl::debug() << pmut_val;
            bsl::alert() << pmut_val;
            bsl::error() << pmut_val;
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            // Needed to validate the output of the fmt logic for a pointer
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            void const *const val{reinterpret_cast<void const *>(0x0000000000000042)};
            bsl::print() << val;
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x0000000000000042"));
            };

            bsl::debug() << val;
            bsl::alert() << val;
            bsl::error() << val;
        };
    };

    return bsl::ut_success();
}
