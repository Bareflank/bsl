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

#include <bsl/convert.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"ut success"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_check(bsl::ut_success() == bsl::exit_success);
            };
        };

        bsl::ut_scenario{"silence ut_required_step_failed"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                bsl::ut_required_step_failed();
            };
        };

        bsl::ut_scenario{"ut_required_step success"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_required_step(true);
            };

            bsl::ut_given{} = []() {
                bsl::ut_required_step(bsl::errc_success);
            };

            bsl::ut_given{} = []() {
                bsl::ut_required_step(0_i8);
                bsl::ut_required_step(0_i16);
                bsl::ut_required_step(0_i32);
                bsl::ut_required_step(0_i64);
                bsl::ut_required_step(0_imax);

                bsl::ut_required_step(0_u8);
                bsl::ut_required_step(0_u16);
                bsl::ut_required_step(0_u32);
                bsl::ut_required_step(0_u64);
                bsl::ut_required_step(0_umax);
            };
        };

        bsl::ut_scenario{"silence ut_check_failed"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                bsl::ut_check_failed();
            };
        };

        bsl::ut_scenario{"ut_check success"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_check(true);
            };

            bsl::ut_given{} = []() {
                bsl::ut_check(bsl::errc_success);
            };

            bsl::ut_given{} = []() {
                bsl::ut_check(0_i8);
                bsl::ut_check(0_i16);
                bsl::ut_check(0_i32);
                bsl::ut_check(0_i64);
                bsl::ut_check(0_imax);

                bsl::ut_check(0_u8);
                bsl::ut_check(0_u16);
                bsl::ut_check(0_u32);
                bsl::ut_check(0_u64);
                bsl::ut_check(0_umax);
            };
        };

        return bsl::ut_success();
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
    static_assert(tests() == bsl::ut_success());
    return tests();
}
