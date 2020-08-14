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

#include <bsl/safe_integral.hpp>
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
        bsl::ut_scenario{"left shift assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_when{} = [&val]() {
                    val <<= 1U;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42U * 2U);
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_when{} = [&val]() {
                    val <<= 1U;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"left shift"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val << 1U) == 42U * 2U);
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val << 1U).failure());
                };
            };
        };

        bsl::ut_scenario{"right shift assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_when{} = [&val]() {
                    val >>= 1U;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42U / 2U);
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_when{} = [&val]() {
                    val >>= 1U;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"right shift"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val >> 1U) == 42U / 2U);
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val >> 1U).failure());
                };
            };
        };

        return bsl::ut_success();
    }
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
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
