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

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/sort.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// <!-- description -->
    ///   @brief Implements sort's comparison function in reverse
    ///
    /// <!-- inputs/outputs -->
    ///   @param a the first element to compare
    ///   @param b the second element to compare
    ///   @return Returns true if b is less a, false otherwise
    ///
    [[nodiscard]] constexpr auto
    reverse_sort_cmp(bsl::safe_int32 const &a, bsl::safe_int32 const &b) noexcept -> bool
    {
        return a > b;
    };

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
        bsl::ut_scenario{"sort empty doesn't crash"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bsl::safe_int32> view{};
                bsl::ut_when{} = [&view]() {
                    bsl::sort(view);
                    bsl::ut_then{} = [&view]() {
                        bsl::ut_check(view.empty());
                    };
                };
            };
        };

        bsl::ut_scenario{"sort 1 number"} = []() {
            bsl::ut_given{} = []() {
                bsl::array data{bsl::to_i32(4)};
                bsl::span view{data};
                bsl::ut_when{} = [&view]() {
                    bsl::sort(view);
                    bsl::ut_then{} = [&view]() {
                        bsl::ut_check(*view.at_if(bsl::to_umax(0)) == bsl::to_i32(4));
                    };
                };
            };
        };

        bsl::ut_scenario{"sort 2 numbers"} = []() {
            bsl::ut_given{} = []() {
                bsl::array data{bsl::to_i32(4), bsl::to_i32(23)};
                bsl::span view{data};
                bsl::ut_when{} = [&view]() {
                    bsl::sort(view);
                    bsl::ut_then{} = [&view]() {
                        bsl::ut_check(*view.at_if(bsl::to_umax(0)) == bsl::to_i32(4));
                        bsl::ut_check(*view.at_if(bsl::to_umax(1)) == bsl::to_i32(23));
                    };
                };
            };
        };

        bsl::ut_scenario{"sort random numbers"} = []() {
            bsl::ut_given{} = []() {
                bsl::array data{
                    bsl::to_i32(42),
                    bsl::to_i32(23),
                    bsl::to_i32(16),
                    bsl::to_i32(8),
                    bsl::to_i32(15),
                    bsl::to_i32(4)};
                bsl::span view{data};
                bsl::ut_when{} = [&view]() {
                    bsl::sort(view);
                    bsl::ut_then{} = [&view]() {
                        bsl::ut_check(*view.at_if(bsl::to_umax(0)) == bsl::to_i32(4));
                        bsl::ut_check(*view.at_if(bsl::to_umax(1)) == bsl::to_i32(8));
                        bsl::ut_check(*view.at_if(bsl::to_umax(2)) == bsl::to_i32(15));
                        bsl::ut_check(*view.at_if(bsl::to_umax(3)) == bsl::to_i32(16));
                        bsl::ut_check(*view.at_if(bsl::to_umax(4)) == bsl::to_i32(23));
                        bsl::ut_check(*view.at_if(bsl::to_umax(5)) == bsl::to_i32(42));
                    };
                };
            };
        };

        bsl::ut_scenario{"sort random descending"} = []() {
            bsl::ut_given{} = []() {
                bsl::array data{
                    bsl::to_i32(42),
                    bsl::to_i32(23),
                    bsl::to_i32(16),
                    bsl::to_i32(8),
                    bsl::to_i32(15),
                    bsl::to_i32(4)};
                bsl::span view{data};
                bsl::ut_when{} = [&view]() {
                    bsl::sort(view, &reverse_sort_cmp);
                    bsl::ut_then{} = [&view]() {
                        bsl::ut_check(*view.at_if(bsl::to_umax(0)) == bsl::to_i32(42));
                        bsl::ut_check(*view.at_if(bsl::to_umax(1)) == bsl::to_i32(23));
                        bsl::ut_check(*view.at_if(bsl::to_umax(2)) == bsl::to_i32(16));
                        bsl::ut_check(*view.at_if(bsl::to_umax(3)) == bsl::to_i32(15));
                        bsl::ut_check(*view.at_if(bsl::to_umax(4)) == bsl::to_i32(8));
                        bsl::ut_check(*view.at_if(bsl::to_umax(5)) == bsl::to_i32(4));
                    };
                };
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
