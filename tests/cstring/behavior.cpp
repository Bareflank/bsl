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

#include "../carray_init.hpp"

#include <bsl/carray.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstring.hpp>
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
        bsl::ut_scenario{"builtin_strlen"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::cstr_type const msg1{""};
                bsl::cstr_type const msg2{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::builtin_strlen(msg1) == bsl::to_umx(0));
                    bsl::ut_check(bsl::builtin_strlen(msg2) == bsl::to_umx(5));
                };
            };
        };

        bsl::ut_scenario{"builtin_memset"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_INT_42};
                auto *const pmut_data{mut_arr.data()};
                auto const size{bsl::to_umx(mut_arr.size_bytes())};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::builtin_memset(pmut_data, '\0', 0_umx) == pmut_data);
                    for (bsl::safe_idx mut_i{}; mut_i < mut_arr.size(); ++mut_i) {
                        bsl::ut_check(42 == *mut_arr.at_if(mut_i.get()));
                    }

                    bsl::ut_check(bsl::builtin_memset(pmut_data, '\0', size) == pmut_data);
                    for (bsl::safe_idx mut_i{}; mut_i < mut_arr.size(); ++mut_i) {
                        bsl::ut_check(0 == *mut_arr.at_if(mut_i.get()));
                    }
                };
            };
        };

        bsl::ut_scenario{"builtin_memcpy"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr1{test::CARRAY_INIT_INT_23};
                bsl::carray mut_arr2{test::CARRAY_INIT_INT_42};
                auto *const pmut_data1{mut_arr1.data()};
                auto const size1{bsl::to_umx(mut_arr1.size_bytes())};
                auto const *const data2{mut_arr2.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::builtin_memcpy(pmut_data1, data2, 0_umx) == pmut_data1);
                    for (bsl::safe_idx mut_i{}; mut_i < mut_arr1.size(); ++mut_i) {
                        bsl::ut_check(23 == *mut_arr1.at_if(mut_i.get()));
                    }

                    bsl::ut_check(bsl::builtin_memcpy(pmut_data1, data2, size1) == pmut_data1);
                    for (bsl::safe_idx mut_i{}; mut_i < mut_arr1.size(); ++mut_i) {
                        bsl::ut_check(42 == *mut_arr1.at_if(mut_i.get()));
                    }
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
