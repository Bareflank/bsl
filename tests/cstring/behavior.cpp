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
        bsl::ut_scenario{"builtin_strncmp"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::cstr_type const msg1{"Hello World"};
                bsl::cstr_type const msg2{"Hello World"};
                bsl::cstr_type const msg3{"Hello World with more stuff"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::builtin_strncmp(nullptr, msg2, bsl::builtin_strlen(msg1)));
                    bsl::ut_check(!bsl::builtin_strncmp(msg1, nullptr, bsl::builtin_strlen(msg1)));
                    bsl::ut_check(!bsl::builtin_strncmp(msg1, msg2, bsl::safe_uintmax::failure()));
                    bsl::ut_check(!bsl::builtin_strncmp(msg1, msg3, bsl::npos));
                    bsl::ut_check(!bsl::builtin_strncmp(msg3, msg1, bsl::npos));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::cstr_type const msg1{"Hello"};
                bsl::cstr_type const msg2{"Hello World"};
                bsl::cstr_type const msg3{"Hello World"};
                bsl::cstr_type const msg4{"Hello Plant"};
                bsl::cstr_type const msg5{"Something Else"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::builtin_strncmp(msg1, msg2, bsl::builtin_strlen(msg1)) == 0);
                    bsl::ut_check(bsl::builtin_strncmp(msg2, msg3, bsl::builtin_strlen(msg2)) == 0);
                    bsl::ut_check(bsl::builtin_strncmp(msg3, msg4, bsl::builtin_strlen(msg3)) != 0);
                    bsl::ut_check(bsl::builtin_strncmp(msg4, msg5, bsl::builtin_strlen(msg4)) != 0);
                    bsl::ut_check(bsl::builtin_strncmp(msg1, msg5, bsl::builtin_strlen(msg1)) != 0);
                };
            };
        };

        bsl::ut_scenario{"builtin_strlen"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::cstr_type const msg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::builtin_strlen(nullptr));
                    bsl::ut_check(!bsl::builtin_strlen(msg1));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::cstr_type const msg1{""};
                bsl::cstr_type const msg2{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::builtin_strlen(msg1) == bsl::to_umax(0));
                    bsl::ut_check(bsl::builtin_strlen(msg2) == bsl::to_umax(5));
                };
            };
        };

        bsl::ut_scenario{"builtin_memset"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::array mut_arr{true, true, true, true, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::builtin_memset<bool>(nullptr, '\0', mut_arr.size()) == nullptr);
                    bsl::ut_check(
                        bsl::builtin_memset(mut_arr.data(), '\0', bsl::safe_uintmax::failure()) ==
                        nullptr);
                    bsl::ut_check(
                        bsl::builtin_memset(mut_arr.data(), '\0', 0_umax) == mut_arr.data());
                    for (auto const elem : mut_arr) {
                        bsl::ut_check(*elem.data);
                    }
                    bsl::ut_check(
                        bsl::builtin_memset(mut_arr.data(), '\0', mut_arr.size()) ==
                        mut_arr.data());
                    for (auto const elem : mut_arr) {
                        bsl::ut_check(!*elem.data);
                    }
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{true, true, true, true, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::builtin_memset(mut_arr.data(), '\0', 0_umax) == mut_arr.data());
                    for (auto const elem : mut_arr) {
                        bsl::ut_check(*elem.data);
                    }
                    bsl::ut_check(
                        bsl::builtin_memset(mut_arr.data(), '\0', mut_arr.size()) ==
                        mut_arr.data());
                    for (auto const elem : mut_arr) {
                        bsl::ut_check(!*elem.data);
                    }
                };
            };

            /// NOTE:
            /// - These should not compile as they are not allowed.
            ///

            // bsl::ut_given{} = []() noexcept {
            //     bsl::array mut_arr{42, 42, 42, 42, 42};
            //     bsl::ut_then{} = [&]() noexcept {
            //         bsl::ut_check(bsl::builtin_memset(mut_arr.data(), '*', mut_arr.size()) == nullptr);
            //         bsl::ut_check(bsl::builtin_memset(mut_arr.data(), '\0', 1_umax) == nullptr);
            //         bsl::ut_check(bsl::builtin_memset(mut_arr.data(), '\0', 128_umax) == mut_arr.data());
            //     };
            // };
        };

        bsl::ut_scenario{"builtin_memcpy"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::array mut_arr1{true, true, true, true, true};
                bsl::array mut_arr2{false, false, false, false, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::builtin_memcpy<bool>(nullptr, mut_arr2.data(), mut_arr1.size()) ==
                        nullptr);
                    bsl::ut_check(
                        bsl::builtin_memcpy<bool>(mut_arr1.data(), nullptr, mut_arr1.size()) ==
                        nullptr);
                    bsl::ut_check(
                        bsl::builtin_memcpy(
                            mut_arr1.data(), mut_arr2.data(), bsl::safe_uintmax::failure()) ==
                        nullptr);
                    bsl::ut_check(
                        bsl::builtin_memcpy(mut_arr1.data(), mut_arr2.data(), 0_umax) ==
                        mut_arr1.data());
                    for (auto const elem : mut_arr1) {
                        bsl::ut_check(*elem.data);
                    }
                    bsl::ut_check(
                        bsl::builtin_memcpy(mut_arr1.data(), mut_arr2.data(), mut_arr1.size()) ==
                        mut_arr1.data());
                    for (auto const elem : mut_arr1) {
                        bsl::ut_check(!*elem.data);
                    }
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr1{true, true, true, true, true};
                bsl::array mut_arr2{false, false, false, false, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::builtin_memcpy(mut_arr1.data(), mut_arr2.data(), 0_umax) ==
                        mut_arr1.data());
                    for (auto const elem : mut_arr1) {
                        bsl::ut_check(*elem.data);
                    }
                    bsl::ut_check(
                        bsl::builtin_memcpy(mut_arr1.data(), mut_arr2.data(), mut_arr1.size()) ==
                        mut_arr1.data());
                    for (auto const elem : mut_arr1) {
                        bsl::ut_check(!*elem.data);
                    }
                };
            };

            /// NOTE:
            /// - These should not compile as they are not allowed.
            ///

            // bsl::ut_given{} = []() noexcept {
            //     bsl::array mut_arr1{42, 42, 42, 42, 42};
            //     bsl::array mut_arr2{0, 0, 0, 0, 0};
            //     bsl::ut_then{} = [&]() noexcept {
            //         bsl::ut_check(bsl::builtin_memcpy(mut_arr1.data(), mut_arr2.data(), 1_umax) == nullptr);
            //         bsl::ut_check(bsl::builtin_memcpy(mut_arr1.data(), mut_arr2.data(), 128_umax) == mut_arr1.data());
            //     };
            // };
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
