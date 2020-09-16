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

#include <bsl/from_chars.hpp>
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
        bsl::ut_scenario{"invalid arguments"} = []() {
            bsl::ut_given{} = []() {
                bsl::cstr_type str{"42"};
                bsl::safe_int32 val{0, true};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"42"};
                bsl::safe_int32 val{0};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::safe_int32::zero(true))};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{""};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{" "};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{" \t\n\v\f\r"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"Hello World"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"-"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"  -"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"42"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(42))};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::cstr_type str{"12345678901234567890"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"42"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"-42"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"-42"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::cstr_type str{"12345678901234567890"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(!val);
                    bsl::ut_check(idx == bsl::to_umax(0));
                };
            };
        };

        bsl::ut_scenario{"whitespace"} = []() {
            bsl::ut_given{} = []() {
                bsl::cstr_type str{" \t\n\v\f\r42"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == 42);
                    bsl::ut_check(idx == bsl::to_umax(8));
                };
            };
        };

        bsl::ut_scenario{"dec"} = []() {
            bsl::ut_given{} = []() {
                bsl::cstr_type str{"0"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == 0);
                    bsl::ut_check(idx == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"42"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == 42);
                    bsl::ut_check(idx == bsl::to_umax(2));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"042"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == 42);
                    bsl::ut_check(idx == bsl::to_umax(3));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"420"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == 420);
                    bsl::ut_check(idx == bsl::to_umax(3));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"1234567890"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == 1234567890);
                    bsl::ut_check(idx == bsl::to_umax(10));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"42 "};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == 42);
                    bsl::ut_check(idx == bsl::to_umax(2));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"-42"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == -42);
                    bsl::ut_check(idx == bsl::to_umax(3));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"42"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(10))};
                    bsl::ut_check(val == 42);
                    bsl::ut_check(idx == bsl::to_umax(2));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"2147483647"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == bsl::safe_int32::max());
                    bsl::ut_check(idx == bsl::to_umax(10));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"-2147483648"};
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == bsl::safe_int32::min());
                    bsl::ut_check(idx == bsl::to_umax(11));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"42"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == 42U);
                    bsl::ut_check(idx == bsl::to_umax(2));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"4294967295"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val)};
                    bsl::ut_check(val == bsl::safe_uint32::max());
                    bsl::ut_check(idx == bsl::to_umax(10));
                };
            };
        };

        bsl::ut_scenario{"hex"} = []() {
            bsl::ut_given{} = []() {
                bsl::cstr_type str{"0"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(val == 0U);
                    bsl::ut_check(idx == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"42"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(val == 0x42U);
                    bsl::ut_check(idx == bsl::to_umax(2));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"042"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(val == 0x42U);
                    bsl::ut_check(idx == bsl::to_umax(3));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"420"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(val == 0x420U);
                    bsl::ut_check(idx == bsl::to_umax(3));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"12345"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(val == 0x12345U);
                    bsl::ut_check(idx == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"67890"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(val == 0x67890U);
                    bsl::ut_check(idx == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"abcdef"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(val == 0xabcdefU);
                    bsl::ut_check(idx == bsl::to_umax(6));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"ABCDEF"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(val == 0xABCDEFU);
                    bsl::ut_check(idx == bsl::to_umax(6));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"42 "};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(val == 0x42U);
                    bsl::ut_check(idx == bsl::to_umax(2));
                };
            };

            bsl::ut_given{} = []() {
                bsl::cstr_type str{"FFFFFFFF"};
                bsl::safe_uint32 val{};
                bsl::ut_then{} = [&str, &val]() {
                    bsl::safe_uintmax idx{bsl::from_chars(str, val, bsl::to_i32(16))};
                    bsl::ut_check(val == bsl::safe_uint32::max());
                    bsl::ut_check(idx == bsl::to_umax(8));
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
