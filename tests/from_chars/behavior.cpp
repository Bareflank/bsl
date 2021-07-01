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
        /// NOTE:
        /// - All of these are in the same file to ensure branch coverage is
        ///   clean. The downside is that this file is large, but we want to
        ///   ensure that all of the tests are in the same binary, otherwise
        ///   branch coverage will be messed up.
        ///

        // ---------------------------------------------------------------------
        // test bsl::int8
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, bsl::safe_int32::failure()));
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"-42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::int8>(str, 10_i32) == -42_i8);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"--42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-4-2"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-:42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-:"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"-128"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::int8>(str, 10_i32) == bsl::safe_int8::min());
                };
            };
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::int8>(str, 10_i32) == 42_i8);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"127"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::int8>(str, 10_i32) == bsl::safe_int8::max());
                };
            };
        };

        bsl::ut_scenario{"hex"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int8>(str, 16_i32));
                };
            };
        };

        // ---------------------------------------------------------------------
        // test bsl::int16
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, bsl::safe_int32::failure()));
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"-42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::int16>(str, 10_i32) == -42_i16);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"--42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-4-2"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-:42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-:"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"-32768"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::int16>(str, 10_i32) == bsl::safe_int16::min());
                };
            };
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::int16>(str, 10_i32) == 42_i16);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"32767"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::int16>(str, 10_i32) == bsl::safe_int16::max());
                };
            };
        };

        bsl::ut_scenario{"hex"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int16>(str, 16_i32));
                };
            };
        };

        // ---------------------------------------------------------------------
        // test bsl::int32
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, bsl::safe_int32::failure()));
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"-42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::int32>(str, 10_i32) == -42_i32);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"--42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-4-2"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-:42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-:"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"-2147483648"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::int32>(str, 10_i32) == bsl::safe_int32::min());
                };
            };
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::int32>(str, 10_i32) == 42_i32);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"2147483647"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::int32>(str, 10_i32) == bsl::safe_int32::max());
                };
            };
        };

        bsl::ut_scenario{"hex"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int32>(str, 16_i32));
                };
            };
        };

        // ---------------------------------------------------------------------
        // test bsl::int64
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, bsl::safe_int32::failure()));
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"-42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::int64>(str, 10_i32) == -42_i64);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"--42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-4-2"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-:42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-:"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"-9223372036854775808"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::int64>(str, 10_i32) == bsl::safe_int64::min());
                };
            };
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::int64>(str, 10_i32) == 42_i64);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"9223372036854775807"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::int64>(str, 10_i32) == bsl::safe_int64::max());
                };
            };
        };

        bsl::ut_scenario{"hex"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::int64>(str, 16_i32));
                };
            };
        };

        // ---------------------------------------------------------------------
        // test bsl::intmax
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, bsl::safe_int32::failure()));
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"-42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::intmax>(str, 10_i32) == -42_imax);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"--42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-4-2"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-:42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-:"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"-9223372036854775808"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::intmax>(str, 10_i32) == bsl::safe_intmax::min());
                };
            };
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::intmax>(str, 10_i32) == 42_imax);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"9223372036854775807"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::intmax>(str, 10_i32) == bsl::safe_intmax::max());
                };
            };
        };

        bsl::ut_scenario{"hex"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::intmax>(str, 16_i32));
                };
            };
        };

        // ---------------------------------------------------------------------
        // test bsl::uint8
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, bsl::safe_int32::failure()));
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 10_i32));
                };
            };
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint8>(str, 10_i32) == 42_u8);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"255"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint8>(str, 10_i32) == bsl::safe_uint8::max());
                };
            };
        };

        bsl::ut_scenario{"hex positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint8>(str, 16_i32) == 0x42_u8);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"90"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint8>(str, 16_i32) == 0x90_u8);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"af"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint8>(str, 16_i32) == 0xAF_u8);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"Af"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint8>(str, 16_i32) == 0xAF_u8);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"aF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint8>(str, 16_i32) == 0xAF_u8);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"AF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint8>(str, 16_i32) == 0xAF_u8);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"@42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"G42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"`42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"g42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"@"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"G"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"`"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"g"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint8>(str, 16_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"0"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint8>(str, 16_i32) == bsl::safe_uint8::min());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"FF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint8>(str, 16_i32) == bsl::safe_uint8::max());
                };
            };
        };

        // ---------------------------------------------------------------------
        // test bsl::uint16
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, bsl::safe_int32::failure()));
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 10_i32));
                };
            };
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint16>(str, 10_i32) == 42_u16);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"65535"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint16>(str, 10_i32) == bsl::safe_uint16::max());
                };
            };
        };

        bsl::ut_scenario{"hex positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint16>(str, 16_i32) == 0x42_u16);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"90"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint16>(str, 16_i32) == 0x90_u16);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"af"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint16>(str, 16_i32) == 0xAF_u16);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"Af"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint16>(str, 16_i32) == 0xAF_u16);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"aF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint16>(str, 16_i32) == 0xAF_u16);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"AF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint16>(str, 16_i32) == 0xAF_u16);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"@42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"G42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"`42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"g42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"@"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"G"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"`"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"g"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint16>(str, 16_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"0"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint16>(str, 16_i32) == bsl::safe_uint16::min());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"FFFF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint16>(str, 16_i32) == bsl::safe_uint16::max());
                };
            };
        };

        // ---------------------------------------------------------------------
        // test bsl::uint32
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, bsl::safe_int32::failure()));
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 10_i32));
                };
            };
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint32>(str, 10_i32) == 42_u32);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"4294967295"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint32>(str, 10_i32) == bsl::safe_uint32::max());
                };
            };
        };

        bsl::ut_scenario{"hex positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint32>(str, 16_i32) == 0x42_u32);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"90"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint32>(str, 16_i32) == 0x90_u32);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"af"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint32>(str, 16_i32) == 0xAF_u32);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"Af"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint32>(str, 16_i32) == 0xAF_u32);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"aF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint32>(str, 16_i32) == 0xAF_u32);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"AF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint32>(str, 16_i32) == 0xAF_u32);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"@42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"G42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"`42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"g42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"@"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"G"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"`"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"g"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint32>(str, 16_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"0"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint32>(str, 16_i32) == bsl::safe_uint32::min());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"FFFFFFFF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint32>(str, 16_i32) == bsl::safe_uint32::max());
                };
            };
        };

        // ---------------------------------------------------------------------
        // test bsl::uint64
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, bsl::safe_int32::failure()));
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 10_i32));
                };
            };
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint64>(str, 10_i32) == 42_u64);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"18446744073709551615"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint64>(str, 10_i32) == bsl::safe_uint64::max());
                };
            };
        };

        bsl::ut_scenario{"hex positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint64>(str, 16_i32) == 0x42_u64);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"90"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint64>(str, 16_i32) == 0x90_u64);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"af"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint64>(str, 16_i32) == 0xAF_u64);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"Af"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint64>(str, 16_i32) == 0xAF_u64);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"aF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint64>(str, 16_i32) == 0xAF_u64);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"AF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uint64>(str, 16_i32) == 0xAF_u64);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"@42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"G42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"`42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"g42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"@"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"G"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"`"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"g"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uint64>(str, 16_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"0"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint64>(str, 16_i32) == bsl::safe_uint64::min());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"FFFFFFFFFFFFFFFF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uint64>(str, 16_i32) == bsl::safe_uint64::max());
                };
            };
        };

        // ---------------------------------------------------------------------
        // test bsl::uintmax
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, bsl::safe_int32::failure()));
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"-42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 10_i32));
                };
            };
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uintmax>(str, 10_i32) == 42_umax);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 10_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 10_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"18446744073709551615"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uintmax>(str, 10_i32) == bsl::safe_uintmax::max());
                };
            };
        };

        bsl::ut_scenario{"hex positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uintmax>(str, 16_i32) == 0x42_umax);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"90"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uintmax>(str, 16_i32) == 0x90_umax);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"af"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uintmax>(str, 16_i32) == 0xAF_umax);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"Af"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uintmax>(str, 16_i32) == 0xAF_umax);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"aF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uintmax>(str, 16_i32) == 0xAF_umax);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"AF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<bsl::uintmax>(str, 16_i32) == 0xAF_umax);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"@42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"G42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"`42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"g42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"@"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"G"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"`"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"g"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!bsl::from_chars<bsl::uintmax>(str, 16_i32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"0"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uintmax>(str, 16_i32) == bsl::safe_uintmax::min());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"FFFFFFFFFFFFFFFF"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        bsl::from_chars<bsl::uintmax>(str, 16_i32) == bsl::safe_uintmax::max());
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
