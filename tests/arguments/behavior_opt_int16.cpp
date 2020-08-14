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

#include <bsl/arguments.hpp>
#include <bsl/array.hpp>
#include <bsl/cstr_type.hpp>
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
        using namespace bsl;

        bsl::ut_scenario{"get optional safe_int16"} = []() {
            bsl::ut_given{} = []() {
                arguments args{0, nullptr};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(!args.get<safe_int16>("-app"));
                };
            };

            bsl::ut_given{} = []() {
                array argv{"-app"};
                arguments args{argv.size(), argv.data()};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(!args.get<safe_int16>(""));
                };
            };

            bsl::ut_given{} = []() {
                array argv{"app"};
                arguments args{argv.size(), argv.data()};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(!args.get<safe_int16>("-app"));
                };
            };

            bsl::ut_given{} = []() {
                array argv{"-app"};
                arguments args{argv.size(), argv.data()};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(!args.get<safe_int16>("-app_blah"));
                };
            };

            bsl::ut_given{} = []() {
                array argv{"-app"};
                arguments args{argv.size(), argv.data()};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(!args.get<safe_int16>("-ap"));
                };
            };

            bsl::ut_given{} = []() {
                array argv{"-app"};
                arguments args{argv.size(), argv.data()};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(!args.get<safe_int16>("-app"));
                };
            };

            bsl::ut_given{} = []() {
                array argv{"-app="};
                arguments args{argv.size(), argv.data()};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(!args.get<safe_int16>("-app"));
                };
            };

            bsl::ut_given{} = []() {
                array argv{"-app=42"};
                arguments args{argv.size(), argv.data()};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(!args.get<safe_int16>("-app="));
                };
            };

            bsl::ut_given{} = []() {
                array argv{"-app=42 "};
                arguments args{argv.size(), argv.data()};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(!args.get<safe_int16>("-app"));
                };
            };

            bsl::ut_given{} = []() {
                array argv{"-app=hello"};
                arguments args{argv.size(), argv.data()};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(!args.get<safe_int16>("-app"));
                };
            };

            bsl::ut_given{} = []() {
                array argv{"-app=ignored", "pos1", "-4=16", "-8=23", "pos2", "-15=42", "-app=42"};
                arguments args{argv.size(), argv.data()};
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(args.get<safe_int16>("-app") == to_i16(42));
                    bsl::ut_check(args.get<safe_int16>("-4") == to_i16(16));
                    bsl::ut_check(args.get<safe_int16>("-8") == to_i16(23));
                    bsl::ut_check(args.get<safe_int16>("-15") == to_i16(42));
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
