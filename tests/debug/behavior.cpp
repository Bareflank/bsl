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

#include <bsl/discard.hpp>
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
        bsl::ut_scenario{"bool from constexpr"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_then{} = []() {
                    bsl::print() << true << '\n';
                    bsl::alert() << true << '\n';
                    bsl::alert() << true << '\n';
                    bsl::error() << true << '\n';
                };
            };
        };

        bsl::ut_scenario{"char_type from constexpr"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_then{} = []() {
                    bsl::print() << '*' << '\n';
                    bsl::alert() << '*' << '\n';
                    bsl::alert() << '*' << '\n';
                    bsl::error() << '*' << '\n';
                };
            };
        };

        bsl::ut_scenario{"cstr_type from constexpr"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_then{} = []() {
                    bsl::print() << "42" << '\n';
                    bsl::alert() << "42" << '\n';
                    bsl::alert() << "42" << '\n';
                    bsl::error() << "42" << '\n';
                };
            };
        };

        bsl::ut_scenario{"integral from constexpr"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_then{} = []() {
                    bsl::print() << 42 << '\n';
                    bsl::alert() << 42 << '\n';
                    bsl::alert() << 42 << '\n';
                    bsl::error() << 42 << '\n';
                };
            };
        };

        bsl::ut_scenario{"small integral from constexpr"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_then{} = []() {
                    bsl::print() << bsl::to_u8(42) << '\n';
                    bsl::alert() << bsl::to_u8(42) << '\n';
                    bsl::alert() << bsl::to_u8(42) << '\n';
                    bsl::error() << bsl::to_u8(42) << '\n';
                };
            };
        };

        bsl::ut_scenario{"nullptr from constexpr"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_then{} = []() {
                    bsl::print() << nullptr << '\n';
                    bsl::alert() << nullptr << '\n';
                    bsl::alert() << nullptr << '\n';
                    bsl::error() << nullptr << '\n';
                };
            };
        };

        bsl::ut_scenario{"pointer from constexpr"} = []() {
            bsl::ut_given{} = []() {
                bool val{};
                bsl::ut_then{} = [&val]() {
                    bsl::print() << &val << '\n';
                    bsl::alert() << &val << '\n';
                    bsl::alert() << &val << '\n';
                    bsl::error() << &val << '\n';
                };
            };
        };

        bsl::ut_scenario{"fmt from constexpr"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_then{} = []() {
                    bsl::print() << bsl::fmt{"#010x", 42} << '\n';
                    bsl::alert() << bsl::fmt{"#010x", 42} << '\n';
                    bsl::alert() << bsl::fmt{"#010x", 42} << '\n';
                    bsl::error() << bsl::fmt{"#010x", 42} << '\n';
                };
            };
        };

        bsl::ut_scenario{"disable from constexpr"} = []() {
            bsl::ut_given{} = []() {
                bsl::ut_then{} = []() {
                    bsl::alert<42>() << true << '\n';
                    bsl::alert<42>() << true << '\n';
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
