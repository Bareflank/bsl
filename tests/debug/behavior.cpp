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
#include <bsl/details/out_char.hpp>
#include <bsl/details/out_cstr.hpp>
#include <bsl/details/out_line.hpp>
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
        bsl::ut_scenario{"bool from constexpr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::print() << true << '\n';
                    bsl::debug() << true << '\n';
                    bsl::alert() << true << '\n';
                    bsl::error() << true << '\n';
                };
            };
        };

        bsl::ut_scenario{"char_type from constexpr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::print() << '*' << '\n';
                    bsl::debug() << '*' << '\n';
                    bsl::alert() << '*' << '\n';
                    bsl::error() << '*' << '\n';
                };
            };
        };

        bsl::ut_scenario{"cstr_type from constexpr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::print() << "42" << '\n';
                    bsl::debug() << "42" << '\n';
                    bsl::alert() << "42" << '\n';
                    bsl::error() << "42" << '\n';
                };
            };
        };

        bsl::ut_scenario{"integral from constexpr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::print() << 42 << '\n';
                    bsl::debug() << 42 << '\n';
                    bsl::alert() << 42 << '\n';
                    bsl::error() << 42 << '\n';
                };
            };
        };

        bsl::ut_scenario{"small integral from constexpr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::print() << bsl::to_u8(42) << '\n';
                    bsl::debug() << bsl::to_u8(42) << '\n';
                    bsl::alert() << bsl::to_u8(42) << '\n';
                    bsl::error() << bsl::to_u8(42) << '\n';
                };
            };
        };

        bsl::ut_scenario{"nullptr from constexpr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::print() << nullptr << '\n';
                    bsl::debug() << nullptr << '\n';
                    bsl::alert() << nullptr << '\n';
                    bsl::error() << nullptr << '\n';
                };
            };
        };

        bsl::ut_scenario{"pointer from constexpr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bool const val{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::print() << &val << '\n';
                    bsl::debug() << &val << '\n';
                    bsl::alert() << &val << '\n';
                    bsl::error() << &val << '\n';
                };
            };
        };

        bsl::ut_scenario{"source location from constexpr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::print() << bsl::here();
                    bsl::debug() << bsl::here();
                    bsl::alert() << bsl::here();
                    bsl::error() << bsl::here();
                };
            };
        };

        bsl::ut_scenario{"fmt from constexpr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::print() << bsl::fmt{"#010x", 42} << '\n';
                    bsl::debug() << bsl::fmt{"#010x", 42} << '\n';
                    bsl::alert() << bsl::fmt{"#010x", 42} << '\n';
                    bsl::error() << bsl::fmt{"#010x", 42} << '\n';
                };
            };
        };

        bsl::ut_scenario{"fmt from constexpr (using hex)"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::print() << bsl::hex(42U) << '\n';
                    bsl::debug() << bsl::hex(42U) << '\n';
                    bsl::alert() << bsl::hex(42U) << '\n';
                    bsl::error() << bsl::hex(42U) << '\n';
                };
            };
        };

        bsl::ut_scenario{"disable from constexpr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::debug<42>() << true << '\n';
                    bsl::alert<42>() << true << '\n';
                };
            };
        };

        bsl::ut_scenario{"details checks"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_then{} = []() noexcept {
                    bsl::details::out_char('*');
                    bsl::details::out_cstr("42", bsl::safe_umx::magic_2().get());
                    bsl::details::out_line(0);     // NOLINT
                    bsl::details::out_line(42);    // NOLINT
                    bsl::details::out_line(
                        static_cast<bsl::details::line_type>(0xFFFFFFFFFFFFFFFF));
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
