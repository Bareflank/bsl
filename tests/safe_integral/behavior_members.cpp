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

#undef BSL_ASSERT_FAST_FAILS
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define BSL_ASSERT_FAST_FAILS false

#include <bsl/convert.hpp>
#include <bsl/numeric_limits.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace bsl
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
    template<typename T>
    [[nodiscard]] constexpr auto
    tests_members() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"default constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == static_cast<T>(0));
                    bsl::ut_check(!val.is_invalid());
                    bsl::ut_check(!val.is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"value constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == static_cast<T>(42));
                    bsl::ut_check(!val.is_invalid());
                    bsl::ut_check(!val.is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"value with safe_integral constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_i8::magic_1()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2 == static_cast<T>(42));
                    bsl::ut_check(!val2.is_invalid());
                    bsl::ut_check(!val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_i16::magic_1()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2 == static_cast<T>(42));
                    bsl::ut_check(!val2.is_invalid());
                    bsl::ut_check(!val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_i32::magic_1()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2 == static_cast<T>(42));
                    bsl::ut_check(!val2.is_invalid());
                    bsl::ut_check(!val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_i64::magic_1()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2 == static_cast<T>(42));
                    bsl::ut_check(!val2.is_invalid());
                    bsl::ut_check(!val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_u8::magic_1()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2 == static_cast<T>(42));
                    bsl::ut_check(!val2.is_invalid());
                    bsl::ut_check(!val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_u16::magic_1()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2 == static_cast<T>(42));
                    bsl::ut_check(!val2.is_invalid());
                    bsl::ut_check(!val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_u32::magic_1()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2 == static_cast<T>(42));
                    bsl::ut_check(!val2.is_invalid());
                    bsl::ut_check(!val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_u64::magic_1()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2 == static_cast<T>(42));
                    bsl::ut_check(!val2.is_invalid());
                    bsl::ut_check(!val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_umx::magic_1()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2 == static_cast<T>(42));
                    bsl::ut_check(!val2.is_invalid());
                    bsl::ut_check(!val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_i8::failure()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2.is_invalid());
                    bsl::ut_check(val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_i16::failure()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2.is_invalid());
                    bsl::ut_check(val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_i32::failure()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2.is_invalid());
                    bsl::ut_check(val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_i64::failure()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2.is_invalid());
                    bsl::ut_check(val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_u8::failure()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2.is_invalid());
                    bsl::ut_check(val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_u16::failure()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2.is_invalid());
                    bsl::ut_check(val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_u32::failure()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2.is_invalid());
                    bsl::ut_check(val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_u64::failure()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2.is_invalid());
                    bsl::ut_check(val2.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_umx::failure()};
                bsl::safe_integral<T> const val2{static_cast<T>(42), val1};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val2.is_invalid());
                    bsl::ut_check(val2.is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"safe_integral with safe_integral constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_i8::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3 == static_cast<T>(1));
                    bsl::ut_check(!val3.is_invalid());
                    bsl::ut_check(!val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_i16::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3 == static_cast<T>(1));
                    bsl::ut_check(!val3.is_invalid());
                    bsl::ut_check(!val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_i32::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3 == static_cast<T>(1));
                    bsl::ut_check(!val3.is_invalid());
                    bsl::ut_check(!val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_i64::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3 == static_cast<T>(1));
                    bsl::ut_check(!val3.is_invalid());
                    bsl::ut_check(!val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_u8::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3 == static_cast<T>(1));
                    bsl::ut_check(!val3.is_invalid());
                    bsl::ut_check(!val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_u16::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3 == static_cast<T>(1));
                    bsl::ut_check(!val3.is_invalid());
                    bsl::ut_check(!val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_u32::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3 == static_cast<T>(1));
                    bsl::ut_check(!val3.is_invalid());
                    bsl::ut_check(!val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_u64::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3 == static_cast<T>(1));
                    bsl::ut_check(!val3.is_invalid());
                    bsl::ut_check(!val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_umx::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3 == static_cast<T>(1));
                    bsl::ut_check(!val3.is_invalid());
                    bsl::ut_check(!val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_i8::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_i16::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_i32::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_i64::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_u8::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_u16::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_u32::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_u64::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_umx::magic_1()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_i8::failure()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_i16::failure()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_i32::failure()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_i64::failure()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_u8::failure()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_u16::failure()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_u32::failure()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_u64::failure()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_umx::failure()};
                bsl::safe_integral<T> const val3{val1, val2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val3.is_invalid());
                    bsl::ut_check(val3.is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"value assignment"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val = static_cast<T>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42));
                        bsl::ut_check(!mut_val.is_invalid());
                        bsl::ut_check(!mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    mut_val = static_cast<T>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42));
                        bsl::ut_check(!mut_val.is_invalid());
                        bsl::ut_check(!mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val = static_cast<T>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42));
                        bsl::ut_check(!mut_val.is_invalid());
                        bsl::ut_check(!mut_val.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"max_value"} = []() noexcept {
            bsl::ut_check(safe_integral<T>::max_value() == bsl::numeric_limits<T>::max_value());
        };

        bsl::ut_scenario{"min_value"} = []() noexcept {
            bsl::ut_check(safe_integral<T>::min_value() == bsl::numeric_limits<T>::min_value());
        };

        if constexpr (bsl::is_signed<T>::value) {
            bsl::ut_scenario{"magic_neg_1"} = []() noexcept {
                bsl::ut_check(safe_integral<T>::magic_neg_1() == static_cast<T>(-1));
            };

            bsl::ut_scenario{"magic_neg_2"} = []() noexcept {
                bsl::ut_check(safe_integral<T>::magic_neg_2() == static_cast<T>(-2));
            };

            bsl::ut_scenario{"magic_neg_3"} = []() noexcept {
                bsl::ut_check(safe_integral<T>::magic_neg_3() == static_cast<T>(-3));
            };
        }

        bsl::ut_scenario{"magic_0"} = []() noexcept {
            bsl::ut_check(safe_integral<T>::magic_0() == static_cast<T>(0));
        };

        bsl::ut_scenario{"magic_1"} = []() noexcept {
            bsl::ut_check(safe_integral<T>::magic_1() == static_cast<T>(1));
        };

        bsl::ut_scenario{"magic_2"} = []() noexcept {
            bsl::ut_check(safe_integral<T>::magic_2() == static_cast<T>(2));
        };

        bsl::ut_scenario{"magic_3"} = []() noexcept {
            bsl::ut_check(safe_integral<T>::magic_3() == static_cast<T>(3));
        };

        bsl::ut_scenario{"data_as_ref"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(1) == mut_val.data_as_ref());    // NOLINT
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(1) == val.data_as_ref());    // NOLINT
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(1) == val.cdata_as_ref());    // NOLINT
                };
            };
        };

        bsl::ut_scenario{"data"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(1) == *mut_val.data());    // NOLINT
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(1) == *val.data());    // NOLINT
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(1) == *val.cdata());    // NOLINT
                };
            };
        };

        bsl::ut_scenario{"get"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(1) == val.get());    // NOLINT
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(static_cast<T>(2) == mut_val.checked().get());    // NOLINT
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::discard(val.get());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::discard(mut_val.get());
                    };
                };
            };
        };

        bsl::ut_scenario{"is_pos"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_pos());
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given{} = []() noexcept {
                    auto const val{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_pos());
                    };
                };
            }

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_0()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_pos());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::discard(val.is_pos());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::discard(mut_val.is_pos());
                    };
                };
            };
        };

        bsl::ut_scenario{"is_neg"} = []() noexcept {
            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given{} = []() noexcept {
                    auto const val{bsl::safe_integral<T>::magic_1()};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_neg());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto const val{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(val.is_neg());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto const val{bsl::safe_integral<T>::magic_0()};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val{bsl::safe_integral<T>::failure()};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::discard(val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val{bsl::safe_integral<T>::magic_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        ++mut_val;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::discard(mut_val.is_neg());
                        };
                    };
                };
            }
        };

        bsl::ut_scenario{"is_zero"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero());
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given{} = []() noexcept {
                    auto const val{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_zero());
                    };
                };
            }

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_0()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::discard(val.is_zero());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::discard(mut_val.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"is_poisoned"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_val.is_poisoned());
                    bsl::ut_check(!mut_val.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_poisoned());
                        bsl::ut_check(!mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.is_poisoned());
                    bsl::ut_check(mut_val.is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"is_invalid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_invalid());
                    bsl::ut_check(!val.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_invalid());
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_invalid());
                    bsl::ut_check(val.is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"is_valid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_valid());
                    bsl::ut_check(!val.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_valid());
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_valid());
                    bsl::ut_check(val.is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"is_zero_or_poisoned"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_val.is_zero_or_poisoned());
                    bsl::ut_check(!mut_val.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_0()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.is_zero_or_poisoned());
                    bsl::ut_check(!mut_val.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_zero_or_poisoned());
                        bsl::ut_check(!mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_zero_or_poisoned());
                        bsl::ut_check(!mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.is_zero_or_poisoned());
                    bsl::ut_check(mut_val.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(1), bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.is_zero_or_poisoned());
                    bsl::ut_check(mut_val.is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"is_zero_or_invalid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero_or_invalid());
                    bsl::ut_check(!val.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_0()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero_or_invalid());
                    bsl::ut_check(!val.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_zero_or_invalid());
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_zero_or_invalid());
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero_or_invalid());
                    bsl::ut_check(val.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{
                    static_cast<T>(1), bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero_or_invalid());
                    bsl::ut_check(val.is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"checked"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.checked().is_invalid());
                    bsl::ut_check(!val.checked().is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.checked().is_invalid());
                        bsl::ut_check(!mut_val.checked().is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.checked().is_invalid());
                    bsl::ut_check(val.checked().is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"is_unchecked"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_unchecked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_unchecked());
                };
            };
        };

        bsl::ut_scenario{"is_checked"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_checked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_checked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_checked());
                };
            };
        };

        bsl::ut_scenario{"is_valid_and_checked"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_valid_and_checked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_valid_and_checked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_valid_and_checked());
                };
            };
        };

        bsl::ut_scenario{"failure"} = []() noexcept {
            bsl::ut_check(safe_integral<T>::failure().is_invalid());
            bsl::ut_check(safe_integral<T>::failure().is_unchecked());
        };

        bsl::ut_scenario{"max"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1.max(val2)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result == val2);
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(!result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val2.max(val1)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result == val2);
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(!result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val2.max(val1)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val2.max(val1)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"min"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1.min(val2)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result == val1);
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(!result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val2.min(val1)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result == val1);
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(!result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val2.min(val1)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val2.min(val1)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
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
    bsl::safe_integrals_must_be_checked_before_use();
    bsl::a_poisoned_safe_integral_was_read();
    bsl::a_safe_idx_was_poisoned();
    bsl::integral_overflow_underflow_wrap_error();

    static_assert(bsl::tests_members<bsl::int8>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int16>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int32>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int64>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uintmx>() == bsl::ut_success());

    bsl::discard(bsl::tests_members<bsl::int8>());
    bsl::discard(bsl::tests_members<bsl::int16>());
    bsl::discard(bsl::tests_members<bsl::int32>());
    bsl::discard(bsl::tests_members<bsl::int64>());
    bsl::discard(bsl::tests_members<bsl::uint8>());
    bsl::discard(bsl::tests_members<bsl::uint16>());
    bsl::discard(bsl::tests_members<bsl::uint32>());
    bsl::discard(bsl::tests_members<bsl::uint64>());
    bsl::discard(bsl::tests_members<bsl::uintmx>());

    return bsl::ut_success();
}
