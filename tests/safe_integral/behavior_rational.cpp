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
    tests_rational() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"equals"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 == mut_val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 == val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 == mut_val2));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 == val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 == mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 == val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 == mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 == val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 == mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 == val2));
                };
            };
        };

        bsl::ut_scenario{"equals with a value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val == static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(42) == mut_val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(42) == val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val == static_cast<T>(23)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val == static_cast<T>(23)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(23) == mut_val));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(23) == val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val == static_cast<T>(42)));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val == static_cast<T>(42)));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) == mut_val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) == val));
                };
            };
        };

        bsl::ut_scenario{"not equals"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 != mut_val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 != val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 != mut_val2));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 != val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 != mut_val2);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 != val2);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 != mut_val2);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 != val2);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 != mut_val2);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 != val2);
                };
            };
        };

        bsl::ut_scenario{"not equals with a value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val != static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val != static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(23) != mut_val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(23) != val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val != static_cast<T>(42)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val != static_cast<T>(42)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) != mut_val));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) != val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val != static_cast<T>(42));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val != static_cast<T>(42));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(42) != mut_val);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(42) != val);
                };
            };
        };

        bsl::ut_scenario{"lt"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 < mut_val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23)};
                bsl::safe_integral<T> const val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 < val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 < mut_val2));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 < val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 < mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 < val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 < mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), false};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 < val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 < mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 < val2));
                };
            };
        };

        bsl::ut_scenario{"lt with a value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val < static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val < static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(23) < mut_val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(23) < val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val < static_cast<T>(23)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val < static_cast<T>(23)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) < mut_val));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) < val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) < mut_val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) < val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val < static_cast<T>(23)));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val < static_cast<T>(23)));
                };
            };
        };

        bsl::ut_scenario{"gt"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 > mut_val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 > val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 > mut_val2));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23)};
                bsl::safe_integral<T> const val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 > val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 > mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 > val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 > mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 > val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 > mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 > val2));
                };
            };
        };

        bsl::ut_scenario{"gt with a value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val > static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val > static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(42) > mut_val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(42) > val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val > static_cast<T>(42)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val > static_cast<T>(42)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(23) > mut_val));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(23) > val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(23) > mut_val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(23) > val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val > static_cast<T>(42)));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val > static_cast<T>(42)));
                };
            };
        };

        bsl::ut_scenario{"lte"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 <= mut_val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 <= val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 <= mut_val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23)};
                bsl::safe_integral<T> const val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 <= val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 <= mut_val2));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 <= val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 <= mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 <= val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 <= mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), false};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 <= val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 <= mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 <= val2));
                };
            };
        };

        bsl::ut_scenario{"lte with a value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val <= static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val <= static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val <= static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val <= static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(23) <= mut_val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(23) <= val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val <= static_cast<T>(23)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val <= static_cast<T>(23)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) <= mut_val));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) <= val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) <= mut_val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(42) <= val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val <= static_cast<T>(23)));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val <= static_cast<T>(23)));
                };
            };
        };

        bsl::ut_scenario{"gte"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 >= mut_val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 >= val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1 >= mut_val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 >= val2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 >= mut_val2));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23)};
                bsl::safe_integral<T> const val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 >= val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 >= mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 >= val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 >= mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 >= val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val1 >= mut_val2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val1 >= val2));
                };
            };
        };

        bsl::ut_scenario{"gte with a value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val >= static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val >= static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val >= static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val >= static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(42) >= mut_val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<T>(42) >= val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val >= static_cast<T>(42)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val >= static_cast<T>(42)));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(23) >= mut_val));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(23) >= val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(23) >= mut_val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(static_cast<T>(23) >= val));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_val >= static_cast<T>(42)));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(val >= static_cast<T>(42)));
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
    static_assert(bsl::tests_rational<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::uintmax>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::int8>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::int16>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::int32>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::int64>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::intmax>() == bsl::ut_success());

    bsl::discard(bsl::tests_rational<bsl::uint8>());
    bsl::discard(bsl::tests_rational<bsl::uint16>());
    bsl::discard(bsl::tests_rational<bsl::uint32>());
    bsl::discard(bsl::tests_rational<bsl::uint64>());
    bsl::discard(bsl::tests_rational<bsl::uintmax>());
    bsl::discard(bsl::tests_rational<bsl::int8>());
    bsl::discard(bsl::tests_rational<bsl::int16>());
    bsl::discard(bsl::tests_rational<bsl::int32>());
    bsl::discard(bsl::tests_rational<bsl::int64>());
    bsl::discard(bsl::tests_rational<bsl::intmax>());

    return bsl::ut_success();
}
