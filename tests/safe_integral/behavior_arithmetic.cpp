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
#include <bsl/numeric_limits.hpp>
#include <bsl/ut.hpp>

/// <!-- description -->
///   @brief Used to execute the actual checks. We put the checks in this
///     function so that we can validate the tests both at compile-time
///     and at run-time. If a bsl::ut_check fails, the tests will either
///     fail fast at run-time, or will produce a compile-time error.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
constexpr bsl::exit_code
tests() noexcept
{
    bsl::ut_scenario{"add"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42};
            bsl::safe_int32 val2{42};
            bsl::ut_then{} = [&val1, &val2]() {
                bsl::ut_check(val1 + val2 == 42 + 42);
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
            bsl::safe_int32 val2{1};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 + val2).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
            bsl::safe_int32 val2{-1};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 + val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, true};
            bsl::safe_int32 val2{42, false};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 + val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, false};
            bsl::safe_int32 val2{42, true};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 + val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, true};
            bsl::safe_int32 val2{42, true};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 + val2).failure());
                };
            };
        };
    };

    bsl::ut_scenario{"add with value"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val + 42 == 42 + 42);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(42 + val == 42 + 42);
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val + 1).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((1 + val).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val + (-1)).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(((-1) + val).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42, true};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val + 42).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42, true};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42 + val).failure());
                };
            };
        };
    };

    bsl::ut_scenario{"sub"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42};
            bsl::safe_int32 val2{23};
            bsl::ut_then{} = [&val1, &val2]() {
                bsl::ut_check(val1 - val2 == 42 - 23);
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
            bsl::safe_int32 val2{-1};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 - val2).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
            bsl::safe_int32 val2{1};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 - val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, true};
            bsl::safe_int32 val2{23, false};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 - val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, false};
            bsl::safe_int32 val2{23, true};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 - val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, true};
            bsl::safe_int32 val2{23, true};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 - val2).failure());
                };
            };
        };
    };

    bsl::ut_scenario{"sub with value"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val - 23 == 42 - 23);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{23};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(42 - val == 42 - 23);
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val - (-1)).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{-1};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((bsl::numeric_limits<bsl::int32>::max() - val).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val - 1).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{1};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((bsl::numeric_limits<bsl::int32>::min() - val).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42, true};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val - 23).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{23, true};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42 - val).failure());
                };
            };
        };
    };

    bsl::ut_scenario{"mul"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42};
            bsl::safe_int32 val2{42};
            bsl::ut_then{} = [&val1, &val2]() {
                bsl::ut_check(val1 * val2 == 42 * 42);
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
            bsl::safe_int32 val2{2};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 * val2).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
            bsl::safe_int32 val2{-2};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 * val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, true};
            bsl::safe_int32 val2{42, false};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 * val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, false};
            bsl::safe_int32 val2{42, true};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 * val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, true};
            bsl::safe_int32 val2{42, true};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 * val2).failure());
                };
            };
        };
    };

    bsl::ut_scenario{"mul with value"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val * 42 == 42 * 42);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(42 * val == 42 * 42);
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val * 2).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((2 * val).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val * (-2)).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(((-2) * val).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42, true};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val * 42).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42, true};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42 * val).failure());
                };
            };
        };
    };

    bsl::ut_scenario{"div"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42};
            bsl::safe_int32 val2{23};
            bsl::ut_then{} = [&val1, &val2]() {
                bsl::ut_check(val1 / val2 == 42 / 23);
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val1{42};
            bsl::safe_int32 val2{0};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 / val2).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
            bsl::safe_int32 val2{-1};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 / val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, true};
            bsl::safe_int32 val2{23, false};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 / val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, false};
            bsl::safe_int32 val2{23, true};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 / val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, true};
            bsl::safe_int32 val2{23, true};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 / val2).failure());
                };
            };
        };
    };

    bsl::ut_scenario{"div with value"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val / 23 == 42 / 23);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{23};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(42 / val == 42 / 23);
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val / 0).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{0};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42 / val).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val / (-1)).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{-1};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((bsl::numeric_limits<bsl::int32>::min() / val).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42, true};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val / 23).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{23, true};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42 / val).failure());
                };
            };
        };
    };

    bsl::ut_scenario{"mod"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42};
            bsl::safe_int32 val2{23};
            bsl::ut_then{} = [&val1, &val2]() {
                bsl::ut_check(val1 % val2 == 42 % 23);
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val1{42};
            bsl::safe_int32 val2{0};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 % val2).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
            bsl::safe_int32 val2{-1};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 % val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, true};
            bsl::safe_int32 val2{23, false};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 % val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, false};
            bsl::safe_int32 val2{23, true};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 % val2).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42, true};
            bsl::safe_int32 val2{23, true};
            bsl::ut_when{} = [&val1, &val2]() {
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 % val2).failure());
                };
            };
        };
    };

    bsl::ut_scenario{"mod with value"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val % 23 == 42 % 23);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{23};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(42 % val == 42 % 23);
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val % 0).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{0};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42 % val).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val % (-1)).failure());
                };
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{-1};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((bsl::numeric_limits<bsl::int32>::min() % val).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42, true};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val % 23).failure());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{23, true};
            bsl::ut_when{} = [&val]() {
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42 % val).failure());
                };
            };
        };
    };

    bsl::ut_scenario{"unary"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(-val == -42);
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check((-val).failure());
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42, true};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check((-val).failure());
            };
        };
    };

    return bsl::ut_success();
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    static_assert(tests() == bsl::ut_success());
    return tests();
}
