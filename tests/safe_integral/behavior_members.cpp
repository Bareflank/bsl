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

#include <bsl/numeric_limits.hpp>
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
        bsl::ut_scenario{"default constructor"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val == 0);
                    bsl::ut_check(!val.failure());
                };
            };
        };

        bsl::ut_scenario{"value constructor"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val == 42);
                    bsl::ut_check(!val.failure());
                };
            };
        };

        bsl::ut_scenario{"value/error constructor"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, false};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val == 42);
                    bsl::ut_check(!val.failure());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.failure());
                };
            };
        };

        bsl::ut_scenario{"value assignment"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{23, false};
                bsl::ut_when{} = [&val]() {
                    val = 42;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42);
                        bsl::ut_check(!val.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{23, true};
                bsl::ut_when{} = [&val]() {
                    val = 42;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42);
                        bsl::ut_check(!val.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"get"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, false};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.get() == 42);
                    bsl::ut_check(!val.failure());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.failure());
                };
            };
        };

        bsl::ut_scenario{"operator bool"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, false};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!!val);
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val);
                };
            };
        };

        bsl::ut_scenario{"failure"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, false};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.failure());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.failure());
                };
            };
        };

        bsl::ut_scenario{"set_failure"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, false};
                bsl::ut_then{} = [&val]() {
                    val.set_failure();
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_then{} = [&val]() {
                    val.set_failure();
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"max"} = []() {
            bsl::ut_check(bsl::safe_uintmax::max() == bsl::numeric_limits<bsl::uintmax>::max());

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{23, false};
                bsl::safe_int32 val2{42, false};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check(val1.max(val2) == 42);
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{23, false};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.max(42) == 42);
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{23, true};
                bsl::safe_int32 val2{42, false};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check(val1.max(val2).failure());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{23, false};
                bsl::safe_int32 val2{42, true};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check(val1.max(val2).failure());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{23, true};
                bsl::safe_int32 val2{42, true};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check(val1.max(val2).failure());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{23, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.max(42).failure());
                };
            };
        };

        bsl::ut_scenario{"min"} = []() {
            bsl::ut_check(bsl::safe_uintmax::min() == bsl::numeric_limits<bsl::uintmax>::min());

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{23, false};
                bsl::safe_int32 val2{42, false};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check(val1.min(val2) == 23);
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{23, false};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.min(42) == 23);
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{23, true};
                bsl::safe_int32 val2{42, false};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check(val1.min(val2).failure());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{23, false};
                bsl::safe_int32 val2{42, true};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check(val1.min(val2).failure());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{23, true};
                bsl::safe_int32 val2{42, true};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check(val1.min(val2).failure());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{23, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.min(42).failure());
                };
            };
        };

        bsl::ut_scenario{"zero"} = []() {
            bsl::ut_check(bsl::safe_intmax::zero() == bsl::to_imax(0));
            bsl::ut_check(!bsl::safe_intmax::zero(true));
            bsl::ut_check(bsl::safe_uintmax::zero() == bsl::to_umax(0));
            bsl::ut_check(!bsl::safe_uintmax::zero(true));
        };

        bsl::ut_scenario{"one"} = []() {
            bsl::ut_check(bsl::safe_intmax::one() == bsl::to_imax(1));
            bsl::ut_check(!bsl::safe_intmax::one(true));
            bsl::ut_check(bsl::safe_uintmax::one() == bsl::to_umax(1));
            bsl::ut_check(!bsl::safe_uintmax::one(true));
        };

        bsl::ut_scenario{"is_signed_type"} = []() {
            bsl::ut_check(bsl::safe_intmax::is_signed_type());
            bsl::ut_check(!bsl::safe_uintmax::is_signed_type());
        };

        bsl::ut_scenario{"is_unsigned_type"} = []() {
            bsl::ut_check(!bsl::safe_intmax::is_unsigned_type());
            bsl::ut_check(bsl::safe_uintmax::is_unsigned_type());
        };

        bsl::ut_scenario{"is_pos"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{42};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.is_pos());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{0};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_pos());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{-42};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_pos());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{42, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_pos());
                };
            };
        };

        bsl::ut_scenario{"is_neg"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{-42};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.is_neg());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{0};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{42};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{-42, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_zero"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{0};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.is_zero());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{42};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_zero());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{-42};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_zero());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{0, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.is_zero());
                };
            };
        };

        bsl::ut_scenario{"is_max"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{bsl::safe_int32::max()};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.is_max());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{bsl::safe_int32::min()};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_max());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{bsl::safe_int32::max(), true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_max());
                };
            };
        };

        bsl::ut_scenario{"is_min"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{bsl::safe_int32::min()};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(val.is_min());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{bsl::safe_int32::max()};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_min());
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 const val{bsl::safe_int32::min(), true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(!val.is_min());
                };
            };
        };

        bsl::ut_scenario{"add assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{42};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 += val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1 == 42 + 42);
                        bsl::ut_check(!val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 val2{1};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 += val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 val2{-1};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 += val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 val2{1};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 += val2;
                    val1 += val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 val2{1, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 += val2;
                    val1 += val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, true};
                bsl::safe_int32 val2{42, false};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 += val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, false};
                bsl::safe_int32 val2{42, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 += val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, true};
                bsl::safe_int32 val2{42, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 += val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"add assign with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    val += 42;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42 + 42);
                        bsl::ut_check(!val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&val]() {
                    val += 1;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&val]() {
                    val += (-1);
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&val]() {
                    val += 1;
                    val += 1;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_when{} = [&val]() {
                    val += 42;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{23};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 -= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1 == 42 - 23);
                        bsl::ut_check(!val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 val2{-1};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 -= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 val2{1};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 -= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 val2{-1};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 -= val2;
                    val1 -= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 val2{-1, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 -= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, true};
                bsl::safe_int32 val2{23, false};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 -= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, false};
                bsl::safe_int32 val2{23, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 -= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, true};
                bsl::safe_int32 val2{23, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 -= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub assign with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    val -= 23;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42 - 23);
                        bsl::ut_check(!val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&val]() {
                    val -= (-1);
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&val]() {
                    val -= (1);
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&val]() {
                    val -= (-1);
                    val -= (-1);
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_when{} = [&val]() {
                    val -= 23;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{42};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 *= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1 == 42 * 42);
                        bsl::ut_check(!val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 val2{2};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 *= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 val2{-2};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 *= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 val2{2};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 *= val2;
                    val1 *= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 val2{2, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 *= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, true};
                bsl::safe_int32 val2{42, false};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 *= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, false};
                bsl::safe_int32 val2{42, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 *= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, true};
                bsl::safe_int32 val2{42, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 *= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul assign with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    val *= 42;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42 * 42);
                        bsl::ut_check(!val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&val]() {
                    val *= 2;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&val]() {
                    val *= (-2);
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&val]() {
                    val *= 2;
                    val *= 2;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_when{} = [&val]() {
                    val *= 42;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"div assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{23};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 /= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1 == 42 / 23);
                        bsl::ut_check(!val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{0};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 /= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{0};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 /= val2;
                    val1 /= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{0, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 /= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 val2{-1};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 /= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 val2{-1};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 /= val2;
                    val1 /= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 val2{-1, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 /= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, true};
                bsl::safe_int32 val2{23, false};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 /= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, false};
                bsl::safe_int32 val2{23, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 /= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, true};
                bsl::safe_int32 val2{23, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 /= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"div assign with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    val /= 23;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42 / 23);
                        bsl::ut_check(!val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    val /= 0;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    val /= 0;
                    val /= 0;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&val]() {
                    val /= (-1);
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&val]() {
                    val /= (-1);
                    val /= (-1);
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_when{} = [&val]() {
                    val /= 23;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{23};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 %= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1 == 42 % 23);
                        bsl::ut_check(!val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{0};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 %= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{0};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 %= val2;
                    val1 %= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{42};
                bsl::safe_int32 val2{0, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 %= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 val2{-1};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 %= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 val2{-1};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 %= val2;
                    val1 %= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 val2{-1, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 %= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, true};
                bsl::safe_int32 val2{23, false};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 %= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, false};
                bsl::safe_int32 val2{23, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 %= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val1{42, true};
                bsl::safe_int32 val2{23, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 %= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod assign with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    val %= 23;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42 % 23);
                        bsl::ut_check(!val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    val %= 0;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    val %= 0;
                    val %= 0;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&val]() {
                    val %= (-1);
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&val]() {
                    val %= (-1);
                    val %= (-1);
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_when{} = [&val]() {
                    val %= 23;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"inc"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    ++val;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42 + 1);
                        bsl::ut_check(!val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&val]() {
                    ++val;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&val]() {
                    ++val;
                    ++val;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_when{} = [&val]() {
                    ++val;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"dec"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42};
                bsl::ut_when{} = [&val]() {
                    --val;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == 42 - 1);
                        bsl::ut_check(!val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&val]() {
                    --val;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_int32 val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&val]() {
                    --val;
                    --val;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_int32 val{42, true};
                bsl::ut_when{} = [&val]() {
                    --val;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.failure());
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
    static_assert(tests() == bsl::ut_success());
    return tests();
}
