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
#include <bsl/is_signed.hpp>
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
    template<typename T>
    constexpr void
    tests_arithmetic_add() noexcept
    {
        bsl::ut_scenario{"add assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::max_value()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 += val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::magic_neg_1()};
                    auto const val2{bsl::safe_integral<T>::min_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 += val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"add assign with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::max_value()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(-1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 += val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"add"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::max_value()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 + val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::magic_neg_1()};
                    auto const val2{bsl::safe_integral<T>::min_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 + val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"add with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::max_value()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(-1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 + val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{static_cast<T>(-1)};    // NOLINT
                    auto const val2{bsl::safe_integral<T>::min_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 + val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };
    }

    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    template<typename T>
    constexpr void
    tests_arithmetic_sub() noexcept
    {
        bsl::ut_scenario{"sub assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::max_value()};
                    auto const val2{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 -= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::magic_neg_2()};
                    auto const val2{bsl::safe_integral<T>::max_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 -= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::min_value()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::magic_1()};
                    auto const val2{bsl::safe_integral<T>::min_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 -= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub assign with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::max_value()};
                    auto const val2{static_cast<T>(-1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 -= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::min_value()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::max_value()};
                    auto const val2{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 - val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::magic_neg_2()};
                    auto const val2{bsl::safe_integral<T>::max_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 - val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::min_value()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::magic_1()};
                    auto const val2{bsl::safe_integral<T>::min_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 - val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::max_value()};
                    auto const val2{static_cast<T>(-1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 - val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{static_cast<T>(-2)};    // NOLINT
                    auto const val2{bsl::safe_integral<T>::max_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 - val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::min_value()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{static_cast<T>(1)};    // NOLINT
                    auto const val2{bsl::safe_integral<T>::min_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 - val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };
    }

    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    template<typename T>
    constexpr void
    tests_arithmetic_mul() noexcept
    {
        bsl::ut_scenario{"mul assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::max_value()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_2()};
                auto const val2{bsl::safe_integral<T>::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_neg_2()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 *= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::magic_neg_2()};
                    auto const val2{bsl::safe_integral<T>::min_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 *= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul assign with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(2)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::max_value()};
                auto const val2{static_cast<T>(2)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(-2)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 *= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::max_value()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_2()};
                auto const val2{bsl::safe_integral<T>::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_neg_2()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 * val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::magic_neg_2()};
                    auto const val2{bsl::safe_integral<T>::min_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 * val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(2)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::max_value()};
                auto const val2{static_cast<T>(2)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{static_cast<T>(2)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(-2)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 * val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{static_cast<T>(-2)};    // NOLINT
                    auto const val2{bsl::safe_integral<T>::min_value()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 * val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 * val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };
    }

    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    template<typename T>
    constexpr void
    tests_arithmetic_div() noexcept
    {
        bsl::ut_scenario{"div assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_0()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 /= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 /= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::min_value());
                            bsl::ut_check(!mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"div assign with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(2)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(0)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(-1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 /= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 /= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::min_value());
                            bsl::ut_check(!mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"div"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 / val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_0()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 / val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 / val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 / val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.checked() == bsl::safe_integral<T>::min_value());
                            bsl::ut_check(!result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 / val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 / val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 / val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"div with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(2)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 / val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 / val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(0)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 / val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(-1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 / val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::numeric_limits<T>::min_value()};    // NOLINT
                    auto const val2{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 / val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 / val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.checked() == bsl::safe_integral<T>::min_value());
                            bsl::ut_check(!result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto const val1{bsl::numeric_limits<T>::min_value()};    // NOLINT
                    auto const val2{bsl::safe_integral<T>::magic_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 / val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.checked() == bsl::safe_integral<T>::min_value());
                            bsl::ut_check(!result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 / val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 / val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };
    }

    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    template<typename T>
    constexpr void
    tests_arithmetic_mod() noexcept
    {
        bsl::ut_scenario{"mod assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_1());
                        bsl::ut_check(!mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_0()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 %= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 %= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_0());
                            bsl::ut_check(!mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod assign with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(2)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_1());
                        bsl::ut_check(!mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(0)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(-1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 %= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto mut_val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 %= val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.checked() == bsl::safe_integral<T>::magic_0());
                            bsl::ut_check(!mut_val1.is_invalid());
                            bsl::ut_check(mut_val1.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val1{bsl::safe_integral<T>::failure()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                        bsl::ut_check(mut_val1.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 % val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_1());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::magic_0()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 % val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 % val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{bsl::safe_integral<T>::magic_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 % val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_0());
                            bsl::ut_check(!result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 % val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 % val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 % val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(2)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 % val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_1());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::magic_2()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 % val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_1());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::magic_1()};
                auto const val2{static_cast<T>(0)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 % val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(-1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 % val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    auto const val1{bsl::numeric_limits<T>::min_value()};    // NOLINT
                    auto const val2{bsl::safe_integral<T>::magic_neg_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 % val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto const val1{bsl::safe_integral<T>::min_value()};
                    auto const val2{static_cast<T>(1)};    // NOLINT
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 % val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_0());
                            bsl::ut_check(!result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    auto const val1{bsl::numeric_limits<T>::min_value()};    // NOLINT
                    auto const val2{bsl::safe_integral<T>::magic_1()};
                    bsl::ut_when{} = [&]() noexcept {
                        auto const result{val1 % val2};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(result.checked() == bsl::safe_integral<T>::magic_0());
                            bsl::ut_check(!result.is_invalid());
                            bsl::ut_check(result.is_unchecked());
                        };
                    };
                };
            }

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{bsl::safe_integral<T>::failure()};
                auto const val2{static_cast<T>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 % val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val1{static_cast<T>(1)};    // NOLINT
                auto const val2{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 % val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };
    }

    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    template<typename T>
    constexpr void
    tests_arithmetic_inc() noexcept
    {
        bsl::ut_scenario{"inc"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.checked() == bsl::safe_integral<T>::magic_2());
                        bsl::ut_check(!mut_val.is_invalid());
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_invalid());
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_invalid());
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };
        };
    }

    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    template<typename T>
    constexpr void
    tests_arithmetic_dec() noexcept
    {
        bsl::ut_scenario{"dec"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.checked() == bsl::safe_integral<T>::magic_0());
                        bsl::ut_check(!mut_val.is_invalid());
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                auto mut_val{bsl::safe_integral<T>::min_value()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_invalid());
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(1), bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_invalid());
                        bsl::ut_check(mut_val.is_unchecked());
                    };
                };
            };
        };
    }

    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    template<typename T>
    constexpr void
    tests_arithmetic_unary() noexcept
    {
        bsl::ut_scenario{"unary"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{-val};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result == bsl::safe_integral<T>::magic_neg_1());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(!result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::magic_neg_1()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{-val};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result == bsl::safe_integral<T>::magic_1());
                        bsl::ut_check(!result.is_invalid());
                        bsl::ut_check(!result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::min_value()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{-val};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_integral<T>::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{-val};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                        bsl::ut_check(result.is_unchecked());
                    };
                };
            };
        };
    }

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
    tests_arithmetic() noexcept -> bsl::exit_code
    {
        tests_arithmetic_add<T>();
        tests_arithmetic_sub<T>();
        tests_arithmetic_mul<T>();
        tests_arithmetic_div<T>();
        tests_arithmetic_mod<T>();
        tests_arithmetic_inc<T>();
        tests_arithmetic_dec<T>();

        if constexpr (bsl::is_signed<T>::value) {
            tests_arithmetic_unary<T>();
        }

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
    static_assert(bsl::tests_arithmetic<bsl::int8>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int16>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int32>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int64>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uintmx>() == bsl::ut_success());

    bsl::discard(bsl::tests_arithmetic<bsl::int8>());
    bsl::discard(bsl::tests_arithmetic<bsl::int16>());
    bsl::discard(bsl::tests_arithmetic<bsl::int32>());
    bsl::discard(bsl::tests_arithmetic<bsl::int64>());
    bsl::discard(bsl::tests_arithmetic<bsl::uint8>());
    bsl::discard(bsl::tests_arithmetic<bsl::uint16>());
    bsl::discard(bsl::tests_arithmetic<bsl::uint32>());
    bsl::discard(bsl::tests_arithmetic<bsl::uint64>());
    bsl::discard(bsl::tests_arithmetic<bsl::uintmx>());

    return bsl::ut_success();
}
