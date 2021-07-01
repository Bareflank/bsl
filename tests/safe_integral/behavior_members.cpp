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
                    bsl::ut_check(!val.invalid());
                };
            };
        };

        bsl::ut_scenario{"value constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == static_cast<T>(42));
                    bsl::ut_check(!val.invalid());
                };
            };
        };

        bsl::ut_scenario{"value/error constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == static_cast<T>(42));
                    bsl::ut_check(!val.invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.invalid());
                };
            };
        };

        bsl::ut_scenario{"value assignment"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23), false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val = static_cast<T>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42));
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val = static_cast<T>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42));
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"get"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        static_cast<bsl::uintmax>(42) == static_cast<bsl::uintmax>(mut_val.get()));
                    bsl::ut_check(!mut_val.invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        static_cast<bsl::uintmax>(42) == static_cast<bsl::uintmax>(val.get()));
                    bsl::ut_check(!val.invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        static_cast<bsl::uintmax>(0) == static_cast<bsl::uintmax>(mut_val.get()));
                    bsl::ut_check(mut_val.invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        static_cast<bsl::uintmax>(0) == static_cast<bsl::uintmax>(val.get()));
                    bsl::ut_check(val.invalid());
                };
            };
        };

        bsl::ut_scenario{"data"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        static_cast<bsl::uintmax>(42) ==
                        static_cast<bsl::uintmax>(*mut_val.data()));
                    bsl::ut_check(!mut_val.invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        static_cast<bsl::uintmax>(42) == static_cast<bsl::uintmax>(*val.data()));
                    bsl::ut_check(!val.invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        static_cast<bsl::uintmax>(42) ==
                        static_cast<bsl::uintmax>(*mut_val.data()));
                    bsl::ut_check(mut_val.invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        static_cast<bsl::uintmax>(42) == static_cast<uintmax>(*val.data()));
                    bsl::ut_check(val.invalid());
                };
            };
        };

        bsl::ut_scenario{"operator bool"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!!mut_val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!!val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val);
                };
            };
        };

        bsl::ut_scenario{"max"} = []() noexcept {
            bsl::ut_check(bsl::safe_integral<T>::max() == bsl::numeric_limits<T>::max());

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1.max(mut_val2) == static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), false};
                bsl::safe_integral<T> const val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.max(val2) == static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1.max(mut_val2) == static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.max(val2) == static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.max(static_cast<T>(42)) == static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.max(static_cast<T>(42)) == static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.max(static_cast<T>(23)) == static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.max(static_cast<T>(23)) == static_cast<T>(42));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1.max(mut_val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.max(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1.max(mut_val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), false};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.max(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1.max(mut_val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.max(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.max(static_cast<T>(42)).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.max(static_cast<T>(42)).invalid());
                };
            };
        };

        bsl::ut_scenario{"min"} = []() noexcept {
            bsl::ut_check(bsl::safe_integral<T>::min() == bsl::numeric_limits<T>::min());

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1.min(mut_val2) == static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), false};
                bsl::safe_integral<T> const val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.min(val2) == static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1.min(mut_val2) == static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.min(val2) == static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.min(static_cast<T>(42)) == static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.min(static_cast<T>(42)) == static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.min(static_cast<T>(23)) == static_cast<T>(23));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.min(static_cast<T>(23)) == static_cast<T>(23));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1.min(mut_val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.min(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1.min(mut_val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), false};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.min(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(23), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val1.min(mut_val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(23), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.min(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.min(static_cast<T>(42)).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.min(static_cast<T>(42)).invalid());
                };
            };
        };

        bsl::ut_scenario{"is_pos"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.is_pos());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_pos());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_val.is_pos());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_pos());
                };
            };

            bsl::ut_given{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val{static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_pos());
                    };
                }
            };

            bsl::ut_given{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_pos());
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_val.is_pos());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_pos());
                };
            };
        };

        bsl::ut_scenario{"is_neg"} = []() noexcept {
            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::safe_integral<T> mut_val{static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_neg());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::safe_integral<T> const val{static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(val.is_neg());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::safe_integral<T> mut_val{static_cast<T>(0)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_neg());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::safe_integral<T> const val{static_cast<T>(0)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_neg());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_neg());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::safe_integral<T> const val{static_cast<T>(42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> mut_val{static_cast<T>(-42), true};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> const val{static_cast<T>(-42), true};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_neg());
                    };
                };
            }
            else {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> mut_val{static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> const val{static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> mut_val{static_cast<T>(0)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> const val{static_cast<T>(0)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> const val{static_cast<T>(42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> mut_val{static_cast<T>(-42), true};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_val.is_neg());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> const val{static_cast<T>(-42), true};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!val.is_neg());
                    };
                };
            }
        };

        bsl::ut_scenario{"is_zero"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.is_zero());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_val.is_zero());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(0), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_val.is_zero());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(0), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero());
                };
            };
        };

        bsl::ut_scenario{"is_zero_or_invalid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.is_zero_or_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero_or_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_val.is_zero_or_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero_or_invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(0), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.is_zero_or_invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(0), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero_or_invalid());
                };
            };
        };

        bsl::ut_scenario{"invalid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_val.invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_val.invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.invalid());
                };
            };
        };

        bsl::ut_scenario{"add assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == static_cast<T>(42 + 42));
                        bsl::ut_check(!mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::max()};
                bsl::safe_integral<T> mut_val2{static_cast<T>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 += mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::max()};
                bsl::safe_integral<T> mut_val2{static_cast<T>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::max()};
                bsl::safe_integral<T> mut_val2{static_cast<T>(1), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"add assign with mut_value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val += static_cast<T>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42 + 42));
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val += static_cast<T>(1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val += static_cast<T>(-1);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val += static_cast<T>(1);
                    mut_val += static_cast<T>(1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val += static_cast<T>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == static_cast<T>(42 - 23));
                        bsl::ut_check(!mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::max()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 -= mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::min()};
                bsl::safe_integral<T> mut_val2{static_cast<T>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::max()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 -= mut_val2;
                        mut_val1 -= mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::max()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-1), true};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 -= mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub assign with mut_value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val -= static_cast<T>(23);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42 - 23));
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::max()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val -= static_cast<T>(-1);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val -= static_cast<T>(1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::max()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val -= static_cast<T>(-1);
                        mut_val -= static_cast<T>(-1);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val -= static_cast<T>(23);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(2)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(2)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == static_cast<T>(2 * 2));
                        bsl::ut_check(!mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::max()};
                bsl::safe_integral<T> mut_val2{static_cast<T>(2)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-2)};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 *= mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::max()};
                bsl::safe_integral<T> mut_val2{static_cast<T>(2)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::max()};
                bsl::safe_integral<T> mut_val2{static_cast<T>(2), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul assign with mut_value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(2)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val *= static_cast<T>(2);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(2 * 2));
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val *= static_cast<T>(2);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val *= static_cast<T>(-2);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val *= static_cast<T>(2);
                    mut_val *= static_cast<T>(2);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val *= static_cast<T>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"div assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == static_cast<T>(42 / 23));
                        bsl::ut_check(!mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(0)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(0)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(0), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 /= mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 /= mut_val2;
                        mut_val1 /= mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-1), true};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 /= mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"div assign with mut_value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val /= static_cast<T>(23);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42 / 23));
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val /= static_cast<T>(0);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val /= static_cast<T>(0);
                    mut_val /= static_cast<T>(0);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val /= static_cast<T>(-1);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val /= static_cast<T>(-1);
                        mut_val /= static_cast<T>(-1);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val /= static_cast<T>(23);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == static_cast<T>(42 % 23));
                        bsl::ut_check(!mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(0)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(0)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42)};
                bsl::safe_integral<T> mut_val2{static_cast<T>(0), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 %= mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 %= mut_val2;
                        mut_val1 %= mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> mut_val2{static_cast<T>(-1), true};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val1 %= mut_val2;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val1.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), false};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val1{static_cast<T>(42), true};
                bsl::safe_integral<T> mut_val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod assign with mut_value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val %= static_cast<T>(23);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42 % 23));
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val %= static_cast<T>(0);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val %= static_cast<T>(0);
                    mut_val %= static_cast<T>(0);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val %= static_cast<T>(-1);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        mut_val %= static_cast<T>(-1);
                        mut_val %= static_cast<T>(-1);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(mut_val.invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val %= static_cast<T>(23);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"inc"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42 + 1));
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"dec"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<T>(42 - 1));
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{bsl::numeric_limits<T>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> mut_val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
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
    static_assert(bsl::tests_members<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uintmax>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int8>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int16>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int32>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int64>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::intmax>() == bsl::ut_success());

    bsl::discard(bsl::tests_members<bsl::uint8>());
    bsl::discard(bsl::tests_members<bsl::uint16>());
    bsl::discard(bsl::tests_members<bsl::uint32>());
    bsl::discard(bsl::tests_members<bsl::uint64>());
    bsl::discard(bsl::tests_members<bsl::uintmax>());
    bsl::discard(bsl::tests_members<bsl::int8>());
    bsl::discard(bsl::tests_members<bsl::int16>());
    bsl::discard(bsl::tests_members<bsl::int32>());
    bsl::discard(bsl::tests_members<bsl::int64>());
    bsl::discard(bsl::tests_members<bsl::intmax>());

    return bsl::ut_success();
}
