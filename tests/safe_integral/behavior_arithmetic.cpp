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
    tests_arithmetic() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"add"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 + val2 == static_cast<T>(static_cast<T>(42 + 42)));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{bsl::numeric_limits<T>::max()};
                bsl::safe_integral<T> const val2{static_cast<T>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 + val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> const val2{static_cast<T>(static_cast<T>(-1))};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((val1 + val2).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), false};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 + val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 + val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 + val2).invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"add with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(val + static_cast<T>(42) == static_cast<T>(42 + 42));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(static_cast<T>(42) + val == static_cast<T>(42 + 42));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{bsl::numeric_limits<T>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val + static_cast<T>(1)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{bsl::numeric_limits<T>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((static_cast<T>(1) + val).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((val + static_cast<T>(static_cast<T>(-1))).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((static_cast<T>(static_cast<T>(-1)) + val).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val + static_cast<T>(42)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((static_cast<T>(42) + val).invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 - val2 == static_cast<T>(42 - 23));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val1{bsl::numeric_limits<T>::max()};
                    bsl::safe_integral<T> const val2{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((val1 - val2).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{bsl::numeric_limits<T>::min()};
                bsl::safe_integral<T> const val2{static_cast<T>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 - val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(23), false};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 - val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 - val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 - val2).invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(val - static_cast<T>(23) == static_cast<T>(42 - 23));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(static_cast<T>(42) - val == static_cast<T>(42 - 23));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{bsl::numeric_limits<T>::max()};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((val - (static_cast<T>(-1))).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((bsl::numeric_limits<T>::max() - val).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{bsl::numeric_limits<T>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val - static_cast<T>(1)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((bsl::numeric_limits<T>::min() - val).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val - static_cast<T>(23)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((static_cast<T>(42) - val).invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(2)};
                bsl::safe_integral<T> const val2{static_cast<T>(2)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 * val2 == static_cast<T>(2 * 2));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{bsl::numeric_limits<T>::max()};
                bsl::safe_integral<T> const val2{static_cast<T>(2)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 * val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> const val2{static_cast<T>(-2)};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((val1 * val2).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), false};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 * val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 * val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 * val2).invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(2)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(val * static_cast<T>(2) == static_cast<T>(2 * 2));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(2)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(static_cast<T>(2) * val == static_cast<T>(2 * 2));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{bsl::numeric_limits<T>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val * static_cast<T>(2)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{bsl::numeric_limits<T>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((static_cast<T>(2) * val).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((val * static_cast<T>(-2)).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((static_cast<T>(-2) * val).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val * static_cast<T>(42)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((static_cast<T>(42) * val).invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"div"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 / val2 == static_cast<T>(42 / 23));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(0)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 / val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> const val2{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((val1 / val2).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(23), false};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 / val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 / val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 / val2).invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"div with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(val / static_cast<T>(23) == static_cast<T>(42 / 23));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(static_cast<T>(42) / val == static_cast<T>(42 / 23));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val / static_cast<T>(0)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(0)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((static_cast<T>(42) / val).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((val / (static_cast<T>(-1))).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{bsl::numeric_limits<T>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!(val / static_cast<T>(42)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((bsl::numeric_limits<T>::min() / val).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val / static_cast<T>(23)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((static_cast<T>(42) / val).invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(23)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1 % val2 == static_cast<T>(42 % 23));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42)};
                bsl::safe_integral<T> const val2{static_cast<T>(0)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 % val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val1{bsl::numeric_limits<T>::min()};
                    bsl::safe_integral<T> const val2{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((val1 % val2).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(23), false};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 % val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), false};
                bsl::safe_integral<T> const val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 % val2).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val1{static_cast<T>(42), true};
                bsl::safe_integral<T> const val2{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val1 % val2).invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(val % static_cast<T>(23) == static_cast<T>(42 % 23));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(static_cast<T>(42) % val == static_cast<T>(42 % 23));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val % static_cast<T>(0)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(0)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((static_cast<T>(42) % val).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{bsl::numeric_limits<T>::min()};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((val % (static_cast<T>(-1))).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{bsl::numeric_limits<T>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!(val % static_cast<T>(42)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                if constexpr (bsl::is_signed<T>::value) {
                    bsl::safe_integral<T> const val{static_cast<T>(-1)};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check((bsl::numeric_limits<T>::min() % val).invalid());
                        };
                    };
                }
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(42), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((val % static_cast<T>(23)).invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_integral<T> const val{static_cast<T>(23), true};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((static_cast<T>(42) % val).invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"unary"} = []() noexcept {
            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::safe_integral<T> const val{static_cast<T>(42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(-val == static_cast<T>(-42));
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> const val{bsl::numeric_limits<T>::min()};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((-val).invalid());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::safe_integral<T> const val{static_cast<T>(42), true};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check((-val).invalid());
                    };
                };
            }
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
    static_assert(bsl::tests_arithmetic<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uintmax>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int8>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int16>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int32>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int64>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::intmax>() == bsl::ut_success());

    bsl::discard(bsl::tests_arithmetic<bsl::uint8>());
    bsl::discard(bsl::tests_arithmetic<bsl::uint16>());
    bsl::discard(bsl::tests_arithmetic<bsl::uint32>());
    bsl::discard(bsl::tests_arithmetic<bsl::uint64>());
    bsl::discard(bsl::tests_arithmetic<bsl::uintmax>());
    bsl::discard(bsl::tests_arithmetic<bsl::int8>());
    bsl::discard(bsl::tests_arithmetic<bsl::int16>());
    bsl::discard(bsl::tests_arithmetic<bsl::int32>());
    bsl::discard(bsl::tests_arithmetic<bsl::int64>());
    bsl::discard(bsl::tests_arithmetic<bsl::intmax>());

    return bsl::ut_success();
}
