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
    tests_binary() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"and assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val1{42U};
                bsl::safe_uint32 val2{23U};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 &= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1 == (42U & 23U));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, false};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 &= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, false};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 &= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 &= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"and assign with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_when{} = [&val]() {
                    val &= 23U;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == (42U & 23U));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_when{} = [&val]() {
                    val &= 23U;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"and"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val1{42U};
                bsl::safe_uint32 val2{23U};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 & val2) == (42U & 23U));
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, false};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 & val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, false};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 & val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 & val2).invalid());
                };
            };
        };

        bsl::ut_scenario{"and with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val & 23U) == (42U & 23U));
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{23U};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42U & val) == (42U & 23U));
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val & 23U).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val{23U, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42U & val).invalid());
                };
            };
        };

        bsl::ut_scenario{"or assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val1{42U};
                bsl::safe_uint32 val2{23U};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 |= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1 == (42U | 23U));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, false};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 |= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, false};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 |= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 |= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"or assign with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_when{} = [&val]() {
                    val |= 23U;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == (42U | 23U));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_when{} = [&val]() {
                    val |= 23U;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"or"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val1{42U};
                bsl::safe_uint32 val2{23U};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 | val2) == (42U | 23U));
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, false};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 | val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, false};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 | val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 | val2).invalid());
                };
            };
        };

        bsl::ut_scenario{"or with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val | 23U) == (42U | 23U));
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{23U};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42U | val) == (42U | 23U));
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val | 23U).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val{23U, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42U | val).invalid());
                };
            };
        };

        bsl::ut_scenario{"xor assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val1{42U};
                bsl::safe_uint32 val2{23U};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 ^= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1 == (42U ^ 23U));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, false};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 ^= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, false};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 ^= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_when{} = [&val1, &val2]() {
                    val1 ^= val2;
                    bsl::ut_then{} = [&val1]() {
                        bsl::ut_check(val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"xor assign with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_when{} = [&val]() {
                    val ^= 23U;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val == (42U ^ 23U));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_when{} = [&val]() {
                    val ^= 23U;
                    bsl::ut_then{} = [&val]() {
                        bsl::ut_check(val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"xor"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val1{42U};
                bsl::safe_uint32 val2{23U};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 ^ val2) == (42U ^ 23U));
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, false};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 ^ val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, false};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 ^ val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val1{42U, true};
                bsl::safe_uint32 val2{23U, true};
                bsl::ut_then{} = [&val1, &val2]() {
                    bsl::ut_check((val1 ^ val2).invalid());
                };
            };
        };

        bsl::ut_scenario{"xor with value"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val ^ 23U) == (42U ^ 23U));
                };
            };

            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{23U};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42U ^ val) == (42U ^ 23U));
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((val ^ 23U).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val{23U, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((42U ^ val).invalid());
                };
            };
        };

        bsl::ut_scenario{"complement"} = []() {
            bsl::ut_given{} = []() {
                bsl::safe_uint32 val{42U};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check(~val == ~42U);
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::safe_uint32 val{42U, true};
                bsl::ut_then{} = [&val]() {
                    bsl::ut_check((~val).invalid());
                };
            };
        };

        return bsl::ut_success();
    }
}
