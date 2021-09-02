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

#include <bsl/numeric_limits.hpp>
#include <bsl/safe_idx.hpp>
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
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"add assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx mut_val1{static_cast<bsl::uintmx>(42)};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == static_cast<bsl::uintmx>(42 + 42));
                        bsl::ut_check(!mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{bsl::numeric_limits<bsl::uintmx>::max_value()};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{static_cast<bsl::uintmx>(1)};
                bsl::safe_idx const val2{bsl::numeric_limits<bsl::uintmx>::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{static_cast<bsl::uintmx>(1)};
                bsl::safe_idx const val2{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::safe_idx const val2{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"add assign with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx mut_val1{static_cast<bsl::uintmx>(42)};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(42)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == static_cast<bsl::uintmx>(42 + 42));
                        bsl::ut_check(!mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{bsl::numeric_limits<bsl::uintmx>::max_value()};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{static_cast<bsl::uintmx>(1)};
                bsl::uintmx const val2{bsl::numeric_limits<bsl::uintmx>::max_value()};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"add"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx const val1{static_cast<bsl::uintmx>(42)};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result == static_cast<bsl::uintmx>(42 + 42));
                        bsl::ut_check(!result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{bsl::numeric_limits<bsl::uintmx>::max_value()};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{static_cast<bsl::uintmx>(1)};
                bsl::safe_idx const val2{bsl::numeric_limits<bsl::uintmx>::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{static_cast<bsl::uintmx>(1)};
                bsl::safe_idx const val2{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::safe_idx const val2{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"add with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx const val1{static_cast<bsl::uintmx>(42)};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(42)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result == static_cast<bsl::uintmx>(42 + 42));
                        bsl::ut_check(!result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{bsl::numeric_limits<bsl::uintmx>::max_value()};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{static_cast<bsl::uintmx>(1)};
                bsl::uintmx const val2{bsl::numeric_limits<bsl::uintmx>::max_value()};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 + val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx mut_val1{static_cast<bsl::uintmx>(42)};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == static_cast<bsl::uintmx>(42 - 42));
                        bsl::ut_check(!mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{bsl::numeric_limits<bsl::uintmx>::min_value()};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{static_cast<bsl::uintmx>(1)};
                bsl::safe_idx const val2{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::safe_idx const val2{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub assign with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx mut_val1{static_cast<bsl::uintmx>(42)};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(42)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == static_cast<bsl::uintmx>(42 - 42));
                        bsl::ut_check(!mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{bsl::numeric_limits<bsl::uintmx>::min_value()};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx const val1{static_cast<bsl::uintmx>(42)};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result == static_cast<bsl::uintmx>(42 - 42));
                        bsl::ut_check(!result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{bsl::numeric_limits<bsl::uintmx>::min_value()};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::safe_idx const val2{static_cast<bsl::uintmx>(1)};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{static_cast<bsl::uintmx>(1)};
                bsl::safe_idx const val2{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::safe_idx const val2{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub with value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx const val1{static_cast<bsl::uintmx>(42)};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(42)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result == static_cast<bsl::uintmx>(42 - 42));
                        bsl::ut_check(!result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{bsl::numeric_limits<bsl::uintmx>::min_value()};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val1{bsl::safe_umx::failure(), bsl::here()};
                bsl::uintmx const val2{static_cast<bsl::uintmx>(1)};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    auto const result{val1 - val2};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(result.is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"inc"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx mut_val{static_cast<bsl::uintmx>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<bsl::uintmx>(43));
                        bsl::ut_check(!mut_val.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val{bsl::numeric_limits<bsl::uintmx>::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"dec"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx mut_val{static_cast<bsl::uintmx>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<bsl::uintmx>(41));
                        bsl::ut_check(!mut_val.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val{bsl::numeric_limits<bsl::uintmx>::min_value()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.is_invalid());
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
    static_assert(bsl::tests() == bsl::ut_success());
    return bsl::tests();
}
