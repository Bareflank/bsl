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

#include <bsl/discard.hpp>
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
        bsl::ut_scenario{"default constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx const val{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == static_cast<bsl::uintmx>(0));
                    bsl::ut_check(!val.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"value constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx const val{static_cast<bsl::uintmx>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == static_cast<bsl::uintmx>(42));
                    bsl::ut_check(!val.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"safe_integral constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx const val{bsl::safe_umx::magic_0(), bsl::here()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == static_cast<bsl::uintmx>(0));
                    bsl::ut_check(!val.is_invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"value assignment"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx mut_val{static_cast<bsl::uintmx>(23)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val = static_cast<bsl::uintmx>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<bsl::uintmx>(42));
                        bsl::ut_check(!mut_val.is_invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx mut_val{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val = static_cast<bsl::uintmx>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == static_cast<bsl::uintmx>(42));
                        bsl::ut_check(!mut_val.is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"max_value"} = []() noexcept {
            bsl::ut_check(safe_idx::max_value() == bsl::numeric_limits<bsl::uintmx>::max_value());
        };

        bsl::ut_scenario{"min_value"} = []() noexcept {
            bsl::ut_check(safe_idx::min_value() == bsl::numeric_limits<bsl::uintmx>::min_value());
        };

        bsl::ut_scenario{"magic_0"} = []() noexcept {
            bsl::ut_check(safe_idx::magic_0() == static_cast<bsl::uintmx>(0));
        };

        bsl::ut_scenario{"magic_1"} = []() noexcept {
            bsl::ut_check(safe_idx::magic_1() == static_cast<bsl::uintmx>(1));
        };

        bsl::ut_scenario{"magic_2"} = []() noexcept {
            bsl::ut_check(safe_idx::magic_2() == static_cast<bsl::uintmx>(2));
        };

        bsl::ut_scenario{"magic_3"} = []() noexcept {
            bsl::ut_check(safe_idx::magic_3() == static_cast<bsl::uintmx>(3));
        };

        bsl::ut_scenario{"data_as_ref"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_idx::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<bsl::uintmx>(1) == mut_val.data_as_ref());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_idx::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<bsl::uintmx>(1) == val.data_as_ref());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_idx::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<bsl::uintmx>(1) == val.cdata_as_ref());
                };
            };
        };

        bsl::ut_scenario{"data"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto mut_val{bsl::safe_idx::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<bsl::uintmx>(1) == *mut_val.data());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_idx::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<bsl::uintmx>(1) == *val.data());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_idx::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<bsl::uintmx>(1) == *val.cdata());
                };
            };
        };

        bsl::ut_scenario{"get"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_idx::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(static_cast<bsl::uintmx>(1) == val.get());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::discard(val.get());
                };
            };
        };

        bsl::ut_scenario{"is_pos"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_idx::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_pos());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_idx::magic_0()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_pos());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::discard(val.is_pos());
                };
            };
        };

        bsl::ut_scenario{"is_zero"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_idx::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero());
                };
            };

            bsl::ut_given{} = []() noexcept {
                auto const val{bsl::safe_idx::magic_0()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::discard(val.is_zero());
                };
            };
        };

        bsl::ut_scenario{"invalid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx const val{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"valid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_idx const val{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_valid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_idx const val{bsl::safe_umx::failure(), bsl::here()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_valid());
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
