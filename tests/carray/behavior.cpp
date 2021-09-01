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

#include "../carray_init.hpp"

#include <bsl/carray.hpp>
#include <bsl/convert.hpp>
#include <bsl/npos.hpp>
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
        bsl::ut_scenario{"at_if"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(0)) == bsl::to_i32(4));
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(1)) == bsl::to_i32(8));
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(2)) == bsl::to_i32(15));
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(3)) == bsl::to_i32(16));
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(4)) == bsl::to_i32(23));
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(5)) == bsl::to_i32(42));
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(6)) == nullptr);
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_INT_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(0)) == bsl::to_i32(42));
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(1)) == bsl::to_i32(42));
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(2)) == bsl::to_i32(42));
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(3)) == bsl::to_i32(42));
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(4)) == bsl::to_i32(42));
                    bsl::ut_check(*mut_arr.at_if(static_cast<bsl::uintmx>(5)) == bsl::to_i32(42));
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(6)) == nullptr);
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 70> mut_arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(0)) != nullptr);
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 10000> mut_arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(0)) != nullptr);
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_STR_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(0)) != nullptr);
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_STR_ARGS};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(0)) != nullptr);
                    bsl::ut_check(mut_arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(0)) == bsl::to_i32(4));
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(1)) == bsl::to_i32(8));
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(2)) == bsl::to_i32(15));
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(3)) == bsl::to_i32(16));
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(4)) == bsl::to_i32(23));
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(5)) == bsl::to_i32(42));
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(6)) == nullptr);
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_INT_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(0)) == bsl::to_i32(42));
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(1)) == bsl::to_i32(42));
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(2)) == bsl::to_i32(42));
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(3)) == bsl::to_i32(42));
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(4)) == bsl::to_i32(42));
                    bsl::ut_check(*arr.at_if(static_cast<bsl::uintmx>(5)) == bsl::to_i32(42));
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(6)) == nullptr);
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 70> const arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(0)) != nullptr);
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 10000> const arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(0)) != nullptr);
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_STR_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(0)) != nullptr);
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_STR_ARGS};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(0)) != nullptr);
                    bsl::ut_check(arr.at_if(static_cast<bsl::uintmx>(0xFFFFFFFFFF)) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"data"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 70> mut_arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 10000> mut_arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_STR_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_STR_ARGS};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_INT_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 70> const arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 10000> const arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_STR_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_STR_ARGS};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.data() != nullptr);
                };
            };
        };

        bsl::ut_scenario{"size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.size() == bsl::to_umx(6));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_INT_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.size() == bsl::to_umx(6));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 70> mut_arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.size() == bsl::to_umx(70));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 10000> mut_arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.size() == bsl::to_umx(10000));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_STR_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.size() == bsl::to_umx(1));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_STR_ARGS};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.size() == bsl::to_umx(9));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.size() == bsl::to_umx(6));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_INT_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.size() == bsl::to_umx(6));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 70> const arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.size() == bsl::to_umx(70));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 10000> const arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.size() == bsl::to_umx(10000));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_STR_42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.size() == bsl::to_umx(1));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_STR_ARGS};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.size() == bsl::to_umx(9));
                };
            };
        };

        bsl::ut_scenario{"size_bytes"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(6) * sizeof(bsl::safe_i32)).checked()};
                    bsl::ut_check(mut_arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_INT_42};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(6) * sizeof(bsl::int32)).checked()};
                    bsl::ut_check(mut_arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 70> mut_arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(70) * sizeof(bsl::char_type)).checked()};
                    bsl::ut_check(mut_arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 10000> mut_arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(10000) * sizeof(bsl::char_type)).checked()};
                    bsl::ut_check(mut_arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_STR_42};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(1) * sizeof(bsl::cstr_type)).checked()};
                    bsl::ut_check(mut_arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray mut_arr{test::CARRAY_INIT_STR_ARGS};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(9) * sizeof(bsl::cstr_type)).checked()};
                    bsl::ut_check(mut_arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(6) * sizeof(bsl::safe_i32)).checked()};
                    bsl::ut_check(arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_INT_42};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(6) * sizeof(bsl::int32)).checked()};
                    bsl::ut_check(arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 70> const arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(70) * sizeof(bsl::char_type)).checked()};
                    bsl::ut_check(arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray<bsl::char_type, 10000> const arr{};    // NOLINT
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(10000) * sizeof(bsl::char_type)).checked()};
                    bsl::ut_check(arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_STR_42};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(1) * sizeof(bsl::cstr_type)).checked()};
                    bsl::ut_check(arr.size_bytes() == expected);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const arr{test::CARRAY_INIT_STR_ARGS};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(bsl::to_umx(9) * sizeof(bsl::cstr_type)).checked()};
                    bsl::ut_check(arr.size_bytes() == expected);
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
