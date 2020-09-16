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

#include <bsl/span.hpp>
#include <bsl/array.hpp>
#include <bsl/npos.hpp>
#include <bsl/ut.hpp>

namespace
{
    constexpr bsl::array test_arr{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(23),
        bsl::to_i32(42)};

    constexpr bsl::array test_arr2{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(0),
        bsl::to_i32(42)};

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
        bsl::ut_scenario{"at_if"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.at_if(bsl::to_umax(0)) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.at_if(bsl::to_umax(0)) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{nullptr, bsl::to_umax(5)};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.at_if(bsl::to_umax(0)) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{nullptr, bsl::to_umax(5)};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.at_if(bsl::to_umax(0)) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), bsl::to_umax(0)};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.at_if(bsl::to_umax(0)) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span const spn{arr.data(), bsl::to_umax(0)};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.at_if(bsl::to_umax(0)) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*spn.at_if(bsl::to_umax(0)) == bsl::to_i32(4));
                    bsl::ut_check(*spn.at_if(bsl::to_umax(1)) == bsl::to_i32(8));
                    bsl::ut_check(*spn.at_if(bsl::to_umax(2)) == bsl::to_i32(15));
                    bsl::ut_check(*spn.at_if(bsl::to_umax(3)) == bsl::to_i32(16));
                    bsl::ut_check(*spn.at_if(bsl::to_umax(4)) == bsl::to_i32(23));
                    bsl::ut_check(*spn.at_if(bsl::to_umax(5)) == bsl::to_i32(42));
                    bsl::ut_check(spn.at_if(bsl::to_umax(6)) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*spn.at_if(bsl::to_umax(0)) == bsl::to_i32(4));
                    bsl::ut_check(*spn.at_if(bsl::to_umax(1)) == bsl::to_i32(8));
                    bsl::ut_check(*spn.at_if(bsl::to_umax(2)) == bsl::to_i32(15));
                    bsl::ut_check(*spn.at_if(bsl::to_umax(3)) == bsl::to_i32(16));
                    bsl::ut_check(*spn.at_if(bsl::to_umax(4)) == bsl::to_i32(23));
                    bsl::ut_check(*spn.at_if(bsl::to_umax(5)) == bsl::to_i32(42));
                    bsl::ut_check(spn.at_if(bsl::to_umax(6)) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"front_if"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.front_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.front_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*spn.front_if() == bsl::to_i32(4));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*spn.front_if() == bsl::to_i32(4));
                };
            };
        };

        bsl::ut_scenario{"back_if"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.back_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.back_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*spn.back_if() == bsl::to_i32(42));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*spn.back_if() == bsl::to_i32(42));
                };
            };
        };

        bsl::ut_scenario{"data"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.data() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.data() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.data() != nullptr);
                };
            };
        };

        bsl::ut_scenario{"begin"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.begin().get_if() == nullptr);
                    bsl::ut_check(spn.begin().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.begin().get_if() == nullptr);
                    bsl::ut_check(spn.begin().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.begin().get_if() == nullptr);
                    bsl::ut_check(spn.cbegin().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.begin().get_if()) == bsl::to_i32(4));
                    bsl::ut_check(spn.begin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.begin().get_if()) == bsl::to_i32(4));
                    bsl::ut_check(spn.begin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.cbegin().get_if()) == bsl::to_i32(4));
                    bsl::ut_check(spn.cbegin().index() == bsl::to_umax(0));
                };
            };
        };

        bsl::ut_scenario{"end"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.end().get_if() == nullptr);
                    bsl::ut_check(spn.end().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.end().get_if() == nullptr);
                    bsl::ut_check(spn.end().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.end().get_if() == nullptr);
                    bsl::ut_check(spn.cend().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.end().get_if() == nullptr);
                    bsl::ut_check(spn.end().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.end().get_if() == nullptr);
                    bsl::ut_check(spn.end().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.cend().get_if() == nullptr);
                    bsl::ut_check(spn.cend().index() == spn.size());
                };
            };
        };

        bsl::ut_scenario{"iter"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.iter(bsl::to_umax(0)).get_if() == nullptr);
                    bsl::ut_check(spn.iter(bsl::to_umax(0)).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.iter(bsl::to_umax(0)).get_if() == nullptr);
                    bsl::ut_check(spn.iter(bsl::to_umax(0)).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.iter(bsl::to_umax(0)).get_if() == nullptr);
                    bsl::ut_check(spn.citer(bsl::to_umax(0)).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.iter(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(spn.iter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.iter(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(spn.iter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.citer(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(spn.citer(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.iter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(spn.iter(bsl::npos).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.iter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(spn.iter(bsl::npos).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.citer(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(spn.citer(bsl::npos).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.iter(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(spn.iter(bsl::safe_uintmax::zero(true)).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.iter(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(spn.iter(bsl::safe_uintmax::zero(true)).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.citer(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(spn.citer(bsl::safe_uintmax::zero(true)).index() == spn.size());
                };
            };
        };

        bsl::ut_scenario{"rbegin"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.rbegin().get_if() == nullptr);
                    bsl::ut_check(spn.rbegin().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.rbegin().get_if() == nullptr);
                    bsl::ut_check(spn.rbegin().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.rbegin().get_if() == nullptr);
                    bsl::ut_check(spn.crbegin().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.rbegin().get_if()) == bsl::to_i32(42));
                    bsl::ut_check(spn.rbegin().index() == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.rbegin().get_if()) == bsl::to_i32(42));
                    bsl::ut_check(spn.rbegin().index() == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.crbegin().get_if()) == bsl::to_i32(42));
                    bsl::ut_check(spn.crbegin().index() == bsl::to_umax(5));
                };
            };
        };

        bsl::ut_scenario{"rend"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.rend().get_if() == nullptr);
                    bsl::ut_check(spn.rend().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.rend().get_if() == nullptr);
                    bsl::ut_check(spn.rend().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.rend().get_if() == nullptr);
                    bsl::ut_check(spn.crend().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.rend().get_if() == nullptr);
                    bsl::ut_check(spn.rend().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.rend().get_if() == nullptr);
                    bsl::ut_check(spn.rend().index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.crend().get_if() == nullptr);
                    bsl::ut_check(spn.crend().index() == spn.size());
                };
            };
        };

        bsl::ut_scenario{"riter"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.riter(bsl::to_umax(0)).get_if() == nullptr);
                    bsl::ut_check(spn.riter(bsl::to_umax(0)).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.riter(bsl::to_umax(0)).get_if() == nullptr);
                    bsl::ut_check(spn.riter(bsl::to_umax(0)).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.riter(bsl::to_umax(0)).get_if() == nullptr);
                    bsl::ut_check(spn.criter(bsl::to_umax(0)).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.riter(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(spn.riter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.riter(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(spn.riter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(*(spn.criter(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(spn.criter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.riter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(spn.riter(bsl::npos).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.riter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(spn.riter(bsl::npos).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.riter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(spn.riter(bsl::npos).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.riter(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(spn.riter(bsl::safe_uintmax::zero(true)).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.riter(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(spn.riter(bsl::safe_uintmax::zero(true)).index() == spn.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.riter(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(spn.riter(bsl::safe_uintmax::zero(true)).index() == spn.size());
                };
            };
        };

        bsl::ut_scenario{"empty"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.empty());
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.empty());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(!spn.empty());
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(!spn.empty());
                };
            };
        };

        bsl::ut_scenario{"operator bool"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(!spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(!spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(!!spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(!!spn);
                };
            };
        };

        bsl::ut_scenario{"size"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.size() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.size() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.size() == bsl::to_umax(6));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.size() == bsl::to_umax(6));
                };
            };
        };

        bsl::ut_scenario{"max_size"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.max_size() == bsl::safe_uintmax::max() / sizeof(bool));
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.max_size() == bsl::safe_uintmax::max() / sizeof(bool));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(
                        spn.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::safe_int32));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(
                        spn.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::safe_int32));
                };
            };
        };

        bsl::ut_scenario{"size_bytes"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.size_bytes() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.size_bytes() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.size_bytes() == bsl::to_umax(6) * sizeof(bsl::safe_int32));
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.size_bytes() == bsl::to_umax(6) * sizeof(bsl::safe_int32));
                };
            };
        };

        bsl::ut_scenario{"first"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.first() == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.first() == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.first(bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.first(bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.first(bsl::to_umax(0)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.first(bsl::to_umax(0)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.first() == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.first() == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::array arr2{bsl::to_i32(4), bsl::to_i32(8), bsl::to_i32(15)};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.first(bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr1{test_arr};
                bsl::array const arr2{bsl::to_i32(4), bsl::to_i32(8), bsl::to_i32(15)};
                bsl::span const spn1{arr1.data(), arr1.size()};
                bsl::span const spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.first(bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32> spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.first(bsl::to_umax(0)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32 const> const spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.first(bsl::to_umax(0)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32> spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.first(bsl::safe_uintmax::zero(true)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32 const> const spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.first(bsl::safe_uintmax::zero(true)) == spn2);
                };
            };
        };

        bsl::ut_scenario{"last"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.last() == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.last() == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.last(bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.last(bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.last(bsl::to_umax(0)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.last(bsl::to_umax(0)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.last() == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.last() == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::array arr2{bsl::to_i32(16), bsl::to_i32(23), bsl::to_i32(42)};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.last(bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr1{test_arr};
                bsl::array const arr2{bsl::to_i32(16), bsl::to_i32(23), bsl::to_i32(42)};
                bsl::span const spn1{arr1.data(), arr1.size()};
                bsl::span const spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.last(bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32> spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.last(bsl::to_umax(0)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32 const> const spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.last(bsl::to_umax(0)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32> spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.last(bsl::safe_uintmax::zero(true)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32 const> const spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.last(bsl::safe_uintmax::zero(true)) == spn2);
                };
            };
        };

        bsl::ut_scenario{"subspan"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::to_umax(0)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::to_umax(0)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::to_umax(0), bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::to_umax(0), bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::to_umax(1), bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::to_umax(1), bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::npos) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::npos) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::safe_uintmax::zero(true)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::safe_uintmax::zero(true)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::npos, bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::npos, bsl::to_umax(3)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::npos, bsl::npos) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::npos, bsl::npos) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(
                        spn.subspan(bsl::to_umax(0), bsl::safe_uintmax::zero(true)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::span<bool> const spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(
                        spn.subspan(bsl::to_umax(0), bsl::safe_uintmax::zero(true)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::to_umax(0)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::ut_check(spn.subspan(bsl::to_umax(0)) == spn);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::array arr2{bsl::to_i32(16), bsl::to_i32(23), bsl::to_i32(42)};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr1{test_arr};
                bsl::array const arr2{bsl::to_i32(16), bsl::to_i32(23), bsl::to_i32(42)};
                bsl::span const spn1{arr1.data(), arr1.size()};
                bsl::span const spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::array arr2{bsl::to_i32(4), bsl::to_i32(8), bsl::to_i32(15)};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::to_umax(0), bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr1{test_arr};
                bsl::array const arr2{bsl::to_i32(4), bsl::to_i32(8), bsl::to_i32(15)};
                bsl::span const spn1{arr1.data(), arr1.size()};
                bsl::span const spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::to_umax(0), bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::array arr2{bsl::to_i32(8), bsl::to_i32(15), bsl::to_i32(16)};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::to_umax(1), bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr1{test_arr};
                bsl::array const arr2{bsl::to_i32(8), bsl::to_i32(15), bsl::to_i32(16)};
                bsl::span const spn1{arr1.data(), arr1.size()};
                bsl::span const spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::to_umax(1), bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32> spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::npos) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32 const> const spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::npos) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32> spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::npos, bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32 const> const spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::npos, bsl::to_umax(3)) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr{test_arr};
                bsl::span spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32> spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::npos, bsl::npos) == spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span const spn1{arr.data(), arr.size()};
                bsl::span<bsl::safe_int32 const> const spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1.subspan(bsl::npos, bsl::npos) == spn2);
                };
            };
        };

        bsl::ut_scenario{"as_bytes"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                bsl::array arr{test_arr};
                bsl::ut_then{} = [&arr]() {
                    bsl::ut_check(!as_bytes(nullptr, arr.size_bytes()));
                    bsl::ut_check(!as_bytes(arr.data(), bsl::to_umax(0)));
                    bsl::ut_check(!as_bytes(bsl::span{arr.data(), bsl::to_umax(0)}));
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::array arr{test_arr};
                bsl::ut_then{} = [&arr]() {
                    bsl::ut_check(!!as_bytes(arr.data(), arr.size_bytes()));
                    bsl::ut_check(
                        as_bytes(arr.data(), arr.size_bytes()).size() == arr.size_bytes());
                    bsl::ut_check(
                        as_bytes(bsl::span{arr.data(), arr.size()}).size() == arr.size_bytes());
                };
            };
        };

        bsl::ut_scenario{"as_writable_bytes"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                bsl::array arr{test_arr};
                bsl::ut_then{} = [&arr]() {
                    bsl::ut_check(!as_writable_bytes(nullptr, arr.size_bytes()));
                    bsl::ut_check(!as_writable_bytes(arr.data(), bsl::to_umax(0)));
                    bsl::ut_check(!as_writable_bytes(bsl::span{arr.data(), bsl::to_umax(0)}));
                };
            };

            bsl::ut_given_at_runtime{} = []() {
                bsl::array arr{test_arr};
                bsl::ut_then{} = [&arr]() {
                    bsl::ut_check(!!as_writable_bytes(arr.data(), arr.size_bytes()));
                    bsl::ut_check(
                        as_writable_bytes(arr.data(), arr.size_bytes()).size() == arr.size_bytes());
                    bsl::ut_check(
                        as_writable_bytes(bsl::span{arr.data(), arr.size()}).size() ==
                        arr.size_bytes());
                };
            };
        };

        bsl::ut_scenario{"equals"} = []() {
            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::array arr2{test_arr};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1 == spn2);
                };
            };
        };

        bsl::ut_scenario{"not equals"} = []() {
            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span<bsl::safe_int32> spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1 != spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span<bsl::safe_int32> spn2{};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn2 != spn1);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::array arr2{bsl::to_i32(4), bsl::to_i32(8), bsl::to_i32(15)};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1 != spn2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::array arr2{bsl::to_i32(4), bsl::to_i32(8), bsl::to_i32(15)};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn2 != spn1);
                };
            };

            bsl::ut_given{} = []() {
                bsl::array arr1{test_arr};
                bsl::array arr2{test_arr2};
                bsl::span spn1{arr1.data(), arr1.size()};
                bsl::span spn2{arr2.data(), arr2.size()};
                bsl::ut_then{} = [&spn1, &spn2]() {
                    bsl::ut_check(spn1 != spn2);
                };
            };
        };

        bsl::ut_scenario{"output doesn't crash"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bool> spn{};
                bsl::ut_then{} = [&spn]() {
                    bsl::debug() << spn << '\n';
                };
            };

            bsl::ut_given{} = []() {
                bsl::array const arr{test_arr};
                bsl::span spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&spn]() {
                    bsl::debug() << spn << '\n';
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
